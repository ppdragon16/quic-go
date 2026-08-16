package quic

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

type packetBuffer struct {
	Data []byte

	// refCount counts how many packets Data is used in.
	// It doesn't support concurrent use.
	// It is > 1 when used for coalesced packet.
	refCount int

	// addr is the remote address that sent this packet.
	// It shares the lifecycle of the packetBuffer: when the buffer goes back
	// to the pool (via putBack), the addr is also returned to an addr pool.
	// The *net.UDPAddr is recycled and its IP backing array is pre-allocated
	// (16 bytes), so filling from netip.AddrPort requires no allocation.
	addr *net.UDPAddr
}

// Split increases the refCount.
// It must be called when a packet buffer is used for more than one packet,
// e.g. when splitting coalesced packets.
func (b *packetBuffer) Split() {
	b.refCount++
}

// Decrement decrements the reference counter.
// It doesn't put the buffer back into the pool.
func (b *packetBuffer) Decrement() {
	b.refCount--
	if b.refCount < 0 {
		panic("negative packetBuffer refCount")
	}
}

// MaybeRelease puts the packet buffer back into the pool,
// if the reference counter already reached 0.
func (b *packetBuffer) MaybeRelease() {
	// only put the packetBuffer back if it's not used any more
	if b.refCount == 0 {
		b.putBack()
	}
}

// Release puts back the packet buffer into the pool.
// It should be called when processing is definitely finished.
func (b *packetBuffer) Release() {
	b.Decrement()
	if b.refCount != 0 {
		panic("packetBuffer refCount not zero")
	}
	b.putBack()
}

// Len returns the length of Data
func (b *packetBuffer) Len() protocol.ByteCount { return protocol.ByteCount(len(b.Data)) }
func (b *packetBuffer) Cap() protocol.ByteCount { return protocol.ByteCount(cap(b.Data)) }

func (b *packetBuffer) putBack() {
	if b.addr != nil {
		// Only pool addresses whose IP backing array is large enough to be
		// refilled for both IPv4 and IPv6 (fillAddrFromPort needs cap >= 16).
		// Addresses sourced from x/net or the stdlib on the non-OOB paths may
		// have a 4-byte backing array; those are dropped and GC'd instead.
		if cap(b.addr.IP) >= net.IPv6len {
			addrPool.put(b.addr)
		}
		b.addr = nil
	}
	if cap(b.Data) == protocol.MaxPacketBufferSize {
		bufferPool.put(b)
		return
	}
	if cap(b.Data) == protocol.MaxLargePacketBufferSize {
		largeBufferPool.put(b)
		return
	}
	panic("putPacketBuffer called with packet of wrong size!")
}

// bufferPool and largeBufferPool retain packet buffers of the normal and
// GSO-sized capacities, respectively; addrPool retains *net.UDPAddr. They are
// all GC-surviving (see ringPool) so a GC pass does not evict the working set
// of receive buffers/addresses and force fresh allocations.
var bufferPool, largeBufferPool *ringPool[*packetBuffer]
var addrPool *ringPool[*net.UDPAddr]

func getPacketBuffer() *packetBuffer {
	buf := bufferPool.get()
	buf.refCount = 1
	buf.Data = buf.Data[:0]
	buf.addr = nil
	return buf
}

func getLargePacketBuffer() *packetBuffer {
	buf := largeBufferPool.get()
	buf.refCount = 1
	buf.Data = buf.Data[:0]
	buf.addr = nil
	return buf
}

// getPooledAddr returns a *net.UDPAddr from the addr pool, populated from addrPort.
// The IP backing array is pre-allocated (16 bytes), so no allocation.
func getPooledAddr(addrPort netip.AddrPort) *net.UDPAddr {
	addr := addrPool.get()
	fillAddrFromPort(addr, addrPort)
	return addr
}

// fillAddrFromPort fills a *net.UDPAddr from netip.AddrPort.
// addr.IP must have cap >= 16, which is guaranteed by the addr pool.
func fillAddrFromPort(addr *net.UDPAddr, addrPort netip.AddrPort) {
	a := addrPort.Addr()
	if a.Is4() {
		ip4 := a.As4()
		addr.IP = addr.IP[:4]
		copy(addr.IP, ip4[:])
	} else if a.Is6() {
		ip6 := a.As16()
		addr.IP = addr.IP[:16]
		copy(addr.IP, ip6[:])
	} else {
		addr.IP = addr.IP[:0]
	}
	addr.Port = int(addrPort.Port())
	addr.Zone = a.Zone()
}

const (
	// poolTTL is how long a released object may sit idle in a ring before a
	// background sweeper demotes it to the GC-cleared overflow pool, so an idle
	// process does not hold onto peak memory forever.
	poolTTL = 3 * time.Minute

	// poolSweepBatch caps how many expired entries the sweeper demotes from one
	// ring per pass, so it never holds a ring's lock long enough to stall
	// get/put. Leftover expired entries are drained on later passes.
	poolSweepBatch = 512

	// packetBufferByteBudget caps how many bytes each packet-buffer ring may
	// retain across GCs (8 MiB, mirroring the outbound/pool budget).
	packetBufferByteBudget = 8 << 20

	// addrRingCapacity caps how many pooled addresses the addr ring retains
	// across GCs (~4096 × ~56 B ≈ 229 KiB).
	addrRingCapacity = 4096
)

// ringEntry is a pooled object plus the time it was returned to the pool.
type ringEntry[T any] struct {
	v       T
	putTime time.Time
}

// ringPool is a bounded, GC-surviving LIFO ring of T with a GC-cleared
// sync.Pool overflow.
//
// Unlike a plain sync.Pool it is not cleared by the GC: the ring keeps the
// steady-state working set alive across GC cycles, avoiding the allocation
// spiral where every GC pass evicts the objects and the next users each
// re-allocate a fresh one. The ring is bounded (by capacity) and the sweeper
// evicts idle entries (in O(1) from the head) so a quiescent process
// eventually releases its peak memory.
//
// get pops the newest entry (LIFO) for cache locality and so a low-rate
// trickle only keeps the few most-recent objects warm: with LIFO the deeper
// (oldest) entries age out untouched and are reclaimed by the sweeper.
type ringPool[T any] struct {
	newFn func() T

	spool sync.Pool // GC-cleared overflow: ring misses / evictions

	mu   sync.Mutex
	buf  []ringEntry[T] // fixed size == cap == capacity (a power of two)
	head int            // index of the oldest entry
	n    int            // number of live entries
	mask int

	// byteSize is the approximate bytes retained per pooled object, used for
	// the retained-bytes summary in PoolStats.
	byteSize int

	// Cumulative counters, surfaced via PoolStats. Updated with atomics so
	// they never contend with the ring mutex on the hot path.
	gets    atomic.Uint64 // get() calls
	puts    atomic.Uint64 // put() calls
	ringHit atomic.Uint64 // served directly by the GC-surviving ring
	poolHit atomic.Uint64 // served by the GC-cleared sync.Pool overflow
	alloc   atomic.Uint64 // both missed: served by a fresh newFn allocation
	demoted atomic.Uint64 // ring entries evicted to the overflow (sweeper / expired-head reuse)
}

// newRingPool creates a pool with a ring of the given capacity (must be a power
// of two) and an approximate per-object byte size.
func newRingPool[T any](newFn func() T, capacity, byteSize int) *ringPool[T] {
	return &ringPool[T]{
		newFn:    newFn,
		buf:      make([]ringEntry[T], capacity),
		mask:     capacity - 1,
		byteSize: byteSize,
	}
}

// get returns an object from the ring, the overflow pool, or a fresh allocation.
func (p *ringPool[T]) get() T {
	p.gets.Add(1)
	if v, ok := p.pop(); ok {
		p.ringHit.Add(1)
		return v
	}
	if v := p.spool.Get(); v != nil {
		p.poolHit.Add(1)
		return v.(T)
	}
	p.alloc.Add(1)
	return p.newFn()
}

// pop removes and returns the newest (LIFO) object, or false if the ring is empty.
func (p *ringPool[T]) pop() (T, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == 0 {
		var zero T
		return zero, false
	}
	idx := (p.head + p.n - 1) & p.mask
	e := p.buf[idx]
	p.buf[idx] = ringEntry[T]{}
	p.n--
	return e.v, true
}

// put returns v to the ring, or to the overflow pool if the ring is full.
func (p *ringPool[T]) put(v T) {
	p.puts.Add(1)
	now := time.Now()
	p.mu.Lock()
	if p.n == len(p.buf) {
		// Ring full. Reuse the head slot only if its entry has already
		// expired — entries are inserted in time order so the head is the
		// oldest. The replaced object is demoted to the GC-cleared overflow,
		// same as the sweeper, so it stays reusable until GC.
		if now.Sub(p.buf[p.head].putTime) > poolTTL {
			p.spool.Put(p.buf[p.head].v)
			p.demoted.Add(1)
			p.buf[p.head] = ringEntry[T]{v: v, putTime: now}
			p.head = (p.head + 1) & p.mask
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		p.spool.Put(v)
		return
	}
	p.buf[(p.head+p.n)&p.mask] = ringEntry[T]{v: v, putTime: now}
	p.n++
	p.mu.Unlock()
}

// sweep demotes entries that have sat idle since before expiredBefore from the
// ring into the GC-cleared overflow pool. It drains at most poolSweepBatch
// entries per call so the ring lock is never held for long.
func (p *ringPool[T]) sweep(expiredBefore time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < poolSweepBatch && p.n > 0 && p.buf[p.head].putTime.Before(expiredBefore); i++ {
		p.spool.Put(p.buf[p.head].v)
		p.demoted.Add(1)
		p.buf[p.head] = ringEntry[T]{}
		p.head = (p.head + 1) & p.mask
		p.n--
	}
}

// PoolStats is a point-in-time snapshot of a ringPool's counters, mirroring
// the outbound/pool Stats shape so the two buffer pools can be compared with
// the same tooling.
type PoolStats struct {
	Gets      uint64 // get() calls
	Puts      uint64 // put() calls
	RingHit   uint64 // served directly by the GC-surviving ring
	PoolHit   uint64 // served by the GC-cleared sync.Pool overflow
	Alloc     uint64 // both missed: served by a fresh allocation
	Demoted   uint64 // ring entries evicted to the overflow pool
	Occupancy int    // live entries currently held by the ring
	Max       int    // ring capacity
	ByteSize  int    // approximate bytes retained per pooled object
}

// HitRate is the overall reuse efficiency: the fraction of get() calls served
// by a pooled object instead of a fresh allocation.
func (s PoolStats) HitRate() float64 {
	if s.Gets == 0 {
		return 0
	}
	return float64(s.Gets-s.Alloc) / float64(s.Gets)
}

// RingHitRate is the fraction of get() calls served by the GC-surviving ring
// specifically.
func (s PoolStats) RingHitRate() float64 {
	if s.Gets == 0 {
		return 0
	}
	return float64(s.RingHit) / float64(s.Gets)
}

// InFlight is the number of objects currently checked out: gotten but not yet
// put back (Gets - Puts). A leak shows up as this value growing monotonically
// while traffic stays flat.
func (s PoolStats) InFlight() uint64 {
	return s.Gets - s.Puts
}

// stats snapshots one ring pool. Occupancy is read under the ring mutex so it
// is consistent; the counters are atomic loads.
func (p *ringPool[T]) stats() PoolStats {
	p.mu.Lock()
	n := p.n
	p.mu.Unlock()
	return PoolStats{
		Gets:      p.gets.Load(),
		Puts:      p.puts.Load(),
		RingHit:   p.ringHit.Load(),
		PoolHit:   p.poolHit.Load(),
		Alloc:     p.alloc.Load(),
		Demoted:   p.demoted.Load(),
		Occupancy: n,
		Max:       len(p.buf),
		ByteSize:  p.byteSize,
	}
}

// PacketBufferPoolStats returns snapshots of the three GC-surviving pools: the
// normal packet buffers, the large (GSO) packet buffers, and the addresses.
func PacketBufferPoolStats() (buffer, large, addr PoolStats) {
	return bufferPool.stats(), largeBufferPool.stats(), addrPool.stats()
}

// ringCapacity returns the ring capacity for a buffer of bufSize bytes: the
// byte budget divided by bufSize, rounded down to a power of two so the
// mask-based ring indexing stays valid.
func ringCapacity(bufSize int) int {
	n := packetBufferByteBudget / bufSize
	c := 1
	for c*2 <= n {
		c *= 2
	}
	return c
}

func init() {
	bufferPool = newRingPool(func() *packetBuffer {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxPacketBufferSize)}
	}, ringCapacity(protocol.MaxPacketBufferSize), int(unsafe.Sizeof(packetBuffer{}))+protocol.MaxPacketBufferSize)
	largeBufferPool = newRingPool(func() *packetBuffer {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxLargePacketBufferSize)}
	}, ringCapacity(protocol.MaxLargePacketBufferSize), int(unsafe.Sizeof(packetBuffer{}))+protocol.MaxLargePacketBufferSize)
	addrPool = newRingPool(func() *net.UDPAddr {
		return &net.UDPAddr{IP: make([]byte, 16)}
	}, addrRingCapacity, int(unsafe.Sizeof(net.UDPAddr{}))+net.IPv6len)

	// Background sweeper: periodically demote expired objects from each ring
	// into the GC-cleared overflow pool, so an idle process's peak memory is
	// actually released on the next GC.
	go func() {
		t := time.NewTicker(poolTTL / 2)
		defer t.Stop()
		for range t.C {
			expiredBefore := time.Now().Add(-poolTTL)
			bufferPool.sweep(expiredBefore)
			largeBufferPool.sweep(expiredBefore)
			addrPool.sweep(expiredBefore)
		}
	}()
}
