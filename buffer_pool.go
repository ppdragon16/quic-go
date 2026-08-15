package quic

import (
	"net"
	"net/netip"
	"sync"
	"time"

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
}

// newRingPool creates a pool with a ring of the given capacity (must be a power of two).
func newRingPool[T any](newFn func() T, capacity int) *ringPool[T] {
	return &ringPool[T]{
		newFn: newFn,
		buf:   make([]ringEntry[T], capacity),
		mask:  capacity - 1,
	}
}

// get returns an object from the ring, the overflow pool, or a fresh allocation.
func (p *ringPool[T]) get() T {
	if v, ok := p.pop(); ok {
		return v
	}
	if v := p.spool.Get(); v != nil {
		return v.(T)
	}
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
	now := time.Now()
	p.mu.Lock()
	if p.n == len(p.buf) {
		// Ring full. Reuse the head slot only if its entry has already
		// expired — entries are inserted in time order so the head is the
		// oldest. The replaced object is demoted to the GC-cleared overflow,
		// same as the sweeper, so it stays reusable until GC.
		if now.Sub(p.buf[p.head].putTime) > poolTTL {
			p.spool.Put(p.buf[p.head].v)
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
		p.buf[p.head] = ringEntry[T]{}
		p.head = (p.head + 1) & p.mask
		p.n--
	}
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
	}, ringCapacity(protocol.MaxPacketBufferSize))
	largeBufferPool = newRingPool(func() *packetBuffer {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxLargePacketBufferSize)}
	}, ringCapacity(protocol.MaxLargePacketBufferSize))
	addrPool = newRingPool(func() *net.UDPAddr {
		return &net.UDPAddr{IP: make([]byte, 16)}
	}, addrRingCapacity)

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
