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
	// in addrPool.New, so filling from netip.AddrPort requires no allocation.
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
		addrPool.Put(b.addr)
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
// GSO-sized capacities, respectively. They are GC-surviving (see
// packetBufferPool) so a GC pass does not evict the working set of receive
// buffers and force a fresh allocation of their (relatively large) backing
// arrays.
var bufferPool, largeBufferPool *packetBufferPool

var addrPool sync.Pool

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
// The IP backing array is pre-allocated by addrPool.New (16 bytes), so no allocation.
func getPooledAddr(addrPort netip.AddrPort) *net.UDPAddr {
	addr := addrPool.Get().(*net.UDPAddr)
	fillAddrFromPort(addr, addrPort)
	return addr
}

// fillAddrFromPort fills a *net.UDPAddr from netip.AddrPort.
// addr.IP must have cap >= 16, which is guaranteed by addrPool.New.
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
	// packetBufferByteBudget caps how many bytes each packet-buffer pool may
	// retain across GCs (8 MiB, mirroring the outbound/pool budget).
	packetBufferByteBudget = 8 << 20

	// packetBufferTTL is how long a released buffer may sit idle in the ring
	// before a background sweeper demotes it to the GC-cleared overflow pool,
	// so an idle process does not hold onto peak memory forever.
	packetBufferTTL = 3 * time.Minute

	// packetBufferSweepBatch caps how many expired entries the sweeper demotes
	// from one pool per pass, so it never holds a ring's lock long enough to
	// stall get/put. Leftover expired entries are drained on later passes.
	packetBufferSweepBatch = 512
)

// bufEntry is a pooled buffer plus the time it was returned to the pool.
type bufEntry struct {
	ptr     *packetBuffer
	putTime time.Time
}

// packetBufferPool is a bounded, GC-surviving LIFO ring of *packetBuffer with
// a GC-cleared sync.Pool overflow.
//
// Unlike a plain sync.Pool it is not cleared by the GC: the ring keeps the
// steady-state working set of receive buffers alive across GC cycles, avoiding
// the allocation spiral where every GC pass evicts the buffers and the next
// packets each re-allocate a fresh MaxPacketBufferSize backing array. The ring
// is bounded by a byte budget and the sweeper evicts idle entries (in O(1)
// from the head) so a quiescent process eventually releases its peak memory.
//
// get pops the newest entry (LIFO) for cache locality and so a low-rate
// trickle only keeps the few most-recent buffers warm: with LIFO the deeper
// (oldest) entries age out untouched and are reclaimed by the sweeper.
type packetBufferPool struct {
	newFn func() *packetBuffer

	spool sync.Pool // GC-cleared overflow: ring misses / evictions

	mu   sync.Mutex
	buf  []bufEntry // fixed size == cap == max (a power of two)
	head int        // index of the oldest entry
	n    int        // number of live entries
	mask int
}

// newPacketBufferPool creates a pool with a ring of the given capacity.
func newPacketBufferPool(newFn func() *packetBuffer, capacity int) *packetBufferPool {
	return &packetBufferPool{
		newFn: newFn,
		buf:   make([]bufEntry, capacity),
		mask:  capacity - 1,
	}
}

// get returns a buffer from the ring, the overflow pool, or a fresh allocation.
func (p *packetBufferPool) get() *packetBuffer {
	if b := p.pop(); b != nil {
		return b
	}
	if v := p.spool.Get(); v != nil {
		return v.(*packetBuffer)
	}
	return p.newFn()
}

// pop removes and returns the newest (LIFO) buffer, or nil if the ring is empty.
func (p *packetBufferPool) pop() *packetBuffer {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == 0 {
		return nil
	}
	idx := (p.head + p.n - 1) & p.mask
	e := p.buf[idx]
	p.buf[idx] = bufEntry{}
	p.n--
	return e.ptr
}

// put returns b to the ring, or to the overflow pool if the ring is full.
func (p *packetBufferPool) put(b *packetBuffer) {
	now := time.Now()
	p.mu.Lock()
	if p.n == len(p.buf) {
		// Ring full. Reuse the head slot only if its entry has already
		// expired — entries are inserted in time order so the head is the
		// oldest. The replaced buffer is demoted to the GC-cleared overflow,
		// same as the sweeper, so it stays reusable until GC.
		if now.Sub(p.buf[p.head].putTime) > packetBufferTTL {
			p.spool.Put(p.buf[p.head].ptr)
			p.buf[p.head] = bufEntry{ptr: b, putTime: now}
			p.head = (p.head + 1) & p.mask
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()
		p.spool.Put(b)
		return
	}
	p.buf[(p.head+p.n)&p.mask] = bufEntry{ptr: b, putTime: now}
	p.n++
	p.mu.Unlock()
}

// sweep demotes entries that have sat idle since before expiredBefore from the
// ring into the GC-cleared overflow pool. It drains at most packetBufferSweepBatch
// entries per call so the ring lock is never held for long.
func (p *packetBufferPool) sweep(expiredBefore time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < packetBufferSweepBatch && p.n > 0 && p.buf[p.head].putTime.Before(expiredBefore); i++ {
		p.spool.Put(p.buf[p.head].ptr)
		p.buf[p.head] = bufEntry{}
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
	bufferPool = newPacketBufferPool(func() *packetBuffer {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxPacketBufferSize)}
	}, ringCapacity(protocol.MaxPacketBufferSize))
	largeBufferPool = newPacketBufferPool(func() *packetBuffer {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxLargePacketBufferSize)}
	}, ringCapacity(protocol.MaxLargePacketBufferSize))
	addrPool.New = func() any {
		return &net.UDPAddr{IP: make([]byte, 16)}
	}

	// Background sweeper: periodically demote expired buffers from each ring
	// into the GC-cleared overflow pool, so an idle process's peak memory is
	// actually released on the next GC.
	go func() {
		t := time.NewTicker(packetBufferTTL / 2)
		defer t.Stop()
		for range t.C {
			expiredBefore := time.Now().Add(-packetBufferTTL)
			bufferPool.sweep(expiredBefore)
			largeBufferPool.sweep(expiredBefore)
		}
	}()
}
