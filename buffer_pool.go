package quic

import (
	"net"
	"net/netip"
	"sync"

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
		bufferPool.Put(b)
		return
	}
	if cap(b.Data) == protocol.MaxLargePacketBufferSize {
		largeBufferPool.Put(b)
		return
	}
	panic("putPacketBuffer called with packet of wrong size!")
}

var bufferPool, largeBufferPool sync.Pool
var addrPool sync.Pool

func getPacketBuffer() *packetBuffer {
	buf := bufferPool.Get().(*packetBuffer)
	buf.refCount = 1
	buf.Data = buf.Data[:0]
	buf.addr = nil
	return buf
}

func getLargePacketBuffer() *packetBuffer {
	buf := largeBufferPool.Get().(*packetBuffer)
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

func init() {
	bufferPool.New = func() any {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxPacketBufferSize)}
	}
	largeBufferPool.New = func() any {
		return &packetBuffer{Data: make([]byte, 0, protocol.MaxLargePacketBufferSize)}
	}
	addrPool.New = func() any {
		return &net.UDPAddr{IP: make([]byte, 16)}
	}
}
