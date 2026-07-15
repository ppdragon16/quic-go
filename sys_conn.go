package quic

import (
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/utils"
)

// OOBCapablePacketConn is a connection that allows the reading of ECN bits from the IP header.
// If the PacketConn passed to Dial or Listen satisfies this interface, quic-go will use it.
// In this case, ReadMsgUDP() will be used instead of ReadFrom() to read packets.
type OOBCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

var _ OOBCapablePacketConn = &net.UDPConn{}

func wrapConn(pc net.PacketConn) (rawConn, error) {
	_ = setReceiveBuffer(pc)
	_ = setSendBuffer(pc)

	conn, ok := pc.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	var supportsDF bool
	if ok {
		rawConn, err := conn.SyscallConn()
		if err != nil {
			return nil, err
		}

		// only set DF on UDP sockets
		if _, ok := pc.LocalAddr().(*net.UDPAddr); ok {
			var err error
			supportsDF, err = setDF(rawConn)
			if err != nil {
				return nil, err
			}
		}
	}
	c, ok := pc.(OOBCapablePacketConn)
	if !ok {
		utils.DefaultLogger.Infof("PacketConn is not a net.UDPConn. Disabling optimizations possible on UDP connections.")
		return &basicConn{PacketConn: pc, supportsDF: supportsDF}, nil
	}
	return newConn(c, supportsDF)
}

// The basicConn is the most trivial implementation of a rawConn.
// It reads a single packet from the underlying net.PacketConn.
// It is used when
// * the net.PacketConn is not a OOBCapablePacketConn, and
// * when the OS doesn't support OOB.
type basicConn struct {
	net.PacketConn
	supportsDF bool
}

var _ rawConn = &basicConn{}

func (c *basicConn) ReadPacket() (receivedPacket, error) {
	buffer := getPacketBuffer()
	// The packet size should not exceed protocol.MaxPacketBufferSize bytes
	// If it does, we only read a truncated packet, which will then end up undecryptable
	buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]

	// Fast path: use ReadFromUDPAddrPort / ReadFromAddrPort (Go 1.18+) to get
	// netip.AddrPort without heap allocation, then fill a pooled *net.UDPAddr.
	var n int
	var addrPort netip.AddrPort
	var err error

	if udpConn, ok := c.PacketConn.(*net.UDPConn); ok {
		n, addrPort, err = udpConn.ReadFromUDPAddrPort(buffer.Data)
	} else if apr, ok := c.PacketConn.(interface {
		ReadFromAddrPort(p []byte) (n int, addr netip.AddrPort, err error)
	}); ok {
		n, addrPort, err = apr.ReadFromAddrPort(buffer.Data)
	}
	if err != nil {
		return receivedPacket{}, err
	}
	if addrPort.IsValid() {
		buffer.addr = getPooledAddr(addrPort)
		return receivedPacket{
			remoteAddr: buffer.addr,
			rcvTime:    time.Now(),
			data:       buffer.Data[:n],
			buffer:     buffer,
		}, nil
	}

	// Fallback: use net.PacketConn.ReadFrom.
	// The *net.UDPAddr is allocated by the stdlib, but we store it in buffer.addr
	// so it gets recycled via the addr pool when the buffer is released.
	n, addr, err := c.PacketConn.ReadFrom(buffer.Data)
	if err != nil {
		return receivedPacket{}, err
	}
	buffer.addr = addr.(*net.UDPAddr)
	return receivedPacket{
		remoteAddr: buffer.addr,
		rcvTime:    time.Now(),
		data:       buffer.Data[:n],
		buffer:     buffer,
	}, nil
}

func (c *basicConn) WritePacket(b []byte, addr net.Addr, _ []byte, gsoSize uint16, ecn protocol.ECN) (n int, err error) {
	if gsoSize != 0 {
		panic("cannot use GSO with a basicConn")
	}
	if ecn != protocol.ECNUnsupported {
		panic("cannot use ECN with a basicConn")
	}
	return c.PacketConn.WriteTo(b, addr)
}

func (c *basicConn) capabilities() connCapabilities { return connCapabilities{DF: c.supportsDF} }
