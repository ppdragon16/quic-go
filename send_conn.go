package quic

import (
	"net"
	"sync/atomic"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/utils"
)

// A sendConn allows sending using a simple Write() on a non-connected packet conn.
type sendConn interface {
	Write(b []byte, gsoSize uint16, ecn protocol.ECN) error
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetRemoteAddr(net.Addr)

	capabilities() connCapabilities
}

type sconn struct {
	rawConn

	localAddr  net.Addr
	remoteAddr atomic.Value

	logger utils.Logger

	packetInfoOOB []byte
	// If GSO enabled, and we receive a GSO error for this remote address, GSO is disabled.
	// Stored from the sendQueue goroutine (Write) and read from the
	// connection's run loop and application goroutines (capabilities),
	// so it must be atomic (quic-go#4228). The check-then-batch race this
	// leaves open is benign by design: a GSO batch composed concurrently
	// with the flip is still drained packet-by-packet by the fallback in
	// Write; the flag only disables future batching.
	gotGSOError atomic.Bool
	// Used to catch the error sometimes returned by the first sendmsg call on Linux,
	// see https://github.com/golang/go/issues/63322.
	// Only accessed from the sendQueue goroutine: every packet write goes
	// through sendQueue.Run, so no synchronization is required.
	wroteFirstPacket bool
}

var _ sendConn = &sconn{}

func newSendConn(c rawConn, remote net.Addr, info packetInfo, logger utils.Logger) *sconn {
	localAddr := c.LocalAddr()
	if info.addr.IsValid() {
		if udpAddr, ok := localAddr.(*net.UDPAddr); ok {
			addrCopy := *udpAddr
			addrCopy.IP = info.addr.AsSlice()
			localAddr = &addrCopy
		}
	}

	oob := info.OOB()
	// increase oob slice capacity, so we can add the UDP_SEGMENT and ECN control messages without allocating
	l := len(oob)
	oob = append(oob, make([]byte, 64)...)[:l]
	sc := &sconn{
		rawConn:       c,
		localAddr:     localAddr,
		remoteAddr:    atomic.Value{},
		packetInfoOOB: oob,
		logger:        logger,
	}
	sc.SetRemoteAddr(remote)
	return sc
}

func (c *sconn) Write(p []byte, gsoSize uint16, ecn protocol.ECN) error {
	remoteAddr := c.remoteAddr.Load().(net.Addr)
	// Route through the lowercase wrapper: it catches the spurious EPERM
	// sometimes returned by the very first sendmsg call on Linux
	// (golang/go#63322) and retries once. Calling WritePacket directly
	// turned that workaround into dead code.
	err := c.writePacket(p, remoteAddr, c.packetInfoOOB, gsoSize, ecn)
	if err != nil && isGSOError(err) {
		// disable GSO for future calls
		c.gotGSOError.Store(true)
		if c.logger.Debug() {
			c.logger.Debugf("GSO failed when sending to %s", remoteAddr)
		}
		// send out the packets one by one
		for len(p) > 0 {
			l := len(p)
			if l > int(gsoSize) {
				l = int(gsoSize)
			}
			if _, err := c.WritePacket(p[:l], remoteAddr, c.packetInfoOOB, 0, ecn); err != nil {
				return err
			}
			p = p[l:]
		}
		return nil
	}
	return err
}

func (c *sconn) writePacket(p []byte, addr net.Addr, oob []byte, gsoSize uint16, ecn protocol.ECN) error {
	_, err := c.WritePacket(p, addr, oob, gsoSize, ecn)
	if err != nil && !c.wroteFirstPacket && isPermissionError(err) {
		_, err = c.WritePacket(p, addr, oob, gsoSize, ecn)
	}
	c.wroteFirstPacket = true
	return err
}

func (c *sconn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	if capabilities.GSO {
		capabilities.GSO = !c.gotGSOError.Load()
	}
	return capabilities
}

func (c *sconn) RemoteAddr() net.Addr { return c.remoteAddr.Load().(net.Addr) }
func (c *sconn) LocalAddr() net.Addr  { return c.localAddr }

func (c *sconn) SetRemoteAddr(addr net.Addr) {
	if addr == nil {
		return
	}
	c.remoteAddr.Store(addr)
}
