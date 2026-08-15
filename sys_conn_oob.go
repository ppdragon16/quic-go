//go:build darwin || linux || freebsd

package quic

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/utils"
)

const (
	ecnMask       = 0x3
	oobBufferSize = 128
)

func inspectReadBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func inspectWriteBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func isECNDisabledUsingEnv() bool {
	disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN"))
	return err == nil && disabled
}

// oobReadState is the platform-specific batched-receive machinery of an
// oobConn. It owns everything that differs between implementations: on Linux
// it is a direct recvmmsg loop that parses raw sockaddr bytes into a pooled
// *net.UDPAddr (no per-packet allocation), and elsewhere it is the x/net
// ReadBatch path.
type oobReadState interface {
	// read refills the `refill` most-recently-consumed buffer slots with fresh
	// packet buffers, issues one batched read, and returns the number of
	// datagrams received.
	read(c *oobConn, refill int) (int, error)
	// datagram returns the payload, received control-message bytes, and the
	// remote address of the i-th received datagram (0 <= i < n). It stores the
	// address on the packet buffer so it is recycled when the buffer is
	// released.
	datagram(c *oobConn, i int) (payload, oob []byte, addr *net.UDPAddr)
}

type oobConn struct {
	OOBCapablePacketConn
	rawConn syscall.RawConn

	readPos  uint8
	msgCount int
	buffers  [batchSize]*packetBuffer
	read     oobReadState

	cap connCapabilities
}

var _ rawConn = &oobConn{}

func newConn(c OOBCapablePacketConn, supportsDF bool) (*oobConn, error) {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return nil, err
	}
	var needsPacketInfo bool
	if udpAddr, ok := c.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}
	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errECNIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		errECNIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)

		if needsPacketInfo {
			errPIIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipv4PKTINFO, 1)
			errPIIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		}
	}); err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			return nil, errors.New("activating packet info failed for both IPv4 and IPv6")
		}
	}

	oobConn := &oobConn{
		OOBCapablePacketConn: c,
		rawConn:              rawConn,
		read:                 newOOBReadState(c),
		cap: connCapabilities{
			DF:  supportsDF,
			GSO: isGSOEnabled(rawConn),
			ECN: isECNEnabled(),
		},
	}
	return oobConn, nil
}

var invalidCmsgOnceV4, invalidCmsgOnceV6 sync.Once

func (c *oobConn) ReadPacket() (receivedPacket, error) {
	if int(c.readPos) == c.msgCount { // all messages read. Read the next batch of messages.
		n, err := c.read.read(c, int(c.readPos))
		if n == 0 || err != nil {
			return receivedPacket{}, err
		}
		c.msgCount = n
		c.readPos = 0
	}

	i := int(c.readPos)
	payload, oob, addr := c.read.datagram(c, i)
	buffer := c.buffers[i]
	c.readPos++

	p := receivedPacket{
		remoteAddr: addr,
		rcvTime:    time.Now(),
		data:       payload,
		buffer:     buffer,
	}
	for len(oob) > 0 {
		hdr, body, remainder, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return receivedPacket{}, err
		}
		if hdr.Level == unix.IPPROTO_IP {
			switch hdr.Type {
			case msgTypeIPTOS:
				p.ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
			case ipv4PKTINFO:
				ip, ifIndex, ok := parseIPv4PktInfo(body)
				if ok {
					p.info.addr = ip
					p.info.ifIndex = ifIndex
				} else {
					invalidCmsgOnceV4.Do(func() {
						log.Printf("Received invalid IPv4 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		if hdr.Level == unix.IPPROTO_IPV6 {
			switch hdr.Type {
			case unix.IPV6_TCLASS:
				p.ecn = protocol.ParseECNHeaderBits(body[0] & ecnMask)
			case unix.IPV6_PKTINFO:
				// struct in6_pktinfo {
				// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
				// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
				// };
				if len(body) == 20 {
					p.info.addr = netip.AddrFrom16(*(*[16]byte)(body[:16])).Unmap()
					p.info.ifIndex = binary.LittleEndian.Uint32(body[16:])
				} else {
					invalidCmsgOnceV6.Do(func() {
						log.Printf("Received invalid IPv6 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		oob = remainder
	}
	return p, nil
}

// WritePacket writes a new packet.
func (c *oobConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("quic: oobConn.WritePacket: address is not a *net.UDPAddr")
	}

	oob := packetInfoOOB
	if gsoSize > 0 {
		if !c.capabilities().GSO {
			panic("GSO disabled")
		}
		// Only request UDP GSO when the payload will actually be segmented.
		// Some drivers/devices misbehave when UDP_SEGMENT is set for an
		// effectively single-segment send (segment_size >= payload length).
		if len(b) > int(gsoSize) {
			oob = appendUDPSegmentSizeMsg(oob, gsoSize)
		}
	}

	// Marshal the remote address into a raw sockaddr on the stack. This avoids
	// the per-send syscall.Sockaddr allocation that net.UDPConn.WriteMsgUDP
	// performs via net.ipToSockaddr — the largest allocation source on the
	// QUIC send path.
	isIPv4 := udpAddr.IP.To4() != nil
	var saBuf [28]byte // sockaddr_in6 is the largest sockaddr used here
	salen, err := marshalSockaddr(saBuf[:], udpAddr, isIPv4)
	if err != nil {
		return 0, err
	}

	if ecn != protocol.ECNUnsupported {
		if !c.capabilities().ECN {
			panic("tried to send an ECN-marked packet although ECN is disabled")
		}
		if isIPv4 {
			oob = appendIPv4ECNMsg(oob, ecn)
		} else {
			oob = appendIPv6ECNMsg(oob, ecn)
		}
	}

	var n int
	err = c.rawConn.Write(func(fd uintptr) bool {
		var werr error
		n, werr = sendmsgRaw(int(fd), b, oob, saBuf[:salen])
		return werr != syscall.EAGAIN && werr != syscall.EWOULDBLOCK
	})
	if err != nil {
		return n, err
	}
	return n, nil
}

// marshalSockaddr marshals addr into buf as a raw sockaddr (sockaddr_in for
// IPv4, sockaddr_in6 for IPv6) and returns the number of bytes written.
func marshalSockaddr(buf []byte, addr *net.UDPAddr, isIPv4 bool) (int, error) {
	if addr.Port < 0 || addr.Port > 0xFFFF {
		return 0, errors.New("quic: invalid UDP port")
	}
	if isIPv4 {
		ip4 := addr.IP.To4()
		// sockaddr_in: family + port + addr + 8 bytes of zero padding.
		binary.NativeEndian.PutUint16(buf[0:2], syscall.AF_INET)
		binary.BigEndian.PutUint16(buf[2:4], uint16(addr.Port))
		copy(buf[4:8], ip4)
		return 16, nil
	}
	ip6 := addr.IP.To16()
	if ip6 == nil {
		return 0, errors.New("quic: invalid IP address")
	}
	var zoneID uint32
	if addr.Zone != "" {
		ifi, err := net.InterfaceByName(addr.Zone)
		if err != nil {
			return 0, err
		}
		zoneID = uint32(ifi.Index)
	}
	// sockaddr_in6: family + port + flowinfo + addr + scope_id.
	binary.NativeEndian.PutUint16(buf[0:2], syscall.AF_INET6)
	binary.BigEndian.PutUint16(buf[2:4], uint16(addr.Port))
	// flowinfo (buf[4:8]) stays zero.
	copy(buf[8:24], ip6)
	binary.NativeEndian.PutUint32(buf[24:28], zoneID)
	return 28, nil
}

func (c *oobConn) capabilities() connCapabilities {
	return c.cap
}

type packetInfo struct {
	addr    netip.Addr
	ifIndex uint32
}

func (info *packetInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if info.addr.Is4() {
		ip := info.addr.As4()
		// struct in_pktinfo {
		// 	unsigned int   ipi_ifindex;  /* Interface index */
		// 	struct in_addr ipi_spec_dst; /* Local address */
		// 	struct in_addr ipi_addr;     /* Header Destination address */
		// };
		cm := ipv4.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	} else if info.addr.Is6() {
		ip := info.addr.As16()
		// struct in6_pktinfo {
		// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
		// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
		// };
		cm := ipv6.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.ifIndex),
		}
		return cm.Marshal()
	}
	return nil
}

func appendIPv4ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(ecnIPv4DataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IP
	h.Type = unix.IP_TOS
	h.SetLen(unix.CmsgLen(ecnIPv4DataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	b[offset] = val.ToHeaderBits()
	return b
}

func appendIPv6ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	const dataLen = 4
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IPV6
	h.Type = unix.IPV6_TCLASS
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	b[offset] = val.ToHeaderBits()
	return b
}
