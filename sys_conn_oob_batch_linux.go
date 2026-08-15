//go:build linux && !386 && !s390x

package quic

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

// sockaddrBufSize is the per-datagram buffer reserved for the raw sockaddr
// written by recvmmsg. 28 bytes (sockaddr_in6) is the maximum for UDP, but a
// larger buffer is harmless and guards against any other address family the
// kernel might report.
const sockaddrBufSize = 128

// mmsghdr mirrors the kernel's struct mmsghdr: a struct msghdr followed by a
// msg_len. We reuse unix.Msghdr (already correct per-arch, including its
// padding) and rely on Go's own trailing padding to match the C layout, which
// holds on both 32- and 64-bit: struct mmsghdr == struct msghdr + uint32.
type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
}

func recvmmsg(fd int, hs []mmsghdr, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(
		syscall.SYS_RECVMMSG, uintptr(fd), uintptr(unsafe.Pointer(&hs[0])),
		uintptr(len(hs)), uintptr(flags), 0, 0)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

// linuxOOBRead is the recvmmsg-based batched reader. Unlike the x/net
// ReadBatch path, it never allocates a *net.UDPAddr per datagram: the raw
// sockaddr bytes are parsed straight into a pooled address (see
// sockaddrToPooledAddr).
type linuxOOBRead struct {
	hs        [batchSize]mmsghdr
	iovs      [batchSize]unix.Iovec
	sockaddrs [batchSize][sockaddrBufSize]byte
	oob       [batchSize][oobBufferSize]byte
}

func newOOBReadState(OOBCapablePacketConn) oobReadState {
	return &linuxOOBRead{}
}

func (r *linuxOOBRead) read(c *oobConn, refill int) (int, error) {
	// Acquire fresh packet buffers for the slots consumed since the last
	// batch. The remaining slots still hold pristine buffers and are reused.
	for i := 0; i < refill; i++ {
		buffer := getPacketBuffer()
		buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
		c.buffers[i] = buffer
	}
	for i := 0; i < batchSize; i++ {
		buffer := c.buffers[i]
		if buffer == nil { // first batch: lazily acquire
			buffer = getPacketBuffer()
			buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
			c.buffers[i] = buffer
		}
		buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
		sa := &r.sockaddrs[i]
		hdr := &r.hs[i].Hdr
		hdr.Name = (*byte)(unsafe.Pointer(sa))
		hdr.Namelen = sockaddrBufSize
		hdr.Iov = &r.iovs[i]
		hdr.SetIovlen(1)
		r.iovs[i].Base = &buffer.Data[0]
		r.iovs[i].SetLen(len(buffer.Data))
		hdr.Control = &r.oob[i][0]
		hdr.SetControllen(len(r.oob[i]))
		hdr.Flags = 0
		r.hs[i].Len = 0
	}

	var n int
	var errno error
	err := c.rawConn.Read(func(fd uintptr) bool {
		n, errno = recvmmsg(int(fd), r.hs[:], 0)
		return errno != syscall.EAGAIN && errno != syscall.EWOULDBLOCK
	})
	if err != nil {
		return n, err
	}
	if errno != nil {
		return n, errno
	}
	return n, nil
}

func (r *linuxOOBRead) datagram(c *oobConn, i int) (payload, oob []byte, addr *net.UDPAddr) {
	hdr := &r.hs[i].Hdr
	buffer := c.buffers[i]
	payload = buffer.Data[:r.hs[i].Len]
	oob = r.oob[i][:hdr.Controllen]
	addr = sockaddrToPooledAddr(r.sockaddrs[i][:hdr.Namelen])
	buffer.addr = addr
	return
}

// sockaddrToPooledAddr parses a raw sockaddr (as returned by recvmmsg) into a
// pooled *net.UDPAddr, avoiding the per-datagram allocation that
// x/net's parseInetAddr performs. The address is recycled via addrPool when
// the owning packetBuffer is released.
func sockaddrToPooledAddr(sa []byte) *net.UDPAddr {
	if len(sa) < 2 {
		return getPooledAddr(netip.AddrPort{})
	}
	family := binary.NativeEndian.Uint16(sa[:2])
	switch family {
	case syscall.AF_INET:
		if len(sa) < 8 {
			return getPooledAddr(netip.AddrPort{})
		}
		ip := netip.AddrFrom4(*(*[4]byte)(sa[4:8]))
		return getPooledAddr(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(sa[2:4])))
	case syscall.AF_INET6:
		if len(sa) < 28 {
			return getPooledAddr(netip.AddrPort{})
		}
		ip := netip.AddrFrom16(*(*[16]byte)(sa[8:24]))
		port := binary.BigEndian.Uint16(sa[2:4])
		if scope := binary.NativeEndian.Uint32(sa[24:28]); scope > 0 {
			if ifi, err := net.InterfaceByIndex(int(scope)); err == nil {
				ip = ip.WithZone(ifi.Name)
			}
		}
		return getPooledAddr(netip.AddrPortFrom(ip, port))
	default:
		return getPooledAddr(netip.AddrPort{})
	}
}
