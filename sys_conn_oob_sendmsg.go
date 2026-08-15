//go:build darwin || freebsd || (linux && !386 && !s390x)

package quic

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendmsgRaw sends p with control data oob to the raw sockaddr sa using a
// single sendmsg syscall. All buffers are consumed synchronously by the
// syscall, so they may live on the caller's stack (no per-send allocation).
func sendmsgRaw(fd int, p, oob, sa []byte) (int, error) {
	var iov unix.Iovec
	var msg unix.Msghdr
	if len(p) > 0 {
		iov.Base = &p[0]
		iov.SetLen(len(p))
		msg.Iov = &iov
		msg.SetIovlen(1)
	}
	if len(oob) > 0 {
		msg.Control = &oob[0]
		msg.SetControllen(len(oob))
	}
	if len(sa) > 0 {
		msg.Name = &sa[0]
		msg.Namelen = uint32(len(sa))
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(&msg)), 0, 0, 0, 0)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}
