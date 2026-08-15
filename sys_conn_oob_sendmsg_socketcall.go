//go:build linux && (386 || s390x)

package quic

import (
	"encoding/binary"
	"syscall"

	"golang.org/x/sys/unix"
)

// sendmsgRaw sends p with control data oob to the raw sockaddr sa. On 386 and
// s390x the sendmsg syscall is multiplexed through socketcall, so use the
// x/sys/unix wrapper (which handles that) after reconstructing a Sockaddr from
// the raw bytes. This allocates, but these architectures are not performance
// targets.
func sendmsgRaw(fd int, p, oob, sa []byte) (int, error) {
	var to unix.Sockaddr
	if len(sa) >= 8 {
		switch binary.NativeEndian.Uint16(sa[:2]) {
		case syscall.AF_INET:
			to = &unix.SockaddrInet4{
				Port: int(binary.BigEndian.Uint16(sa[2:4])),
				Addr: [4]byte(sa[4:8]),
			}
		case syscall.AF_INET6:
			if len(sa) >= 28 {
				to = &unix.SockaddrInet6{
					Port:   int(binary.BigEndian.Uint16(sa[2:4])),
					ZoneId: binary.NativeEndian.Uint32(sa[24:28]),
					Addr:   [16]byte(sa[8:24]),
				}
			}
		}
	}
	return unix.SendmsgN(fd, p, oob, to, 0)
}
