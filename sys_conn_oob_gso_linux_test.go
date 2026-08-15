//go:build linux

package quic

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

func TestSysConnSendGSO(t *testing.T) {
	if !platformSupportsGSO {
		t.Skip("GSO not supported on this platform")
	}

	// GSO is requested by appending a UDP_SEGMENT control message to the OOB
	// data. Verify it is well-formed.
	oob := appendUDPSegmentSizeMsg(nil, 3)
	require.NotEmpty(t, oob)
	hdr, body, _, err := unix.ParseOneSocketControlMessage(oob)
	require.NoError(t, err)
	require.Equal(t, int(unix.IPPROTO_UDP), int(hdr.Level))
	require.Equal(t, int(unix.UDP_SEGMENT), int(hdr.Type))
	require.Equal(t, uint16(3), binary.NativeEndian.Uint16(body))
}
