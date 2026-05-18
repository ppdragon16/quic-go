package wire

import (
	"io"
	"testing"

	"github.com/daeuniverse/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseRetireConnectionID(t *testing.T) {
	data := encodeVarInt(0xdeadbeef) // sequence number
	var frame RetireConnectionIDFrame
	l, err := parseRetireConnectionIDFrame(&frame, data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, uint64(0xdeadbeef), frame.SequenceNumber)
	require.Equal(t, len(data), l)
}

func TestParseRetireConnectionIDErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdeadbeef) // sequence number
	var frame RetireConnectionIDFrame
	l, err := parseRetireConnectionIDFrame(&frame, data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, err := parseRetireConnectionIDFrame(&frame, data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteRetireConnectionID(t *testing.T) {
	frame := &RetireConnectionIDFrame{SequenceNumber: 0x1337}
	b, err := frame.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{retireConnectionIDFrameType}
	expected = append(expected, encodeVarInt(0x1337)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(frame.Length(protocol.Version1)))
}
