package wire

import (
	"io"
	"testing"

	"github.com/daeuniverse/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

func TestParseMaxDataFrame(t *testing.T) {
	data := encodeVarInt(0xdecafbad123456) // byte offset
	var frame MaxDataFrame
	l, err := parseMaxDataFrame(&frame, data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(0xdecafbad123456), frame.MaximumData)
	require.Equal(t, len(data), l)
}

func TestParseMaxDataErrorsOnEOFs(t *testing.T) {
	data := encodeVarInt(0xdecafbad1234567) // byte offset
	var frame MaxDataFrame
	l, err := parseMaxDataFrame(&frame, data, protocol.Version1)
	require.NoError(t, err)
	require.Equal(t, len(data), l)
	for i := range data {
		_, err := parseMaxDataFrame(&frame, data[:i], protocol.Version1)
		require.Equal(t, io.EOF, err)
	}
}

func TestWriteMaxDataFrame(t *testing.T) {
	f := &MaxDataFrame{MaximumData: 0xdeadbeefcafe}
	b, err := f.Append(nil, protocol.Version1)
	require.NoError(t, err)
	expected := []byte{maxDataFrameType}
	expected = append(expected, encodeVarInt(0xdeadbeefcafe)...)
	require.Equal(t, expected, b)
	require.Len(t, b, int(f.Length(protocol.Version1)))
}
