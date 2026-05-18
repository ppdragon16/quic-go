package wire

import (
	"io"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

// A PathResponseFrame is a PATH_RESPONSE frame
type PathResponseFrame struct {
	Data [8]byte
}

func parsePathResponseFrame(frame *PathResponseFrame, b []byte, _ protocol.Version) (int, error) {
	if len(b) < 8 {
		return 0, io.EOF
	}
	copy(frame.Data[:], b)
	return 8, nil
}

func (f *PathResponseFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, pathResponseFrameType)
	b = append(b, f.Data[:]...)
	return b, nil
}

// Length of a written frame
func (f *PathResponseFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + 8
}
