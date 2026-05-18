package wire

import (
	"io"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

// A PathChallengeFrame is a PATH_CHALLENGE frame
type PathChallengeFrame struct {
	Data [8]byte
}

func parsePathChallengeFrame(frame *PathChallengeFrame, b []byte, _ protocol.Version) (int, error) {
	if len(b) < 8 {
		return 0, io.EOF
	}
	copy(frame.Data[:], b)
	return 8, nil
}

func (f *PathChallengeFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, pathChallengeFrameType)
	b = append(b, f.Data[:]...)
	return b, nil
}

// Length of a written frame
func (f *PathChallengeFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + 8
}
