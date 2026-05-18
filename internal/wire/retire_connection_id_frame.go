package wire

import (
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A RetireConnectionIDFrame is a RETIRE_CONNECTION_ID frame
type RetireConnectionIDFrame struct {
	SequenceNumber uint64
}

func parseRetireConnectionIDFrame(frame *RetireConnectionIDFrame, b []byte, _ protocol.Version) (int, error) {
	seq, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	frame.SequenceNumber = seq
	return l, nil
}

func (f *RetireConnectionIDFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, retireConnectionIDFrameType)
	b = quicvarint.Append(b, f.SequenceNumber)
	return b, nil
}

// Length of a written frame
func (f *RetireConnectionIDFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(f.SequenceNumber))
}
