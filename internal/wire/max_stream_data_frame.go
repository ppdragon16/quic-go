package wire

import (
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A MaxStreamDataFrame is a MAX_STREAM_DATA frame
type MaxStreamDataFrame struct {
	StreamID          protocol.StreamID
	MaximumStreamData protocol.ByteCount
}

func parseMaxStreamDataFrame(frame *MaxStreamDataFrame, b []byte, _ protocol.Version) (int, error) {
	startLen := len(b)
	sid, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	offset, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	frame.StreamID = protocol.StreamID(sid)
	frame.MaximumStreamData = protocol.ByteCount(offset)
	return startLen - len(b), nil
}

func (f *MaxStreamDataFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, maxStreamDataFrameType)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.MaximumStreamData))
	return b, nil
}

// Length of a written frame
func (f *MaxStreamDataFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.MaximumStreamData)))
}
