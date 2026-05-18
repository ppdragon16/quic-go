package wire

import (
	"fmt"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A MaxStreamsFrame is a MAX_STREAMS frame
type MaxStreamsFrame struct {
	Type         protocol.StreamType
	MaxStreamNum protocol.StreamNum
}

func parseMaxStreamsFrame(frame *MaxStreamsFrame, b []byte, typ uint64, _ protocol.Version) (int, error) {
	switch typ {
	case bidiMaxStreamsFrameType:
		frame.Type = protocol.StreamTypeBidi
	case uniMaxStreamsFrameType:
		frame.Type = protocol.StreamTypeUni
	}
	streamID, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	frame.MaxStreamNum = protocol.StreamNum(streamID)
	if frame.MaxStreamNum > protocol.MaxStreamCount {
		return 0, fmt.Errorf("%d exceeds the maximum stream count", frame.MaxStreamNum)
	}
	return l, nil
}

func (f *MaxStreamsFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	switch f.Type {
	case protocol.StreamTypeBidi:
		b = append(b, bidiMaxStreamsFrameType)
	case protocol.StreamTypeUni:
		b = append(b, uniMaxStreamsFrameType)
	}
	b = quicvarint.Append(b, uint64(f.MaxStreamNum))
	return b, nil
}

// Length of a written frame
func (f *MaxStreamsFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.MaxStreamNum)))
}
