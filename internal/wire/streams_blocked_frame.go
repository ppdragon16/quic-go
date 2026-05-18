package wire

import (
	"fmt"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A StreamsBlockedFrame is a STREAMS_BLOCKED frame
type StreamsBlockedFrame struct {
	Type        protocol.StreamType
	StreamLimit protocol.StreamNum
}

func parseStreamsBlockedFrame(frame *StreamsBlockedFrame, b []byte, typ uint64, _ protocol.Version) (int, error) {
	switch typ {
	case bidiStreamBlockedFrameType:
		frame.Type = protocol.StreamTypeBidi
	case uniStreamBlockedFrameType:
		frame.Type = protocol.StreamTypeUni
	}
	streamLimit, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	frame.StreamLimit = protocol.StreamNum(streamLimit)
	if frame.StreamLimit > protocol.MaxStreamCount {
		return 0, fmt.Errorf("%d exceeds the maximum stream count", frame.StreamLimit)
	}
	return l, nil
}

func (f *StreamsBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	switch f.Type {
	case protocol.StreamTypeBidi:
		b = append(b, bidiStreamBlockedFrameType)
	case protocol.StreamTypeUni:
		b = append(b, uniStreamBlockedFrameType)
	}
	b = quicvarint.Append(b, uint64(f.StreamLimit))
	return b, nil
}

// Length of a written frame
func (f *StreamsBlockedFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamLimit)))
}
