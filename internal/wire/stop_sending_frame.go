package wire

import (
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/qerr"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A StopSendingFrame is a STOP_SENDING frame
type StopSendingFrame struct {
	StreamID  protocol.StreamID
	ErrorCode qerr.StreamErrorCode
}

// parseStopSendingFrame parses a STOP_SENDING frame
func parseStopSendingFrame(frame *StopSendingFrame, b []byte, _ protocol.Version) (int, error) {
	startLen := len(b)
	streamID, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	errorCode, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]

	frame.StreamID = protocol.StreamID(streamID)
	frame.ErrorCode = qerr.StreamErrorCode(errorCode)
	return startLen - len(b), nil
}

// Length of a written frame
func (f *StopSendingFrame) Length(_ protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.ErrorCode)))
}

func (f *StopSendingFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, stopSendingFrameType)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.ErrorCode))
	return b, nil
}
