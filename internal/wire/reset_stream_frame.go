package wire

import (
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/qerr"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A ResetStreamFrame is a RESET_STREAM frame in QUIC
type ResetStreamFrame struct {
	StreamID  protocol.StreamID
	ErrorCode qerr.StreamErrorCode
	FinalSize protocol.ByteCount
}

func parseResetStreamFrame(frame *ResetStreamFrame, b []byte, _ protocol.Version) (int, error) {
	startLen := len(b)
	sid, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	frame.StreamID = protocol.StreamID(sid)
	errorCode, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	frame.ErrorCode = qerr.StreamErrorCode(errorCode)
	bo, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	frame.FinalSize = protocol.ByteCount(bo)
	return startLen - len(b) + l, nil
}

func (f *ResetStreamFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, resetStreamFrameType)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.ErrorCode))
	b = quicvarint.Append(b, uint64(f.FinalSize))
	return b, nil
}

// Length of a written frame
func (f *ResetStreamFrame) Length(protocol.Version) protocol.ByteCount {
	return 1 + protocol.ByteCount(quicvarint.Len(uint64(f.StreamID))+quicvarint.Len(uint64(f.ErrorCode))+quicvarint.Len(uint64(f.FinalSize)))
}
