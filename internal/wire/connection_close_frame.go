package wire

import (
	"io"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/quicvarint"
)

// A ConnectionCloseFrame is a CONNECTION_CLOSE frame
type ConnectionCloseFrame struct {
	IsApplicationError bool
	ErrorCode          uint64
	FrameType          uint64
	ReasonPhrase       string
}

func parseConnectionCloseFrame(frame *ConnectionCloseFrame, b []byte, typ uint64, _ protocol.Version) (int, error) {
	startLen := len(b)
	frame.IsApplicationError = typ == applicationCloseFrameType
	ec, l, err := quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	frame.ErrorCode = ec
	// read the Frame Type, if this is not an application error
	if !frame.IsApplicationError {
		ft, l, err := quicvarint.Parse(b)
		if err != nil {
			return 0, replaceUnexpectedEOF(err)
		}
		b = b[l:]
		frame.FrameType = ft
	}
	var reasonPhraseLen uint64
	reasonPhraseLen, l, err = quicvarint.Parse(b)
	if err != nil {
		return 0, replaceUnexpectedEOF(err)
	}
	b = b[l:]
	if int(reasonPhraseLen) > len(b) {
		return 0, io.EOF
	}

	reasonPhrase := make([]byte, reasonPhraseLen)
	copy(reasonPhrase, b)
	frame.ReasonPhrase = string(reasonPhrase)
	return startLen - len(b) + int(reasonPhraseLen), nil
}

// Length of a written frame
func (f *ConnectionCloseFrame) Length(protocol.Version) protocol.ByteCount {
	length := 1 + protocol.ByteCount(quicvarint.Len(f.ErrorCode)+quicvarint.Len(uint64(len(f.ReasonPhrase)))) + protocol.ByteCount(len(f.ReasonPhrase))
	if !f.IsApplicationError {
		length += protocol.ByteCount(quicvarint.Len(f.FrameType)) // for the frame type
	}
	return length
}

func (f *ConnectionCloseFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	if f.IsApplicationError {
		b = append(b, applicationCloseFrameType)
	} else {
		b = append(b, connectionCloseFrameType)
	}

	b = quicvarint.Append(b, f.ErrorCode)
	if !f.IsApplicationError {
		b = quicvarint.Append(b, f.FrameType)
	}
	b = quicvarint.Append(b, uint64(len(f.ReasonPhrase)))
	b = append(b, []byte(f.ReasonPhrase)...)
	return b, nil
}
