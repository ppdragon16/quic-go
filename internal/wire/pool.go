package wire

import (
	"sync"

	quicpool "github.com/daeuniverse/quic-go/pool"
)

var streamFramePool sync.Pool
var datagramFramePool sync.Pool

func init() {
	streamFramePool.New = func() any { return &StreamFrame{} }
	datagramFramePool.New = func() any { return &DatagramFrame{} }
}

// GetStreamFrame returns a StreamFrame from the shared pool. The frame's
// Data field is nil; use GetBuffer to allocate Data when needed.
// Return the frame with putStreamFrame (or PutBack) once it has been acked.
func GetStreamFrame() *StreamFrame {
	f := streamFramePool.Get().(*StreamFrame)
	f.Data = nil
	return f
}

// GetDatagramFrame returns a DatagramFrame from the shared pool. The frame's
// Data field is nil; use GetBuffer to allocate Data when needed.
// Return the frame with PutDatagramFrame once it has been packed.
func GetDatagramFrame() *DatagramFrame {
	f := datagramFramePool.Get().(*DatagramFrame)
	f.Data = nil
	return f
}

// PutDatagramFrame returns a pooled DatagramFrame (and its Data buffer via
// PutBuffer) to the pool.
func PutDatagramFrame(f *DatagramFrame) {
	if f.Data != nil {
		quicpool.PutBuffer(f.Data)
	}
	f.DataLenPresent = false
	datagramFramePool.Put(f)
}

func putStreamFrame(f *StreamFrame) {
	if f.Data != nil {
		quicpool.PutBuffer(f.Data)
	}
	streamFramePool.Put(f)
}
