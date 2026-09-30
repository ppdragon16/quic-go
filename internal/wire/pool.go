package wire

import (
	"github.com/daeuniverse/quic-go/internal/utils"
	quicpool "github.com/daeuniverse/quic-go/pool"
)

// The shared frame pools. Frame structs are pooled rather than allocated per
// frame: a received or sent frame is short-lived and handed straight back, so
// recycling them removes the per-frame allocation from both hot paths.
var (
	streamFramePool   = utils.NewPool(func() *StreamFrame { return &StreamFrame{} }, framePoolMax)
	datagramFramePool = utils.NewPool(func() *DatagramFrame { return &DatagramFrame{} }, framePoolMax)
)

// framePoolMax bounds how many frames each pool retains. Frames are tens of
// bytes, so this caps retention at a few hundred KB per pool while still
// covering the in-flight working set of a busy relay.
const framePoolMax = 4096

// GetStreamFrame returns a StreamFrame from the shared pool. The frame's
// Data field is nil; use GetBuffer to allocate Data when needed.
// Return the frame with putStreamFrame (or PutBack) once it has been acked.
func GetStreamFrame() *StreamFrame {
	f := streamFramePool.Get()
	f.Data = nil
	f.putBack = false
	return f
}

// GetDatagramFrame returns a DatagramFrame from the shared pool. The frame's
// Data field is nil; use GetBuffer to allocate Data when needed.
// Return the frame with PutDatagramFrame once it has been packed.
func GetDatagramFrame() *DatagramFrame {
	f := datagramFramePool.Get()
	f.Data = nil
	f.putBack = false
	return f
}

// PutDatagramFrame returns a pooled DatagramFrame (and its Data buffer via
// PutBuffer) to the pool.
func PutDatagramFrame(f *DatagramFrame) {
	if f.putBack {
		panic("wire.DatagramFrame double-put: frame returned to the pool more than once")
	}
	f.putBack = true
	if f.Data != nil {
		quicpool.PutBuffer(f.Data)
		f.Data = nil
	}
	f.DataLenPresent = false
	datagramFramePool.Put(f)
}

func putStreamFrame(f *StreamFrame) {
	if f.putBack {
		panic("wire.StreamFrame double-put: frame returned to the pool more than once")
	}
	f.putBack = true
	if f.Data != nil {
		quicpool.PutBuffer(f.Data)
		f.Data = nil
	}
	streamFramePool.Put(f)
}
