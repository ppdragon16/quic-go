package wire

import (
	"sync"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

var pool sync.Pool
var datagramFramePool sync.Pool

func init() {
	pool.New = func() interface{} {
		return &StreamFrame{
			Data:     make([]byte, 0, protocol.MaxPacketBufferSize),
			fromPool: true,
		}
	}
	datagramFramePool.New = func() interface{} {
		return &DatagramFrame{
			Data:     make([]byte, 0, MaxDatagramSize),
			fromPool: true,
		}
	}
}

func GetStreamFrame() *StreamFrame {
	f := pool.Get().(*StreamFrame)
	f.Data = f.Data[:0]
	return f
}

// GetDatagramFrame returns a DatagramFrame from the shared pool. The frame's
// Data buffer has capacity MaxDatagramSize and must be re-sliced before use.
// Return the frame with PutDatagramFrame once it has been packed.
func GetDatagramFrame() *DatagramFrame {
	return datagramFramePool.Get().(*DatagramFrame)
}

// PutDatagramFrame returns a pooled DatagramFrame (and its Data buffer) to
// the pool. Frames not originating from the pool are ignored.
func PutDatagramFrame(f *DatagramFrame) {
	if !f.fromPool {
		return
	}
	if protocol.ByteCount(cap(f.Data)) > MaxDatagramSize {
		// Oversized datagram buffer: skip pooling to avoid pinning a large
		// allocation in the pool.
		return
	}
	f.Data = f.Data[:0]
	f.DataLenPresent = false
	datagramFramePool.Put(f)
}

func putStreamFrame(f *StreamFrame) {
	if !f.fromPool {
		return
	}
	if protocol.ByteCount(cap(f.Data)) != protocol.MaxPacketBufferSize {
		panic("wire.PutStreamFrame called with packet of wrong size!")
	}
	pool.Put(f)
}
