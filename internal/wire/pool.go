package wire

import (
	"sync"

	quicpool "github.com/daeuniverse/quic-go/pool"
)

// framePool is a bounded, GC-surviving LIFO pool of frame structs.
//
// It replaces sync.Pool for the shared frame pools on purpose: sync.Pool is
// emptied at every GC, so the hot receive path had to allocate fresh frames
// after each cycle (a relay heap profile showed ~8MB of refills through the
// pool's New function, wire.init.func1). This pool survives the GC, grows
// lazily, and is bounded so a burst cannot pin unbounded memory. It is typed,
// so Get/Put do not box the pointer into an interface.
//
// A single mutex guards the LIFO, mirroring ackhandler.slicePool. Pool
// operations are a handful of instructions and the alternative (a channel)
// adds scheduler traffic on a per-frame hot path.
type framePool[T any] struct {
	mu    sync.Mutex
	buf   []*T
	newFn func() *T
}

// framePoolMax bounds how many frames one pool retains. Frames are tens of
// bytes, so this caps retention at a few hundred KB per pool while still
// covering the in-flight working set of a busy relay.
const framePoolMax = 4096

func (p *framePool[T]) get() *T {
	p.mu.Lock()
	n := len(p.buf)
	if n == 0 {
		p.mu.Unlock()
		return p.newFn()
	}
	f := p.buf[n-1]
	p.buf[n-1] = nil // do not keep a ghost reference in the backing array
	p.buf = p.buf[:n-1]
	p.mu.Unlock()
	return f
}

func (p *framePool[T]) put(f *T) {
	p.mu.Lock()
	if len(p.buf) < framePoolMax {
		p.buf = append(p.buf, f)
	}
	p.mu.Unlock()
}

var (
	streamFramePool   = &framePool[StreamFrame]{newFn: func() *StreamFrame { return &StreamFrame{} }}
	datagramFramePool = &framePool[DatagramFrame]{newFn: func() *DatagramFrame { return &DatagramFrame{} }}
)

// GetStreamFrame returns a StreamFrame from the shared pool. The frame's
// Data field is nil; use GetBuffer to allocate Data when needed.
// Return the frame with putStreamFrame (or PutBack) once it has been acked.
func GetStreamFrame() *StreamFrame {
	f := streamFramePool.get()
	f.Data = nil
	f.putBack = false
	return f
}

// GetDatagramFrame returns a DatagramFrame from the shared pool. The frame's
// Data field is nil; use GetBuffer to allocate Data when needed.
// Return the frame with PutDatagramFrame once it has been packed.
func GetDatagramFrame() *DatagramFrame {
	f := datagramFramePool.get()
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
	datagramFramePool.put(f)
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
	streamFramePool.put(f)
}
