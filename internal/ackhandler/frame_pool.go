package ackhandler

import "sync"

// slicePool is a bounded, GC-surviving LIFO pool of slices. It is typed (unlike
// sync.Pool), so Get and Put do not box the slice into an interface and thus
// allocate nothing per operation. Excess slices beyond the capacity are dropped
// and left for the GC.
type slicePool[T any] struct {
	newFn func() T

	mu  sync.Mutex
	buf []T
}

func newSlicePool[T any](newFn func() T, capacity int) *slicePool[T] {
	return &slicePool[T]{newFn: newFn, buf: make([]T, 0, capacity)}
}

func (p *slicePool[T]) get() T {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n := len(p.buf); n > 0 {
		v := p.buf[n-1]
		// Clear the popped slot so the backing array does not keep a ghost
		// reference to v while the caller owns it.
		var zero T
		p.buf[n-1] = zero
		p.buf = p.buf[:n-1]
		return v
	}
	return p.newFn()
}

func (p *slicePool[T]) put(v T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) < cap(p.buf) {
		p.buf = append(p.buf, v)
	}
}

const frameSlicePoolCapacity = 4096

var (
	framesPool       = newSlicePool(func() []Frame { return make([]Frame, 0, 4) }, frameSlicePoolCapacity)
	streamFramesPool = newSlicePool(func() []StreamFrame { return make([]StreamFrame, 0, 2) }, frameSlicePoolCapacity)
)

// GetFrames returns a zero-length slice with capacity for a few control frames.
func GetFrames() []Frame { return framesPool.get()[:0] }

// PutFrames returns frames to the pool. It must not be used afterwards.
func PutFrames(frames []Frame) { framesPool.put(frames[:0]) }

// GetStreamFrames returns a zero-length slice with capacity for a few stream frames.
func GetStreamFrames() []StreamFrame { return streamFramesPool.get()[:0] }

// PutStreamFrames returns streamFrames to the pool. It must not be used afterwards.
func PutStreamFrames(streamFrames []StreamFrame) { streamFramesPool.put(streamFrames[:0]) }
