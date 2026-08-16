package ackhandler

import "sync"

// slicePool is a bounded, GC-surviving LIFO pool of slices. It is typed (unlike
// sync.Pool), so Get and Put do not box the slice into an interface and thus
// allocate nothing per operation. The backing store grows lazily by doubling
// from a small initial capacity up to max, so an idle process does not commit
// the full metadata up front. Excess slices beyond max are dropped and left
// for the GC.
type slicePool[T any] struct {
	newFn func() T
	min   int
	max   int

	mu  sync.Mutex
	buf []T // len = retained count; cap = current capacity (grows toward max)
}

func newSlicePool[T any](newFn func() T, min, max int) *slicePool[T] {
	return &slicePool[T]{newFn: newFn, min: min, max: max}
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
	if len(p.buf) == cap(p.buf) {
		// Full. Grow by doubling (up to max), otherwise drop v.
		if cap(p.buf) >= p.max {
			return
		}
		buf := make([]T, len(p.buf), min(max(cap(p.buf)*2, p.min), p.max))
		copy(buf, p.buf)
		p.buf = buf
	}
	p.buf = append(p.buf, v)
}

const (
	// frameSlicePoolMin is the starting capacity of a slicePool's
	// backing store.
	frameSlicePoolMin = 32

	// frameSlicePoolMax caps how many slices each frame pool retains. This is a
	// per-process bound shared by all connections, reached only under load and
	// grown lazily.
	frameSlicePoolMax = 4096
)

var (
	framesPool       = newSlicePool(func() []Frame { return make([]Frame, 0, 4) }, frameSlicePoolMin, frameSlicePoolMax)
	streamFramesPool = newSlicePool(func() []StreamFrame { return make([]StreamFrame, 0, 8) }, frameSlicePoolMin, frameSlicePoolMax)
)

// GetFrames returns a zero-length slice with capacity for a few control frames.
func GetFrames() []Frame { return framesPool.get()[:0] }

// PutFrames returns frames to the pool. It must not be used afterwards.
func PutFrames(frames []Frame) { framesPool.put(frames[:0]) }

// GetStreamFrames returns a zero-length slice with capacity for a few stream frames.
func GetStreamFrames() []StreamFrame { return streamFramesPool.get()[:0] }

// PutStreamFrames returns streamFrames to the pool. It must not be used afterwards.
func PutStreamFrames(streamFrames []StreamFrame) { streamFramesPool.put(streamFrames[:0]) }
