package utils

import "sync"

// Pool is a bounded, GC-surviving LIFO pool of values.
//
// It exists because sync.Pool is emptied at every GC and, under bursty Put
// traffic, its internal chain allocates new blocks
// (sync.(*poolChain).pushHead was ~24MB in a relay heap profile, the bulk of
// it from the frame and packet pools). This pool survives the GC, is typed so
// Get/Put do not box the value into an interface, and is bounded so a burst
// cannot pin unbounded memory. It grows lazily and never shrinks.
//
// It is generic over the pooled value, so it serves both slices (T = []Frame)
// and single objects (T = *packet). Put must not receive the zero value: for
// pointer types that would hand a nil back to a caller, and the hot paths
// never have one to return.
type Pool[T any] struct {
	mu    sync.Mutex
	buf   []T
	newFn func() T
	max   int
}

// NewPool returns a pool that allocates with newFn and retains at most max
// values.
func NewPool[T any](newFn func() T, max int) *Pool[T] {
	return &Pool[T]{newFn: newFn, max: max}
}

// Get returns a pooled value, or a fresh one from newFn when empty.
func (p *Pool[T]) Get() T {
	p.mu.Lock()
	n := len(p.buf)
	if n == 0 {
		p.mu.Unlock()
		return p.newFn()
	}
	v := p.buf[n-1]
	var zero T
	p.buf[n-1] = zero // do not keep a ghost reference in the backing array
	p.buf = p.buf[:n-1]
	p.mu.Unlock()
	return v
}

// Put returns a value to the pool. Values beyond the bound are dropped and
// left to the GC.
func (p *Pool[T]) Put(v T) {
	p.mu.Lock()
	if len(p.buf) < p.max {
		p.buf = append(p.buf, v)
	}
	p.mu.Unlock()
}

// Len reports how many values the pool currently retains (diagnostics/tests).
func (p *Pool[T]) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buf)
}
