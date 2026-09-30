package wire

import (
	"runtime"
	"testing"
)

func TestGetAndPutStreamFrames(t *testing.T) {
	f := GetStreamFrame()
	putStreamFrame(f)
}

func TestPuttingStreamFrameWithExternalData(t *testing.T) {
	f := GetStreamFrame()
	f.Data = []byte("foobar")
	putStreamFrame(f)
	// No assertion needed — just checking it doesn't panic
}

func TestPuttingNonPooledStreamFrame(t *testing.T) {
	f := &StreamFrame{Data: []byte("foobar")}
	putStreamFrame(f)
	// No assertion needed — just checking it doesn't panic
}

// The shared frame pool must survive a GC: sync.Pool was cleared at every
// cycle, which forced the hot path to re-allocate frames (the very churn this
// pool exists to avoid).
func TestFramePoolSurvivesGC(t *testing.T) {
	f := GetStreamFrame()
	putStreamFrame(f)

	runtime.GC()
	runtime.GC()

	if got := GetStreamFrame(); got != f {
		t.Fatalf("frame pool did not survive GC: got %p, want the recycled %p", got, f)
	}
}

// The pool must stay bounded: a burst of puts may not grow retention past
// framePoolMax.
func TestFramePoolIsBounded(t *testing.T) {
	p := &framePool[StreamFrame]{newFn: func() *StreamFrame { return &StreamFrame{} }}
	for i := 0; i < framePoolMax*2; i++ {
		p.put(&StreamFrame{})
	}
	if got := len(p.buf); got != framePoolMax {
		t.Fatalf("pool retained %d frames, want the bound %d", got, framePoolMax)
	}
	// Over-put frames are dropped, but gets still hand out usable frames.
	if f := p.get(); f == nil {
		t.Fatal("get returned nil after over-put")
	}
}
