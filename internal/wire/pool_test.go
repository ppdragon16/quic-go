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
