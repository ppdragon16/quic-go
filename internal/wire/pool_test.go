package wire

import (
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
