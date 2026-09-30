package ackhandler

import (
	"runtime"
	"testing"
)

// The packet pool must survive a GC: sync.Pool was emptied at every cycle,
// forcing the send path to re-allocate packets afterwards.
func TestPacketPoolSurvivesGC(t *testing.T) {
	p := getPacket()
	p.PacketNumber = 42
	putPacket(p)

	runtime.GC()
	runtime.GC()

	if got := getPacket(); got != p {
		t.Fatalf("packet pool did not survive GC: got %p, want the recycled %p", got, p)
	}
	// getPacket must hand out a zeroed packet.
	if p.PacketNumber != 0 || p.Frames != nil || p.StreamFrames != nil {
		t.Fatalf("getPacket returned a dirty packet: %+v", p)
	}
}

// Frame slices must return to their own pools on putPacket, and the packet
// itself must be reusable.
func TestPutPacketReturnsFrameSlices(t *testing.T) {
	p := getPacket()
	p.Frames = GetFrames()
	p.Frames = append(p.Frames, Frame{})
	p.StreamFrames = GetStreamFrames()
	p.StreamFrames = append(p.StreamFrames, StreamFrame{})
	putPacket(p)

	if p.Frames != nil || p.StreamFrames != nil {
		t.Fatal("putPacket kept frame slice references on the packet")
	}
	// Both slice pools were populated; getting them back must not allocate a
	// new backing array.
	frames := GetFrames()
	if cap(frames) == 0 {
		t.Fatal("frames pool handed out a zero-capacity slice")
	}
	PutFrames(frames)
}

// The packet pool must stay bounded.
func TestObjectPoolIsBounded(t *testing.T) {
	p := newObjectPool(func() *packet { return &packet{} })
	for i := 0; i < objectPoolMax*2; i++ {
		p.put(&packet{})
	}
	if got := len(p.buf); got != objectPoolMax {
		t.Fatalf("pool retained %d packets, want the bound %d", got, objectPoolMax)
	}
	if p.get() == nil {
		t.Fatal("get returned nil after over-put")
	}
}
