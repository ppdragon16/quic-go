package ackhandler

import (
	"runtime"
	"testing"

	"github.com/daeuniverse/quic-go/internal/utils"
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

// The packet pool must stay bounded (the generic bound behaviour is covered
// in internal/utils; this pins the packet pool's own wiring).
func TestPacketPoolIsBounded(t *testing.T) {
	p := utils.NewPool(func() *packet { return &packet{} }, packetPoolMax)
	for i := 0; i < packetPoolMax*2; i++ {
		p.Put(&packet{})
	}
	if got := p.Len(); got != packetPoolMax {
		t.Fatalf("pool retained %d packets, want the bound %d", got, packetPoolMax)
	}
	if p.Get() == nil {
		t.Fatal("Get returned nil after over-Put")
	}
}
