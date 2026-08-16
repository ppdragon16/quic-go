package ackhandler

import (
	"sync"
	"time"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

// A Packet is a packet
type packet struct {
	SendTime        time.Time
	PacketNumber    protocol.PacketNumber
	StreamFrames    []StreamFrame
	Frames          []Frame
	LargestAcked    protocol.PacketNumber // InvalidPacketNumber if the packet doesn't contain an ACK
	Length          protocol.ByteCount
	EncryptionLevel protocol.EncryptionLevel

	IsPathMTUProbePacket bool // We don't report the loss of Path MTU probe packets to the congestion controller.

	includedInBytesInFlight bool
	declaredLost            bool
	skippedPacket           bool
}

func (p *packet) outstanding() bool {
	return !p.declaredLost && !p.skippedPacket && !p.IsPathMTUProbePacket
}

var packetPool = sync.Pool{New: func() any { return &packet{} }}

func getPacket() *packet {
	p := packetPool.Get().(*packet)
	*p = packet{}
	return p
}

func putPacket(p *packet) {
	PutFrames(p.Frames)
	PutStreamFrames(p.StreamFrames)
	p.Frames = nil
	p.StreamFrames = nil
	packetPool.Put(p)
}
