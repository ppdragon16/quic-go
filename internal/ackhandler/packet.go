package ackhandler

import (
	"time"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/utils"
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
	// noRetransmittableFrames marks packets that were sent without any
	// retained frame -- a DATAGRAM-only packet is ack-eliciting but its
	// frame is pooled right after serialization and is never retransmitted
	// (RFC 9221). Losing such a packet has nothing to requeue.
	noRetransmittableFrames bool
}

func (p *packet) outstanding() bool {
	return !p.declaredLost && !p.skippedPacket && !p.IsPathMTUProbePacket
}

var packetPool = utils.NewPool(func() *packet { return &packet{} }, packetPoolMax)

// packetPoolMax bounds how many packets the pool retains (~120B each).
const packetPoolMax = 4096

func getPacket() *packet {
	p := packetPool.Get()
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
