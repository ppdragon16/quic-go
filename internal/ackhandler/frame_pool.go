package ackhandler

import (
	"github.com/daeuniverse/quic-go/internal/utils"
)

// The frame slice pools. GetFrames/GetStreamFrames hand out pooled slices so
// packing a packet does not allocate per controlled frame, and the pools are
// GC-surviving and bounded (see utils.Pool).
var (
	framesPool       = utils.NewPool(func() []Frame { return make([]Frame, 0, 8) }, frameSlicePoolMax)
	streamFramesPool = utils.NewPool(func() []StreamFrame { return make([]StreamFrame, 0, 8) }, frameSlicePoolMax)
)

// frameSlicePoolMax caps how many slices each frame pool retains. This is a
// per-process bound shared by all connections, reached only under load.
const frameSlicePoolMax = 4096

// GetFrames returns a zero-length slice with capacity for a few control frames.
func GetFrames() []Frame { return framesPool.Get()[:0] }

// PutFrames returns frames to the pool. It must not be used afterwards.
func PutFrames(frames []Frame) { framesPool.Put(frames[:0]) }

// GetStreamFrames returns a zero-length slice with capacity for a few stream frames.
func GetStreamFrames() []StreamFrame { return streamFramesPool.Get()[:0] }

// PutStreamFrames returns streamFrames to the pool. It must not be used afterwards.
func PutStreamFrames(streamFrames []StreamFrame) { streamFramesPool.Put(streamFrames[:0]) }
