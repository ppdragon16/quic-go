package quic

import (
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/quic-go/internal/ackhandler"
	"github.com/daeuniverse/quic-go/internal/flowcontrol"
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/utils/minheap"
	"github.com/daeuniverse/quic-go/internal/utils/ringbuffer"
	"github.com/daeuniverse/quic-go/internal/wire"
	"github.com/daeuniverse/quic-go/quicvarint"
)

const (
	maxPathResponses = 256
	maxControlFrames = 16 << 10
)

// This is the largest possible size of a stream-related control frame
// (which is the RESET_STREAM frame).
const maxStreamControlFrameSize = 25

type streamControlFrameGetter interface {
	getControlFrame(time.Time) (_ ackhandler.Frame, ok, hasMore bool)
}

// streamQueueEntry identifies a queued generation of a stream.
type streamQueueEntry struct {
	id         protocol.StreamID
	generation uint32
}

// streamPriorityBucket contains the streams of one RFC 9218 urgency level.
type streamPriorityBucket struct {
	// Incremental streams are scheduled round-robin...
	Incremental ringbuffer.RingBuffer[streamQueueEntry]
	// ...while non-incremental streams are scheduled in stream ID order.
	NonIncremental minheap.Heap[protocol.StreamID, uint32 /* generation */]
	// If a bucket holds both kinds, we round-robin between them.
	LastSendWasIncremental bool
}

func (b *streamPriorityBucket) Len() int {
	return b.Incremental.Len() + b.NonIncremental.Len()
}

func (b *streamPriorityBucket) Clear() {
	b.Incremental.Clear()
	b.NonIncremental.Clear()
	b.LastSendWasIncremental = false
}

// queuedStream is an active stream together with the generation of the priority
// it was queued with. A queue entry whose generation no longer matches is stale
// and gets discarded.
type queuedStream struct {
	sendStreamI
	generation uint32
}

type framer struct {
	mutex sync.Mutex

	activeStreams map[protocol.StreamID]queuedStream
	// streamQueue contains the active streams, indexed by urgency (0-7).
	// Lower urgencies are sent first.
	streamQueue              [8]streamPriorityBucket
	streamsWithControlFrames map[protocol.StreamID]streamControlFrameGetter

	controlFrameMutex          sync.Mutex
	controlFrames              []wire.Frame
	pathResponses              []*wire.PathResponseFrame
	connFlowController         flowcontrol.ConnectionFlowController
	queuedTooManyControlFrames bool
}

func newFramer(connFlowController flowcontrol.ConnectionFlowController) *framer {
	return &framer{
		activeStreams:            make(map[protocol.StreamID]queuedStream),
		streamsWithControlFrames: make(map[protocol.StreamID]streamControlFrameGetter),
		connFlowController:       connFlowController,
	}
}

func (f *framer) HasData() bool {
	f.mutex.Lock()
	var hasData bool
	for urgency := range f.streamQueue {
		if f.streamQueue[urgency].Len() > 0 {
			hasData = true
			break
		}
	}
	f.mutex.Unlock()
	if hasData {
		return true
	}
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()
	return len(f.streamsWithControlFrames) > 0 || len(f.controlFrames) > 0 || len(f.pathResponses) > 0
}

func (f *framer) QueueControlFrame(frame wire.Frame) {
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	if pr, ok := frame.(*wire.PathResponseFrame); ok {
		// Only queue up to maxPathResponses PATH_RESPONSE frames.
		// This limit should be high enough to never be hit in practice,
		// unless the peer is doing something malicious.
		if len(f.pathResponses) >= maxPathResponses {
			return
		}
		f.pathResponses = append(f.pathResponses, pr)
		return
	}
	// This is a hack.
	if len(f.controlFrames) >= maxControlFrames {
		f.queuedTooManyControlFrames = true
		return
	}
	f.controlFrames = append(f.controlFrames, frame)
}

func (f *framer) Append(
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	maxLen protocol.ByteCount,
	now time.Time,
	v protocol.Version,
) ([]ackhandler.Frame, []ackhandler.StreamFrame, protocol.ByteCount) {
	f.controlFrameMutex.Lock()
	frames, controlFrameLen := f.appendControlFrames(frames, maxLen, now, v)
	maxLen -= controlFrameLen

	var lastFrame ackhandler.StreamFrame
	var streamFrameLen protocol.ByteCount
	f.mutex.Lock()
	// pop STREAM frames, until less than 128 bytes are left in the packet.
	// Streams of a lower urgency are served first.
	for urgency := range f.streamQueue {
		bucket := &f.streamQueue[urgency]
		numActiveStreams := bucket.Len()

		for range numActiveStreams {
			if protocol.MinStreamFrameSize > maxLen {
				break
			}
			sf, blocked := f.getNextStreamFrame(maxLen, int8(urgency), v)
			if sf.Frame != nil {
				streamFrames = append(streamFrames, sf)
				maxLen -= sf.Frame.Length(v)
				lastFrame = sf
				streamFrameLen += sf.Frame.Length(v)
			}
			// If the stream just became blocked on stream flow control, attempt to pack the
			// STREAM_DATA_BLOCKED into the same packet.
			if blocked != nil {
				l := blocked.Length(v)
				// In case it doesn't fit, queue it for the next packet.
				if maxLen < l {
					f.controlFrames = append(f.controlFrames, blocked)
					break
				}
				frames = append(frames, ackhandler.Frame{Frame: blocked})
				maxLen -= l
				controlFrameLen += l
			}
		}
	}

	// The only way to become blocked on connection-level flow control is by sending STREAM frames.
	if isBlocked, offset := f.connFlowController.IsNewlyBlocked(); isBlocked {
		blocked := &wire.DataBlockedFrame{MaximumData: offset}
		l := blocked.Length(v)
		// In case it doesn't fit, queue it for the next packet.
		if maxLen >= l {
			frames = append(frames, ackhandler.Frame{Frame: blocked})
			controlFrameLen += l
		} else {
			f.controlFrames = append(f.controlFrames, blocked)
		}
	}

	f.mutex.Unlock()
	f.controlFrameMutex.Unlock()

	if lastFrame.Frame != nil {
		// account for the smaller size of the last STREAM frame
		streamFrameLen -= lastFrame.Frame.Length(v)
		lastFrame.Frame.DataLenPresent = false
		streamFrameLen += lastFrame.Frame.Length(v)
	}

	return frames, streamFrames, controlFrameLen + streamFrameLen
}

func (f *framer) appendControlFrames(
	frames []ackhandler.Frame,
	maxLen protocol.ByteCount,
	now time.Time,
	v protocol.Version,
) ([]ackhandler.Frame, protocol.ByteCount) {
	var length protocol.ByteCount
	// add a PATH_RESPONSE first, but only pack a single PATH_RESPONSE per packet
	if len(f.pathResponses) > 0 {
		frame := f.pathResponses[0]
		frameLen := frame.Length(v)
		if frameLen <= maxLen {
			frames = append(frames, ackhandler.Frame{Frame: frame})
			length += frameLen
			f.pathResponses = f.pathResponses[1:]
		}
	}

	// add stream-related control frames
	for id, str := range f.streamsWithControlFrames {
	start:
		remainingLen := maxLen - length
		if remainingLen <= maxStreamControlFrameSize {
			break
		}
		fr, ok, hasMore := str.getControlFrame(now)
		if !hasMore {
			delete(f.streamsWithControlFrames, id)
		}
		if !ok {
			continue
		}
		frames = append(frames, fr)
		length += fr.Frame.Length(v)
		if hasMore {
			// It is rare that a stream has more than one control frame to queue.
			// We don't want to spawn another loop for just to cover that case.
			goto start
		}
	}

	for len(f.controlFrames) > 0 {
		frame := f.controlFrames[len(f.controlFrames)-1]
		frameLen := frame.Length(v)
		if length+frameLen > maxLen {
			break
		}
		frames = append(frames, ackhandler.Frame{Frame: frame})
		length += frameLen
		f.controlFrames = f.controlFrames[:len(f.controlFrames)-1]
	}

	return frames, length
}

// QueuedTooManyControlFrames says if the control frame queue exceeded its maximum queue length.
// This is a hack.
// It is easier to implement than propagating an error return value in QueueControlFrame.
// The correct solution would be to queue frames with their respective structs.
// See https://github.com/daeuniverse/quic-go/issues/4271 for the queueing of stream-related control frames.
func (f *framer) QueuedTooManyControlFrames() bool {
	return f.queuedTooManyControlFrames
}

func (f *framer) AddActiveStream(id protocol.StreamID, str sendStreamI) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	urgency, incremental, generation := str.priority()
	if activeStr, ok := f.activeStreams[id]; ok && activeStr.generation == generation {
		return
	}
	f.enqueueStream(id, urgency, incremental, generation, str)
}

// enqueueStream adds a stream to the queue of its urgency level.
func (f *framer) enqueueStream(id protocol.StreamID, urgency int8, incremental bool, generation uint32, str sendStreamI) {
	bucket := &f.streamQueue[urgency]
	if incremental {
		bucket.Incremental.PushBack(streamQueueEntry{id: id, generation: generation})
	} else {
		bucket.NonIncremental.Push(id, generation)
	}
	f.activeStreams[id] = queuedStream{sendStreamI: str, generation: generation}
}

// UpdateStreamPriority re-queues a stream whose priority changed. The stream's
// previous queue entry is left in place; it is dropped once it reaches the
// front and its generation no longer matches.
func (f *framer) UpdateStreamPriority(id protocol.StreamID) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	str, ok := f.activeStreams[id]
	if !ok {
		return
	}
	urgency, incremental, generation := str.priority()
	if str.generation != generation {
		f.enqueueStream(id, urgency, incremental, generation, str.sendStreamI)
	}
}

func (f *framer) AddStreamWithControlFrames(id protocol.StreamID, str streamControlFrameGetter) {
	f.controlFrameMutex.Lock()
	if _, ok := f.streamsWithControlFrames[id]; !ok {
		f.streamsWithControlFrames[id] = str
	}
	f.controlFrameMutex.Unlock()
}

// RemoveActiveStream is called when a stream completes.
func (f *framer) RemoveActiveStream(id protocol.StreamID) {
	f.mutex.Lock()
	// We don't delete the stream from the queues and heaps,
	// since we'd have to find it there first.
	// Instead, we check if the stream is still active when appending STREAM frames.
	delete(f.activeStreams, id)
	f.mutex.Unlock()
}

func (f *framer) getNextStreamFrame(
	maxLen protocol.ByteCount,
	urgency int8,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	bucket := &f.streamQueue[urgency]
	if bucket.NonIncremental.Empty() || (!bucket.LastSendWasIncremental && !bucket.Incremental.Empty()) {
		return f.getNextIncrementalStreamFrame(maxLen, urgency, v)
	}
	return f.getNextNonIncrementalStreamFrame(maxLen, urgency, v)
}

func (f *framer) getNextIncrementalStreamFrame(
	maxLen protocol.ByteCount,
	urgency int8,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	bucket := &f.streamQueue[urgency]
	if bucket.Incremental.Empty() {
		return ackhandler.StreamFrame{}, nil
	}
	entry := bucket.Incremental.PopFront()
	str, ok := f.activeStreams[entry.id]
	// The stream might have been removed, or re-queued with a new priority,
	// after being enqueued.
	if !ok || str.generation != entry.generation {
		return ackhandler.StreamFrame{}, nil
	}
	frame, blocked, hasMoreData := f.popStreamFrame(entry.id, str, maxLen, v)
	if hasMoreData { // put the stream back in the queue (at the end)
		bucket.Incremental.PushBack(entry)
	}
	bucket.LastSendWasIncremental = true
	return frame, blocked
}

func (f *framer) getNextNonIncrementalStreamFrame(
	maxLen protocol.ByteCount,
	urgency int8,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame) {
	bucket := &f.streamQueue[urgency]
	if bucket.NonIncremental.Empty() {
		return ackhandler.StreamFrame{}, nil
	}
	id, queuedGeneration := bucket.NonIncremental.Peek()
	str, ok := f.activeStreams[id]
	if !ok || str.generation != queuedGeneration {
		bucket.NonIncremental.Pop()
		return ackhandler.StreamFrame{}, nil
	}
	frame, blocked, hasMoreData := f.popStreamFrame(id, str, maxLen, v)
	if !hasMoreData { // no more data to send. Stream is not active
		bucket.NonIncremental.Pop()
	}
	bucket.LastSendWasIncremental = false
	return frame, blocked
}

func (f *framer) popStreamFrame(
	id protocol.StreamID,
	str queuedStream,
	maxLen protocol.ByteCount,
	v protocol.Version,
) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
	// For the last STREAM frame, we'll remove the DataLen field later.
	// Therefore, we can pretend to have more bytes available when popping
	// the STREAM frame (which will always have the DataLen set).
	maxLen += protocol.ByteCount(quicvarint.Len(uint64(maxLen)))
	frame, blocked, hasMoreData := str.popStreamFrame(maxLen, v)
	if !hasMoreData {
		delete(f.activeStreams, id)
	}
	// Note that the frame.Frame can be nil:
	// * if the stream was canceled after it said it had data
	// * the remaining size doesn't allow us to add another STREAM frame
	return frame, blocked, hasMoreData
}

func (f *framer) Handle0RTTRejection() {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.controlFrameMutex.Lock()
	defer f.controlFrameMutex.Unlock()

	for urgency := range f.streamQueue {
		f.streamQueue[urgency].Clear()
	}
	for id := range f.activeStreams {
		delete(f.activeStreams, id)
	}
	var j int
	for i, frame := range f.controlFrames {
		switch frame.(type) {
		case *wire.MaxDataFrame, *wire.MaxStreamDataFrame, *wire.MaxStreamsFrame,
			*wire.DataBlockedFrame, *wire.StreamDataBlockedFrame, *wire.StreamsBlockedFrame:
			continue
		default:
			f.controlFrames[j] = f.controlFrames[i]
			j++
		}
	}
	f.controlFrames = slices.Delete(f.controlFrames, j, len(f.controlFrames))
}
