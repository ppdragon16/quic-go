package quic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/daeuniverse/quic-go/internal/ackhandler"
	"github.com/daeuniverse/quic-go/internal/flowcontrol"
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"
)

// Tests for the RFC 9218 stream scheduling, ported from quic-go PR #5774.
// The retransmission-priority tests from upstream are not ported: in this fork
// retransmissions are tracked outside the framer.

// newMockPriorityStream creates a mock stream that produces packet-sized frames
// at the given priority.
func newMockPriorityStream(t *testing.T, id protocol.StreamID, urgency int8, incremental bool, numFrames int) *MockSendStreamI {
	t.Helper()

	str := NewMockSendStreamI(gomock.NewController(t))
	str.EXPECT().priority().Return(urgency, incremental, uint32(0)).AnyTimes()
	remaining := numFrames
	str.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
		func(_ protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			frame := &wire.StreamFrame{StreamID: id, DataLenPresent: true}
			frame.Data = make([]byte, frame.MaxDataLen(protocol.MinStreamFrameSize, v))
			remaining--
			return ackhandler.StreamFrame{Frame: frame}, nil, remaining > 0
		},
	).Times(numFrames)
	return str
}

// appendPriorityPackets appends one STREAM frame per packet and returns their stream IDs.
func appendPriorityPackets(t *testing.T, framer *framer, numPackets int) []protocol.StreamID {
	t.Helper()

	ids := make([]protocol.StreamID, 0, numPackets)
	for range numPackets {
		_, frames, _ := framer.Append(nil, nil, protocol.MinStreamFrameSize, time.Now(), protocol.Version1)
		require.Len(t, frames, 1)
		ids = append(ids, frames[0].Frame.StreamID)
	}
	return ids
}

func newPriorityFramer() *framer {
	return newFramer(flowcontrol.NewConnectionFlowController(0, 0, nil, nil, nil))
}

// TestFramerSchedulesIncrementalStreams checks that lower urgencies are served
// first and that streams of the same urgency round-robin.
func TestFramerSchedulesIncrementalStreams(t *testing.T) {
	framer := newPriorityFramer()
	framer.AddActiveStream(8, newMockPriorityStream(t, 8, 0, true, 3))
	framer.AddActiveStream(0, newMockPriorityStream(t, 0, 1, true, 1))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 0, true, 2))

	require.Equal(t,
		[]protocol.StreamID{8, 4, 8, 4, 8, 0},
		appendPriorityPackets(t, framer, 6),
	)
	require.False(t, framer.HasData())
}

// TestFramerSchedulesNonIncrementalStreams checks that non-incremental streams
// are served in stream ID order, and that a lower urgency still wins.
func TestFramerSchedulesNonIncrementalStreams(t *testing.T) {
	framer := newPriorityFramer()
	framer.AddActiveStream(8, newMockPriorityStream(t, 8, 0, false, 2))
	framer.AddActiveStream(0, newMockPriorityStream(t, 0, 1, false, 1))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 0, false, 3))

	require.Equal(t,
		[]protocol.StreamID{4, 4, 4, 8, 8, 0},
		appendPriorityPackets(t, framer, 6),
	)
	require.False(t, framer.HasData())
}

// TestFramerAlternatesIncrementalAndNonIncrementalStreams covers a bucket that
// holds both kinds: the stream of every second turn goes to the non-incremental
// stream, the incremental ones round-robin in between.
func TestFramerAlternatesIncrementalAndNonIncrementalStreams(t *testing.T) {
	framer := newPriorityFramer()
	framer.AddActiveStream(8, newMockPriorityStream(t, 8, 0, true, 2))
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 0, false, 3))
	framer.AddActiveStream(12, newMockPriorityStream(t, 12, 0, true, 1))

	require.Equal(t,
		[]protocol.StreamID{8, 4, 12, 4, 8, 4},
		appendPriorityPackets(t, framer, 6),
	)
	require.False(t, framer.HasData())
}

// TestFramerSchedulesReprioritizedStream checks that a priority change takes
// effect immediately and that the stream's stale queue entries are discarded.
func TestFramerSchedulesReprioritizedStream(t *testing.T) {
	const updatedStreamID = protocol.StreamID(8)
	framer := newPriorityFramer()
	framer.AddActiveStream(4, newMockPriorityStream(t, 4, 1, true, 1))
	framer.AddActiveStream(12, newMockPriorityStream(t, 12, 2, true, 1))

	// stream 8 starts at urgency 0 with enough data for two packets
	updatedStr := NewMockSendStreamI(gomock.NewController(t))
	urgency, incremental, generation := int8(0), true, uint32(0)
	updatedStr.EXPECT().priority().DoAndReturn(func() (int8, bool, uint32) {
		return urgency, incremental, generation
	}).AnyTimes()
	remaining := 2
	updatedStr.EXPECT().popStreamFrame(gomock.Any(), protocol.Version1).DoAndReturn(
		func(_ protocol.ByteCount, v protocol.Version) (ackhandler.StreamFrame, *wire.StreamDataBlockedFrame, bool) {
			frame := &wire.StreamFrame{StreamID: updatedStreamID, DataLenPresent: true}
			frame.Data = make([]byte, frame.MaxDataLen(protocol.MinStreamFrameSize, v))
			remaining--
			return ackhandler.StreamFrame{Frame: frame}, nil, remaining > 0
		},
	).Times(2)
	framer.AddActiveStream(updatedStreamID, updatedStr)

	// the first packet contains stream 8 and leaves it queued at urgency 0
	ids := appendPriorityPackets(t, framer, 1)
	// lower stream 8 to urgency 2 and make it non-incremental, leaving its old
	// queue entry stale
	urgency, incremental, generation = 2, false, 1
	framer.UpdateStreamPriority(updatedStreamID)
	ids = append(ids, appendPriorityPackets(t, framer, 3)...)

	// the stale entry is skipped, so stream 4 runs next; without the update,
	// stream 8 would run next. At urgency 2, incremental stream 12 is scheduled
	// before non-incremental stream 8.
	require.Equal(t, []protocol.StreamID{8, 4, 12, 8}, ids)
	require.False(t, framer.HasData())
}

// TestFramerDefaultPriority pins the default: urgency 3, incremental, matching
// the scheduling behaviour before RFC 9218 support was added.
func TestFramerDefaultPriority(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	sender.EXPECT().updateStreamPriority(gomock.Any()).AnyTimes()
	str := newSendStream(t.Context(), 4, sender, nil)
	urgency, incremental, generation := str.priority()
	require.Equal(t, int8(3), urgency)
	require.True(t, incremental)
	require.Zero(t, generation)

	// SetPriority clips the urgency to the RFC 9218 range 0..7
	str.SetPriority(-3, true)
	urgency, _, _ = str.priority()
	require.Equal(t, int8(0), urgency)
	str.SetPriority(10, true)
	urgency, _, _ = str.priority()
	require.Equal(t, int8(7), urgency)
}

// TestSendStreamSetPriorityNotifiesSender checks the framer is told about a
// priority change, and only when the priority actually changed.
func TestSendStreamSetPriorityNotifiesSender(t *testing.T) {
	sender := NewMockStreamSender(gomock.NewController(t))
	str := newSendStream(t.Context(), 4, sender, nil)

	// two of the three calls below change the priority, so two notifications
	sender.EXPECT().updateStreamPriority(protocol.StreamID(4)).Times(2)
	str.SetPriority(1, false)
	// setting the same priority again must not notify
	str.SetPriority(1, false)
	str.SetPriority(1, true)
}
