package quic

import (
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestSendPathStallReport pins when the watchdog speaks up. The line it prints
// is the only evidence a stalled transport leaves behind (the connection stays
// alive, so nothing else logs), and the distinction it carries is the point:
// a blocked socket write versus a connection that stopped packing.
func TestSendPathStallReport(t *testing.T) {
	for _, tc := range []struct {
		name           string
		packets        int
		datagrams      int
		stalled        time.Duration
		writeBlocked   time.Duration
		wantStalled    bool
		wantSubstrings []string
	}{
		{
			name: "idle connection is not a stall",
		},
		{
			// A long silence with nothing queued is a quiet link, not a stall.
			name:    "quiet connection is not a stall",
			stalled: time.Minute,
		},
		{
			name:      "queued work but recent activity is not a stall",
			packets:   8,
			datagrams: 128,
			stalled:   100 * time.Millisecond,
		},
		{
			name:         "blocked socket write is reported early",
			packets:      8,
			datagrams:    128,
			stalled:      300 * time.Millisecond,
			writeBlocked: 900 * time.Millisecond,
			wantStalled:  true,
			wantSubstrings: []string{
				"8 packet(s) queued",
				"128 datagram(s) queued",
				"socket write blocked for 900ms",
			},
		},
		{
			name:        "packing stopped while packets are queued",
			packets:     8,
			stalled:     3 * time.Second,
			wantStalled: true,
			wantSubstrings: []string{
				"Send path stalled for 3s",
				"socket write blocked for 0s",
			},
		},
		{
			name:        "packing stopped while datagrams are queued",
			datagrams:   128,
			stalled:     5 * time.Second,
			wantStalled: true,
			wantSubstrings: []string{
				"128 datagram(s) queued",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, stalled := sendPathStallReport(tc.packets, tc.datagrams, tc.stalled, tc.writeBlocked)
			require.Equal(t, tc.wantStalled, stalled)
			if !tc.wantStalled {
				require.Empty(t, msg)
				return
			}
			for _, want := range tc.wantSubstrings {
				require.Contains(t, msg, want)
			}
		})
	}
}

// TestSendQueueTracksSendPathActivity pins the state the watchdog reads: a write
// that is in flight has to be visible as such (that is how a blocked socket
// write is told apart from a connection that stopped packing), and a completed
// write has to clear it again.
func TestSendQueueTracksSendPathActivity(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	c := NewMockSendConn(mockCtrl)
	q := newSendQueue(c).(*sendQueue)

	require.True(t, q.LastActivity().IsZero(), "no activity before the first packet")
	require.Zero(t, q.WriteBlockedFor(time.Now()))

	writeStarted := make(chan struct{})
	releaseWrite := make(chan struct{})
	c.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func([]byte, uint16, protocol.ECN) error {
			close(writeStarted)
			<-releaseWrite
			return nil
		},
	)

	done := make(chan struct{})
	go func() {
		q.Run()
		close(done)
	}()

	q.Send(getPacketWithContents([]byte("foobar")), 0, protocol.ECNUnsupported)
	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for the write to start")
	}

	require.False(t, q.LastActivity().IsZero(), "queued packet must record activity")
	require.Positive(t, q.WriteBlockedFor(time.Now()), "an in-flight write must be visible as blocked")
	require.Zero(t, q.Pending(), "the packet was handed to the socket writer")

	close(releaseWrite)
	q.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for the run loop to stop")
	}
	require.Zero(t, q.WriteBlockedFor(time.Now()), "a completed write must clear the in-flight marker")
}
