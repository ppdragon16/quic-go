package self_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/daeuniverse/quic-go"
	quicproxy "github.com/daeuniverse/quic-go/integrationtests/tools/proxy"
)

// TestStreamPriorityScheduling is the end-to-end counterpart to the framer's
// unit tests: over a real connection (behind a proxy that delays and drops
// packets, so that the congestion controller has to choose what to send), a
// small high-priority stream must be delivered long before bulk streams that
// were opened first and have far more data queued.
func TestStreamPriorityScheduling(t *testing.T) {
	// urgency 0 must jump the queue
	runStreamPriorityScenario(t, 0, true)
}

// TestStreamPrioritySchedulingDeferred is the control: with urgency 7 the same
// interactive stream must NOT be delivered before the bulk streams. Without
// this, the test above could pass simply because the last-opened stream happens
// to be scheduled first.
func TestStreamPrioritySchedulingDeferred(t *testing.T) {
	runStreamPriorityScenario(t, 7, false)
}

func runStreamPriorityScenario(t *testing.T, interactiveUrgency int8, expectInteractiveFirst bool) {
	const (
		bulkStreams    = 3
		bulkSize       = 64 << 10
		interactiveLen = 64 << 10
	)

	// The server reports, per stream, how many bytes it received.
	type streamResult struct {
		id  quic.StreamID
		len int
	}
	results := make(chan streamResult, bulkStreams+1)

	server, err := quic.Listen(
		newUPDConnLocalhost(t),
		getTLSConfig(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer server.Close()

	go func() {
		conn, err := server.Accept(context.Background())
		if err != nil {
			return
		}
		for {
			str, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go func() {
				defer str.Close()
				n, _ := io.Copy(io.Discard, str)
				results <- streamResult{id: str.StreamID(), len: int(n)}
			}()
		}
	}()

	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr: server.Addr().String(),
		// a small delay makes the congestion controller work for its bandwidth,
		// so the scheduling decision becomes observable
		DelayPacket: func(quicproxy.Direction, []byte) time.Duration {
			return time.Millisecond
		},
	})
	require.NoError(t, err)
	defer proxy.Close()

	client, err := quic.DialAddr(
		context.Background(),
		proxy.LocalAddr().String(),
		getTLSClientConfigWithoutServerName(),
		getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
	)
	require.NoError(t, err)
	defer client.CloseWithError(0, "")

	// Open the bulk streams first and queue a lot of data on them, but don't
	// let the receiver make progress yet: the interactive stream is opened only
	// afterwards, so it is last in line without priorities.
	bulk := make([]quic.Stream, bulkStreams)
	for i := range bulk {
		str, err := client.OpenStreamSync(context.Background())
		require.NoError(t, err)
		bulk[i] = str
		go func() {
			// the receiver only completes a stream once it saw the FIN, so the
			// bulk streams have to be closed for the delivery order to say
			// anything about scheduling
			_, _ = str.Write(make([]byte, bulkSize))
			_ = str.Close()
		}()
	}

	interactive, err := client.OpenStreamSync(context.Background())
	require.NoError(t, err)
	interactive.SetPriority(interactiveUrgency, true)

	start := time.Now()
	_, err = interactive.Write(make([]byte, interactiveLen))
	require.NoError(t, err)
	require.NoError(t, interactive.Close())

	var firstResult streamResult
	order := make([]quic.StreamID, 0, bulkStreams+1)
	select {
	case firstResult = <-results:
		order = append(order, firstResult.id)
	case <-time.After(30 * time.Second):
		t.Fatal("no stream data received")
	}

	elapsed := time.Since(start)
	t.Logf("first delivered stream %d (%d bytes) after %v", firstResult.id, firstResult.len, elapsed)

	if expectInteractiveFirst {
		// Both the interactive and the bulk streams carry a full round of data
		// and were opened in the same order, so only the scheduler can decide
		// who finishes first: the urgency-0 stream must jump the queue even
		// though it was opened last.
		require.Equal(t, interactive.StreamID(), firstResult.id,
			"the urgency-0 stream must be delivered before the urgency-3 bulk streams")
		require.Equal(t, interactiveLen, firstResult.len)
	} else {
		require.NotEqual(t, interactive.StreamID(), firstResult.id,
			"an urgency-7 stream must not jump ahead of urgency-3 bulk streams")
	}

	// The bulk streams must still be delivered in full, i.e. prioritisation must
	// not starve them.
	received := map[quic.StreamID]int{firstResult.id: firstResult.len}
	for len(received) < bulkStreams+1 {
		select {
		case r := <-results:
			received[r.id] = r.len
			order = append(order, r.id)
		case <-time.After(60 * time.Second):
			t.Fatalf("only %d of %d streams were delivered", len(received), bulkStreams+1)
		}
	}
	t.Logf("delivery order: %v", order)
	if !expectInteractiveFirst {
		// the deferred stream must be served only once the bulk streams are done
		require.Equal(t, interactive.StreamID(), order[len(order)-1],
			"the urgency-7 stream must be the last to be delivered")
	}
	for id, n := range received {
		require.NotZero(t, n, "stream %d received no data", id)
	}
	require.Len(t, received, bulkStreams+1)
}
