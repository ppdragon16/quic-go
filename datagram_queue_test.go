package quic

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/internal/utils"
	"github.com/daeuniverse/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

func TestDatagramQueuePeekAndPop(t *testing.T) {
	var queued []struct{}
	queue := newDatagramQueue(func() { queued = append(queued, struct{}{}) }, utils.DefaultLogger)
	require.Nil(t, queue.Peek())
	require.Empty(t, queued)
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("foo")}))
	require.Len(t, queued, 1)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	// calling peek again returns the same datagram
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foo")}, queue.Peek())
	queue.Pop()
	require.Nil(t, queue.Peek())
}

func TestDatagramQueueSendQueueLength(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// peeking doesn't remove the datagram from the queue...
	require.NotNil(t, queue.Peek())
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}

	// ...but popping does
	queue.Pop()
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	// pop all the remaining datagrams
	for i := 1; i < maxDatagramSendQueueLen; i++ {
		queue.Pop()
	}
	f := queue.Peek()
	require.NotNil(t, f)
	require.Equal(t, &wire.DatagramFrame{Data: []byte("foobar")}, f)
}

func TestDatagramQueueReceive(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// receive frames that were received earlier
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foo")})
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("bar")})
	data, err := queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), data)
	data, err = queue.Receive(context.Background())
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), data)
}

func TestDatagramQueueReceiveBlocking(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	// block until a new frame is received
	type result struct {
		data []byte
		err  error
	}
	resultChan := make(chan result, 1)
	go func() {
		data, err := queue.Receive(context.Background())
		resultChan <- result{data, err}
	}()

	select {
	case <-resultChan:
		t.Fatal("expected to not receive result")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	queue.HandleDatagramFrame(&wire.DatagramFrame{Data: []byte("foobar")})
	select {
	case result := <-resultChan:
		require.NoError(t, result.err)
		require.Equal(t, []byte("foobar"), result.data)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// unblock when the context is canceled
	ctx, cancel := context.WithCancel(context.Background())
	errChan := make(chan error, 1)
	go func() {
		_, err := queue.Receive(ctx)
		errChan <- err
	}()
	select {
	case <-errChan:
		t.Fatal("expected to not receive error")
	case <-time.After(scaleDuration(10 * time.Millisecond)):
	}
	cancel()
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestDatagramQueueClose(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}
	errChan1 := make(chan error, 1)
	go func() { errChan1 <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()
	errChan2 := make(chan error, 1)
	go func() {
		_, err := queue.Receive(context.Background())
		errChan2 <- err
	}()

	queue.CloseWithError(errors.New("test error"))

	select {
	case err := <-errChan1:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	select {
	case err := <-errChan2:
		require.EqualError(t, err, "test error")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

// A full send queue must surface ErrDatagramQueueFullTimeout after
// datagramSendQueueFullTimeout instead of parking the sender forever, and the
// connection must stay alive so a later datagram can still be queued.
func TestDatagramQueueAddTimeout(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}

	old := datagramSendQueueFullTimeout
	datagramSendQueueFullTimeout = scaleDuration(20 * time.Millisecond)
	defer func() { datagramSendQueueFullTimeout = old }()

	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("foobar")}) }()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrDatagramQueueFullTimeout)
	case <-time.After(scaleDuration(2 * time.Second)):
		t.Fatal("expected Add to return after the queue-full timeout")
	}

	// The connection is still alive: once the queue drains, a subsequent Add succeeds.
	queue.Pop()
	require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte("baz")}))
}

// A trickle of sent notifications must not reset the queue-full deadline.
// The old timer-in-the-loop waited another full timeout after every Pop
// signal, so a chronically full queue parked the sender indefinitely.
func TestDatagramQueueAddTimeoutAbsoluteDeadline(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	for i := 0; i < maxDatagramSendQueueLen; i++ {
		require.NoError(t, queue.Add(&wire.DatagramFrame{Data: []byte{0}}))
	}

	old := datagramSendQueueFullTimeout
	datagramSendQueueFullTimeout = scaleDuration(40 * time.Millisecond)
	defer func() { datagramSendQueueFullTimeout = old }()

	errChan := make(chan error, 1)
	go func() { errChan <- queue.Add(&wire.DatagramFrame{Data: []byte("late")}) }()

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		ticker := time.NewTicker(scaleDuration(5 * time.Millisecond))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				// Pop and refill under the same lock so the blocked Add
				// cannot sneak into the vacated slot. Then signal sent,
				// which is what a real Pop would do.
				queue.sendMx.Lock()
				if !queue.sendQueue.Empty() {
					_ = queue.sendQueue.PopFront()
					queue.sendQueue.PushBack(&wire.DatagramFrame{Data: []byte{1}})
				}
				select {
				case queue.sent <- struct{}{}:
				default:
				}
				queue.sendMx.Unlock()
			}
		}
	}()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, ErrDatagramQueueFullTimeout)
	case <-time.After(scaleDuration(2 * time.Second)):
		t.Fatal("expected Add to time out at the original deadline despite periodic sent signals")
	}
}

func TestDatagramQueueCloseWithErrorDrainsQueuedFrames(t *testing.T) {
	queue := newDatagramQueue(func() {}, utils.DefaultLogger)

	f := wire.GetDatagramFrame()
	f.Data = append(f.Data, "queued"...)
	require.NoError(t, queue.Add(f))
	require.NotNil(t, queue.Peek())

	incoming := &wire.DatagramFrame{Data: []byte("recv")}
	queue.HandleDatagramFrame(incoming)

	queue.CloseWithError(errors.New("closed"))

	require.Nil(t, queue.Peek(), "send queue must be drained on close")
	_, err := queue.Receive(context.Background())
	require.EqualError(t, err, "closed", "receive queue must be drained, not handed to Receive")

	late := wire.GetDatagramFrame()
	require.Error(t, queue.Add(late))
}

// TestReceiveQueueStorageBoundedWithoutFullDrain pins the ring-buffer
// conversion: consuming entries must release their slots even while the queue
// never fully drains, so the underlying storage stays at the initialized
// capacity across many receive/release/enqueue cycles.
func TestReceiveQueueStorageBoundedWithoutFullDrain(t *testing.T) {
	q := newDatagramQueue(nil, nil)
	// HandleDatagramFrame takes ownership of the frame (its payload is copied
	// and the frame is returned to the wire pool), so every call gets a fresh
	// frame.
	newFrame := func() *wire.DatagramFrame { return &wire.DatagramFrame{Data: make([]byte, 64)} }

	// Seed two entries, then run many cycles that keep at least one entry
	// queued at every enqueue (the old slice+head scheme retained every
	// consumed header in this pattern, growing without bound).
	q.HandleDatagramFrame(newFrame())
	q.HandleDatagramFrame(newFrame())
	for i := 0; i < 20000; i++ {
		data, err := q.Receive(context.Background())
		if err != nil {
			t.Fatalf("Receive: %v", err)
		}
		q.ReleaseDatagram(data)
		q.HandleDatagramFrame(newFrame()) // never lets the queue drain empty
		if q.rcvQueue.Len() != 2 {
			t.Fatalf("iteration %d: queue len = %d, want 2", i, q.rcvQueue.Len())
		}
	}
	// Drain in FIFO order.
	for i := 0; i < 2; i++ {
		if _, err := q.Receive(context.Background()); err != nil {
			t.Fatalf("final Receive %d: %v", i, err)
		}
	}
	if !q.rcvQueue.Empty() {
		t.Fatal("queue must be empty after drain")
	}
}

// TestDatagramSendQueueFullTimeoutDefault pins the default bound on a stalled
// datagram send queue.
//
// A peer that stops ACKing leaves this queue undrained for as long as the
// retransmission timeout keeps backing off (congestion-limited packing never
// pops a datagram), so this timeout is both how fast a black-holed path is
// detected and how long the writing goroutine blocks. It has to stay well below
// the 30s idle timeout and above a transient congestion burst; raising it back
// to a "safer" value silently restores a multi-second hang per stalled write.
func TestDatagramSendQueueFullTimeoutDefault(t *testing.T) {
	if datagramSendQueueFullTimeout != 5*time.Second {
		t.Fatalf("datagramSendQueueFullTimeout = %v, want 5s", datagramSendQueueFullTimeout)
	}
}
