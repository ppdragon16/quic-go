package quic

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/utils"
	"github.com/daeuniverse/quic-go/internal/utils/ringbuffer"
	"github.com/daeuniverse/quic-go/internal/wire"
)

const (
	// Initial and maximum send queue capacities. The queue starts at the
	// initial size and grows once to the maximum on first overflow, avoiding
	// both wasteful pre-allocation for idle connections and head-of-line
	// blocking under load (e.g. when the pacer or cwnd throttles sending
	// during concurrent TCP traffic).
	initDatagramSendQueueLen = 32
	maxDatagramSendQueueLen  = 128
	// Initial and maximum receive queue capacities. The queue starts at the
	// initial size and grows once to the maximum on first overflow, absorbing
	// bursts (game server explosions, mass player events) without silent drops.
	initDatagramRcvQueueLen = 128
	maxDatagramRcvQueueLen  = 512
	// maxDatagramBufPoolLen bounds how many receive buffers are retained for
	// reuse. It must cover the worst-case in-flight depth, not just this
	// queue: the MASQUE consumer adds another maxUDPFlows*4 (=512) slots of
	// readCh on top of maxDatagramRcvQueueLen, so a burst can hold >1024
	// buffers. With a 256-slot pool every datagram beyond 256 in flight
	// allocated on Get and was dropped on Put — a permanent per-datagram
	// allocation treadmill (117MB cumulative in a MASQUE-relay heap profile).
	// 1024 x 1452B = ~1.5MB worst-case retention.
	maxDatagramBufPoolLen = 1024
)

// datagramSendQueueFullTimeout bounds how long Add waits on a full send queue
// before dropping the datagram and returning ErrDatagramQueueFullTimeout. It
// is a var so tests can shorten the wait.
//
// The timer measures the length of a *zero-drain* stall: every datagram that
// is dequeued (h.sent) resets it, so slow-but-steady backpressure never trips
// it — only a queue that stays full with nothing sent for the whole interval
// does. Note that congestion-limited packing never drains this queue at all:
// SendAck packs an ACK-only packet, and composeNextPacket returns before the
// DATAGRAM handling, so a peer that stops ACKing leaves a full queue undrained
// while the retransmission timeout backs off (each PTO doubles the interval).
// The timeout is therefore both the bound on a black-holed path and the bound
// on how long the writing goroutine blocks; 5s stays above a transient
// congestion burst (cwnd collapse and recovery are RTT-scale) and well below
// the 30s idle timeout (see hy2 defaultMaxIdleTimeout), which is receive-side
// and masked by keep-alives while the peer is reachable.
var datagramSendQueueFullTimeout = 5 * time.Second

// ErrDatagramQueueFullTimeout is returned by Add when the send queue stayed
// full for datagramSendQueueFullTimeout. The datagram was dropped and the
// connection is still alive; callers may retry with a later datagram, or treat
// the error as a signal that the transport is stalled and retire it.
var ErrDatagramQueueFullTimeout = errors.New("datagram send queue full: timed out")

// datagramBufPool recycles the receive-side datagram buffers. Incoming
// DATAGRAM frames are copied out of the packet buffer into one of these,
// handed to ReceiveDatagram, and returned via ReleaseDatagram. Without the
// pool, every inbound datagram allocates (line-rate UDP relay = constant GC
// pressure); with it, buffers are reused and only the ones actually in flight
// are live.
//
// A bounded channel is used instead of sync.Pool: sync.Pool boxes []byte into
// an interface on every Put/Get (a 24B slice-header escape allocation per
// datagram), and it has no upper bound, so a burst can pin arbitrarily many
// buffers until the next GC. The channel pool is allocation-free and capped.
var datagramBufPool *datagramBufPoolT
var datagramBufPoolOnce sync.Once

// getDatagramBufPool lazily initializes the receive-side datagram buffer pool
// on first use instead of at package init, so processes that never receive a
// QUIC datagram do not pay the pool's pre-warm cost.
func getDatagramBufPool() *datagramBufPoolT {
	datagramBufPoolOnce.Do(func() {
		datagramBufPool = newDatagramBufPool()
	})
	return datagramBufPool
}

type datagramBufPoolT struct {
	ch chan []byte
}

func newDatagramBufPool() *datagramBufPoolT {
	p := &datagramBufPoolT{ch: make(chan []byte, maxDatagramBufPoolLen)}
	// warm the pool so the first bursts don't all allocate
	for i := 0; i < maxDatagramBufPoolLen/4; i++ {
		p.ch <- make([]byte, 0, protocol.MaxPacketBufferSize)
	}
	return p
}

func (p *datagramBufPoolT) Get() []byte {
	select {
	case b := <-p.ch:
		return b[:0]
	default:
		return make([]byte, 0, protocol.MaxPacketBufferSize)
	}
}

func (p *datagramBufPoolT) Put(b []byte) {
	if cap(b) != protocol.MaxPacketBufferSize {
		// Not one of ours (oversized datagram or caller buffer): let GC
		// reclaim it instead of pinning a large allocation in the pool.
		return
	}
	select {
	case p.ch <- b:
	default:
		// pool full: drop the buffer, GC reclaims it
	}
}

type datagramQueue struct {
	sendMx    sync.Mutex
	sendQueue ringbuffer.RingBuffer[*wire.DatagramFrame]
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvMx    sync.Mutex
	rcvQueue ringbuffer.RingBuffer[[]byte]
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	q := &datagramQueue{
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
		sendQueue: func() ringbuffer.RingBuffer[*wire.DatagramFrame] {
			var rb ringbuffer.RingBuffer[*wire.DatagramFrame]
			rb.Init(initDatagramSendQueueLen)
			return rb
		}(),
		// Use a ring buffer for the receive queue so steady-state enqueue
		// never triggers slice growth allocations.
		rcvQueue: func() ringbuffer.RingBuffer[[]byte] {
			var rb ringbuffer.RingBuffer[[]byte]
			rb.Init(initDatagramRcvQueueLen)
			return rb
		}(),
	}
	return q
}

// Add queues a new DATAGRAM frame for sending.
// The send queue starts at initDatagramSendQueueLen entries and grows once
// to maxDatagramSendQueueLen on first overflow. Once the maximum is reached,
// Add blocks until space is available or datagramSendQueueFullTimeout elapses,
// whichever comes first. The timeout is a wall-clock deadline from the first
// blocked wait: a trickle of Pop/sent notifications must not reset it, or a
// chronically full queue would park the sender indefinitely.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	// Absolute deadline from the first blocked wait; the timer is created
	// once and never reset, so dequeue notifications cannot extend the
	// wait. Stopped in defer on the way out.
	var deadline time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	for {
		// Fail fast when the connection closed while this Add was waiting
		// for the mutex: a frame queued after CloseWithError's drain would
		// otherwise be dropped silently while Add reports success.
		select {
		case <-h.closed:
			h.sendMx.Unlock()
			return h.closeErr
		default:
		}
		if h.sendQueue.Len() < h.sendQueue.Cap() {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
		// Queue at current capacity — try one-time expansion.
		if h.sendQueue.Cap() < maxDatagramSendQueueLen {
			h.sendQueue.GrowTo(maxDatagramSendQueueLen)
			continue
		}
		// Already at absolute maximum — block.
		select {
		case <-h.sent: // drain the queue so we don't loop immediately
		default:
		}
		h.sendMx.Unlock()

		if deadline.IsZero() {
			deadline = time.Now().Add(datagramSendQueueFullTimeout)
			timer = time.NewTimer(time.Until(deadline))
		}

		select {
		case <-h.closed:
			// Connection closed while blocked on a full queue; the frame was
			// never packed, so nothing references it: return it to the pool.
			wire.PutDatagramFrame(f)
			return h.closeErr
		case <-h.sent:
		case <-timer.C:
			// Queue stayed full with nothing dequeued for the whole timeout:
			// the transport is stalled, not merely backpressured. Drop this
			// datagram and surface a bounded error instead of parking forever.
			// The frame was never packed: return it to the pool.
			wire.PutDatagramFrame(f)
			return ErrDatagramQueueFullTimeout
		}
		h.sendMx.Lock()
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	if h.sendQueue.Empty() {
		return nil
	}
	return h.sendQueue.PeekFront()
}

func (h *datagramQueue) Pop() {
	h.sendMx.Lock()
	defer h.sendMx.Unlock()
	_ = h.sendQueue.PopFront()
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
// The receive queue starts at initDatagramRcvQueueLen entries and grows once
// to maxDatagramRcvQueueLen on first overflow. Once the maximum is reached,
// incoming datagrams are silently dropped.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	buf := getDatagramBufPool().Get()
	if cap(buf) < len(f.Data) {
		getDatagramBufPool().Put(buf)
		buf = make([]byte, len(f.Data))
	} else {
		buf = buf[:len(f.Data)]
	}
	copy(buf, f.Data)
	// Return the parsed frame to the pool: its payload has been copied into
	// our own buffer, so the frame (and its Data) can be reused.
	wire.PutDatagramFrame(f)
	var queued bool
	h.rcvMx.Lock()
	if h.rcvQueue.Len() < h.rcvQueue.Cap() {
		h.rcvQueue.PushBack(buf)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	} else if h.rcvQueue.Cap() < maxDatagramRcvQueueLen {
		// Queue at current capacity — one-time expansion.
		h.rcvQueue.GrowTo(maxDatagramRcvQueueLen)
		h.rcvQueue.PushBack(buf)
		queued = true
		select {
		case h.rcvd <- struct{}{}:
		default:
		}
	}
	h.rcvMx.Unlock()
	if !queued && h.logger.Debug() {
		h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
	}
}

// ReleaseDatagram returns a datagram previously handed out by Receive back to
// the pool. Callers MUST call this exactly once per datagram after they are
// done with the buffer. It is a no-op for buffers that were not pooled (e.g.
// ones whose size exceeded the pool cap at receive time).
func (h *datagramQueue) ReleaseDatagram(data []byte) {
	if data == nil {
		return
	}
	if cap(data) != protocol.MaxPacketBufferSize {
		// Buffer was not taken from the pool (oversized datagram or a
		// caller-supplied buffer); let GC reclaim it.
		return
	}
	getDatagramBufPool().Put(data)
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		h.rcvMx.Lock()
		if !h.rcvQueue.Empty() {
			data := h.rcvQueue.PopFront()
			h.rcvMx.Unlock()
			return data, nil
		}
		h.rcvMx.Unlock()
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
	close(h.closed)
	// Drain queued frames/buffers so they are released instead of sitting
	// until GC. Packer and Receive stop after the connection run loop
	// exits, so nothing else will consume these entries.
	h.sendMx.Lock()
	// Queued send frames were never packed, so nothing references them:
	// return them to the pool.
	for !h.sendQueue.Empty() {
		wire.PutDatagramFrame(h.sendQueue.PopFront())
	}
	h.sendMx.Unlock()
	h.rcvMx.Lock()
	for !h.rcvQueue.Empty() {
		getDatagramBufPool().Put(h.rcvQueue.PopFront())
	}
	h.rcvMx.Unlock()
}
