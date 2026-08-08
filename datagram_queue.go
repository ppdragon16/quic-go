package quic

import (
	"context"
	"sync"

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
	// reuse. 256 x 1452B = ~372KB worst-case steady-state retention, which
	// caps the pool's footprint while still absorbing line-rate bursts.
	maxDatagramBufPoolLen = 256
)

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
var datagramBufPool = newDatagramBufPool()

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
	return &datagramQueue{
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
}

// Add queues a new DATAGRAM frame for sending.
// The send queue starts at initDatagramSendQueueLen entries and grows once
// to maxDatagramSendQueueLen on first overflow. Once the maximum is reached,
// Add blocks until space is available.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
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
		select {
		case <-h.closed:
			// Connection closed while blocked on a full queue: the frame
			// was never sent, return it to the pool.
			wire.PutDatagramFrame(f)
			return h.closeErr
		case <-h.sent:
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
	buf := datagramBufPool.Get()
	if cap(buf) < len(f.Data) {
		datagramBufPool.Put(buf)
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
	datagramBufPool.Put(data)
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
}
