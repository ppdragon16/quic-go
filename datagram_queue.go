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
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
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
	rcvQueue [][]byte
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
		// Pre-allocate the receive queue so steady-state enqueue never
		// triggers slice growth allocations.
		rcvQueue: make([][]byte, 0, maxDatagramRcvQueueLen),
	}
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	h.sendMx.Lock()

	for {
		if h.sendQueue.Len() < maxDatagramSendQueueLen {
			h.sendQueue.PushBack(f)
			h.sendMx.Unlock()
			h.hasData()
			return nil
		}
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
	if len(h.rcvQueue) < maxDatagramRcvQueueLen {
		h.rcvQueue = append(h.rcvQueue, buf)
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
		if len(h.rcvQueue) > 0 {
			data := h.rcvQueue[0]
			h.rcvQueue = h.rcvQueue[1:]
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
