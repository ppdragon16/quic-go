package quic

import (
	"sync/atomic"
	"time"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn

	// Send-path watchdog state. Run is the only writer; the connection's
	// watchdog goroutine reads them to tell a socket write that is stuck (the
	// kernel send buffer or device queue is not draining) apart from a
	// connection that stopped packing packets altogether — the two ways a
	// transport stalls, which are otherwise indistinguishable from outside and
	// from a merely idle connection.
	//
	// lastActivity is the unix-nano time of the last packet queued or written;
	// writeStarted is the unix-nano time the in-flight socket write began
	// (0 when no write is in flight).
	lastActivity atomic.Int64
	writeStarted atomic.Int64
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 8

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
		h.lastActivity.Store(time.Now().UnixNano())
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
	defer close(h.runStopped)
	var shouldClose bool
	for {
		if shouldClose && len(h.queue) == 0 {
			return nil
		}
		select {
		case <-h.closeCalled:
			h.closeCalled = nil // prevent this case from being selected again
			// make sure that all queued packets are actually sent out
			shouldClose = true
		case e := <-h.queue:
			h.writeStarted.Store(time.Now().UnixNano())
			werr := h.conn.Write(e.buf.Data, e.gsoSize, e.ecn)
			h.writeStarted.Store(0)
			h.lastActivity.Store(time.Now().UnixNano())
			if werr != nil {
				// This additional check enables:
				// 1. Checking for "datagram too large" message from the kernel, as such,
				// 2. Path MTU discovery,and
				// 3. Eventual detection of loss PingFrame.
				if !isSendMsgSizeErr(werr) {
					// Unrecoverable write error: release this buffer and the
					// remaining queued buffers before stopping, otherwise they
					// would be leaked (never sent and never released).
					e.buf.Release()
					for {
						select {
						case queued := <-h.queue:
							queued.buf.Release()
						default:
							return werr
						}
					}
				}
			}
			e.buf.Release()
			select {
			case h.available <- struct{}{}:
			default:
			}
		}
	}
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}

// LastActivity reports when a packet was last queued for sending or written to
// the socket; the zero time before either happens.
func (h *sendQueue) LastActivity() time.Time {
	ns := h.lastActivity.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Pending reports how many packets are waiting to be written to the socket.
func (h *sendQueue) Pending() int { return len(h.queue) }

// WriteBlockedFor reports how long the socket write that is currently in flight
// has been running, or 0 when no write is in flight.
func (h *sendQueue) WriteBlockedFor(now time.Time) time.Duration {
	ns := h.writeStarted.Load()
	if ns == 0 {
		return 0
	}
	return now.Sub(time.Unix(0, ns))
}
