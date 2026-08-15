//go:build darwin || freebsd || (linux && (386 || s390x))

package quic

import (
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

// Contrary to what the naming suggests, the ipv{4,6}.Message is not dependent
// on the IP version. They're both just aliases for x/net/internal/socket.Message.
// This means we can use this struct to read from a socket that receives both
// IPv4 and IPv6 messages.
var _ ipv4.Message = ipv6.Message{}

// ipv4OOBRead is the x/net ReadBatch-based batched reader. It is the fallback
// used on platforms without recvmmsg (or where recvmmsg uses the socketcall
// multiplexer). Each datagram's address is allocated by x/net's parseInetAddr
// and then recycled via addrPool when the buffer is released.
type ipv4OOBRead struct {
	batchConn batchConn
	messages  []ipv4.Message
}

func newOOBReadState(c OOBCapablePacketConn) oobReadState {
	var bc batchConn
	if ibc, ok := c.(batchConn); ok {
		bc = ibc
	} else {
		bc = ipv4.NewPacketConn(c)
	}
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		// preallocate the [][]byte
		msgs[i].Buffers = make([][]byte, 1)
	}
	r := &ipv4OOBRead{batchConn: bc, messages: msgs}
	for i := 0; i < batchSize; i++ {
		r.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return r
}

func (r *ipv4OOBRead) read(c *oobConn, refill int) (int, error) {
	r.messages = r.messages[:batchSize]
	// replace the data buffers of the packets consumed during the last batch
	for i := uint8(0); i < uint8(refill); i++ {
		buffer := getPacketBuffer()
		buffer.Data = buffer.Data[:protocol.MaxPacketBufferSize]
		c.buffers[i] = buffer
		r.messages[i].Buffers[0] = c.buffers[i].Data
	}
	n, err := r.batchConn.ReadBatch(r.messages, 0)
	if err != nil {
		return n, err
	}
	r.messages = r.messages[:n]
	return n, nil
}

func (r *ipv4OOBRead) datagram(c *oobConn, i int) (payload, oob []byte, addr *net.UDPAddr) {
	msg := r.messages[i]
	buffer := c.buffers[i]
	payload = msg.Buffers[0][:msg.N]
	oob = msg.OOB[:msg.NN]
	// The *net.UDPAddr is allocated by x/net's ReadBatch; storing it on the
	// buffer lets putBack recycle it via the addr pool.
	if udpAddr, ok := msg.Addr.(*net.UDPAddr); ok {
		buffer.addr = udpAddr
	}
	return payload, oob, buffer.addr
}
