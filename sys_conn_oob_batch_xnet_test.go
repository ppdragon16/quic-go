//go:build darwin || freebsd || (linux && (386 || s390x))

package quic

import (
	"fmt"
	"testing"

	"golang.org/x/net/ipv4"

	"github.com/daeuniverse/quic-go/internal/protocol"

	"github.com/stretchr/testify/require"
)

type mockBatchConn struct {
	t           *testing.T
	numMsgRead  int
	callCounter int
}

var _ batchConn = &mockBatchConn{}

func (c *mockBatchConn) ReadBatch(ms []ipv4.Message, _ int) (int, error) {
	require.Len(c.t, ms, batchSize)
	for i := 0; i < c.numMsgRead; i++ {
		require.Len(c.t, ms[i].Buffers, 1)
		require.Len(c.t, ms[i].Buffers[0], protocol.MaxPacketBufferSize)
		data := []byte(fmt.Sprintf("message %d", c.callCounter*c.numMsgRead+i))
		ms[i].Buffers[0] = data
		ms[i].N = len(data)
	}
	c.callCounter++
	return c.numMsgRead, nil
}

func TestReadsMultipleMessagesInOneBatch(t *testing.T) {
	bc := &mockBatchConn{t: t, numMsgRead: batchSize/2 + 1}

	udpConn := newUPDConnLocalhost(t)
	oobConn, err := newConn(udpConn, true)
	require.NoError(t, err)
	oobConn.read.(*ipv4OOBRead).batchConn = bc

	for i := 0; i < batchSize+1; i++ {
		p, err := oobConn.ReadPacket()
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("message %d", i), string(p.data))
	}
	require.Equal(t, 2, bc.callCounter)
}
