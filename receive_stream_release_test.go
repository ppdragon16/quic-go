package quic

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go/internal/mocks"
	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestStreamFrameDoublePutPanics guards the frame pool against the silent
// double-put corruption bug: returning the same *wire.StreamFrame to the pool
// twice hands its Data buffer to two connections, which then overwrite each
// other's data. This mirrors packetBuffer.Release, which already panics when a
// packet buffer is released twice (see TestBufferPoolRelease).
func TestStreamFrameDoublePutPanics(t *testing.T) {
	f := wire.GetStreamFrame()
	f.Data = []byte("abcd")
	f.PutBack()
	require.Nil(t, f.Data, "PutBack must clear Data so the pooled frame holds no stale buffer reference")
	require.Panics(t, func() { f.PutBack() }, "a double-put must panic instead of corrupting data")
}

// TestDatagramFrameDoublePutPanics guards the DATAGRAM frame pool the same way
// as TestStreamFrameDoublePutPanics: PutDatagramFrame returns the frame's Data
// buffer to the shared pool, so returning the same frame twice would hand one
// buffer to two connections.
func TestDatagramFrameDoublePutPanics(t *testing.T) {
	f := wire.GetDatagramFrame()
	f.Data = []byte("abcd")
	wire.PutDatagramFrame(f)
	require.Nil(t, f.Data, "PutDatagramFrame must clear Data so the pooled frame holds no stale buffer reference")
	require.Panics(t, func() { wire.PutDatagramFrame(f) }, "a double-put must panic instead of corrupting data")
}

// TestReceiveStreamSinglePutOnReleasePaths exercises every receive-stream
// release path that pairs two teardown steps (read-to-EOF, CancelRead,
// RESET_STREAM, closeForShutdown). If any of them ever returns the same frame
// to the pool twice, putStreamFrame panics and the test fails loudly.
func TestReceiveStreamSinglePutOnReleasePaths(t *testing.T) {
	testErr := errors.New("shutdown")

	t.Run("EOF then closeForShutdown", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := mocks.NewMockStreamFlowController(mockCtrl)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)

		now := time.Now()
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), true, now)
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(4))
		mockSender.EXPECT().onStreamCompleted(protocol.StreamID(42))

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("abcd"), Fin: true}, now))
		n, err := str.Read(make([]byte, 4))
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, 4, n)

		// The frame was already returned when EOF was read; this second
		// teardown must not return it again.
		str.closeForShutdown(testErr)
	})

	t.Run("CancelRead then closeForShutdown", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := mocks.NewMockStreamFlowController(mockCtrl)
		mockSender := NewMockStreamSender(mockCtrl)
		str := newReceiveStream(42, mockSender, mockFC)

		now := time.Now()
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false, now)
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), false, now)
		mockSender.EXPECT().onHasStreamControlFrame(protocol.StreamID(42), str)

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("abcd")}, now))
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 4, Data: []byte("efgh")}, now))

		// CancelRead drains the sorter (returns both buffered frames)...
		str.CancelRead(1337)
		// ...and a later shutdown must find nothing left to release.
		str.closeForShutdown(testErr)
	})

	t.Run("Reset then closeForShutdown", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := mocks.NewMockStreamFlowController(mockCtrl)
		str := newReceiveStream(42, nil, mockFC)

		now := time.Now()
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false, now)
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), false, now)
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), true, gomock.Any())
		mockFC.EXPECT().Abandon()

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("abcd")}, now))
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 4, Data: []byte("efgh")}, now))

		// RESET releases the buffered frames...
		require.NoError(t, str.handleResetStreamFrame(
			&wire.ResetStreamFrame{StreamID: 42, ErrorCode: 1234, FinalSize: 8},
			time.Now(),
		))
		// ...so the follow-up shutdown must not release them again.
		str.closeForShutdown(testErr)
	})

	t.Run("partial read then closeForShutdown", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		mockFC := mocks.NewMockStreamFlowController(mockCtrl)
		str := newReceiveStream(42, nil, mockFC)

		now := time.Now()
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(4), false, now)
		mockFC.EXPECT().UpdateHighestReceived(protocol.ByteCount(8), false, now)
		mockFC.EXPECT().AddBytesRead(protocol.ByteCount(1))

		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Data: []byte("abcd")}, now))
		require.NoError(t, str.handleStreamFrame(&wire.StreamFrame{Offset: 4, Data: []byte("efgh")}, now))

		// Consume one byte: the first frame becomes currentFrameFrame, the
		// second stays buffered in the sorter.
		n, err := str.Read(make([]byte, 1))
		require.NoError(t, err)
		require.Equal(t, 1, n)

		// Shutdown releases both the in-flight frame and the buffered frame,
		// each exactly once.
		str.closeForShutdown(testErr)
	})
}
