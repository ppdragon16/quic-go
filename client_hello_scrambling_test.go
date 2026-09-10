package quic

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"
)

// getClientHelloWithDefaultCurves builds the ClientHello the library actually
// sends: with the post-quantum key share enabled it is ~1.4 KB, i.e. it does
// not fit into a single Initial packet. That is precisely the situation the
// ClientHello scrambling targets.
func getClientHelloWithDefaultCurves(t testing.TB, serverName string) []byte {
	t.Helper()
	c := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: serverName == "",
		},
	})
	c.SetTransportParameters([]byte("params"))
	require.NoError(t, c.Start(context.Background()))
	ev := c.NextEvent()
	require.Equal(t, tls.QUICWriteData, ev.Kind)
	checkClientHello(t, ev.Data)
	return ev.Data
}

// firstInitialPacketFrames bootstraps a client packet packer, hands it the given
// ClientHello, and returns the CRYPTO frames the packer puts into the FIRST
// Initial packet, ordered by stream offset.
func firstInitialPacketFrames(t *testing.T, clientHello []byte) []*wire.CryptoFrame {
	t.Helper()
	mockCtrl := gomock.NewController(t)
	tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
	tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil).AnyTimes()
	tp.ackFramer.EXPECT().GetAckFrame(protocol.EncryptionInitial, gomock.Any(), false).AnyTimes()
	tp.pnManager.EXPECT().PeekPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42), protocol.PacketNumberLen2).AnyTimes()
	tp.pnManager.EXPECT().PopPacketNumber(protocol.EncryptionInitial).Return(protocol.PacketNumber(0x42)).AnyTimes()

	_, err := tp.initialStream.Write(clientHello)
	require.NoError(t, err)

	hdr, pl := tp.packer.maybeGetCryptoPacket(
		protocol.MinInitialPacketSize, protocol.EncryptionInitial, time.Now(), false, true, protocol.Version1,
	)
	require.NotNil(t, hdr)
	require.NotEmpty(t, pl.frames)

	frames := make([]*wire.CryptoFrame, 0, len(pl.frames))
	for _, f := range pl.frames {
		cf, ok := f.Frame.(*wire.CryptoFrame)
		require.True(t, ok, "first Initial packet should only contain CRYPTO frames, got %T", f.Frame)
		frames = append(frames, cf)
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].Offset < frames[j].Offset })
	return frames
}

// recoverFromFirstPacket reproduces what a middlebox inspecting a single
// datagram can recover: QUIC Initial keys are derived from the connection ID
// and are therefore public, so the CRYPTO frames of the first packet are
// readable. Frames carry their own offsets, so they are reassembled as such;
// a range that was deferred to a later packet stays a hole.
func recoverFromFirstPacket(frames []*wire.CryptoFrame) string {
	var sb strings.Builder
	var next protocol.ByteCount
	for _, f := range frames {
		if f.Offset > next {
			sb.WriteString(strings.Repeat("\x00", int(f.Offset-next)))
		}
		sb.Write(f.Data)
		next = f.Offset + protocol.ByteCount(len(f.Data))
	}
	return sb.String()
}

// TestClientHelloScramblingHidesSNIFromFirstPacket is the purpose-aligned check
// for the ClientHello scrambling: a DPI that decrypts the first Initial packet
// and reassembles its CRYPTO frames must NOT be able to read the server name,
// because the bytes in the middle of the SNI are withheld until a later packet.
func TestClientHelloScramblingHidesSNIFromFirstPacket(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)

	const serverName = "quic-go.net"
	clientHello := getClientHelloWithDefaultCurves(t, serverName)
	require.Contains(t, string(clientHello), serverName, "sanity: the unscrambled ClientHello contains the SNI")
	require.Greater(t, len(clientHello), int(protocol.MinInitialPacketSize),
		"sanity: this test is only meaningful if the ClientHello spans more than one Initial packet")

	frames := firstInitialPacketFrames(t, clientHello)
	recovered := recoverFromFirstPacket(frames)

	require.NotContains(t, recovered, serverName,
		"the SNI must not be recoverable from the first Initial packet alone")
	// The bytes before the cut are still sent, otherwise the peer could not
	// make progress on the handshake.
	require.Contains(t, recovered, serverName[:len(serverName)/2],
		"the part of the SNI before the cut is still sent in the first packet")

	var holes int
	var next protocol.ByteCount
	for _, f := range frames {
		if f.Offset > next {
			holes++
		}
		next = f.Offset + protocol.ByteCount(len(f.Data))
	}
	require.Equal(t, 1, holes, "expected exactly one hole, inside the SNI")
}

// TestClientHelloScramblingDisabledIsContiguous is the control for the test
// above: with scrambling switched off, the first packet carries a contiguous
// prefix of the ClientHello, so the SNI is readable -- proving that the test
// above measures the scrambling and not an artifact of the packing.
func TestClientHelloScramblingDisabledIsContiguous(t *testing.T) {
	t.Setenv(disableClientHelloScramblingEnv, "true")

	const serverName = "quic-go.net"
	clientHello := getClientHelloWithDefaultCurves(t, serverName)
	require.Greater(t, len(clientHello), int(protocol.MinInitialPacketSize))

	frames := firstInitialPacketFrames(t, clientHello)

	var next protocol.ByteCount
	for _, f := range frames {
		require.Equal(t, next, f.Offset, "with scrambling disabled the frames must be contiguous")
		next += protocol.ByteCount(len(f.Data))
	}
	require.Contains(t, recoverFromFirstPacket(frames), serverName,
		"with scrambling disabled the SNI is readable in the first packet")
}

// TestClientHelloScramblingReassemblesToOriginal guards the other half of the
// contract: however the ClientHello is cut, draining the stream must yield
// exactly the original bytes, so the handshake still works.
func TestClientHelloScramblingReassemblesToOriginal(t *testing.T) {
	skipIfDisableScramblingEnvSet(t)

	for _, serverName := range []string{"quic-go.net", "sub.do.ma.in.quic-go.net", "a.example.com"} {
		t.Run(serverName, func(t *testing.T) {
			clientHello := getClientHelloWithDefaultCurves(t, serverName)
			str := newInitialCryptoStream(true)
			_, err := str.Write(clientHello)
			require.NoError(t, err)

			segments := make(map[protocol.ByteCount][]byte)
			for str.HasData() {
				f := str.PopCryptoFrame(protocol.MinInitialPacketSize)
				require.NotNil(t, f)
				segments[f.Offset] = f.Data
			}
			require.Equal(t, clientHello, reassembleCryptoData(t, segments))
		})
	}
}
