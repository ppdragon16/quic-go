package quic

import (
	"context"
	"crypto/rand"
	"io"
	mrand "math/rand/v2"
	"testing"

	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/daeuniverse/quic-go/internal/testdata"
)

// Tests for findSNIAndECH, the ClientHello parser used by the ClientHello
// scrambling in initialCryptoStream. Ported from quic-go PR #5107.

func checkClientHello(t testing.TB, clientHello []byte) {
	t.Helper()

	conn := tls.QUICServer(&tls.QUICConfig{
		TLSConfig: testdata.GetTLSConfig(),
	})
	require.NoError(t, conn.Start(context.Background()))
	defer conn.Close()
	require.NoError(t, conn.HandleData(tls.QUICEncryptionLevelInitial, clientHello))
}

func getClientHello(t testing.TB, serverName string) []byte {
	t.Helper()

	c := tls.QUICClient(&tls.QUICConfig{
		TLSConfig: &tls.Config{
			ServerName:         serverName,
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: serverName == "",
			// disable post-quantum curves: the ClientHello should stay small
			// enough for the packet-splitting assertions to be meaningful
			CurvePreferences: []tls.CurveID{tls.CurveP256},
		},
	})
	b := make([]byte, mrand.IntN(200))
	rand.Read(b)
	c.SetTransportParameters(b)
	require.NoError(t, c.Start(context.Background()))

	ev := c.NextEvent()
	require.Equal(t, tls.QUICWriteData, ev.Kind)
	checkClientHello(t, ev.Data)
	return ev.Data
}

func TestFindSNI(t *testing.T) {
	t.Run("without SNI", func(t *testing.T) {
		testFindSNI(t, "")
	})
	t.Run("without subdomain", func(t *testing.T) {
		testFindSNI(t, "quic-go.net")
	})
	t.Run("with subdomain", func(t *testing.T) {
		testFindSNI(t, "sub.do.ma.in.quic-go.net")
	})
}

func testFindSNI(t *testing.T, serverName string) {
	clientHello := getClientHello(t, serverName)
	sniPos, sniLen, echPos, err := findSNIAndECH(clientHello)
	require.NoError(t, err)
	assert.Equal(t, -1, echPos)
	if serverName == "" {
		require.Equal(t, -1, sniPos)
		return
	}
	assert.Equal(t, len(serverName), sniLen)
	require.NotEqual(t, -1, sniPos)
	require.Equal(t, serverName, string(clientHello[sniPos:sniPos+sniLen]))

	// incomplete ClientHellos result in an io.ErrUnexpectedEOF
	for i := range clientHello {
		_, _, _, err := findSNIAndECH(clientHello[:i])
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	}
}

// TestFindSNIRejectsMalformed covers the parser's error paths: a non-ClientHello
// and a truncated extension block must not be silently accepted, otherwise the
// scrambler would cut the ClientHello at a bogus offset.
func TestFindSNIRejectsMalformed(t *testing.T) {
	clientHello := getClientHello(t, "quic-go.net")

	notAHello := append([]byte{}, clientHello...)
	notAHello[0] = 2 // handshake type: not ClientHello
	_, _, _, err := findSNIAndECH(notAHello)
	require.Error(t, err)

	// corrupt the declared handshake length
	badLen := append([]byte{}, clientHello...)
	badLen[3]++
	_, _, _, err = findSNIAndECH(badLen)
	require.Error(t, err)

	// corrupt an extension length so it runs past the end of the extensions
	// block: the parser must bail out instead of slicing out of range
	corrupted := append([]byte{}, clientHello...)
	sniPos, sniLen, _, err := findSNIAndECH(corrupted)
	require.NoError(t, err)
	require.NotEqual(t, -1, sniPos)
	// the extension length field sits 4 bytes before the extension body
	if sniPos-4 >= 4 && sniPos-2 < len(corrupted) {
		corrupted[sniPos-2] = 0xff
		corrupted[sniPos-1] = 0xff
	}
	_, _, _, err = findSNIAndECH(corrupted)
	require.Error(t, err)
	_ = sniLen
}
