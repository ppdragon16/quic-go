package self_test

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/require"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
	quicproxy "github.com/daeuniverse/quic-go/integrationtests/tools/proxy"
)

// These tests cover the server-side 0-RTT SETTINGS check (quic-go PR #5771):
// the server embeds the SETTINGS it sent into the session ticket, and refuses
// 0-RTT on resumption when those settings are incompatible with the ones it
// would send now.
//
// This fork's settingsFrame carries Datagram and ExtendedConnect (upstream also
// tracks MaxFieldSectionSize), so datagrams are used to change the server's
// settings between the two connections.

// testSessionTicketKey is shared by every server instance in these tests:
// session tickets are only decryptable by a server holding the same key, so
// without this the second server could not resume at all and every 0-RTT
// attempt would fail for the wrong reason.
var testSessionTicketKey = [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}

func startHTTP0RTTEchoServer(t *testing.T, enableDatagrams bool) int {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/0rtt", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strconv.FormatBool(!r.TLS.HandshakeComplete))
	})
	return startHTTPServer(t, mux, func(s *http3.Server) {
		s.EnableDatagrams = enableDatagrams
		tlsConf := getTLSConfig()
		tlsConf.SetSessionTicketKeys([][32]byte{testSessionTicketKey})
		s.TLSConfig = tlsConf
	})
}

// do0RTTRequest performs one 0-RTT request and reports the body ("true" means
// the response was produced from 0-RTT data), the request error, and the number
// of 0-RTT packets the client put on the wire. The packet count says whether
// the client *attempted* 0-RTT; whether the server accepted it shows up in the
// body and in the error.
func do0RTTRequest(t *testing.T, cache tls.ClientSessionCache, puts chan string, serverPort int, first bool) (string, error, uint32) {
	t.Helper()

	var num0RTTPackets atomic.Uint32
	proxy, err := quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
		RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
		DelayPacket: func(_ quicproxy.Direction, data []byte) time.Duration {
			if contains0RTTPacket(data) {
				num0RTTPackets.Add(1)
			}
			return scaleDuration(25 * time.Millisecond)
		},
	})
	require.NoError(t, err)
	defer proxy.Close()

	tlsConf := getTLSClientConfigWithoutServerName()
	tlsConf.ClientSessionCache = newClientSessionCache(cache, nil, puts)
	tr := &http3.Transport{
		TLSClientConfig:    tlsConf,
		QUICConfig:         getQuicConfig(&quic.Config{MaxIdleTimeout: 10 * time.Second}),
		DisableCompression: true,
	}
	defer tr.Close()

	req, err := http.NewRequest(http3.MethodGet0RTT, fmt.Sprintf("https://localhost:%d/0rtt", proxy.LocalPort()), nil)
	require.NoError(t, err)
	rsp, err := tr.RoundTrip(req)
	if err != nil {
		// a rejected 0-RTT attempt surfaces as an error on the request
		if first {
			t.Fatalf("first request must succeed: %v", err)
		}
		return "", err, num0RTTPackets.Load()
	}
	defer rsp.Body.Close()
	require.Equal(t, 200, rsp.StatusCode)
	body, err := io.ReadAll(rsp.Body)
	require.NoError(t, err)
	return string(body), nil, num0RTTPackets.Load()
}

// TestHTTP0RTTSettingsUnchanged is the control: with unchanged settings the
// ticket is accepted and the second connection really uses 0-RTT.
func TestHTTP0RTTSettingsUnchanged(t *testing.T) {
	cache := tls.NewLRUClientSessionCache(10)
	puts := make(chan string, 10)

	port := startHTTP0RTTEchoServer(t, false)
	body, err, n := do0RTTRequest(t, cache, puts, port, true)
	require.NoError(t, err)
	require.Equal(t, "false", body, "first request must complete a full handshake")
	require.Zero(t, n)

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	port = startHTTP0RTTEchoServer(t, false)
	body, err, n = do0RTTRequest(t, cache, puts, port, false)
	require.NoError(t, err)
	require.Equal(t, "true", body, "unchanged settings must still allow 0-RTT")
	require.NotZero(t, n)
}

// TestHTTP0RTTSettingsNewlyEnabled is the compatible-change direction: the
// ticket was issued while datagrams were disabled and they are enabled now, so
// 0-RTT may proceed.
func TestHTTP0RTTSettingsNewlyEnabled(t *testing.T) {
	cache := tls.NewLRUClientSessionCache(10)
	puts := make(chan string, 10)

	port := startHTTP0RTTEchoServer(t, false)
	body, err, _ := do0RTTRequest(t, cache, puts, port, true)
	require.NoError(t, err)
	require.Equal(t, "false", body)

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	port = startHTTP0RTTEchoServer(t, true)
	body, err, n := do0RTTRequest(t, cache, puts, port, false)
	require.NoError(t, err)
	require.Equal(t, "true", body, "enabling datagrams is a compatible change")
	require.NotZero(t, n)
}

// TestHTTP0RTTSettingsIncompatible is the decisive case: the ticket was issued
// while datagrams were enabled, the server now has them disabled. A 0-RTT
// request could use datagrams the server no longer accepts, so the server must
// reject 0-RTT (quic.Err0RTTRejected) instead of accepting the requests.
func TestHTTP0RTTSettingsIncompatible(t *testing.T) {
	cache := tls.NewLRUClientSessionCache(10)
	puts := make(chan string, 10)

	port := startHTTP0RTTEchoServer(t, true)
	body, err, _ := do0RTTRequest(t, cache, puts, port, true)
	require.NoError(t, err)
	require.Equal(t, "false", body)

	select {
	case <-puts:
	case <-time.After(time.Second):
		t.Fatal("did not receive session ticket")
	}

	port = startHTTP0RTTEchoServer(t, false)
	body, err, n := do0RTTRequest(t, cache, puts, port, false)
	require.ErrorIs(t, err, quic.Err0RTTRejected,
		"the server must reject 0-RTT when the ticket's settings are incompatible")
	require.Empty(t, body, "no request may be served from 0-RTT data")
	require.NotZero(t, n, "the client did attempt 0-RTT, so the rejection is what stopped it")
}
