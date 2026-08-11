package qtls

import (
	"bytes"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"

	"github.com/daeuniverse/quic-go/internal/protocol"
)

func SetupConfigForServer(
	conf *utls.Config,
	localAddr, remoteAddr net.Addr,
	getData func() []byte,
	handleSessionTicket func([]byte, bool) bool,
) *utls.Config {
	// Workaround for https://github.com/golang/go/issues/60506.
	// This initializes the session tickets _before_ cloning the config.
	_, _ = conf.DecryptTicket(nil, utls.ConnectionState{})

	conf = conf.Clone()
	conf.MinVersion = utls.VersionTLS13

	// add callbacks to save transport parameters into the session ticket
	origWrapSession := conf.WrapSession
	conf.WrapSession = func(cs utls.ConnectionState, state *utls.SessionState) ([]byte, error) {
		// Add QUIC session ticket
		state.Extra = append(state.Extra, addExtraPrefix(getData()))

		if origWrapSession != nil {
			return origWrapSession(cs, state)
		}
		b, err := conf.EncryptTicket(cs, state)
		return b, err
	}
	origUnwrapSession := conf.UnwrapSession
	// UnwrapSession might be called multiple times, as the client can use multiple session tickets.
	// However, using 0-RTT is only possible with the first session ticket.
	// crypto/tls guarantees that this callback is called in the same order as the session ticket in the ClientHello.
	var unwrapCount int
	conf.UnwrapSession = func(identity []byte, connState utls.ConnectionState) (*utls.SessionState, error) {
		unwrapCount++
		var state *utls.SessionState
		var err error
		if origUnwrapSession != nil {
			state, err = origUnwrapSession(identity, connState)
		} else {
			state, err = conf.DecryptTicket(identity, connState)
		}
		if err != nil || state == nil {
			return nil, err
		}

		extra := findExtraData(state.Extra)
		if extra != nil {
			state.EarlyData = handleSessionTicket(extra, state.EarlyData && unwrapCount == 1)
		} else {
			state.EarlyData = false
		}

		return state, nil
	}
	// The utls.Config contains two callbacks that pass in a utls.ClientHelloInfo.
	// Since crypto/tls doesn't do it, we need to make sure to set the Conn field with a fake net.Conn
	// that allows the caller to get the local and the remote address.
	if conf.GetConfigForClient != nil {
		gcfc := conf.GetConfigForClient
		conf.GetConfigForClient = func(info *utls.ClientHelloInfo) (*utls.Config, error) {
			info.Conn = &conn{localAddr: localAddr, remoteAddr: remoteAddr}
			c, err := gcfc(info)
			if c != nil {
				// We're returning a utls.Config here, so we need to apply this recursively.
				c = SetupConfigForServer(c, localAddr, remoteAddr, getData, handleSessionTicket)
			}
			return c, err
		}
	}
	if conf.GetCertificate != nil {
		gc := conf.GetCertificate
		conf.GetCertificate = func(info *utls.ClientHelloInfo) (*utls.Certificate, error) {
			info.Conn = &conn{localAddr: localAddr, remoteAddr: remoteAddr}
			return gc(info)
		}
	}
	return conf
}

func SetupConfigForClient(
	qconf *utls.QUICConfig,
	getData func(earlyData bool) []byte,
	setData func(data []byte, earlyData bool) (allowEarlyData bool),
) {
	conf := qconf.TLSConfig
	if conf.ClientSessionCache != nil {
		origCache := conf.ClientSessionCache
		conf.ClientSessionCache = &clientSessionCache{
			wrapped: origCache,
			getData: getData,
			setData: setData,
		}
	}
}

func ToTLSEncryptionLevel(e protocol.EncryptionLevel) utls.QUICEncryptionLevel {
	switch e {
	case protocol.EncryptionInitial:
		return utls.QUICEncryptionLevelInitial
	case protocol.EncryptionHandshake:
		return utls.QUICEncryptionLevelHandshake
	case protocol.Encryption1RTT:
		return utls.QUICEncryptionLevelApplication
	case protocol.Encryption0RTT:
		return utls.QUICEncryptionLevelEarly
	default:
		panic(fmt.Sprintf("unexpected encryption level: %s", e))
	}
}

func FromTLSEncryptionLevel(e utls.QUICEncryptionLevel) protocol.EncryptionLevel {
	switch e {
	case utls.QUICEncryptionLevelInitial:
		return protocol.EncryptionInitial
	case utls.QUICEncryptionLevelHandshake:
		return protocol.EncryptionHandshake
	case utls.QUICEncryptionLevelApplication:
		return protocol.Encryption1RTT
	case utls.QUICEncryptionLevelEarly:
		return protocol.Encryption0RTT
	default:
		panic(fmt.Sprintf("unexpect encryption level: %s", e))
	}
}

const extraPrefix = "quic-go1"

func addExtraPrefix(b []byte) []byte {
	return append([]byte(extraPrefix), b...)
}

func findExtraData(extras [][]byte) []byte {
	prefix := []byte(extraPrefix)
	for _, extra := range extras {
		if len(extra) < len(prefix) || !bytes.Equal(prefix, extra[:len(prefix)]) {
			continue
		}
		return extra[len(prefix):]
	}
	return nil
}
