package http3

import (
	"bytes"

	"github.com/daeuniverse/quic-go/quicvarint"
)

// This file implements the server-side 0-RTT SETTINGS check: the SETTINGS the
// server sent when it issued a session ticket are embedded in the ticket, and
// on resumption the server refuses 0-RTT if those settings are incompatible
// with the ones it would send now. Without this, a client could send 0-RTT
// requests based on a stale view of the server's settings (e.g. after
// datagrams or extended CONNECT were turned off), which the server would then
// have to reject mid-handshake.
// Ported from quic-go PR #5771.

const serverSettingsSessionTicketPrefix = "quic-go h3 settings v1"

type settings = settingsFrame

func settingsForSessionTicket(current *settings) []byte {
	return current.Append([]byte(serverSettingsSessionTicketPrefix))
}

func settingsDataFromSessionTicket(extras [][]byte) ([]byte, bool) {
	prefix := []byte(serverSettingsSessionTicketPrefix)
	for _, extra := range extras {
		if data, ok := bytes.CutPrefix(extra, prefix); ok {
			return data, true
		}
	}
	return nil, false
}

func settingsCompatibleFor0RTT(data []byte, current *settings) bool {
	r := bytes.NewReader(data)
	frameType, err := quicvarint.Read(r)
	if err != nil || frameType != 0x4 {
		return false
	}
	length, err := quicvarint.Read(r)
	if err != nil || uint64(r.Len()) != length {
		return false
	}
	old, err := parseSettingsFrame(r, length)
	if err != nil {
		return false
	}
	// An unknown setting might belong to an extension that this version no
	// longer supports.
	if len(old.Other) > 0 {
		return false
	}
	// Note: upstream also compares MaxFieldSectionSize here. This fork's
	// settingsFrame does not carry that field (header sizes are bounded at the
	// QPACK decoder instead), so there is nothing to compare.
	if old.Datagram && !current.Datagram {
		return false
	}
	if old.ExtendedConnect && !current.ExtendedConnect {
		return false
	}
	return true
}
