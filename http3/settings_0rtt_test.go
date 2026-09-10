package http3

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Ported from quic-go PR #5771; the MaxFieldSectionSize cases are omitted
// because this fork's settingsFrame does not carry that field.
func TestSettingsCompatibleFor0RTT(t *testing.T) {
	ticket := func(saved *settings) [][]byte {
		return [][]byte{settingsForSessionTicket(saved)}
	}

	for _, tc := range []struct {
		name       string
		current    *settings
		extra      [][]byte
		compatible bool
	}{
		{
			name:       "identical settings",
			current:    &settings{Datagram: true, ExtendedConnect: true},
			extra:      ticket(&settings{Datagram: true, ExtendedConnect: true}),
			compatible: true,
		},
		{
			name:       "datagrams enabled later",
			current:    &settings{Datagram: true},
			extra:      ticket(&settings{}),
			compatible: true,
		},
		{
			name:    "missing settings",
			current: &settings{},
		},
		{
			name:    "malformed settings",
			current: &settings{},
			extra:   [][]byte{append([]byte(serverSettingsSessionTicketPrefix), 0xff)},
		},
		{
			name:    "datagrams disabled",
			current: &settings{},
			extra:   ticket(&settings{Datagram: true}),
		},
		{
			name:    "extended connect disabled",
			current: &settings{},
			extra:   ticket(&settings{ExtendedConnect: true}),
		},
		{
			name:    "unknown setting",
			current: &settings{Datagram: true},
			extra:   ticket(&settings{Datagram: true, Other: map[uint64]uint64{13: 37}}),
		},
		{
			name:    "wrong frame type",
			current: &settings{},
			extra:   [][]byte{append([]byte(serverSettingsSessionTicketPrefix), 0x5, 0)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, ok := settingsDataFromSessionTicket(tc.extra)
			require.Equal(t, tc.compatible, ok && settingsCompatibleFor0RTT(data, tc.current))
		})
	}
}

// TestSettingsRoundTrip checks the ticket payload is exactly what the parser
// expects, i.e. a varint-framed SETTINGS frame after the prefix, and that a
// ticket issued with the current settings is accepted for 0-RTT.
func TestSettingsRoundTrip(t *testing.T) {
	current := &settings{Datagram: true, ExtendedConnect: true}
	extra := [][]byte{[]byte("unrelated"), settingsForSessionTicket(current)}
	data, ok := settingsDataFromSessionTicket(extra)
	require.True(t, ok)
	require.True(t, settingsCompatibleFor0RTT(data, current))
}

// TestSettingsUnknownAdditionalSettingRejects0RTT pins the documented
// fail-closed consequence of AdditionalSettings: the saved settings are then
// always considered unknown, so 0-RTT is refused rather than guessed at.
func TestSettingsUnknownAdditionalSettingRejects0RTT(t *testing.T) {
	current := &settings{Datagram: true, ExtendedConnect: true, Other: map[uint64]uint64{0x2: 5}}
	data, ok := settingsDataFromSessionTicket([][]byte{settingsForSessionTicket(current)})
	require.True(t, ok)
	require.False(t, settingsCompatibleFor0RTT(data, current))
}
