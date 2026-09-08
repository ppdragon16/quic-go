package quic

import (
	"context"
	"testing"

	"github.com/daeuniverse/quic-go/internal/wire"
)

// BenchmarkDatagramReceivePooled measures the receive path with the pool:
// HandleDatagramFrame (pool.Get) -> Receive -> ReleaseDatagram (pool.Put).
// This is the steady-state UDP relay loop for hy2/tuic.
func BenchmarkDatagramReceivePooled(b *testing.B) {
	q := newDatagramQueue(nil, nil)
	f := &wire.DatagramFrame{Data: make([]byte, 1200)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.HandleDatagramFrame(f)
		data, err := q.Receive(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		q.ReleaseDatagram(data)
	}
}

// BenchmarkDatagramReceiveLegacy simulates the pre-pool path: every datagram
// allocates a fresh buffer in HandleDatagramFrame (make) and never reuses it.
func BenchmarkDatagramReceiveLegacy(b *testing.B) {
	q := newDatagramQueue(nil, nil)
	f := &wire.DatagramFrame{Data: make([]byte, 1200)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Pre-pool behavior: allocate + copy per frame
		data := make([]byte, len(f.Data))
		copy(data, f.Data)
		q.rcvMx.Lock()
		q.rcvQueue.PushBack(data)
		q.rcvMx.Unlock()
		_, err := q.Receive(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDatagramRoundTripPooled is the full pooled loop including the
// channel notification, closer to real line-rate behavior.
func BenchmarkDatagramRoundTripPooled(b *testing.B) {
	q := newDatagramQueue(nil, nil)
	f := &wire.DatagramFrame{Data: make([]byte, 1200)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		q.HandleDatagramFrame(f)
		data, _ := q.Receive(context.Background())
		q.ReleaseDatagram(data)
	}
}
