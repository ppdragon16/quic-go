package quic

import (
	"testing"

	"golang.org/x/exp/rand"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"
)

// ── Shared interface ───────────────────────────────────────────────────────

type sorterBench interface {
	Push(data []byte, offset protocol.ByteCount, frame *wire.StreamFrame) error
	Pop() (protocol.ByteCount, []byte, *wire.StreamFrame)
	HasMoreData() bool
}

var sorterFactories = map[string]func() sorterBench{
	"v1_map":   func() sorterBench { return newFrameSorter() },
	"v2_chunk": func() sorterBench { return newFrameSorter2() },
	"v3_slice": func() sorterBench { return newFrameSorterSlice() },
}

// ── Frame generators ───────────────────────────────────────────────────────

type benchFrame struct {
	offset protocol.ByteCount
	Data   []byte
}

func genSequential(n int, size int) []benchFrame {
	f := make([]benchFrame, n)
	for i := 0; i < n; i++ {
		f[i] = benchFrame{
			offset: protocol.ByteCount(i * size),
			Data:   make([]byte, size),
		}
	}
	return f
}

func genRandom(n int, size int, seed uint64) []benchFrame {
	f := genSequential(n, size)
	rng := rand.New(rand.NewSource(seed))
	rng.Shuffle(n, func(i, j int) { f[i], f[j] = f[j], f[i] })
	return f
}

// ── Interleaved benchmark: push a batch, pop what's available, repeat ──────

// simulateInterleaved pushes frames in arrival order, popping available data
// after each push. Much closer to real-world behavior than push-all-then-pop-all.
func benchInterleaved(b *testing.B, newSorter func() sorterBench, frames []benchFrame) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := newSorter()
		b.StartTimer()
		for _, f := range frames {
			s.Push(f.Data, f.offset, nil)
			// Drain whatever is ready at readPos
			for {
				_, d, _ := s.Pop()
				if d == nil {
					break
				}
			}
		}
	}
}

// ── Benchmarks ─────────────────────────────────────────────────────────────

func BenchmarkSequential_1k_1400B(b *testing.B) {
	frames := genSequential(1000, 1400)
	for name, fn := range sorterFactories {
		b.Run(name, func(b *testing.B) { benchInterleaved(b, fn, frames) })
	}
}

func BenchmarkRandom_1k_1400B(b *testing.B) {
	frames := genRandom(1000, 1400, 42)
	for name, fn := range sorterFactories {
		b.Run(name, func(b *testing.B) { benchInterleaved(b, fn, frames) })
	}
}

func BenchmarkSequential_1k_16B(b *testing.B) {
	frames := genSequential(1000, 16)
	for name, fn := range sorterFactories {
		b.Run(name, func(b *testing.B) { benchInterleaved(b, fn, frames) })
	}
}

// Small frames in random order — stresses the merge path: entries land in gaps,
// become contiguous, then compactAround triggers newData allocations.
func BenchmarkRandom_1k_16B(b *testing.B) {
	frames := genRandom(1000, 16, 42)
	for name, fn := range sorterFactories {
		b.Run(name, func(b *testing.B) { benchInterleaved(b, fn, frames) })
	}
}

func BenchmarkSequential_5k_16B(b *testing.B) {
	frames := genSequential(5000, 16)
	for name, fn := range sorterFactories {
		b.Run(name, func(b *testing.B) { benchInterleaved(b, fn, frames) })
	}
}

func BenchmarkRandom_5k_1400B(b *testing.B) {
	frames := genRandom(5000, 1400, 99)
	for name, fn := range sorterFactories {
		b.Run(name, func(b *testing.B) { benchInterleaved(b, fn, frames) })
	}
}
