package quic

import (
	"testing"

	"golang.org/x/exp/rand"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// dataGen creates deterministic data of the given length, starting with a prefix.
func dataGen(prefix string, l int) []byte {
	b := make([]byte, l)
	copy(b, prefix)
	for i := len(prefix); i < l; i++ {
		b[i] = byte('a' + (i % 26))
	}
	return b
}

func TestFrameSorter2SimpleCases(t *testing.T) {
	s := newFrameSorter2()
	_, data, frame := s.Pop()
	require.Nil(t, data)
	require.Nil(t, frame)

	// empty frames are ignored
	require.NoError(t, s.Push(nil, 0, nil))
	_, data, frame = s.Pop()
	require.Nil(t, data)
	require.Nil(t, frame)

	// Use data >= 128 bytes for consistent large-frame behavior
	bar := dataGen("bar", 200)
	foo := dataGen("foo", 200)

	frame1 := &wire.StreamFrame{}
	frame2 := &wire.StreamFrame{}
	require.NoError(t, s.Push(bar, 200, frame2))
	require.True(t, s.HasMoreData())
	require.NoError(t, s.Push(foo, 0, frame1))

	offset, data, frame := s.Pop()
	require.Equal(t, foo, data)
	require.Zero(t, offset)
	require.NotNil(t, frame)
	frame.PutBack()
	require.True(t, s.HasMoreData())

	offset, data, frame = s.Pop()
	require.Equal(t, bar, data)
	require.Equal(t, protocol.ByteCount(200), offset)
	require.NotNil(t, frame)
	frame.PutBack()
	require.False(t, s.HasMoreData())

	// now receive a duplicate
	frame3 := &wire.StreamFrame{}
	require.NoError(t, s.Push(foo, 0, frame3))
	require.False(t, s.HasMoreData())

	// now receive a later frame that overlaps with the ones we already consumed
	frame4 := &wire.StreamFrame{}
	require.NoError(t, s.Push(dataGen("barbaz", 300), 200, frame4))
	require.True(t, s.HasMoreData())

	offset, data, _ = s.Pop()
	require.Equal(t, protocol.ByteCount(400), offset)
	require.Equal(t, dataGen("barbaz", 300)[200:], data) // 200 consumed, only last 100 bytes remain
	require.False(t, s.HasMoreData())
}

// TestFrameSorter2GapHandling tests that out-of-order frame insertion produces
// correct sequential output after gaps are filled.
// Uses data >= 128 bytes for consistent behavior across all sorter versions.
func TestFrameSorter2GapHandling(t *testing.T) {
	getData := func(l protocol.ByteCount) []byte {
		b := make([]byte, l)
		rand.Read(b)
		return b
	}

	const ds = protocol.ByteCount(200)

	// ---xxx--------------
	//       ++++++
	// =>
	// ---xxx++++++--------
	t.Run("contiguous after", func(t *testing.T) {
		s := newFrameSorter2()
		f1 := getData(ds) // 0..ds
		f2 := getData(ds) // ds..2*ds
		require.NoError(t, s.Push(f1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(f2, ds, &wire.StreamFrame{}))
		// Pop both
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, f1, data)
		offset, data, _ = s.Pop()
		require.Equal(t, ds, offset)
		require.Equal(t, f2, data)
	})

	// ---xxx-----------------
	//          +++++++
	// =>
	// ---xxx---+++++++--------
	t.Run("gap between", func(t *testing.T) {
		s := newFrameSorter2()
		f1 := getData(ds)   // 0..ds
		f2 := getData(ds)   // 3*ds..4*ds
		gapFill := getData(ds) // ds..2*ds
		require.NoError(t, s.Push(f1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(f2, 3*ds, &wire.StreamFrame{}))

		// Cannot pop past f1
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, f1, data)

		// Gap from ds to 3*ds
		_, data, _ = s.Pop()
		require.Nil(t, data)

		// Fill gap at ds (not filling the entire gap)
		require.NoError(t, s.Push(gapFill, ds, nil))
		offset, data, _ = s.Pop()
		require.Equal(t, ds, offset)
		require.Equal(t, gapFill, data)

		// Still gap remaining (2*ds to 3*ds)
		_, data, _ = s.Pop()
		require.Nil(t, data)
	})

	// ---xxx----xxxxxx-------
	//        ++++++++++
	// => overlap starts inside existing entry range (but not at entry offset),
	//    so data is trimmed to gap boundary.
	t.Run("overlap inside existing entry range", func(t *testing.T) {
		s := newFrameSorter2()
		f1 := getData(3 * ds) // 0..3ds (600 bytes)
		f2 := getData(2 * ds) // 5*ds..7ds (1000..1400)
		require.NoError(t, s.Push(f1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(f2, 5*ds, &wire.StreamFrame{}))

		// Overlap at 2*ds (400), which is inside f1 but not at an entry boundary.
		// The gap starts at 3*ds (600). Since start (400) is not in a gap,
		// data is trimmed to gap start → data[200:] at offset 600.
		overlap := getData(2 * ds)
		require.NoError(t, s.Push(overlap, 2*ds, &wire.StreamFrame{}))

		// Pop: f1 is intact at 0..3ds
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, f1, data)

		// Then overlap trimmed to 600..800 (200 bytes from data[200:]).
		// But wait — after insertion, compactAround may merge it with f1.
		// f1 starts at 0 and ends at 600. The overlap entry after trimming
		// starts at 600 (gap boundary). Since both are large (>= 128),
		// they are NOT merged.
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3*ds), offset)
		require.Equal(t, overlap[int(ds):], data) // overlap[200:] = 200 bytes

		// Gap 800..1000 remains, can't pop f2 yet
		_, data, _ = s.Pop()
		require.Nil(t, data)

		// Fill 800..1000 gap
		gapFill := getData(ds) // 200 bytes
		require.NoError(t, s.Push(gapFill, 4*ds, nil)) // at 800
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4*ds), offset)
		require.Equal(t, gapFill, data)

		// Now f2 can pop
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(5*ds), offset)
		require.Equal(t, f2, data)
	})
}

// TestFrameSorter2DuplicateData verifies duplicate detection and overlap behavior.
func TestFrameSorter2DuplicateData(t *testing.T) {
	t.Run("exact duplicate", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{})) // duplicate, ignored
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("foo"), data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
	})

	t.Run("partial overlap at start", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("hello"), 0, &wire.StreamFrame{}))
		// Sub-range already covered
		require.NoError(t, s.Push([]byte("he"), 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("hello"), data)
	})

	t.Run("longer frame replaces shorter", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("hi"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("hello"), 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("hello"), data)
	})

	t.Run("adjacent small frames stay separate", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bar"), 3, &wire.StreamFrame{}))
		// No frame merging — each entry stays independent
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("foo"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3), offset)
		require.Equal(t, []byte("bar"), data)
	})

	t.Run("duplicate with large data not merged", func(t *testing.T) {
		s := newFrameSorter2()
		large := dataGen("data", 200)
		require.NoError(t, s.Push(large, 0, &wire.StreamFrame{}))
		// Same data again at same offset — duplicate
		require.NoError(t, s.Push(large, 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, large, data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
	})
}

// TestFrameSorter2ChunkSplit verifies that pushing many frames correctly splits chunks.
// Uses large data at contiguous offsets.
func TestFrameSorter2ChunkSplit(t *testing.T) {
	s := newFrameSorter2()

	const ds = 200
	const n = 200

	for i := 0; i < n; i++ {
		d := make([]byte, ds)
		// Mark each chunk uniquely
		d[0] = byte(i >> 8)
		d[1] = byte(i & 0xff)
		offset := protocol.ByteCount(i * ds)
		require.NoError(t, s.Push(d, offset, &wire.StreamFrame{}))
	}

	for i := 0; i < n; i++ {
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(i*ds), offset)
		require.Len(t, data, ds)
		require.Equal(t, byte(i>>8), data[0])
		require.Equal(t, byte(i&0xff), data[1])
	}
	require.False(t, s.HasMoreData())
}

// TestFrameSorter2TooManyGaps verifies that too many gaps returns an error.
func TestFrameSorter2TooManyGaps(t *testing.T) {
	s := newFrameSorter2()
	for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
		require.NoError(t, s.Push([]byte("foobar"), protocol.ByteCount(i*7), nil))
	}
	err := s.Push([]byte("foobar"), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*7)+100, nil)
	require.EqualError(t, err, "too many gaps in received data")
}

// TestFrameSorter2NoMerge verifies that adjacent frames are NOT merged,
// regardless of size. Small-frame merging was removed to preserve buffer
// pooling semantics (Data comes from pools, merging allocates newData).
func TestFrameSorter2NoMerge(t *testing.T) {
	t.Run("adjacent small frames NOT merged", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bar"), 3, &wire.StreamFrame{}))
		// No merging — each frame pops independently
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("foo"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3), offset)
		require.Equal(t, []byte("bar"), data)
	})

	t.Run("adjacent large frames not merged", func(t *testing.T) {
		s := newFrameSorter2()
		large1 := dataGen("aaa", 200)
		large2 := dataGen("bbb", 200)
		require.NoError(t, s.Push(large1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(large2, 200, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, large1, data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(200), offset)
		require.Equal(t, large2, data)
	})

	t.Run("small and large adjacent NOT merged", func(t *testing.T) {
		s := newFrameSorter2()
		large := make([]byte, 200)
		rand.Read(large)
		small := make([]byte, 10)
		rand.Read(small)
		require.NoError(t, s.Push(small, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(large, 10, &wire.StreamFrame{}))
		// No merging — each pops independently
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, small, data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(10), offset)
		require.Equal(t, large, data)
	})

	t.Run("three small contiguous stay separate", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("aaa"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bbb"), 6, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("ccc"), 3, &wire.StreamFrame{}))
		// All three pop independently, in offset order
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("aaa"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3), offset)
		require.Equal(t, []byte("ccc"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(6), offset)
		require.Equal(t, []byte("bbb"), data)
	})

	t.Run("many small contiguous stay separate", func(t *testing.T) {
		s := newFrameSorter2()
		for i := 0; i < 16; i++ {
			offset := protocol.ByteCount(i * 4)
			require.NoError(t, s.Push([]byte("test"), offset, &wire.StreamFrame{}))
		}
		// Each of the 16 frames pops independently; no merging
		for i := 0; i < 16; i++ {
			offset, data, _ := s.Pop()
			require.Equal(t, protocol.ByteCount(i*4), offset)
			require.Equal(t, []byte("test"), data)
		}
		require.False(t, s.HasMoreData())
	})
}

// TestFrameSorter2Randomized performs randomized testing with reference data.
func TestFrameSorter2Randomized(t *testing.T) {
	t.Run("short", func(t *testing.T) {
		testFrameSorter2Randomized(t, 25, false, false)
	})
	t.Run("long", func(t *testing.T) {
		testFrameSorter2Randomized(t, 2*protocol.MinStreamFrameSize, false, false)
	})
	t.Run("short, with duplicates", func(t *testing.T) {
		testFrameSorter2Randomized(t, 25, true, false)
	})
	t.Run("long, with duplicates", func(t *testing.T) {
		testFrameSorter2Randomized(t, 2*protocol.MinStreamFrameSize, true, false)
	})
	t.Run("short, with overlaps", func(t *testing.T) {
		testFrameSorter2Randomized(t, 25, false, true)
	})
	t.Run("long, with overlaps", func(t *testing.T) {
		testFrameSorter2Randomized(t, 2*protocol.MinStreamFrameSize, false, true)
	})
}

func testFrameSorter2Randomized(t *testing.T, dataLen protocol.ByteCount, injectDuplicates, injectOverlaps bool) {
	type frame struct {
		offset protocol.ByteCount
		data   []byte
	}

	const num = 1000

	data := make([]byte, num*int(dataLen))
	rand.Read(data)

	frames := make([]frame, num)
	for i := 0; i < num; i++ {
		b := make([]byte, dataLen)
		offset := i * int(dataLen)
		copy(b, data[offset:offset+int(dataLen)])
		frames[i] = frame{
			offset: protocol.ByteCount(i) * dataLen,
			data:   b,
		}
	}
	rand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })

	s := newFrameSorter2()

	for _, f := range frames {
		require.NoError(t, s.Push(f.data, f.offset, &wire.StreamFrame{}))
	}
	if injectDuplicates {
		for i := 0; i < num/10; i++ {
			df := frames[rand.Intn(len(frames))]
			require.NoError(t, s.Push(df.data, df.offset, &wire.StreamFrame{}))
		}
	}
	if injectOverlaps {
		finalOffset := int(num * dataLen)
		for i := 0; i < num/3; i++ {
			startOffset := protocol.ByteCount(rand.Intn(finalOffset))
			endOffset := startOffset + protocol.ByteCount(rand.Intn(finalOffset-int(startOffset)))
			require.NoError(t, s.Push(data[startOffset:endOffset], startOffset, &wire.StreamFrame{}))
		}
	}

	// read all data
	var read []byte
	for {
		offset, b, frame := s.Pop()
		if b == nil {
			break
		}
		require.Equal(t, offset, protocol.ByteCount(len(read)))
		read = append(read, b...)
		if frame != nil {
			frame.PutBack()
		}
	}

	require.Equal(t, data, read)
	require.False(t, s.HasMoreData())
}

// TestFrameSorter2ReadPosGaps verifies that gap counting and collection
// correctly observe readPos (consumed data should not count as gaps).

func TestFrameSorter2ReadPosGaps(t *testing.T) {
	s := newFrameSorter2()

	ds := protocol.ByteCount(200)
	// Push two frames with a gap. Offsets: 0, 3*ds (gap from ds to 3*ds)
	a := dataGen("hello", int(ds))
	b := dataGen("world", int(ds))
	require.NoError(t, s.Push(a, 0, &wire.StreamFrame{}))      // 0..ds
	require.NoError(t, s.Push(b, 3*ds, &wire.StreamFrame{}))  // 3ds..4ds

	// Consume the first frame → readPos becomes ds
	offset, data, _ := s.Pop()
	require.Equal(t, protocol.ByteCount(0), offset)
	require.Equal(t, a, data)

	// Now readPos is ds. Push a frame that fills the ds..2ds portion of the gap.
	gapFill := dataGen("xxxxx", int(ds))
	require.NoError(t, s.Push(gapFill, ds, &wire.StreamFrame{}))

	// We can consume ds..2ds
	offset, data, _ = s.Pop()
	require.Equal(t, protocol.ByteCount(ds), offset)
	require.Equal(t, gapFill, data)

	// Gap 2ds..3ds still remains → can't pop b yet
	_, data, _ = s.Pop()
	require.Nil(t, data)
}

// TestFrameSorter2PopReadPos verifies that Pop only returns data at readPos.

func TestFrameSorter2PopReadPos(t *testing.T) {
	s := newFrameSorter2()
	ds := protocol.ByteCount(200)
	after := dataGen("foo", int(ds))
	before := dataGen("bar", int(ds))
	require.NoError(t, s.Push(after, ds, &wire.StreamFrame{}))
	require.NoError(t, s.Push(before, 0, &wire.StreamFrame{}))

	// Pop should return the data at readPos=0
	offset, data, _ := s.Pop()
	require.Equal(t, protocol.ByteCount(0), offset)
	require.Equal(t, before, data)

	// Now readPos=ds, can pop the next one
	offset, data, _ = s.Pop()
	require.Equal(t, protocol.ByteCount(ds), offset)
	require.Equal(t, after, data)
}

// Verify that frameSorter2 implements the expected interface contract for external users.
func TestFrameSorter2Interface(t *testing.T) {
	// crypto_stream.go uses frameSorter2 as a value type: `queue frameSorter2`
	var queue frameSorter2
	require.NotPanics(t, func() {
		_, data, frame := queue.Pop()
		require.Nil(t, data)
		require.Nil(t, frame)
		require.False(t, queue.HasMoreData())
	})

	// receive_stream.go uses frameSorter2 as a pointer type: `frameQueue *frameSorter2`
	s := newFrameSorter2()
	require.NotNil(t, s)
	require.NotPanics(t, func() {
		require.NoError(t, s.Push([]byte("test"), 0, nil))
		require.True(t, s.HasMoreData())
	})
}

// TestFrameSorter2PushOverlap verifies that when a new frame overlaps with existing
// entries at both ends, data is correctly trimmed to the gap boundaries.
// Uses data >= 128 bytes to avoid small-frame sizing concerns.
// Scenario: existing [0, 200) and [401, 600), push [150, 350].
//   - [150, 200) discarded (overlaps with [0, 200))
//   - [200, 350) kept (150 bytes of 'b') — goes into the gap
//   - entry2 at [401, 600) intact
//   - Gap remains: [350, 401) — entry2 not reachable yet
func TestFrameSorter2PushOverlap(t *testing.T) {
	s := newFrameSorter2()

	entry1 := make([]byte, 200)
	for i := range entry1 {
		entry1[i] = 'a'
	}
	entry2 := make([]byte, 199)
	for i := range entry2 {
		entry2[i] = 'c'
	}
	require.NoError(t, s.Push(entry1, 0, &wire.StreamFrame{}))
	require.NoError(t, s.Push(entry2, 401, &wire.StreamFrame{}))

	// Push [150, 350] — 200 bytes of 'b'
	newData := make([]byte, 200)
	for i := range newData {
		newData[i] = 'b'
	}
	require.NoError(t, s.Push(newData, 150, &wire.StreamFrame{}))

	// Pop entry1: [0, 200)
	offset, data, frame := s.Pop()
	require.Equal(t, protocol.ByteCount(0), offset)
	require.Equal(t, entry1, data)
	require.NotNil(t, frame)

	// Pop trimmed newData: [200, 350) — 150 bytes from newData[50:]
	offset, data, _ = s.Pop()
	require.Equal(t, protocol.ByteCount(200), offset)
	require.Equal(t, newData[50:], data)

	// Gap [350, 401) — can't pop entry2 yet
	_, data, _ = s.Pop()
	require.Nil(t, data)
	require.True(t, s.HasMoreData())
}

// TestFrameSorter2ChunkOperations covers internal chunk mechanics:
//   - splitting a chunk when it becomes full (17th entry → split at 8)
//   - merging adjacent chunks structurally (tryMergeWithNext consolidates sparse chunks)
//   - combined: gap-fill leaves sparse chunks which tryMergeWithNext consolidates
// Frame merging is not tested — it was removed from frame_sorter2.
func TestFrameSorter2ChunkOperations(t *testing.T) {
	// ── 1. No frame merge: small contiguous frames stay separate ────
	// Frame merging was removed; each entry pops independently.
	t.Run("small contiguous frames stay separate", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("aa"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bb"), 2, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("cc"), 4, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("dd"), 6, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("ee"), 8, &wire.StreamFrame{}))
		// Each pops independently
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("aa"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(2), offset)
		require.Equal(t, []byte("bb"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4), offset)
		require.Equal(t, []byte("cc"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(6), offset)
		require.Equal(t, []byte("dd"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(8), offset)
		require.Equal(t, []byte("ee"), data)
		require.False(t, s.HasMoreData())
	})

	// ── 2. Chunk split ───────────────────────────────────────────────
	// Push 17 large (≥128) contiguous frames — the 17th forces a split
	// because frameChunkSize = 16. Large data disables frame merging.
	t.Run("chunk split", func(t *testing.T) {
		s := newFrameSorter2()
		const ds = 200
		const n = 17 // one more than frameChunkSize
		expected := make([]byte, n*ds)
		for i := 0; i < n; i++ {
			val := byte('A' + i)
			d := make([]byte, ds)
			for j := range d {
				d[j] = val
			}
			copy(expected[i*ds:], d)
			require.NoError(t, s.Push(d, protocol.ByteCount(i*ds), &wire.StreamFrame{}))
		}
		// Each entry stays independent (no frame merge); verify correct Pop
		var got []byte
		for {
			_, data, _ := s.Pop()
			if data == nil {
				break
			}
			got = append(got, data...)
		}
		require.Equal(t, expected, got)
	})

	// ── 3. Adjacent-chunk structural merge ───────────────────────────
	// Create two chunks, then remove enough entries from the first so
	// that tryMergeWithNext can consolidate them.
	t.Run("adjacent chunk merge", func(t *testing.T) {
		s := newFrameSorter2()
		const ds = 200 // large → no frame merge
		// Push 20 entries in reverse order (filling two chunks: 16 + 4).
		for i := 19; i >= 0; i-- {
			d := make([]byte, ds)
			d[0] = byte('A' + i)
			require.NoError(t, s.Push(d, protocol.ByteCount(i*ds), &wire.StreamFrame{}))
		}
		// Now pop the first 15. After each Pop, tryMergeWithNext is called,
		// so when head has only 1 entry left, it absorbs the next chunk.
		for i := 0; i < 15; i++ {
			_, data, _ := s.Pop()
			require.NotNil(t, data)
			require.Equal(t, byte('A'+i), data[0])
		}
		// Head now at offset 15*ds. After tryMergeWithNext consolidations
		// during earlier Pops, head should contain the remaining 5 entries.
		for i := 15; i < 20; i++ {
			offset, data, _ := s.Pop()
			require.NotNil(t, data)
			require.Equal(t, protocol.ByteCount(i*ds), offset)
			require.Equal(t, byte('A'+i), data[0])
		}
		require.False(t, s.HasMoreData())
	})

	// ── 4. Gap-fill then chunk merge → chunk merge ───────────────────────
	// Push 20 small frames out-of-order to fill two chunks (with internal
	// gaps preventing immediate frame merge), then fill the gaps. The frame
	// merging leaves sparse chunks, which tryMergeWithNext then consolidates.
	t.Run("gap fill then chunk merge", func(t *testing.T) {
		s := newFrameSorter2()
		const n = 20
		stride := protocol.ByteCount(4)
		// Step 1: push 20 small frames with 2-byte gaps (offset stride=4, len=2).
		// Reverse order prevents merging across entries during insertion.
		for i := n - 1; i >= 0; i-- {
			offset := protocol.ByteCount(i) * stride
			b := []byte{byte('a' + i), byte('a' + i)}
			require.NoError(t, s.Push(b, offset, &wire.StreamFrame{}))
		}
		// After 20 pushes we have 2 chunks (16 + 4), each entry isolated by gaps.
		// No frame merge yet — entries are not contiguous.

		// Step 2: fill the 2-byte gaps. Each gap-fill makes two adjacent entries
		// contiguous, triggering mergeForward / mergeBackward cascades.
		for i := 0; i < n-1; i++ {
			gapOffset := protocol.ByteCount(i)*stride + 2
			b := []byte{'x', 'x'}
			require.NoError(t, s.Push(b, gapOffset, &wire.StreamFrame{}))
		}
		// After all gaps filled, entries are merged into larger blobs within each
		// chunk, leaving them sparse. tryMergeWithNext then consolidates chunks.

		// Verify the full range [0, 78) is correctly populated.
		// 20 entries × 2 bytes + 19 gap-fills × 2 bytes = 78 bytes.
		expected := make([]byte, 78)
		for i := 0; i < 20; i++ {
			expected[i*4+0] = byte('a' + i)
			expected[i*4+1] = byte('a' + i)
			if i < 19 {
				expected[i*4+2] = 'x'
				expected[i*4+3] = 'x'
			}
		}
		var got []byte
		for {
			_, data, _ := s.Pop()
			if data == nil {
				break
			}
			got = append(got, data...)
		}
		require.Equal(t, expected, got)
	})
}

// TestFrameSorter2GapCount verifies that gapCount is correctly maintained
// across insertions, deletions, overlaps, and Pop operations.
func TestFrameSorter2GapCount(t *testing.T) {
	const ds = 200 // >= compactThreshold (128)

	t.Run("initial state", func(t *testing.T) {
		s := newFrameSorter2()
		require.Equal(t, 1, s.gapCount) // [0, MaxByteCount)
	})

	t.Run("insert away from readPos splits gap", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil)) // [ds, 2ds)
		require.Equal(t, 2, s.gapCount) // [0, ds) + [2ds, Max)
	})

	t.Run("contiguous at readPos fills leading gap", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil)) // [ds, 2ds)
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("b", ds), 0, nil)) // [0, ds), contiguous with readPos
		require.Equal(t, 1, s.gapCount) // only [2ds, Max) remains
	})

	t.Run("three entries two internal gaps", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))   // [ds, 2ds)
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil)) // [3ds, 4ds)
		require.Equal(t, 3, s.gapCount) // [0,ds), [2ds,3ds), [4ds,Max)
	})

	t.Run("fill internal gap exactly", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))   // [ds, 2ds)
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil)) // [3ds, 4ds)
		require.Equal(t, 3, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", ds), 2*ds, nil)) // [2ds, 3ds), fills the gap
		require.Equal(t, 2, s.gapCount) // [0,ds), [4ds,Max)
	})

	t.Run("fill gap partially contiguous at one side", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))    // [0, ds)
		require.NoError(t, s.Push(dataGen("b", ds), 2*ds, nil)) // [2ds, 3ds)
		require.Equal(t, 2, s.gapCount) // [ds, 2ds), [3ds, Max)
		// Fill contiguous after first entry, leaving gap before second
		require.NoError(t, s.Push(dataGen("c", ds/2), ds, nil)) // [ds, ds+ds/2)
		// Gaps: [ds+ds/2, 2ds), [3ds, Max) → count unchanged
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("longer frame replaces shorter at same offset", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))    // [ds, 2ds)
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("b", ds+50), ds, nil)) // [ds, 2ds+50)
		require.Equal(t, 2, s.gapCount) // same gap structure, entry just grew
	})

	t.Run("longer frame replaces with adjacent gap closed", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))   // [ds, 2ds)
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil)) // [3ds, 4ds)
		require.Equal(t, 3, s.gapCount) // [0,ds), [2ds,3ds), [4ds,Max)
		// Replace [ds, 2ds) with [ds, 3ds) — extends to touch [3ds, 4ds)
		require.NoError(t, s.Push(dataGen("c", 2*ds), ds, nil)) // [ds, 3ds)
		require.Equal(t, 2, s.gapCount) // [0,ds), [4ds,Max)
	})

	t.Run("overlap fully covers and deletes entry", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil)) // [ds, 2ds)
		require.Equal(t, 2, s.gapCount)
		// Push frame that fully covers [ds, 2ds) and extends beyond on both sides
		require.NoError(t, s.Push(dataGen("b", ds+100), ds-50, nil)) // [ds-50, 2ds+50)
		// Entry at ds was deleted, new entry spans [ds-50, 2ds+50)
		require.Equal(t, 2, s.gapCount) // [0, ds-50), [2ds+50, Max)
	})

	t.Run("overlap trims start inside entry fills gap", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))     // [0, ds)
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil))  // [3ds, 4ds)
		require.Equal(t, 2, s.gapCount) // [ds, 3ds), [4ds, Max)
		// Push 500 bytes at offset 100; after trimming start from 100→200,
		// 400 bytes remain covering [ds, 3ds)=[200,600) exactly.
		require.NoError(t, s.Push(dataGen("c", int(2*ds+ds/2)), ds/2, nil))
		// All three entries now contiguous: [0,200)+[200,600)+[600,800)
		require.Equal(t, 1, s.gapCount) // [4ds, Max)
		// Verify all data is present
		var total []byte
		for {
			_, d, _ := s.Pop()
			if d == nil {
				break
			}
			total = append(total, d...)
		}
		require.Len(t, total, 4*int(ds))
	})

	t.Run("pop does not change gapCount", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil)) // [ds, 2ds)
		require.NoError(t, s.Push(dataGen("b", ds), 0, nil))  // [0, ds)
		require.Equal(t, 1, s.gapCount) // [2ds, Max)
		s.Pop() // consume [0, ds)
		require.Equal(t, 1, s.gapCount)
		s.Pop() // consume [ds, 2ds)
		require.Equal(t, 1, s.gapCount) // trailing gap always present
		require.False(t, s.HasMoreData())
	})

	t.Run("pop then push new data correct gapCount", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))   // [0, ds)
		require.NoError(t, s.Push(dataGen("b", ds), 2*ds, nil)) // [2ds, 3ds)
		require.Equal(t, 2, s.gapCount) // [ds, 2ds), [3ds, Max)
		s.Pop() // readPos = ds
		require.Equal(t, 2, s.gapCount) // gaps unchanged, now relative to ds
		// Push data starting at ds (the new readPos) — fills leading gap partially
		require.NoError(t, s.Push(dataGen("c", ds/2), ds, nil)) // [ds, ds+ds/2)
		// Still gap [ds+ds/2, 2ds) → count stays 2
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("too many gaps error at threshold", func(t *testing.T) {
		s := newFrameSorter2()
		// Each push at offset i*2*ds creates a gap (entries don't touch).
		for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
			require.NoError(t, s.Push(dataGen("x", ds), protocol.ByteCount(i*2*ds), nil))
		}
		require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gapCount)
		// Next push would create one more gap → exceeds limit
		err := s.Push(dataGen("y", ds), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*2*ds), nil)
		require.EqualError(t, err, "too many gaps in received data")
	})

	t.Run("gapCount rolls back after failed push", func(t *testing.T) {
		s := newFrameSorter2()
		for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
			require.NoError(t, s.Push(dataGen("x", ds), protocol.ByteCount(i*2*ds), nil))
		}
		require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gapCount)
		// This push fails with "too many gaps" and rolls back
		err := s.Push(dataGen("y", ds), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*2*ds), nil)
		require.EqualError(t, err, "too many gaps in received data")
		// gapCount should be unchanged after failed push
		require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gapCount)
	})

	t.Run("insert contiguous after existing entry no gap change", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))    // [0, ds)
		require.Equal(t, 1, s.gapCount) // [ds, Max)
		require.NoError(t, s.Push(dataGen("b", ds), ds, nil))   // [ds, 2ds), contiguous
		require.Equal(t, 1, s.gapCount) // [2ds, Max), gap shifted but count unchanged
	})

	t.Run("insert between two entries not touching either", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))     // [ds, 2ds)
		require.NoError(t, s.Push(dataGen("b", ds), 4*ds, nil))   // [4ds, 5ds)
		require.Equal(t, 3, s.gapCount) // [0,ds), [2ds,4ds), [5ds,Max)
		// Insert in the middle of the big gap, touching neither entry
		require.NoError(t, s.Push(dataGen("c", ds), 3*ds, nil))   // [3ds, 4ds)
		// Splits [2ds,4ds) → [2ds,3ds) + entry touches [4ds,5ds) so no right gap.
		require.Equal(t, 3, s.gapCount) // [0,ds), [2ds,3ds), [5ds,Max)
	})

	// ── Merge scenarios (use data < 128 to trigger merge) ──

	t.Run("small contiguous frames stay separate gapCount", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("bbbb"), 4, nil)) // [4, 8)
		require.NoError(t, s.Push([]byte("aaaa"), 0, nil)) // [0, 4), contiguous
		require.Equal(t, 1, s.gapCount) // [8, Max)
		offset, d, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("aaaa"), d)
		offset, d, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4), offset)
		require.Equal(t, []byte("bbbb"), d)
		require.Equal(t, 1, s.gapCount)
	})

	t.Run("small contiguous backward gapCount", func(t *testing.T) {
		s := newFrameSorter2()
		require.NoError(t, s.Push([]byte("aaaa"), 0, nil)) // [0, 4)
		require.NoError(t, s.Push([]byte("bbbb"), 4, nil)) // contiguous
		require.Equal(t, 1, s.gapCount) // [8, Max)
		offset, d, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("aaaa"), d)
		offset, d, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4), offset)
		require.Equal(t, []byte("bbbb"), d)
	})

	t.Run("many small contiguous entries gapCount", func(t *testing.T) {
		s := newFrameSorter2()
		for i := 0; i < 17; i++ {
			offset := protocol.ByteCount(i * 4)
			require.NoError(t, s.Push([]byte("test"), offset, nil))
		}
		// 17 small contiguous entries, no merging. Gap: [68, Max)
		require.Equal(t, 1, s.gapCount)
		for i := 0; i < 17; i++ {
			offset, d, _ := s.Pop()
			require.Equal(t, protocol.ByteCount(i*4), offset)
			require.Equal(t, []byte("test"), d)
		}
		require.False(t, s.HasMoreData())
	})
}
