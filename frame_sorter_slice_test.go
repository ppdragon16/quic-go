package quic

import (
	"testing"

	"golang.org/x/exp/rand"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"

	"github.com/stretchr/testify/require"
)

// ── GapCount tests ──

func TestFrameSorterSliceGapCount(t *testing.T) {
	const ds = 200 // >= compactThreshold (128)

	newSorter := func() *frameSorterSlice { return newFrameSorterSlice() }

	t.Run("initial state", func(t *testing.T) {
		s := newSorter()
		require.Equal(t, 1, s.gapCount)
	})

	t.Run("insert away from readPos splits gap", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("contiguous at readPos fills leading gap", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("b", ds), 0, nil))
		require.Equal(t, 1, s.gapCount)
	})

	t.Run("three entries two internal gaps", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil))
		require.Equal(t, 3, s.gapCount)
	})

	t.Run("fill internal gap exactly", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil))
		require.Equal(t, 3, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", ds), 2*ds, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("fill gap partially contiguous at one side", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 2*ds, nil))
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", ds/2), ds, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("longer frame replaces shorter at same offset", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("b", ds+50), ds, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("longer frame replaces with adjacent gap closed", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil))
		require.Equal(t, 3, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", 2*ds), ds, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("overlap fully covers and deletes entry", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("b", ds+100), ds-50, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("overlap trims start inside entry fills gap", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 3*ds, nil))
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", int(2*ds+ds/2)), ds/2, nil))
		require.Equal(t, 1, s.gapCount)
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
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 0, nil))
		require.Equal(t, 1, s.gapCount)
		s.Pop()
		require.Equal(t, 1, s.gapCount)
		s.Pop()
		require.Equal(t, 1, s.gapCount)
		require.False(t, s.HasMoreData())
	})

	t.Run("pop then push new data correct gapCount", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 2*ds, nil))
		require.Equal(t, 2, s.gapCount)
		s.Pop()
		require.Equal(t, 2, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", ds/2), ds, nil))
		require.Equal(t, 2, s.gapCount)
	})

	t.Run("insert contiguous after existing entry no gap change", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), 0, nil))
		require.Equal(t, 1, s.gapCount)
		require.NoError(t, s.Push(dataGen("b", ds), ds, nil))
		require.Equal(t, 1, s.gapCount)
	})

	t.Run("insert between two entries not touching either", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push(dataGen("a", ds), ds, nil))
		require.NoError(t, s.Push(dataGen("b", ds), 4*ds, nil))
		require.Equal(t, 3, s.gapCount)
		require.NoError(t, s.Push(dataGen("c", ds), 3*ds, nil))
		require.Equal(t, 3, s.gapCount)
	})

	t.Run("small contiguous frames stay separate", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push([]byte("bbbb"), 4, nil))
		require.NoError(t, s.Push([]byte("aaaa"), 0, nil))
		offset, d, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("aaaa"), d)
		offset, d, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4), offset)
		require.Equal(t, []byte("bbbb"), d)
	})

	t.Run("small contiguous backward stay separate", func(t *testing.T) {
		s := newSorter()
		require.NoError(t, s.Push([]byte("aaaa"), 0, nil))
		require.NoError(t, s.Push([]byte("bbbb"), 4, nil))
		offset, d, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("aaaa"), d)
		offset, d, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4), offset)
		require.Equal(t, []byte("bbbb"), d)
	})

	t.Run("too many gaps error at threshold", func(t *testing.T) {
		s := newSorter()
		for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
			require.NoError(t, s.Push(dataGen("x", ds), protocol.ByteCount(i*2*ds), nil))
		}
		require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gapCount)
		err := s.Push(dataGen("y", ds), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*2*ds), nil)
		require.EqualError(t, err, "too many gaps in received data")
	})

	t.Run("gapCount rolls back after failed push", func(t *testing.T) {
		s := newSorter()
		for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
			require.NoError(t, s.Push(dataGen("x", ds), protocol.ByteCount(i*2*ds), nil))
		}
		require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gapCount)
		err := s.Push(dataGen("y", ds), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*2*ds), nil)
		require.EqualError(t, err, "too many gaps in received data")
		require.Equal(t, protocol.MaxStreamFrameSorterGaps, s.gapCount)
	})
}

// ── Simple cases ──

func TestFrameSorterSliceSimpleCases(t *testing.T) {
	s := newFrameSorterSlice()
	_, data, frame := s.Pop()
	require.Nil(t, data)
	require.Nil(t, frame)

	// empty frames are ignored
	require.NoError(t, s.Push(nil, 0, nil))
	_, data, frame = s.Pop()
	require.Nil(t, data)
	require.Nil(t, frame)

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
	require.Equal(t, dataGen("barbaz", 300)[200:], data)
	require.False(t, s.HasMoreData())
}

// ── Gap handling ──

func TestFrameSorterSliceGapHandling(t *testing.T) {
	const ds = protocol.ByteCount(200)

	t.Run("contiguous after", func(t *testing.T) {
		s := newFrameSorterSlice()
		f1 := dataGen("f1", int(ds))
		f2 := dataGen("f2", int(ds))
		require.NoError(t, s.Push(f1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(f2, ds, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, f1, data)
		offset, data, _ = s.Pop()
		require.Equal(t, ds, offset)
		require.Equal(t, f2, data)
	})

	t.Run("gap between", func(t *testing.T) {
		s := newFrameSorterSlice()
		f1 := dataGen("f1", int(ds))
		f2 := dataGen("f2", int(ds))
		gapFill := dataGen("gf", int(ds))
		require.NoError(t, s.Push(f1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(f2, 3*ds, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, f1, data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
		require.NoError(t, s.Push(gapFill, ds, nil))
		offset, data, _ = s.Pop()
		require.Equal(t, ds, offset)
		require.Equal(t, gapFill, data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
	})

	t.Run("overlap inside existing entry range", func(t *testing.T) {
		s := newFrameSorterSlice()
		f1 := dataGen("f1", int(3*ds))
		f2 := dataGen("f2", int(2*ds))
		require.NoError(t, s.Push(f1, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(f2, 5*ds, &wire.StreamFrame{}))
		overlap := dataGen("ov", int(2*ds))
		require.NoError(t, s.Push(overlap, 2*ds, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, f1, data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3*ds), offset)
		require.Equal(t, overlap[int(ds):], data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
		gapFill := dataGen("gf", int(ds))
		require.NoError(t, s.Push(gapFill, 4*ds, nil))
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(4*ds), offset)
		require.Equal(t, gapFill, data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(5*ds), offset)
		require.Equal(t, f2, data)
	})
}

// ── Duplicate data ──

func TestFrameSorterSliceDuplicateData(t *testing.T) {
	t.Run("exact duplicate", func(t *testing.T) {
		s := newFrameSorterSlice()
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("foo"), data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
	})

	t.Run("partial overlap at start", func(t *testing.T) {
		s := newFrameSorterSlice()
		require.NoError(t, s.Push([]byte("hello"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("he"), 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("hello"), data)
	})

	t.Run("longer frame replaces shorter", func(t *testing.T) {
		s := newFrameSorterSlice()
		require.NoError(t, s.Push([]byte("hi"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("hello"), 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("hello"), data)
	})

	t.Run("adjacent small frames stay separate", func(t *testing.T) {
		s := newFrameSorterSlice()
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bar"), 3, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("foo"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3), offset)
		require.Equal(t, []byte("bar"), data)
	})

	t.Run("duplicate with large data not merged", func(t *testing.T) {
		s := newFrameSorterSlice()
		large := dataGen("data", 200)
		require.NoError(t, s.Push(large, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(large, 0, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, large, data)
		_, data, _ = s.Pop()
		require.Nil(t, data)
	})
}

// ── Many entries ──

func TestFrameSorterSliceManyEntries(t *testing.T) {
	s := newFrameSorterSlice()
	const ds = 200
	const n = 200

	for i := 0; i < n; i++ {
		d := make([]byte, ds)
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

// ── Too many gaps ──

func TestFrameSorterSliceTooManyGaps(t *testing.T) {
	s := newFrameSorterSlice()
	for i := 0; i < protocol.MaxStreamFrameSorterGaps; i++ {
		require.NoError(t, s.Push([]byte("foobar"), protocol.ByteCount(i*7), nil))
	}
	err := s.Push([]byte("foobar"), protocol.ByteCount(protocol.MaxStreamFrameSorterGaps*7)+100, nil)
	require.EqualError(t, err, "too many gaps in received data")
}

// ── No merge (small-frame merging was removed) ──

func TestFrameSorterSliceNoMerge(t *testing.T) {
	t.Run("adjacent small frames NOT merged", func(t *testing.T) {
		s := newFrameSorterSlice()
		require.NoError(t, s.Push([]byte("foo"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bar"), 3, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, []byte("foo"), data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(3), offset)
		require.Equal(t, []byte("bar"), data)
	})

	t.Run("both large frames not merged", func(t *testing.T) {
		s := newFrameSorterSlice()
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
		s := newFrameSorterSlice()
		small := dataGen("s", 10)
		large := dataGen("L", 200)
		require.NoError(t, s.Push(small, 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push(large, 10, &wire.StreamFrame{}))
		offset, data, _ := s.Pop()
		require.Equal(t, protocol.ByteCount(0), offset)
		require.Equal(t, small, data)
		offset, data, _ = s.Pop()
		require.Equal(t, protocol.ByteCount(10), offset)
		require.Equal(t, large, data)
	})

	t.Run("three small contiguous stay separate", func(t *testing.T) {
		s := newFrameSorterSlice()
		require.NoError(t, s.Push([]byte("aaa"), 0, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("bbb"), 6, &wire.StreamFrame{}))
		require.NoError(t, s.Push([]byte("ccc"), 3, &wire.StreamFrame{}))
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
		s := newFrameSorterSlice()
		for i := 0; i < 16; i++ {
			offset := protocol.ByteCount(i * 4)
			require.NoError(t, s.Push([]byte("test"), offset, &wire.StreamFrame{}))
		}
		for i := 0; i < 16; i++ {
			offset, data, _ := s.Pop()
			require.Equal(t, protocol.ByteCount(i*4), offset)
			require.Equal(t, []byte("test"), data)
		}
		require.False(t, s.HasMoreData())
	})
}

// ── ReadPos / Pop ──

func TestFrameSorterSliceReadPosGaps(t *testing.T) {
	s := newFrameSorterSlice()
	ds := protocol.ByteCount(200)
	a := dataGen("hello", int(ds))
	b := dataGen("world", int(ds))
	require.NoError(t, s.Push(a, 0, &wire.StreamFrame{}))
	require.NoError(t, s.Push(b, 3*ds, &wire.StreamFrame{}))
	offset, data, _ := s.Pop()
	require.Equal(t, protocol.ByteCount(0), offset)
	require.Equal(t, a, data)
	gapFill := dataGen("xxxxx", int(ds))
	require.NoError(t, s.Push(gapFill, ds, &wire.StreamFrame{}))
	offset, data, _ = s.Pop()
	require.Equal(t, ds, offset)
	require.Equal(t, gapFill, data)
	_, data, _ = s.Pop()
	require.Nil(t, data)
}

func TestFrameSorterSlicePopReadPos(t *testing.T) {
	s := newFrameSorterSlice()
	ds := protocol.ByteCount(200)
	after := dataGen("foo", int(ds))
	before := dataGen("bar", int(ds))
	require.NoError(t, s.Push(after, ds, &wire.StreamFrame{}))
	require.NoError(t, s.Push(before, 0, &wire.StreamFrame{}))
	offset, data, _ := s.Pop()
	require.Equal(t, protocol.ByteCount(0), offset)
	require.Equal(t, before, data)
	offset, data, _ = s.Pop()
	require.Equal(t, ds, offset)
	require.Equal(t, after, data)
}

// ── Push overlap (dual-sided trim, no merge) ──

func TestFrameSorterSlicePushOverlap(t *testing.T) {
	s := newFrameSorterSlice()
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

// ── Randomized ──

func TestFrameSorterSliceRandomized(t *testing.T) {
	testSliceRandomized := func(t *testing.T, dataLen protocol.ByteCount, injectDuplicates, injectOverlaps bool) {
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
			frames[i] = frame{offset: protocol.ByteCount(i) * dataLen, data: b}
		}
		rand.Shuffle(len(frames), func(i, j int) { frames[i], frames[j] = frames[j], frames[i] })

		s := newFrameSorterSlice()
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

	t.Run("short", func(t *testing.T) { testSliceRandomized(t, 25, false, false) })
	t.Run("long", func(t *testing.T) { testSliceRandomized(t, 2*protocol.MinStreamFrameSize, false, false) })
	t.Run("short, with duplicates", func(t *testing.T) { testSliceRandomized(t, 25, true, false) })
	t.Run("long, with duplicates", func(t *testing.T) { testSliceRandomized(t, 2*protocol.MinStreamFrameSize, true, false) })
	t.Run("short, with overlaps", func(t *testing.T) { testSliceRandomized(t, 25, false, true) })
	t.Run("long, with overlaps", func(t *testing.T) { testSliceRandomized(t, 2*protocol.MinStreamFrameSize, false, true) })
}
