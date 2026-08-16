package quic

import (
	"errors"
	"sort"
	"sync"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"
)

const frameChunkSize = 32

// seqBufCap is the maximum number of entries the fast-path ring can hold
// before spilling to the chunk list. The ring grows toward this limit from
// seqBufInitial as needed, so streams with only a few buffered frames don't
// pay for the full 128-entry allocation (5 KiB) up front.
const seqBufCap = 128
const seqBufInitial = 4

// frameEntry is a single entry in a chunk.
type frameEntry struct {
	offset protocol.ByteCount
	Data   []byte
	frame  *wire.StreamFrame // nil for crypto frames; non-nil → call PutBack on cleanup
}

func (e *frameEntry) offsetEnd() protocol.ByteCount {
	return e.offset + protocol.ByteCount(len(e.Data))
}

// frameChunk is a node in a doubly-linked list, storing up to frameChunkSize entries
// sorted by offset. Entries may or may not be contiguous in byte space
// (gaps are possible both within and between chunks).
type frameChunk struct {
	entries    [frameChunkSize]frameEntry
	len        int // number of valid entries (1 to frameChunkSize)
	next, prev *frameChunk
}

// entry returns a pointer to the i-th logical entry (0 ≤ i < c.len).
func (c *frameChunk) entry(i int) *frameEntry { return &c.entries[i] }

// first returns a pointer to the first entry in the chunk.
func (c *frameChunk) first() *frameEntry { return &c.entries[0] }

// last returns a pointer to the last entry in the chunk.
func (c *frameChunk) last() *frameEntry { return &c.entries[c.len-1] }

// remove removes the entry at idx by shifting subsequent entries left.
// Returns true if the chunk is now empty.
func (c *frameChunk) remove(idx int) bool {
	if e := c.entry(idx); e.frame != nil {
		e.frame.PutBack()
	}
	copy(c.entries[idx:], c.entries[idx+1:c.len])
	c.len--
	*c.entry(c.len) = frameEntry{}
	return c.len == 0
}

// insert inserts an entry at idx, shifting subsequent entries right.
// The caller must ensure the chunk is not full (len < frameChunkSize).
func (c *frameChunk) insert(idx int, entry frameEntry) {
	copy(c.entries[idx+1:], c.entries[idx:c.len])
	*c.entry(idx) = entry
	c.len++
}

// findOffset returns the first index where entries[i].offsetEnd() > offset.
// Returns c.len if offset is beyond all entries.
func (c *frameChunk) findOffset(offset protocol.ByteCount) int {
	return sort.Search(c.len, func(i int) bool {
		return c.entry(i).offsetEnd() > offset
	})
}

// frameChunkPool is a global pool for frameChunk allocations, shared across all
// frameSorter2 instances to reduce GC pressure from frequent chunk create/destroy.
var frameChunkPool = sync.Pool{
	New: func() any { return &frameChunk{} },
}

func allocChunk() *frameChunk {
	return frameChunkPool.Get().(*frameChunk)
}

func freeChunk(c *frameChunk) {
	// Clear entry data references to allow GC of underlying byte slices.
	for i := 0; i < c.len; i++ {
		*c.entry(i) = frameEntry{}
	}
	c.len = 0
	c.next = nil
	c.prev = nil
	frameChunkPool.Put(c)
}

// fastQueue is a ring buffer for fast-path sequential entries at readPos.
// It only holds entries when the chunk list is empty (head == nil).
// Entries are always contiguous starting from readPos.
type fastQueue struct {
	// buf is a growable ring. It starts nil and grows (doubling, up to
	// seqBufCap) on demand, so streams with only a few buffered sequential
	// frames don't pay for the full 128-entry allocation.
	buf   []frameEntry
	write int                // index of the oldest entry
	len   int                // number of valid entries
	end   protocol.ByteCount // end offset of the newest entry
}

func (q *fastQueue) empty() bool { return q.len == 0 }
func (q *fastQueue) full() bool  { return q.len == seqBufCap }

// push appends an entry. Caller guarantees the entry is contiguous (offset == q.end,
// or offset == readPos when queue is empty) and that the queue is not full.
func (q *fastQueue) push(data []byte, offset protocol.ByteCount, frame *wire.StreamFrame) {
	if q.len == cap(q.buf) {
		q.grow()
	}
	q.buf[(q.write+q.len)%cap(q.buf)] = frameEntry{offset: offset, Data: data, frame: frame}
	q.len++
	q.end = offset + protocol.ByteCount(len(data))
}

// grow doubles the ring capacity (from seqBufInitial up to seqBufCap),
// linearizing the wrapped entries so write becomes 0.
func (q *fastQueue) grow() {
	newBuf := make([]frameEntry, min(max(cap(q.buf)*2, seqBufInitial), seqBufCap))
	for i := 0; i < q.len; i++ {
		newBuf[i] = q.buf[(q.write+i)%cap(q.buf)]
	}
	q.buf = newBuf
	q.write = 0
}

// pop removes and returns the oldest entry if its offset matches readPos.
func (q *fastQueue) pop(readPos protocol.ByteCount) (frameEntry, bool) {
	if q.len == 0 {
		return frameEntry{}, false
	}
	e := q.buf[q.write]
	if e.offset != readPos {
		return frameEntry{}, false
	}
	// Clear the slot so no stale Data/frame reference outlives the returned
	// entry (which transfers ownership of the pooled buffer to the caller).
	q.buf[q.write] = frameEntry{}
	q.write = (q.write + 1) % cap(q.buf)
	q.len--
	if q.len == 0 {
		q.write = 0
		q.end = 0
	}
	return e, true
}

// drain calls fn on every queued entry and empties the queue. It is used by
// Release to return the pooled data buffers of buffered frames.
func (q *fastQueue) drain(fn func(frameEntry)) {
	for i := 0; i < q.len; i++ {
		idx := (q.write + i) % cap(q.buf)
		e := q.buf[idx]
		q.buf[idx] = frameEntry{} // drop the stale reference before fn releases the buffer
		fn(e)
	}
	q.write = 0
	q.len = 0
	q.end = 0
}

// drainTo drains all entries into the chunk list, returning the new head.
func (q *fastQueue) drainTo(head *frameChunk) *frameChunk {
	if q.len == 0 {
		return head
	}
	var tail *frameChunk
	for q.len > 0 {
		e := q.buf[q.write]
		q.write = (q.write + 1) % cap(q.buf)
		q.len--
		if tail == nil || tail.len == frameChunkSize {
			c := allocChunk()
			*c.first() = e
			c.len = 1
			if tail != nil {
				tail.next = c
				c.prev = tail
			} else {
				head = c
			}
			tail = c
		} else {
			*tail.entry(tail.len) = e
			tail.len++
		}
	}
	q.write = 0
	q.end = 0
	return head
}

// frameSorter2 is a frame sorter that uses a doubly-linked list of frameChunks
// (each containing up to 32 entries) instead of a map. Gaps between entries
// are derived by walking the chunk list — no separate gap tree is maintained.
// No small-frame merging is performed; each entry stays independent.
type frameSorter2 struct {
	head     *frameChunk
	readPos  protocol.ByteCount
	gapCount int // number of gaps in [readPos, MaxByteCount)

	// queue is a ring buffer for fast-path sequential entries (offset == readPos).
	queue fastQueue
}

func newFrameSorter2() *frameSorter2 {
	return &frameSorter2{gapCount: 1} // trailing gap [0, MaxByteCount)
}

func (s *frameSorter2) Push(data []byte, offset protocol.ByteCount, frame *wire.StreamFrame) error {
	err := s.push(data, offset, frame)
	if err == errDuplicateStreamData {
		if frame != nil {
			frame.PutBack()
		}
		return nil
	}
	return err
}

func (s *frameSorter2) push(data []byte, offset protocol.ByteCount, frame *wire.StreamFrame) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	start := offset
	end := offset + protocol.ByteCount(len(data))

	// Data before readPos has already been consumed.
	if start < s.readPos {
		if end <= s.readPos {
			return errDuplicateStreamData
		}
		data = data[s.readPos-start:]
		start = s.readPos
	}

	if s.head == nil {
		// ── Fast path: sequential append to ring buffer ──
		// And drain ring buffer if it can't accept this entry (full, or not contiguous).
		if s.queue.empty() {
			if start == s.readPos {
				s.queue.push(data, start, frame)
				return nil
			}
		} else {
			if start == s.queue.end && !s.queue.full() {
				s.queue.push(data, start, frame)
				return nil
			}
			s.head = s.queue.drainTo(s.head)
		}
	}

	// ── Walk from readPos to find where start falls ──
	// Determines startsInGap and locates the first relevant chunk/index.
	prevEnd := s.readPos
	var startsInGap bool
	c, idx := s.head, 0

	for c != nil {
		if start < c.first().offset {
			startsInGap = start >= prevEnd
			idx = 0
			break
		}
		e := c.last()
		lastEnd := e.offsetEnd()
		if start >= lastEnd {
			if start == lastEnd {
				// Contiguous after this chunk's last entry.
				idx = c.len
				startsInGap = false
				break
			}
			prevEnd = lastEnd
			c = c.next
			continue
		}
		// start is within this chunk's byte range.
		idx = c.findOffset(start)
		if idx < c.len && start >= c.entry(idx).offset {
			startsInGap = false
		} else {
			if idx > 0 {
				prevEnd = c.entry(idx - 1).offsetEnd()
			}
			startsInGap = start >= prevEnd
		}
		break
	}
	if c == nil {
		startsInGap = start >= prevEnd
	}

	// ── Start-trim: if start is inside an entry (not at its offset) ──
	// and no entry has been replaced yet, trim start to the entry's end.
	pos := start
	hasReplaced := false

	if !startsInGap && c != nil && idx < c.len {
		e := c.entry(idx)
		if start > e.offset {
			// start is inside this entry, not at its boundary.
			eEnd := e.offsetEnd()
			if end <= eEnd {
				return errDuplicateStreamData // fully covered by this entry
			}
			data = data[eEnd-start:]
			start = eEnd
			pos = start
			idx++
			if idx >= c.len {
				c = c.next
				idx = 0
			}
		}
	}

	// ── Walk forward from pos to end, processing overlapping entries ──
	for c != nil {
		for idx < c.len {
			e := c.entry(idx)
			eEnd := e.offsetEnd()

			if eEnd <= pos {
				idx++
				continue
			}
			if e.offset >= end {
				goto insert // past our range
			}
			if e.offset <= pos {
				// Entry at or overlapping pos (overlap case).
				if e.offset == pos {
					oldLen := eEnd - e.offset
					if end-pos > oldLen || (hasReplaced && end-pos == oldLen) {
						nextC := c.next
						if s.removeEntry(c, idx) {
							c = nextC
							idx = 0
							break // inner loop; re-enter outer with new c
						}
						pos += oldLen
						hasReplaced = true
						continue // re-check same idx (entry shifted in)
					}
					if !hasReplaced {
						return errDuplicateStreamData
					}
					data = data[:pos-start]
					end = pos
					goto insert
				}
				// pos is inside the entry; skip past it.
				idx++
				continue
			}

			// e.offset > pos: gap before this entry.
			if eEnd <= end {
				// Entry fully within range — delete it.
				nextC := c.next
				if s.removeEntry(c, idx) {
					c = nextC
					idx = 0
					break // inner loop; re-enter outer with new c
				}
				pos = eEnd
				hasReplaced = true
				continue
			}
			// Entry covers end — trim.
			data = data[:e.offset-start]
			end = e.offset
			goto insert
		}
		if c == nil {
			break
		}
		// Advance to next chunk (inner loop ended naturally or via break with c unchanged).
		if idx >= c.len {
			c = c.next
			idx = 0
		}
	}

insert:
	if start >= end {
		return errDuplicateStreamData
	}

	// ── Insert at the position (c, idx) found by the overlap walk ──
	entry := frameEntry{offset: start, Data: data, frame: frame}
	newEnd := start + protocol.ByteCount(len(data))

	if c != nil {
		if idx < c.len {
			// Insert before c.entry(idx).
			nextStart := c.entry(idx).offset
			prevEnd := s.readPos
			if idx > 0 {
				prevEnd = c.entry(idx - 1).offsetEnd()
			} else if c.prev != nil && c.prev.len > 0 {
				prevEnd = c.prev.last().offsetEnd()
			}
			s.insertIntoChunk(c, idx, entry)
			s.adjustGapInsert(start, newEnd, prevEnd, nextStart)
		} else {
			// Insert at end of chunk c (contiguous: start == c.last().offsetEnd()).
			nextStart := protocol.MaxByteCount
			if c.next != nil && c.next.len > 0 {
				nextStart = c.next.first().offset
			}
			s.insertIntoChunk(c, c.len, entry)
			s.adjustGapInsert(start, newEnd, start, nextStart)
		}
	} else {
		// Insert at end of list.
		prevEnd := s.readPos
		var last *frameChunk
		for cur := s.head; cur != nil; cur = cur.next {
			if cur.len > 0 {
				prevEnd = cur.last().offsetEnd()
			}
			last = cur
		}
		if last != nil && last.len < frameChunkSize {
			s.insertIntoChunk(last, last.len, entry)
		} else {
			newC := allocChunk()
			*newC.first() = entry
			newC.len = 1
			if last != nil {
				last.next = newC
				newC.prev = last
			} else {
				s.head = newC
			}
		}
		s.adjustGapInsert(start, newEnd, prevEnd, protocol.MaxByteCount)
	}

	if s.gapCount > protocol.MaxStreamFrameSorterGaps {
		chunk, i := s.findEntryAt(start)
		if chunk != nil {
			s.removeEntry(chunk, i)
		} else if frame != nil {
			frame.PutBack()
		}
		return errors.New("too many gaps in received data")
	}
	return nil
}

// findEntryAt returns the chunk and index of the entry at exactly the given offset.
// All chunks in the list are guaranteed to have len > 0.
func (s *frameSorter2) findEntryAt(offset protocol.ByteCount) (*frameChunk, int) {
	for c := s.head; c != nil; c = c.next {
		firstOff := c.first().offset
		if offset < firstOff {
			return nil, 0
		}
		lastEntry := c.last()
		lastEnd := lastEntry.offsetEnd()
		if offset >= lastEnd {
			continue
		}
		for i := 0; i < c.len; i++ {
			if c.entry(i).offset == offset {
				return c, i
			}
			if c.entry(i).offset > offset {
				return nil, 0
			}
		}
	}
	return nil, 0
}

// removeEntry removes the entry at the given chunk index, adjusts gapCount,
// and unlinks the chunk if empty. Returns true if the chunk was freed.
func (s *frameSorter2) removeEntry(chunk *frameChunk, idx int) (freed bool) {
	e := chunk.entry(idx)
	pos := e.offset
	end := e.offsetEnd()

	var gapBefore, gapAfter bool
	if idx > 0 {
		prev := chunk.entry(idx - 1)
		gapBefore = prev.offsetEnd() < pos
	} else if chunk.prev != nil && chunk.prev.len > 0 {
		prev := chunk.prev.last()
		gapBefore = prev.offsetEnd() < pos
	} else {
		gapBefore = s.readPos < pos
	}
	if idx+1 < chunk.len {
		next := chunk.entry(idx + 1)
		gapAfter = end < next.offset
	} else if chunk.next != nil && chunk.next.len > 0 {
		next := chunk.next.first()
		gapAfter = end < next.offset
	} else {
		gapAfter = end < protocol.MaxByteCount
	}
	// New gap from entry space, minus any old gaps that merge in.
	s.gapCount += 1
	if gapBefore {
		s.gapCount--
	}
	if gapAfter {
		s.gapCount--
	}

	if chunk.remove(idx) {
		s.unlinkChunk(chunk)
		return true
	}
	s.tryMergeWithNext(chunk)
	return false
}

// unlinkChunk removes the chunk from the linked list and clears its pointers.
func (s *frameSorter2) unlinkChunk(c *frameChunk) {
	if c.prev != nil {
		c.prev.next = c.next
	} else {
		s.head = c.next
	}
	if c.next != nil {
		c.next.prev = c.prev
	}
	c.next = nil
	c.prev = nil
	freeChunk(c)
}

// tryMergeWithNext merges c with subsequent chunks as long as the combined
// entry count fits within frameChunkSize. This prevents the list from
// accumulating sparse chunks after many remove/merge/pop operations.
func (s *frameSorter2) tryMergeWithNext(c *frameChunk) {
	for c != nil && c.next != nil && c.len+c.next.len <= frameChunkSize {
		copy(c.entries[c.len:], c.next.entries[:c.next.len])
		c.len += c.next.len
		s.unlinkChunk(c.next)
	}
}

// adjustGapInsert updates gapCount for an entry insertion at [offset, newEnd).
// prevEnd is the end of the entry before the insertion point (or readPos).
// nextStart is the start of the entry after the insertion point (or MaxByteCount).
func (s *frameSorter2) adjustGapInsert(offset, newEnd, prevEnd, nextStart protocol.ByteCount) {
	delta := -1 // the gap at the insertion point is consumed
	if offset > prevEnd {
		delta++ // left portion remains
	}
	if newEnd < nextStart {
		delta++ // right portion remains
	}
	s.gapCount += delta
}

// insertIntoChunk inserts an entry at the given index within a chunk, splitting first if full.
func (s *frameSorter2) insertIntoChunk(c *frameChunk, idx int, entry frameEntry) {
	if c.len == frameChunkSize {
		mid := frameChunkSize / 2
		s.splitChunk(c)
		if idx >= mid {
			c = c.next
			idx -= mid
		}
	}
	c.insert(idx, entry)
}

// splitChunk splits a full chunk into two halves.
func (s *frameSorter2) splitChunk(c *frameChunk) {
	mid := frameChunkSize / 2
	newC := allocChunk()
	copy(newC.entries[:], c.entries[mid:c.len])
	newC.len = c.len - mid
	c.len = mid

	newC.next = c.next
	newC.prev = c
	c.next = newC
	if newC.next != nil {
		newC.next.prev = newC
	}
}

func (s *frameSorter2) Pop() (protocol.ByteCount, []byte, *wire.StreamFrame) {
	// Check ring buffer first.
	if e, ok := s.queue.pop(s.readPos); ok {
		s.readPos += protocol.ByteCount(len(e.Data))
		return e.offset, e.Data, e.frame
	}
	if s.head == nil || s.head.len == 0 {
		return s.readPos, nil, nil
	}
	if s.head.first().offset != s.readPos {
		return s.readPos, nil, nil
	}
	offset := s.readPos
	// Capture values before the shift (copy will overwrite entries[0])
	entryData := s.head.first().Data
	entryFrame := s.head.first().frame
	s.readPos += protocol.ByteCount(len(entryData))

	copy(s.head.entries[:], s.head.entries[1:s.head.len])
	s.head.len--
	*s.head.entry(s.head.len) = frameEntry{}
	if s.head.len == 0 {
		old := s.head
		s.head = s.head.next
		if s.head != nil {
			s.head.prev = nil
		}
		// Clear pointer and return empty chunk to pool.
		old.next = nil
		freeChunk(old)
	} else {
		s.tryMergeWithNext(s.head)
	}
	return offset, entryData, entryFrame
}

// Release drops every buffered entry and returns each frame's pooled data
// buffer to the pool. It is called when the owning receive stream is closed or
// cancelled while frames are still buffered, so those buffers are not leaked.
// The sorter must not be used after Release.
func (s *frameSorter2) Release() {
	s.queue.drain(func(e frameEntry) {
		if e.frame != nil {
			e.frame.PutBack()
		}
	})
	for c := s.head; c != nil; {
		next := c.next
		for i := 0; i < c.len; i++ {
			if e := c.entry(i); e.frame != nil {
				e.frame.PutBack()
			}
		}
		freeChunk(c)
		c = next
	}
	s.head = nil
	s.gapCount = 1
}

// HasMoreData says if there is any more data queued at *any* offset.
func (s *frameSorter2) HasMoreData() bool {
	return !s.queue.empty() || (s.head != nil && s.head.len > 0)
}
