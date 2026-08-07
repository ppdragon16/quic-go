package quic

import (
	"errors"

	"github.com/daeuniverse/quic-go/internal/protocol"
	"github.com/daeuniverse/quic-go/internal/wire"
)

const popCompactThreshold = 16 // 当头部积累了 16 个废弃空位时，触发平移 compaction

type frameSliceEntry struct {
	offset protocol.ByteCount
	Data   []byte
	frame  *wire.StreamFrame
}

func (e *frameSliceEntry) offsetEnd() protocol.ByteCount {
	return e.offset + protocol.ByteCount(len(e.Data))
}

type frameSorterSlice struct {
	entries  []frameSliceEntry
	head     int // 新增：游标，指向当前有效的第一个元素位置
	readPos  protocol.ByteCount
	gapCount int
}

func newFrameSorterSlice() *frameSorterSlice {
	return &frameSorterSlice{gapCount: 1}
}

func (s *frameSorterSlice) Push(data []byte, offset protocol.ByteCount, frame *wire.StreamFrame) error {
	err := s.push(data, offset, frame)
	if err == errDuplicateStreamData {
		if frame != nil {
			frame.PutBack()
		}
		return nil
	}
	return err
}

func (s *frameSorterSlice) push(data []byte, offset protocol.ByteCount, frame *wire.StreamFrame) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	start, end := offset, offset+protocol.ByteCount(len(data))
	// 1. 过滤已读取的过时数据
	if start < s.readPos {
		if end <= s.readPos {
			return errDuplicateStreamData
		}
		data = data[s.readPos-start:]
		start = s.readPos
	}

	// 2. 遍历 Slice 处理区间覆盖与裁切
	insertIdx := s.head
	for i := s.head; i < len(s.entries); {
		e := &s.entries[i]
		eEnd := e.offsetEnd()

		if eEnd <= start {
			insertIdx = i + 1
			i++
			continue
		}
		if e.offset >= end {
			break // 找到插入点，无需再比对后续节点
		}
		if start > e.offset {
			if end <= eEnd {
				return errDuplicateStreamData // 完全被已有帧覆盖
			}
			data = data[eEnd-start:]
			start = eEnd
			insertIdx = i + 1
			i++
			continue
		}
		if end <= eEnd {
			data = data[:e.offset-start]
			end = e.offset
			break
		}

		// 新数据包裹并完全覆盖了旧帧 e，移除旧帧
		s.removeEntry(i, true)
		// 移除后后续元素自动前移，i 保持不变继续比对
	}

	if start >= end {
		return errDuplicateStreamData
	}

	// 3. 插入新帧并更新 Gap 计数
	s.insertAt(insertIdx, frameSliceEntry{offset: start, Data: data, frame: frame})

	if s.gapCount > protocol.MaxStreamFrameSorterGaps {
		s.removeEntry(insertIdx, true)
		return errors.New("too many gaps in received data")
	}

	return nil
}

func (s *frameSorterSlice) insertAt(idx int, entry frameSliceEntry) {
	prevEnd, nextStart := s.getNeighborhoodOffsets(idx)

	// 利用 Slice copy 原地后移元素（极轻量的连续内存移动）
	s.entries = append(s.entries, frameSliceEntry{})
	copy(s.entries[idx+1:], s.entries[idx:])
	s.entries[idx] = entry

	s.adjustGap(entry.offset, entry.offsetEnd(), prevEnd, nextStart, true)
}

func (s *frameSorterSlice) removeEntry(idx int, updateGap bool) {
	e := &s.entries[idx]
	if updateGap {
		prevEnd := s.readPos
		if idx > s.head {
			prevEnd = s.entries[idx-1].offsetEnd()
		}
		nextStart := protocol.MaxByteCount
		if idx+1 < len(s.entries) {
			nextStart = s.entries[idx+1].offset
		}
		s.adjustGap(e.offset, e.offsetEnd(), prevEnd, nextStart, false)
	}

	if e.frame != nil {
		e.frame.PutBack()
		e.frame = nil
	}

	copy(s.entries[idx:], s.entries[idx+1:])
	s.entries[len(s.entries)-1] = frameSliceEntry{}
	s.entries = s.entries[:len(s.entries)-1]
}

func (s *frameSorterSlice) getNeighborhoodOffsets(idx int) (protocol.ByteCount, protocol.ByteCount) {
	prevEnd := s.readPos
	if idx > s.head {
		prevEnd = s.entries[idx-1].offsetEnd()
	}

	nextStart := protocol.MaxByteCount
	if idx < len(s.entries) {
		nextStart = s.entries[idx].offset
	}
	return prevEnd, nextStart
}

func (s *frameSorterSlice) adjustGap(offset, end, prevEnd, nextStart protocol.ByteCount, isInsert bool) {
	delta := 0
	if offset > prevEnd {
		delta++
	}
	if end < nextStart {
		delta++
	}

	if isInsert {
		s.gapCount += (delta - 1)
	} else {
		s.gapCount -= (delta - 1)
	}
}

func (s *frameSorterSlice) Pop() (protocol.ByteCount, []byte, *wire.StreamFrame) {
	// 注意：有效元素范围是 s.entries[s.head:]
	if s.head >= len(s.entries) || s.entries[s.head].offset != s.readPos {
		return s.readPos, nil, nil
	}

	offset := s.readPos
	e := s.entries[s.head]
	s.readPos += protocol.ByteCount(len(e.Data))

	// 1. 显式置空 0 号位，斩断指针引用，防 GC 内存泄漏
	s.entries[s.head] = frameSliceEntry{}
	s.head++

	// 2. 检查游标阈值：当 head 积累了较多废弃空间时，平移数组归零
	if s.head >= popCompactThreshold {
		s.compactHead()
	}

	return offset, e.Data, e.frame
}

// 将有效数据平移回数组头部，重置 head 为 0
func (s *frameSorterSlice) compactHead() {
	if s.head == 0 {
		return
	}
	n := copy(s.entries, s.entries[s.head:])
	// 清理尾部残留的脏数据（防止 GC 泄漏）
	for i := n; i < len(s.entries); i++ {
		s.entries[i] = frameSliceEntry{}
	}
	s.entries = s.entries[:n]
	s.head = 0
}

func (s *frameSorterSlice) HasMoreData() bool {
	return s.head < len(s.entries)
}
