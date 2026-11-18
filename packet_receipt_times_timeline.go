// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"sort"
	"time"
)

// Receipt-time report blocks carry the middle 32 bits of an NTP
// timestamp (RFC 3611, section 4.3), so one unit is 1/65536 second
// and the values wrap every 2**32 units (65536 seconds).
const (
	receiptTimeUnitsPerSecond = 1 << 16
	// receiptTimeMaxStep is half the wrap range. A forward jump of
	// this size or larger between consecutive receipt times inside
	// one report block is ambiguous with a backward jump and is
	// treated as an illegal time value.
	receiptTimeMaxStep = 1 << 31
	// extendedSeqCycle is the wrap period of the 16-bit RTP
	// sequence number space.
	extendedSeqCycle = 1 << 16
)

// ReceiptTimeEntry is a single RTP packet arrival expanded from a
// PacketReceiptTimesReportBlock.
type ReceiptTimeEntry struct {
	// SSRC is the media source the packet belongs to.
	SSRC uint32 `fmt:"0x%X"`
	// ExtendedSeq is the packet sequence number extended to 64 bit,
	// unfolded across 16-bit sequence number wraparound.
	ExtendedSeq uint64
	// ReceiptTime is the raw receipt time as reported, in units of
	// 1/65536 second, wrapping every 65536 seconds.
	ReceiptTime uint32
	// Offset is the arrival moment relative to the oldest retained
	// received packet of the timeline.
	Offset time.Duration
	// Interval is the time since the previous retained received
	// packet. It is only meaningful when HasInterval is true.
	Interval time.Duration
	// HasInterval is false for the oldest retained received packet,
	// which has no predecessor to measure an interval against.
	HasInterval bool
	// Gap is true when one or more sequence numbers directly before
	// this packet have no receipt in the retained timeline, either
	// because they were reported as not received, were never
	// reported, or were evicted from the window.
	Gap bool
}

// ReceiptTimesTimelineStats counts how a ReceiptTimesTimeline
// resolved the ambiguous and degenerate cases of the incoming
// report blocks. All counters only increase; Retained is the
// current number of sequence numbers held in the window.
type ReceiptTimesTimelineStats struct {
	// Blocks is the number of report blocks applied.
	Blocks int
	// EmptyBlocks is the number of blocks whose sequence range
	// [BeginSeq, EndSeq) was empty; they change nothing.
	EmptyBlocks int
	// ShortBlocks is the number of blocks carrying fewer receipt
	// times than their sequence range implies; only the receipt
	// times actually present are applied.
	ShortBlocks int
	// ExtraTimes is the number of receipt times dropped because
	// they lie past the block's EndSeq.
	ExtraTimes int
	// Added is the number of newly covered sequence numbers.
	Added int
	// Duplicates is the number of receipts for an already covered
	// sequence number carrying the same receipt time.
	Duplicates int
	// Conflicts is the number of receipts for an already covered
	// sequence number carrying a different receipt time; the first
	// receipt seen wins.
	Conflicts int
	// NotReceived is the number of zero receipt times, which
	// RFC 3611 uses to mark packets that were not received.
	NotReceived int
	// InvalidTimes is the number of nonzero receipt times dropped
	// because they jump backward by more than half the wrap range
	// within their report block.
	InvalidTimes int
	// Evicted is the number of entries dropped because the bounded
	// window overflowed; the lowest extended sequence numbers are
	// evicted first.
	Evicted int
	// Retained is the number of sequence numbers currently held.
	Retained int
}

// ReceiptTimesTimeline folds a stream of PacketReceiptTimesReportBlocks
// for a single media source into one per-packet arrival timeline.
// It unfolds 16-bit sequence number wraparound and 32-bit receipt
// time wraparound, tolerates overlapping and reordered reports, and
// retains only a bounded window of sequence numbers.
//
// The timeline is deterministic for a given sequence of AddBlock
// calls: the first receipt seen for a sequence number wins, and
// window overflow always evicts the lowest extended sequence
// numbers. It is not safe for concurrent use.
type ReceiptTimesTimeline struct {
	ssrc    uint32
	hasSSRC bool
	// capacity bounds the number of retained sequence numbers;
	// zero means unbounded.
	capacity uint32
	// times maps extended sequence numbers to receipt times.
	// A zero value marks a packet reported as not received.
	times  map[uint64]uint32
	minExt uint64
	maxExt uint64
	stats  ReceiptTimesTimelineStats
}

// NewReceiptTimesTimeline returns a timeline retaining at most
// capacity sequence numbers. A capacity of zero retains everything.
func NewReceiptTimesTimeline(capacity uint32) *ReceiptTimesTimeline {
	return &ReceiptTimesTimeline{
		capacity: capacity,
		times:    map[uint64]uint32{},
	}
}

// SSRC returns the media source SSRC of the timeline, and whether
// any block has been applied yet.
func (t *ReceiptTimesTimeline) SSRC() (uint32, bool) {
	return t.ssrc, t.hasSSRC
}

// Stats returns the counters describing how the applied blocks were
// resolved into the timeline.
func (t *ReceiptTimesTimeline) Stats() ReceiptTimesTimelineStats {
	t.stats.Retained = len(t.times)

	return t.stats
}

// Coverage returns the half-open range [from, to) of extended
// sequence numbers the retained window spans, and whether any
// sequence number is retained at all. The range may contain
// sequence numbers without receipts.
func (t *ReceiptTimesTimeline) Coverage() (from, to uint64, ok bool) {
	if len(t.times) == 0 {
		return 0, 0, false
	}

	return t.minExt, t.maxExt + 1, true
}

// AddBlock folds one PacketReceiptTimesReportBlock into the
// timeline. Blocks may overlap, arrive out of order, and span
// sequence number or receipt time wraparound. An error is returned
// only when the block is nil or reports a different source SSRC
// than the blocks applied before it; degenerate blocks are
// otherwise absorbed and accounted for in Stats.
//
//nolint:cyclop
func (t *ReceiptTimesTimeline) AddBlock(block *PacketReceiptTimesReportBlock) error {
	if block == nil {
		return errNilReceiptTimesBlock
	}
	if t.hasSSRC && block.SSRC != t.ssrc {
		return errReceiptTimesSSRCMismatch
	}
	t.hasSSRC = true
	t.ssrc = block.SSRC

	// EndSeq is exclusive and the range wraps mod 2**16, so a
	// block with BeginSeq == EndSeq covers no packets.
	rangeLen := int(uint16(block.EndSeq - block.BeginSeq))
	if rangeLen == 0 {
		t.stats.EmptyBlocks++
		t.stats.Blocks++

		return nil
	}
	n := rangeLen
	if len(block.ReceiptTime) < n {
		t.stats.ShortBlocks++
		n = len(block.ReceiptTime)
	}
	t.stats.ExtraTimes += len(block.ReceiptTime) - n

	beginExt := t.extendSeq(block.BeginSeq)

	var lastTime uint32
	haveLast := false
	for i := 0; i < n; i++ {
		rt := block.ReceiptTime[i]
		if rt != 0 {
			// Receipt times inside one block must move forward by
			// less than half the wrap range; anything else is an
			// illegal time value and is dropped.
			if haveLast && rt-lastTime >= receiptTimeMaxStep {
				t.stats.InvalidTimes++

				continue
			}
			lastTime = rt
			haveLast = true
		} else {
			t.stats.NotReceived++
		}

		ext := beginExt + uint64(i) //nolint:gosec // G115
		if old, ok := t.times[ext]; ok {
			// The first receipt seen wins.
			if old == rt {
				t.stats.Duplicates++
			} else {
				t.stats.Conflicts++
			}

			continue
		}
		t.times[ext] = rt
		t.stats.Added++
		if len(t.times) == 1 || ext < t.minExt {
			t.minExt = ext
		}
		if len(t.times) == 1 || ext > t.maxExt {
			t.maxExt = ext
		}
	}
	t.stats.Blocks++
	t.evict()

	return nil
}

// extendSeq unfolds a 16-bit sequence number into the cycle that
// places it closest to the highest retained extended sequence
// number. The first block applied anchors cycle zero.
func (t *ReceiptTimesTimeline) extendSeq(seq uint16) uint64 {
	if len(t.times) == 0 {
		return uint64(seq)
	}
	cycle := (int64(t.maxExt) + extendedSeqCycle/2 - int64(seq)) / extendedSeqCycle //nolint:gosec // G115
	if cycle < 0 {
		cycle = 0
	}

	return uint64(cycle)*extendedSeqCycle + uint64(seq) //nolint:gosec // G115
}

// evict drops the lowest extended sequence numbers until the
// window is within capacity.
func (t *ReceiptTimesTimeline) evict() {
	if t.capacity == 0 || uint64(len(t.times)) <= uint64(t.capacity) {
		return
	}
	keys := t.sortedKeys()
	drop := len(keys) - int(t.capacity) //nolint:gosec // G115
	for _, k := range keys[:drop] {
		delete(t.times, k)
	}
	t.stats.Evicted += drop
	t.minExt = keys[drop]
	t.maxExt = keys[len(keys)-1]
}

func (t *ReceiptTimesTimeline) sortedKeys() []uint64 {
	keys := make([]uint64, 0, len(t.times))
	for k := range t.times {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	return keys
}

// Entries returns the expanded timeline for every retained packet
// that was reported as received, ordered by extended sequence
// number.
func (t *ReceiptTimesTimeline) Entries() []ReceiptTimeEntry {
	return t.expand(0, ^uint64(0))
}

// Window returns the expanded timeline for retained received
// packets whose extended sequence number lies in the half-open
// range [from, to). The result is a contiguous slice of what
// Entries returns, so offsets and intervals are measured against
// the same predecessors regardless of the window bounds.
func (t *ReceiptTimesTimeline) Window(from, to uint64) []ReceiptTimeEntry {
	if from >= to {
		return nil
	}

	return t.expand(from, to-1)
}

// expand builds entries for retained received packets with extended
// sequence numbers in [from, to]. Offsets and intervals are
// anchored at the oldest retained received packet, even when that
// packet lies outside the requested range, so that a Window result
// stays consistent with the full Entries view.
func (t *ReceiptTimesTimeline) expand(from, to uint64) []ReceiptTimeEntry {
	entries := make([]ReceiptTimeEntry, 0, len(t.times))
	var prevTime uint32
	var prevExt uint64
	var prevOffset time.Duration
	havePrev := false
	for _, k := range t.sortedKeys() {
		rt := t.times[k]
		if rt == 0 {
			// Reported as not received: no arrival to expand.
			continue
		}
		entry := ReceiptTimeEntry{
			SSRC:        t.ssrc,
			ExtendedSeq: k,
			ReceiptTime: rt,
		}
		if havePrev {
			// Wrapping subtraction unfolds the 32-bit receipt
			// time wraparound.
			interval := receiptTimeDelta(rt - prevTime)
			entry.Interval = interval
			entry.HasInterval = true
			entry.Offset = prevOffset + interval
			entry.Gap = k != prevExt+1
		}
		prevTime = rt
		prevExt = k
		prevOffset = entry.Offset
		havePrev = true
		if k >= from && k <= to {
			entries = append(entries, entry)
		}
	}

	return entries
}

// receiptTimeDelta converts a receipt time difference into a
// duration. One unit is 1/65536 second.
func receiptTimeDelta(delta uint32) time.Duration {
	return time.Duration(delta) * time.Second / receiptTimeUnitsPerSecond
}
