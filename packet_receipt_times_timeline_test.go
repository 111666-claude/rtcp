// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xrReceiptTimesPacket builds a hand-crafted RTCP XR packet carrying
// a single Packet Receipt Times report block.
func xrReceiptTimesPacket(senderSSRC, ssrc uint32, beginSeq, endSeq uint16, receiptTimes ...uint32) []byte {
	pkt := make([]byte, 20+4*len(receiptTimes))
	// RTCP header: V=2, PT=XR=207, length in 32-bit words minus one.
	pkt[0] = 0x80
	pkt[1] = 0xCF
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)/4-1)) //nolint:gosec // G115
	binary.BigEndian.PutUint32(pkt[4:], senderSSRC)
	// Report block header: BT=3, T=0, block length.
	pkt[8] = PacketReceiptTimesReportBlockType
	pkt[9] = 0
	binary.BigEndian.PutUint16(pkt[10:], uint16(2+len(receiptTimes))) //nolint:gosec // G115
	binary.BigEndian.PutUint32(pkt[12:], ssrc)
	binary.BigEndian.PutUint16(pkt[16:], beginSeq)
	binary.BigEndian.PutUint16(pkt[18:], endSeq)
	for i, rt := range receiptTimes {
		binary.BigEndian.PutUint32(pkt[20+4*i:], rt)
	}

	return pkt
}

// addReceiptTimesPacket unmarshals a hand-crafted XR packet and folds
// its receipt times block into the timeline.
func addReceiptTimesPacket(t *testing.T, tl *ReceiptTimesTimeline, pkt []byte) {
	t.Helper()
	var xr ExtendedReport
	require.NoError(t, xr.Unmarshal(pkt))
	require.Len(t, xr.Reports, 1)
	block, ok := xr.Reports[0].(*PacketReceiptTimesReportBlock)
	require.True(t, ok)
	require.NoError(t, tl.AddBlock(block))
}

// receiptStep is the arrival spacing used by the hand-crafted
// packets: 0x400 receipt time units = 1024/65536 s = 15.625 ms.
const receiptStep = 1024 * time.Second / 65536

func TestReceiptTimesTimelineCrossWrap(t *testing.T) {
	const ssrc = 0xAABBCCDD
	tl := NewReceiptTimesTimeline(0)

	// Report A straddles both the 16-bit sequence number wrap
	// (65535 -> 0) and the 32-bit receipt time wrap
	// (0xFFFFFFFF -> 0). Arrivals are 0x400 units apart.
	addReceiptTimesPacket(t, tl, xrReceiptTimesPacket(0x01020304, ssrc, 65530, 4,
		0xFFFFF100, 0xFFFFF500, 0xFFFFF900, 0xFFFFFD00,
		0x00000100, 0x00000500, 0x00000900, 0x00000D00,
		0x00001100, 0x00001500))

	// Report B continues where A stopped.
	addReceiptTimesPacket(t, tl, xrReceiptTimesPacket(0x01020304, ssrc, 4, 10,
		0x00001900, 0x00001D00, 0x00002100, 0x00002500, 0x00002900, 0x00002D00))

	// Report C overlaps A and B. It repeats five receipts, and
	// reports a conflicting receipt time for sequence number 5.
	addReceiptTimesPacket(t, tl, xrReceiptTimesPacket(0x01020304, ssrc, 2, 8,
		0x00001100, 0x00001500, 0x00001900, 0x00001E00, 0x00002100, 0x00002500))

	// Report D arrives out of order and extends the timeline
	// backwards across the receipt time wrap.
	addReceiptTimesPacket(t, tl, xrReceiptTimesPacket(0x01020304, ssrc, 65528, 65532,
		0xFFFFE900, 0xFFFFED00, 0xFFFFF100, 0xFFFFF500))

	gotSSRC, ok := tl.SSRC()
	assert.True(t, ok)
	assert.Equal(t, uint32(ssrc), gotSSRC)

	stats := tl.Stats()
	assert.Equal(t, ReceiptTimesTimelineStats{
		Blocks:     4,
		Added:      18,
		Duplicates: 7,
		Conflicts:  1,
		Retained:   18,
	}, stats)

	from, to, ok := tl.Coverage()
	assert.True(t, ok)
	assert.Equal(t, uint64(65528), from)
	assert.Equal(t, uint64(65546), to)

	entries := tl.Entries()
	require.Len(t, entries, 18)
	for i, e := range entries {
		assert.Equal(t, uint32(ssrc), e.SSRC)
		assert.Equal(t, uint64(65528+i), e.ExtendedSeq) //nolint:gosec // G115
		assert.False(t, e.Gap)
		if i == 0 {
			assert.False(t, e.HasInterval)
			assert.Zero(t, e.Offset)
		} else {
			assert.True(t, e.HasInterval)
			assert.Equal(t, receiptStep, e.Interval)
			assert.Equal(t, time.Duration(i)*receiptStep, e.Offset)
		}
	}
	// The sequence number wrap lands one cycle above 65535.
	assert.Equal(t, uint64(65536), entries[8].ExtendedSeq)
	// The receipt time wrap is unfolded: 0xFFFFFD00 -> 0x00000100
	// is one ordinary step forward.
	assert.Equal(t, uint32(0x00000100), entries[6].ReceiptTime)
	assert.Equal(t, receiptStep, entries[6].Interval)
	// The conflicting receipt for sequence number 5 did not
	// overwrite the first receipt seen.
	assert.Equal(t, uint32(0x00001D00), entries[13].ReceiptTime)

	// A bounded window query returns a contiguous slice of the
	// full timeline, anchored at the same predecessors.
	window := tl.Window(65536, 65540)
	require.Len(t, window, 4)
	assert.Equal(t, entries[8:12], window)
	assert.Equal(t, 8*receiptStep, window[0].Offset)
	assert.True(t, window[0].HasInterval)
}

func TestReceiptTimesTimelineDegenerateBlocks(t *testing.T) {
	const ssrc = 0x0BADF00D
	tl := NewReceiptTimesTimeline(0)

	// A nil block is rejected.
	assert.ErrorIs(t, tl.AddBlock(nil), errNilReceiptTimesBlock)

	// An empty sequence range is absorbed without effect.
	require.NoError(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: ssrc, BeginSeq: 50, EndSeq: 50,
	}))

	// A block for a different source is rejected.
	assert.ErrorIs(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: 0xDEADBEEF, BeginSeq: 60, EndSeq: 62, ReceiptTime: []uint32{0x1000, 0x1400},
	}), errReceiptTimesSSRCMismatch)

	// A short block on the wire carries fewer receipt times than
	// its sequence range implies; only the times present apply.
	addReceiptTimesPacket(t, tl, xrReceiptTimesPacket(0x01020304, ssrc, 100, 106,
		0x1000, 0x1400, 0x1800))

	// Receipt times past EndSeq are dropped.
	require.NoError(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: ssrc, BeginSeq: 200, EndSeq: 202,
		ReceiptTime: []uint32{0x2000, 0x2400, 0x2800, 0x2C00},
	}))

	// A zero receipt time marks a packet that was not received.
	require.NoError(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: ssrc, BeginSeq: 300, EndSeq: 303,
		ReceiptTime: []uint32{0x1000, 0, 0x1400},
	}))

	// A receipt time jumping backward by more than half the wrap
	// range is illegal and dropped; the block recovers after it.
	require.NoError(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: ssrc, BeginSeq: 400, EndSeq: 404,
		ReceiptTime: []uint32{0x1000, 0x2000, 0x90000000, 0x3000},
	}))

	stats := tl.Stats()
	assert.Equal(t, ReceiptTimesTimelineStats{
		Blocks:       5,
		EmptyBlocks:  1,
		ShortBlocks:  1,
		ExtraTimes:   2,
		Added:        11,
		NotReceived:  1,
		InvalidTimes: 1,
		Retained:     11,
	}, stats)

	entries := tl.Entries()
	require.Len(t, entries, 10)

	// The not-received packet leaves a gap between 300 and 302.
	assert.Equal(t, uint64(300), entries[5].ExtendedSeq)
	assert.Equal(t, uint64(302), entries[6].ExtendedSeq)
	assert.True(t, entries[6].Gap)
	assert.Equal(t, uint32(0x1400), entries[6].ReceiptTime)

	// The illegal time at sequence 402 is gone; 403 survives.
	assert.Equal(t, uint64(400), entries[7].ExtendedSeq)
	assert.Equal(t, uint64(401), entries[8].ExtendedSeq)
	assert.Equal(t, uint64(403), entries[9].ExtendedSeq)
	assert.True(t, entries[9].Gap)
}

func TestReceiptTimesTimelineWindowOverflow(t *testing.T) {
	const ssrc = 0x10203040
	tl := NewReceiptTimesTimeline(8)

	// Ten arrivals into a window of eight evict the two oldest.
	require.NoError(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: ssrc, BeginSeq: 1000, EndSeq: 1010,
		ReceiptTime: []uint32{
			0x1000, 0x1400, 0x1800, 0x1C00, 0x2000,
			0x2400, 0x2800, 0x2C00, 0x3000, 0x3400,
		},
	}))

	stats := tl.Stats()
	assert.Equal(t, 2, stats.Evicted)
	assert.Equal(t, 8, stats.Retained)

	from, to, ok := tl.Coverage()
	assert.True(t, ok)
	assert.Equal(t, uint64(1002), from)
	assert.Equal(t, uint64(1010), to)

	// Offsets re-anchor at the oldest retained packet.
	entries := tl.Entries()
	require.Len(t, entries, 8)
	assert.Equal(t, uint64(1002), entries[0].ExtendedSeq)
	assert.False(t, entries[0].HasInterval)
	assert.Zero(t, entries[0].Offset)
	assert.Equal(t, receiptStep, entries[1].Interval)

	// A window query inside the retained range stays consistent.
	window := tl.Window(1004, 1006)
	require.Len(t, window, 2)
	assert.Equal(t, entries[2:4], window)
	assert.Equal(t, 2*receiptStep, window[0].Offset)

	// Empty and inverted windows return nothing.
	assert.Empty(t, tl.Window(1004, 1004))
	assert.Empty(t, tl.Window(1006, 1004))

	// The next report evicts the oldest entries again.
	require.NoError(t, tl.AddBlock(&PacketReceiptTimesReportBlock{
		SSRC: ssrc, BeginSeq: 1010, EndSeq: 1014,
		ReceiptTime: []uint32{0x3800, 0x3C00, 0x4000, 0x4400},
	}))
	stats = tl.Stats()
	assert.Equal(t, 6, stats.Evicted)
	assert.Equal(t, 8, stats.Retained)
	from, to, ok = tl.Coverage()
	assert.True(t, ok)
	assert.Equal(t, uint64(1006), from)
	assert.Equal(t, uint64(1014), to)
}
