// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var _ Packet = (*CCFeedbackReport)(nil) // assert is a Packet

// buildCCFeedbackBlock assembles one report block with the given number of
// metric blocks (all zeroed), adding the single padding byte when numMetric
// is odd so the block stays 16-bit aligned.
func buildCCFeedbackBlock(mediaSSRC uint32, beginSeq uint16, numMetric int) []byte {
	padded := numMetric
	if padded%2 != 0 {
		padded++
	}
	block := make([]byte, reportsOffset+2*padded)
	binary.BigEndian.PutUint32(block[ssrcOffset:], mediaSSRC)
	binary.BigEndian.PutUint16(block[beginSequenceOffset:], beginSeq)
	if numMetric > 0 {
		binary.BigEndian.PutUint16(block[numReportsOffset:], uint16(numMetric-1))
	}
	return block
}

// buildCCFeedbackPacket wraps report blocks and a report timestamp into a full
// CCFB RTCP packet with a correct header length field.
func buildCCFeedbackPacket(senderSSRC uint32, blocks [][]byte, reportTimestamp uint32) []byte {
	payloadLength := ssrcLength
	for _, block := range blocks {
		payloadLength += len(block)
	}
	payloadLength += reportTimestampLength

	raw := make([]byte, headerLength+payloadLength)
	raw[0] = (rtpVersion << versionShift) | (FormatCCFB & countMask)
	raw[1] = byte(TypeTransportSpecificFeedback)
	binary.BigEndian.PutUint16(raw[2:], uint16((headerLength+payloadLength)/4-1))
	binary.BigEndian.PutUint32(raw[headerLength:], senderSSRC)

	offset := headerLength + ssrcLength
	for _, block := range blocks {
		copy(raw[offset:], block)
		offset += len(block)
	}
	binary.BigEndian.PutUint32(raw[offset:], reportTimestamp)
	return raw
}

func TestCCFeedbackMetricBlockUnmarshalMarshal(t *testing.T) {
	for _, test := range []struct {
		Name string
		Data []byte
		Want CCFeedbackMetricBlock
	}{
		{
			Name: "NotReceived",
			Data: []byte{0x00, 0x00},
			Want: CCFeedbackMetricBlock{
				Received:          false,
				ECN:               0,
				ArrivalTimeOffset: 0,
			},
		},
		{
			Name: "ReceivedNoOffset",
			Data: []byte{0x80, 0x00},
			Want: CCFeedbackMetricBlock{
				Received:          true,
				ECN:               0,
				ArrivalTimeOffset: 0,
			},
		},
		{
			Name: "ReceivedOffset",
			Data: []byte{0x9F, 0xFD},
			Want: CCFeedbackMetricBlock{
				Received:          true,
				ECN:               0,
				ArrivalTimeOffset: 8189,
			},
		},
		{
			Name: "ReceivedOverRangeOffset",
			Data: []byte{0x9F, 0xFE},
			Want: CCFeedbackMetricBlock{
				Received:          true,
				ECN:               0,
				ArrivalTimeOffset: 8190,
			},
		},
		{
			Name: "ReceivedAfterReportTimestamp",
			Data: []byte{0x9F, 0xFF},
			Want: CCFeedbackMetricBlock{
				Received:          true,
				ECN:               0,
				ArrivalTimeOffset: 8191,
			},
		},
		{
			Name: "ReceivedECNCE",
			Data: []byte{0xFF, 0xF8},
			Want: CCFeedbackMetricBlock{
				Received:          true,
				ECN:               ECNCE,
				ArrivalTimeOffset: 8184,
			},
		},
	} {
		test := test
		t.Run(fmt.Sprintf("Unmarshal-%v", test.Name), func(t *testing.T) {
			var block CCFeedbackMetricBlock
			err := block.unmarshal(test.Data)
			assert.NoError(t, err)
			assert.Equal(t, test.Want, block)
		})
		t.Run(fmt.Sprintf("Marshal-%v", test.Name), func(t *testing.T) {
			buf, err := test.Want.marshal()
			assert.NoError(t, err)
			assert.Equal(t, test.Data, buf)
		})
	}

	for _, test := range []struct {
		Name string
		Data []byte
		Want CCFeedbackMetricBlock
	}{
		{
			Name: "NotReceivedECNCE", // Not received must ignore 15 other bits
			Data: []byte{0x62, 0x00},
			Want: CCFeedbackMetricBlock{
				Received:          false,
				ECN:               ECNNonECT,
				ArrivalTimeOffset: 0,
			},
		},
		{
			Name: "NotReceivedECNECT1", // Not received must ignore 15 other bits
			Data: []byte{0x22, 0x00},
			Want: CCFeedbackMetricBlock{
				Received:          false,
				ECN:               ECNNonECT,
				ArrivalTimeOffset: 0,
			},
		},
	} {
		test := test
		t.Run(fmt.Sprintf("Unmarshal-%v", test.Name), func(t *testing.T) {
			var block CCFeedbackMetricBlock
			err := block.unmarshal(test.Data)
			assert.NoError(t, err)
			assert.Equal(t, test.Want, block)
		})
	}

	for _, l := range []int{0, 1, 3} {
		l := l
		t.Run(fmt.Sprintf("shortMetricBlock-%v", l), func(t *testing.T) {
			var block CCFeedbackMetricBlock
			data := make([]byte, l)
			err := block.unmarshal(data)
			assert.Error(t, err)
			assert.ErrorIs(t, err, errMetricBlockLength)
		})
	}
}

func TestCCFeedbackReportBlockUnmarshalMarshal(t *testing.T) {
	for _, test := range []struct {
		Name string
		Data []byte
		Want CCFeedbackReportBlock
	}{
		{
			Name: "ZeroLengthBlock",
			Data: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			Want: CCFeedbackReportBlock{
				MediaSSRC:     0,
				BeginSequence: 0,
			},
		},
		{
			Name: "ReceivedTwoOFFourBlocks",
			Data: []byte{
				0x00, 0x00, 0x00, 0x01, // SSRC
				0x00, 0x02, 0x00, 0x03, // begin_seq, num_reports
				0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
				0x00, 0x00, 0x00, 0x00, // reports[2], reports[3]
			},
			Want: CCFeedbackReportBlock{
				MediaSSRC:     1,
				BeginSequence: 2,
				MetricBlocks: []CCFeedbackMetricBlock{
					{
						Received:          true,
						ECN:               0,
						ArrivalTimeOffset: 8189,
					},
					{
						Received:          true,
						ECN:               0,
						ArrivalTimeOffset: 8188,
					},
					{
						Received:          false,
						ECN:               0,
						ArrivalTimeOffset: 0,
					},
					{
						Received:          false,
						ECN:               0,
						ArrivalTimeOffset: 0,
					},
				},
			},
		},
		{
			Name: "ReceivedTwoOFThreeBlocksPadding",
			Data: []byte{
				0x00, 0x00, 0x00, 0x01, // SSRC
				0x00, 0x02, 0x00, 0x02, // begin_seq, num_reports
				0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
				0x00, 0x00, 0x00, 0x00, // reports[2], Padding
			},
			Want: CCFeedbackReportBlock{
				MediaSSRC:     1,
				BeginSequence: 2,
				MetricBlocks: []CCFeedbackMetricBlock{
					{
						Received:          true,
						ECN:               0,
						ArrivalTimeOffset: 8189,
					},
					{
						Received:          true,
						ECN:               0,
						ArrivalTimeOffset: 8188,
					},
					{
						Received:          false,
						ECN:               0,
						ArrivalTimeOffset: 0,
					},
				},
			},
		},
	} {
		test := test
		t.Run(fmt.Sprintf("Unmarshal-%v", test.Name), func(t *testing.T) {
			var block CCFeedbackReportBlock
			err := block.unmarshal(test.Data)
			assert.NoError(t, err)
			assert.Equal(t, test.Want, block)
		})
		t.Run(fmt.Sprintf("Marshal-%v", test.Name), func(t *testing.T) {
			buf, err := test.Want.marshal()
			assert.NoError(t, err)
			assert.Equal(t, test.Data, buf)
		})
	}

	t.Run("MarshalTooManyMetricBlocks", func(t *testing.T) {
		block := CCFeedbackReportBlock{
			MediaSSRC:     0,
			BeginSequence: 0,
			MetricBlocks:  make([]CCFeedbackMetricBlock, 16385),
		}
		_, err := block.marshal()
		assert.Error(t, err)
		assert.ErrorIs(t, err, errTooManyReports)
	})

	t.Run("emptyRawPacket", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := []byte{}
		err := block.unmarshal(data)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errReportBlockLength)
	})

	t.Run("shortRawPacket", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := []byte{
			0x00, 0x00, 0x00, 0x01, // SSRC
			0x00, 0x02, // begin_seq
		}
		err := block.unmarshal(data)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errReportBlockLength)
	})

	t.Run("incorrectNumReports", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := []byte{
			0x00, 0x00, 0x00, 0x01, // SSRC
			0x00, 0x02, 0x00, 0x05, // begin_seq, num_reports
			0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
			0x00, 0x00, 0x00, 0x00, // reports[2], reports[3]
		}
		err := block.unmarshal(data)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errIncorrectNumReports)
	})

	t.Run("overflowEndSequence", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := []byte{
			0x00, 0x00, 0x00, 0x01, // SSRC
			0xff, 0xfe, 0x00, 0x02, // begin_seq, num_reports
			0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
			0x00, 0x00, 0x00, 0x00, // reports[2], reports[3]
		}
		err := block.unmarshal(data)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errIncorrectNumReports)
	})
}

func TestCCFeedbackReportUnmarshalMarshal(t *testing.T) {
	for _, test := range []struct {
		Name string
		Data []byte
		Want CCFeedbackReport
	}{
		{
			Name: "EmtpyReport",
			Data: []byte{
				0x8B, 0xCD, 0x00, 0x02, // V=2, P=0, FMT=11, PT=205, Length=2
				0x00, 0x00, 0x00, 0x01, // Sender SSRC=1

				0x00, 0x00, 0x00, 0x01, // Report Timestamp=1
			},
			Want: CCFeedbackReport{
				SenderSSRC:      1,
				ReportBlocks:    []CCFeedbackReportBlock{},
				ReportTimestamp: 1,
			},
		},
		{
			Name: "Report",
			Data: []byte{
				0x8B, 0xCD, 0x00, 0x0A, // V=2, P=0, FMT=11, PT=205, Length=10
				0x00, 0x00, 0x00, 0x01, // Sender SSRC=1

				0x00, 0x00, 0x00, 0x01, // SSRC=1
				0x00, 0x02, 0x00, 0x03, // begin_seq, num_reports
				0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
				0x00, 0x00, 0x00, 0x00, // reports[2], reports[3]

				0x00, 0x00, 0x00, 0x02, // Media SSRC=2
				0x00, 0x02, 0x00, 0x02, // begin_seq=2, num_reports=3
				0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
				0x00, 0x00, 0x00, 0x00, // reports[2], Padding

				0x00, 0x00, 0x00, 0x01,
			},
			Want: CCFeedbackReport{
				SenderSSRC: 1,
				ReportBlocks: []CCFeedbackReportBlock{
					{
						MediaSSRC:     1,
						BeginSequence: 2,
						MetricBlocks: []CCFeedbackMetricBlock{
							{
								Received:          true,
								ECN:               0,
								ArrivalTimeOffset: 8189,
							},
							{
								Received:          true,
								ECN:               0,
								ArrivalTimeOffset: 8188,
							},
							{
								Received:          false,
								ECN:               0,
								ArrivalTimeOffset: 0,
							},
							{
								Received:          false,
								ECN:               0,
								ArrivalTimeOffset: 0,
							},
						},
					},
					{
						MediaSSRC:     2,
						BeginSequence: 2,
						MetricBlocks: []CCFeedbackMetricBlock{
							{
								Received:          true,
								ECN:               0,
								ArrivalTimeOffset: 8189,
							},
							{
								Received:          true,
								ECN:               0,
								ArrivalTimeOffset: 8188,
							},
							{
								Received:          false,
								ECN:               0,
								ArrivalTimeOffset: 0,
							},
						},
					},
				},
				ReportTimestamp: 1,
			},
		},
	} {
		test := test
		t.Run(fmt.Sprintf("Unmarshal-%v", test.Name), func(t *testing.T) {
			pkts, err := Unmarshal(test.Data)
			assert.NoError(t, err)
			assert.Len(t, pkts, 1)

			var ok bool
			var report *CCFeedbackReport
			report, ok = pkts[0].(*CCFeedbackReport)
			assert.True(t, ok)

			assert.Equal(t, test.Want, *report)
		})
		t.Run(fmt.Sprintf("Marshal-%v", test.Name), func(t *testing.T) {
			buf, err := test.Want.Marshal()
			assert.NoError(t, err)
			assert.Equal(t, test.Data, buf)
		})
	}
}

// TestCCFeedbackReportNumReportsNear16BitBoundary exercises report counts that
// previously caused uint16 wrap-arounds in offset/length arithmetic. A
// num_reports value of 0x7FFB (32764 reports, i.e. a 65536-byte block) must be
// parsed correctly instead of wrapping to a tiny or negative length.
func TestCCFeedbackReportNumReportsNear16BitBoundary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		numMetric   int
		marshalable bool // blocks larger than maxMetricBlocks parse but cannot be re-marshaled
	}{
		{name: "Anchor0x7FFB", numMetric: 0x7FFB + 1, marshalable: false},
		{name: "EvenPadded0x7FFC", numMetric: 0x7FFC, marshalable: false},
		{name: "OddMaxMarshalable", numMetric: maxMetricBlocks - 1, marshalable: true},
		{name: "MaxMarshalable", numMetric: maxMetricBlocks, marshalable: true},
		{name: "SmallOdd", numMetric: 3, marshalable: true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			block := buildCCFeedbackBlock(0x11223344, 0, tc.numMetric)
			raw := buildCCFeedbackPacket(1, [][]byte{block}, 42)

			pkts, err := Unmarshal(raw)
			assert.NoError(t, err)
			assert.Len(t, pkts, 1)

			report, ok := pkts[0].(*CCFeedbackReport)
			assert.True(t, ok)
			assert.Len(t, report.ReportBlocks, 1)
			assert.Len(t, report.ReportBlocks[0].MetricBlocks, tc.numMetric)
			assert.Equal(t, uint32(0x11223344), report.ReportBlocks[0].MediaSSRC)
			assert.Equal(t, uint32(42), report.ReportTimestamp)

			// Len, MarshalSize and the header length must agree with the wire
			// size even when the block alone exceeds 16 bits.
			assert.Equal(t, len(raw), report.Len())
			assert.Equal(t, len(raw), report.MarshalSize())
			assert.Equal(t, uint16(len(raw)/4-1), report.Header().Length)

			marshaled, err := report.Marshal()
			if !tc.marshalable {
				// Oversized blocks are rejected by the existing marshal guard
				// rather than silently truncated, and never wrap.
				assert.ErrorIs(t, err, errTooManyReports)
				return
			}
			assert.NoError(t, err)
			// Round-trip must reproduce the exact byte sequence, including the
			// single padding byte appended to odd-sized blocks.
			assert.Equal(t, raw, marshaled)

			// Re-parsing the marshaled bytes yields the same report.
			pkts, err = Unmarshal(marshaled)
			assert.NoError(t, err)
			assert.Equal(t, report, pkts[0].(*CCFeedbackReport))
		})
	}
}

// TestCCFeedbackReportLargeNumReportsTruncated checks that a num_reports field
// claiming more reports than the remaining buffer holds is rejected with the
// existing error family, without panicking or allocating beyond the input.
func TestCCFeedbackReportLargeNumReportsTruncated(t *testing.T) {
	for _, tc := range []struct {
		name      string
		numMetric int
	}{
		{name: "Anchor0x7FFB", numMetric: 0x7FFB + 1},
		{name: "MaxWireValue", numMetric: 0xFFFF + 1}, // num_reports field = 0xFFFF
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			block := buildCCFeedbackBlock(1, 0, tc.numMetric)
			raw := buildCCFeedbackPacket(1, [][]byte{block}, 7)

			// Drop the last half of the metric blocks while keeping the header
			// length field consistent with the truncated payload.
			cut := len(raw) - 2*(tc.numMetric/2)
			truncated := make([]byte, cut)
			copy(truncated, raw[:cut])
			binary.BigEndian.PutUint16(truncated[2:], uint16(cut/4-1))

			var report CCFeedbackReport
			err := report.Unmarshal(truncated)
			assert.Error(t, err)
			assert.ErrorIs(t, err, errIncorrectNumReports)
			// A failed parse must not retain partial state.
			assert.Empty(t, report.ReportBlocks)
		})
	}
}

// TestCCFeedbackReportBlockOverrunsTimestamp guards against a block whose
// computed length runs past the report timestamp: it must be reported as a
// report length error rather than silently dropping data.
func TestCCFeedbackReportBlockOverrunsTimestamp(t *testing.T) {
	block := buildCCFeedbackBlock(1, 0, 4)
	raw := buildCCFeedbackPacket(1, [][]byte{block}, 9)

	// Remove two metric bytes but leave the num_reports field untouched. The
	// packet stays 32-bit aligned and the header length is adjusted to match.
	short := make([]byte, len(raw)-4) // drop one metric pair plus keep alignment
	copy(short, raw[:len(short)-reportTimestampLength])
	binary.BigEndian.PutUint32(short[len(short)-reportTimestampLength:], 9)
	binary.BigEndian.PutUint16(short[2:], uint16(len(short)/4-1))

	var report CCFeedbackReport
	err := report.Unmarshal(short)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errIncorrectNumReports)
	assert.Empty(t, report.ReportBlocks)
}

// TestCCFeedbackReportUnmarshalResetsState verifies that reusing one
// CCFeedbackReport instance never inherits ReportBlocks from an earlier parse,
// whether the later parse succeeds or fails.
func TestCCFeedbackReportUnmarshalResetsState(t *testing.T) {
	var report CCFeedbackReport

	good := buildCCFeedbackPacket(1,
		[][]byte{buildCCFeedbackBlock(1, 0, 3)}, 1)
	assert.NoError(t, report.Unmarshal(good))
	assert.Len(t, report.ReportBlocks, 1)

	// A valid empty report clears the previously parsed blocks.
	empty := buildCCFeedbackPacket(2, nil, 2)
	assert.NoError(t, report.Unmarshal(empty))
	assert.Empty(t, report.ReportBlocks)
	assert.Equal(t, uint32(2), report.SenderSSRC)
	assert.Equal(t, uint32(2), report.ReportTimestamp)

	// Repopulate, then confirm a failed parse also leaves no partial blocks and
	// resets the scalar fields.
	assert.NoError(t, report.Unmarshal(good))
	assert.Len(t, report.ReportBlocks, 1)

	bad := buildCCFeedbackPacket(1,
		[][]byte{buildCCFeedbackBlock(1, 0, 8)}, 3)
	// Keep header, sender SSRC and the block header, but cut the metric region
	// short so num_reports overruns the remaining (timestamp-less) buffer.
	bad = bad[:headerLength+ssrcLength+reportsOffset+2]
	binary.BigEndian.PutUint16(bad[2:], uint16(len(bad)/4-1))
	assert.Error(t, report.Unmarshal(bad))
	assert.Empty(t, report.ReportBlocks)
	assert.Zero(t, report.SenderSSRC)
	assert.Zero(t, report.ReportTimestamp)

	// The same object parses a healthy packet again with no inherited state.
	assert.NoError(t, report.Unmarshal(good))
	assert.Len(t, report.ReportBlocks, 1)
}

// TestCCFeedbackReportMultipleBlocksWithBoundaryBlock keeps the existing
// multi-block behavior intact while combining ordinary blocks with a block
// whose size crosses the 16-bit boundary: offsets for the second block must be
// computed in native int width, not wrapped uint16.
func TestCCFeedbackReportMultipleBlocksWithBoundaryBlock(t *testing.T) {
	blocks := [][]byte{
		buildCCFeedbackBlock(0xAA, 10, 3),       // ordinary odd block, padded
		buildCCFeedbackBlock(0xBB, 0, 0x7FFB+1), // 65536-byte anchor block
		buildCCFeedbackBlock(0xCC, 20, 2),       // ordinary even block
	}
	raw := buildCCFeedbackPacket(1, blocks, 99)

	pkts, err := Unmarshal(raw)
	assert.NoError(t, err)
	assert.Len(t, pkts, 1)
	report := pkts[0].(*CCFeedbackReport)

	assert.Len(t, report.ReportBlocks, 3)
	assert.Equal(t, uint32(0xAA), report.ReportBlocks[0].MediaSSRC)
	assert.Len(t, report.ReportBlocks[0].MetricBlocks, 3)
	assert.Equal(t, uint32(0xBB), report.ReportBlocks[1].MediaSSRC)
	assert.Len(t, report.ReportBlocks[1].MetricBlocks, 0x7FFB+1)
	assert.Equal(t, uint32(0xCC), report.ReportBlocks[2].MediaSSRC)
	assert.Len(t, report.ReportBlocks[2].MetricBlocks, 2)
	assert.Equal(t, uint32(99), report.ReportTimestamp)
	assert.Equal(t, len(raw), report.Len())
	assert.Equal(t, len(raw), report.MarshalSize())
}

// TestCCFeedbackReportShortPackets verifies that packets too short to contain
// even the fixed header, sender SSRC and report timestamp are rejected with
// the existing error family, never panic, and leave no state behind.
func TestCCFeedbackReportShortPackets(t *testing.T) {
	for _, n := range []int{0, 1, 4, 8, 11} {
		n := n
		t.Run(fmt.Sprintf("len-%d", n), func(t *testing.T) {
			var report CCFeedbackReport
			report.SenderSSRC = 5 // pre-populate to prove the reset runs
			err := report.Unmarshal(make([]byte, n))
			assert.Error(t, err)
			assert.ErrorIs(t, err, errPacketTooShort)
			assert.Empty(t, report.ReportBlocks)
			assert.Zero(t, report.SenderSSRC)
		})
	}
}

// TestCCFeedbackReportMarshalRejectsOversizedBlocks ensures the marshal path
// cannot be driven into uint16 wrap via an over-limit MetricBlocks slice.
func TestCCFeedbackReportMarshalRejectsOversizedBlocks(t *testing.T) {
	report := CCFeedbackReport{
		SenderSSRC: 1,
		ReportBlocks: []CCFeedbackReportBlock{
			{
				MediaSSRC:    2,
				MetricBlocks: make([]CCFeedbackMetricBlock, maxMetricBlocks+1),
			},
		},
		ReportTimestamp: 1,
	}
	_, err := report.Marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, errTooManyReports)
}

// FuzzCCFeedbackUnmarshal feeds arbitrary bytes to the CCFB unmarshal path. It
// must never panic; every successfully parsed packet must be representable by
// Len/MarshalSize and anything that marshals must round-trip.
func FuzzCCFeedbackUnmarshal(f *testing.F) {
	// Seed with boundary-adjacent shapes: empty report, and reports whose
	// num_reports sits near the 16-bit limits.
	for _, numMetric := range []int{0, 1, 2, 3, 0x7FFB + 1, 0x7FFC, 0xFFFF} {
		var blocks [][]byte
		if numMetric > 0 {
			blocks = append(blocks, buildCCFeedbackBlock(1, 0, numMetric))
		}
		f.Add(buildCCFeedbackPacket(1, blocks, 1))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var report CCFeedbackReport
		if err := report.Unmarshal(data); err != nil {
			return
		}
		if report.Len() != report.MarshalSize() {
			t.Fatalf("Len %d != MarshalSize %d", report.Len(), report.MarshalSize())
		}
		buf, err := report.Marshal()
		if err != nil {
			return
		}
		if len(buf) != report.MarshalSize() {
			t.Fatalf("marshaled %d bytes but MarshalSize is %d", len(buf), report.MarshalSize())
		}

		var roundTrip CCFeedbackReport
		if err := roundTrip.Unmarshal(buf); err != nil {
			t.Fatalf("round-trip unmarshal failed: %v", err)
		}
	})
}
