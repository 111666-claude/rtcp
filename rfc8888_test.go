// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

var _ Packet = (*CCFeedbackReport)(nil) // assert is a Packet

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
		t.Run(fmt.Sprintf("Unmarshal-%v", test.Name), func(t *testing.T) {
			var block CCFeedbackMetricBlock
			err := block.unmarshal(test.Data)
			assert.NoError(t, err)
			assert.Equal(t, test.Want, block)
		})
	}

	for _, l := range []int{0, 1, 3} {
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
				0x00, 0x02, 0x00, 0x04, // begin_seq, num_reports
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
				0x00, 0x02, 0x00, 0x03, // begin_seq, num_reports
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
		{
			Name: "WrapAroundSequenceNumber",
			Data: []byte{
				0x00, 0x00, 0x00, 0x01, // SSRC
				0xff, 0xfe, 0x00, 0x04, // begin_seq, num_reports
				0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
				0x00, 0x00, 0x00, 0x00, // reports[2], reports[3]
			},
			Want: CCFeedbackReportBlock{
				MediaSSRC:     1,
				BeginSequence: 65534,
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
	} {
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

	t.Run("overflowNumReports", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := append([]byte{
			0, 0, 0, 0, // SSRC
			0, 0, 0x7F, 0xFB, // begin_seq, num_reports
		}, bytes.Repeat([]byte{0, 0}, 0x7FFF)...)
		err := block.unmarshal(data)
		assert.NoError(t, err)
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
				0x00, 0x02, 0x00, 0x04, // begin_seq, num_reports
				0x9F, 0xFD, 0x9F, 0xFC, // reports[0], reports[1]
				0x00, 0x00, 0x00, 0x00, // reports[2], reports[3]

				0x00, 0x00, 0x00, 0x02, // Media SSRC=2
				0x00, 0x02, 0x00, 0x03, // begin_seq=2, num_reports=3
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

func TestCCFeedbackOverflow(t *testing.T) {
	p := &CCFeedbackReport{}
	err := p.Unmarshal(append([]byte{
		// Header
		0b10000000, // V = 2
		205,        // h.Type = TypeTransportSpecificFeedback
		0, 0,       // h.Length (unused)
		// SSRC
		0, 0, 0, 0,
		// CCFeedbackReportBlock
		0, 0, 0, 0, 0, 0,
		0x7F, 0xFB, // numReportsField
	}, bytes.Repeat([]byte{0, 0}, 0x7FFF)...))
	assert.ErrorIs(t, err, errReportBlockLength)
}

func TestCCFeedbackReportMarshalMaxLength(t *testing.T) {
	report := CCFeedbackReport{
		SenderSSRC:      1,
		ReportTimestamp: 2,
		ReportBlocks:    make([]CCFeedbackReportBlock, 8),
	}

	for i := range 7 {
		report.ReportBlocks[i] = CCFeedbackReportBlock{
			MediaSSRC:    uint32(i + 1),
			MetricBlocks: make([]CCFeedbackMetricBlock, maxMetricBlocks),
		}
	}
	report.ReportBlocks[7] = CCFeedbackReportBlock{
		MediaSSRC:    8,
		MetricBlocks: make([]CCFeedbackMetricBlock, 16346),
	}

	buf, err := report.Marshal()
	assert.NoError(t, err)
	assert.Len(t, buf, 4*(0xFFFF+1))
	assert.Equal(t, []byte{0x8b, 0xcd, 0xff, 0xff}, buf[:4])
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x02}, buf[len(buf)-4:])
}

func TestCCFeedbackReport_MarshalTooLarge(t *testing.T) {
	report := CCFeedbackReport{
		SenderSSRC:      1,
		ReportTimestamp: 2,
		ReportBlocks:    make([]CCFeedbackReportBlock, 8),
	}
	for i := range 8 {
		report.ReportBlocks[i] = CCFeedbackReportBlock{
			MediaSSRC:    uint32(i + 1),
			MetricBlocks: make([]CCFeedbackMetricBlock, maxMetricBlocks),
		}
	}

	bin, err := report.Marshal()
	assert.ErrorIs(t, err, errPacketTooLarge)
	assert.Nil(t, bin)
}

// TestCCFeedbackReport_MarshalBoundaries covers the small/edge packets that
// must keep marshaling: no blocks, a single block, and a block whose odd number
// of metric blocks is padded to a 4-byte boundary. The computed length, header
// length field, alignment and a re-parse of the bytes must all agree.
func TestCCFeedbackReport_MarshalBoundaries(t *testing.T) {
	metric := func(n int) []CCFeedbackMetricBlock {
		blocks := make([]CCFeedbackMetricBlock, n)
		for i := range blocks {
			blocks[i] = CCFeedbackMetricBlock{Received: true, ArrivalTimeOffset: uint16(i)}
		}

		return blocks
	}

	for _, test := range []struct {
		name   string
		report CCFeedbackReport
	}{
		{
			name: "EmptyBlocks",
			report: CCFeedbackReport{
				SenderSSRC:      1,
				ReportTimestamp: 2,
				ReportBlocks:    []CCFeedbackReportBlock{},
			},
		},
		{
			name: "SingleBlock",
			report: CCFeedbackReport{
				SenderSSRC:      1,
				ReportTimestamp: 2,
				ReportBlocks: []CCFeedbackReportBlock{
					{MediaSSRC: 7, BeginSequence: 100, MetricBlocks: metric(4)},
				},
			},
		},
		{
			name: "OddMetricBlocksPadded",
			report: CCFeedbackReport{
				SenderSSRC:      1,
				ReportTimestamp: 2,
				ReportBlocks: []CCFeedbackReportBlock{
					{MediaSSRC: 7, BeginSequence: 100, MetricBlocks: metric(3)},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			size := test.report.MarshalSize()

			buf, err := test.report.Marshal()
			assert.NoError(t, err)
			assert.NotNil(t, buf)

			// Computed length matches the emitted bytes.
			assert.Len(t, buf, size)
			// Every RTCP packet is 32-bit aligned.
			assert.Zero(t, size%4)
			// The header length field is words-minus-one and matches the size.
			assert.Equal(t, uint16(size/4-1), test.report.Header().Length)

			// The bytes parse back into the same report.
			parsed, err := Unmarshal(buf)
			assert.NoError(t, err)
			assert.Len(t, parsed, 1)
			ccfb, ok := parsed[0].(*CCFeedbackReport)
			assert.True(t, ok)
			assert.Equal(t, test.report, *ccfb)
		})
	}
}

// TestCCFeedbackReport_ExactlyAtLimit marshals a packet whose size is exactly
// the maximum representable in the RTCP length field and confirms it still
// round-trips, while one metric block more is rejected with no partial output.
func TestCCFeedbackReport_ExactlyAtLimit(t *testing.T) {
	build := func(lastMetricBlocks int) CCFeedbackReport {
		report := CCFeedbackReport{
			SenderSSRC:      1,
			ReportTimestamp: 2,
			ReportBlocks:    make([]CCFeedbackReportBlock, 8),
		}
		for i := range 7 {
			report.ReportBlocks[i] = CCFeedbackReportBlock{
				MediaSSRC:    uint32(i + 1),
				MetricBlocks: make([]CCFeedbackMetricBlock, maxMetricBlocks),
			}
		}
		report.ReportBlocks[7] = CCFeedbackReportBlock{
			MediaSSRC:    8,
			MetricBlocks: make([]CCFeedbackMetricBlock, lastMetricBlocks),
		}

		return report
	}

	atLimit := build(16346)
	assert.Equal(t, (math.MaxUint16+1)*4, atLimit.MarshalSize())

	buf, err := atLimit.Marshal()
	assert.NoError(t, err)
	assert.Len(t, buf, (math.MaxUint16+1)*4)
	assert.Equal(t, uint16(math.MaxUint16), atLimit.Header().Length)

	parsed, err := Unmarshal(buf)
	assert.NoError(t, err)
	assert.Len(t, parsed, 1)
	ccfb, ok := parsed[0].(*CCFeedbackReport)
	assert.True(t, ok)
	assert.Equal(t, atLimit, *ccfb)

	// One metric block more (padded to a word) overflows the length field.
	overLimit := build(16347)
	assert.Greater(t, overLimit.MarshalSize(), (math.MaxUint16+1)*4)
	bin, err := overLimit.Marshal()
	assert.ErrorIs(t, err, errPacketTooLarge)
	assert.Nil(t, bin)
}

// TestCCFeedbackReport_ManyBlocksLinear asserts that size accounting stays
// linear and correct when many report blocks are present, including blocks
// with odd metric counts.
func TestCCFeedbackReport_ManyBlocksLinear(t *testing.T) {
	const numBlocks = 200

	report := CCFeedbackReport{
		SenderSSRC:      1,
		ReportTimestamp: 2,
		ReportBlocks:    make([]CCFeedbackReportBlock, numBlocks),
	}
	expected := reportBlockOffset + reportTimestampLength
	for i := range numBlocks {
		// Alternate odd/even metric counts to exercise the per-block padding.
		n := i%2 + 1
		report.ReportBlocks[i] = CCFeedbackReportBlock{
			MediaSSRC:    uint32(i + 1),
			MetricBlocks: make([]CCFeedbackMetricBlock, n),
		}
		expected += report.ReportBlocks[i].len()
	}

	assert.Equal(t, expected, report.MarshalSize())
	assert.Zero(t, expected%4)

	buf, err := report.Marshal()
	assert.NoError(t, err)
	assert.Len(t, buf, expected)

	parsed, err := Unmarshal(buf)
	assert.NoError(t, err)
	ccfb, ok := parsed[0].(*CCFeedbackReport)
	assert.True(t, ok)
	assert.Len(t, ccfb.ReportBlocks, numBlocks)
}
