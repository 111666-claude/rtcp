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

// buildCCFBPacket builds a wire-format CCFB packet holding a single report
// block with numReportsField in the num_reports field and that many zero
// metric blocks (plus even-alignment padding). A negative metricBlockCount
// omits the metric blocks entirely (truncated packet).
func buildCCFBPacket(numReportsField uint16, beginSeq uint16, metricBlockCount int) []byte {
	blockLen := reportsOffset
	if metricBlockCount >= 0 {
		blockLen += metricBlockCount * metricBlockLength
		if metricBlockCount%2 != 0 {
			blockLen += metricBlockLength
		}
	}
	total := reportBlockOffset + blockLen + reportTimestampLength
	buf := make([]byte, total)
	buf[0] = 0x80 | FormatCCFB // V=2, FMT=11
	buf[1] = uint8(TypeTransportSpecificFeedback)
	binary.BigEndian.PutUint16(buf[2:], uint16(total/4-1))
	binary.BigEndian.PutUint32(buf[headerLength:], 1)      // Sender SSRC
	binary.BigEndian.PutUint32(buf[reportBlockOffset:], 1) // Media SSRC
	binary.BigEndian.PutUint16(buf[reportBlockOffset+beginSequenceOffset:], beginSeq)
	binary.BigEndian.PutUint16(buf[reportBlockOffset+numReportsOffset:], numReportsField)
	binary.BigEndian.PutUint32(buf[total-reportTimestampLength:], 1) // Report Timestamp
	return buf
}

func TestCCFeedbackReportUnmarshalNearUint16Boundary(t *testing.T) {
	// num_reports=0x7ffb: 32764 metric blocks, block is exactly 65536 bytes.
	// Every 16-bit offset/length computation would wrap here.
	const numReportsField = 0x7ffb
	const numReports = numReportsField + 1
	data := buildCCFBPacket(numReportsField, 0, numReports)

	pkts, err := Unmarshal(data)
	assert.NoError(t, err)
	assert.Len(t, pkts, 1)
	report, ok := pkts[0].(*CCFeedbackReport)
	assert.True(t, ok)
	assert.Len(t, report.ReportBlocks, 1)
	assert.Len(t, report.ReportBlocks[0].MetricBlocks, numReports)

	// Length accounting must agree with the actual buffer size even though
	// the packet is larger than 0xffff bytes.
	assert.Equal(t, len(data), report.Len())
	assert.Equal(t, len(data), report.MarshalSize())
	assert.Equal(t, uint16(len(data)/4-1), report.Header().Length)

	// The same packet truncated by two bytes (one missing metric block)
	// must fail with the existing error family, not wrap or panic.
	var report2 CCFeedbackReport
	err = report2.Unmarshal(data[:len(data)-reportTimestampLength-metricBlockLength])
	assert.ErrorIs(t, err, errIncorrectNumReports)
	assert.Empty(t, report2.ReportBlocks)
}

func TestCCFeedbackReportBlockUnmarshalUint16Boundary(t *testing.T) {
	// num_reports=0xffff with begin_seq=0: report count is 65536, which
	// wraps a uint16 loop counter to zero.
	t.Run("maxNumReportsTruncated", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := make([]byte, reportsOffset)
		binary.BigEndian.PutUint16(data[numReportsOffset:], 0xffff)
		err := block.unmarshal(data)
		assert.ErrorIs(t, err, errIncorrectNumReports)
		assert.Nil(t, block.MetricBlocks)
	})

	t.Run("maxNumReportsComplete", func(t *testing.T) {
		const numReports = 0x10000 // 0xffff + 1
		data := make([]byte, reportsOffset+numReports*metricBlockLength)
		binary.BigEndian.PutUint16(data[numReportsOffset:], 0xffff)
		var block CCFeedbackReportBlock
		err := block.unmarshal(data)
		assert.NoError(t, err)
		assert.Len(t, block.MetricBlocks, numReports)
		assert.Equal(t, len(data), block.len())
	})

	// begin_seq + num_reports must not overflow the sequence space.
	t.Run("endSequenceOverflow", func(t *testing.T) {
		var block CCFeedbackReportBlock
		data := make([]byte, reportsOffset)
		binary.BigEndian.PutUint16(data[beginSequenceOffset:], 0x8000)
		binary.BigEndian.PutUint16(data[numReportsOffset:], 0x8000)
		err := block.unmarshal(data)
		assert.ErrorIs(t, err, errIncorrectNumReports)
	})
}

func TestCCFeedbackReportUnmarshalNoPartialState(t *testing.T) {
	good := buildCCFBPacket(3, 0, 4) // num_reports=3 -> 4 metric blocks

	var report CCFeedbackReport
	assert.NoError(t, report.Unmarshal(good))
	assert.Len(t, report.ReportBlocks, 1)
	prevBlocks := report.ReportBlocks

	// A failing parse must not leave partially decoded blocks behind and
	// must not clobber previously decoded state.
	broken := buildCCFBPacket(0x7ffb, 0, 10) // claims 32764 reports, has 10
	err := report.Unmarshal(broken)
	assert.ErrorIs(t, err, errIncorrectNumReports)
	assert.Equal(t, prevBlocks, report.ReportBlocks)

	// Reusing the same object for the next packet must not inherit state.
	empty := buildCCFBPacket(0, 0, 0)
	assert.NoError(t, report.Unmarshal(empty))
	assert.Len(t, report.ReportBlocks, 1)
	assert.Empty(t, report.ReportBlocks[0].MetricBlocks)
}

func TestCCFeedbackReportUnmarshalOddBlockAlignment(t *testing.T) {
	// Report blocks are padded to an even number of metric blocks. A block
	// whose padding would overlap the report timestamp must be rejected.
	data := buildCCFBPacket(2, 0, 3) // 3 metric blocks + 2 bytes padding
	// Drop the padding: header length and timestamp move 2 bytes earlier.
	truncated := make([]byte, 0, len(data)-metricBlockLength)
	truncated = append(truncated, data[:len(data)-metricBlockLength-reportTimestampLength]...)
	truncated = append(truncated, data[len(data)-reportTimestampLength:]...)
	binary.BigEndian.PutUint16(truncated[2:], uint16(len(truncated)/4-1))

	var report CCFeedbackReport
	err := report.Unmarshal(truncated)
	assert.ErrorIs(t, err, errIncorrectNumReports)
	assert.Empty(t, report.ReportBlocks)
}

func FuzzCCFeedbackReportUnmarshal(f *testing.F) {
	// Seeds near the 16-bit boundary of num_reports.
	for _, numReports := range []uint16{0, 1, 2, 0x7ffa, 0x7ffb, 0xfffe, 0xffff} {
		f.Add(buildCCFBPacket(numReports, 0, -1))                     // header only, no metric blocks
		f.Add(buildCCFBPacket(numReports, 0, int(numReports)))        // one metric block short
		f.Add(buildCCFBPacket(numReports, 0, int(numReports)+1))      // complete
		f.Add(buildCCFBPacket(numReports, 0x7fff, int(numReports)+1)) // begin_seq at boundary
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var report CCFeedbackReport
		if err := report.Unmarshal(data); err != nil {
			return
		}
		// Anything that parses must have consistent length accounting.
		assert.Equal(t, len(data), report.Len())
		assert.Equal(t, len(data), report.MarshalSize())
		assert.Equal(t, uint16(len(data)/4-1), report.Header().Length)
	})
}
