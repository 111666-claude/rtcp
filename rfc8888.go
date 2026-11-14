// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// https://www.rfc-editor.org/rfc/rfc8888.html#name-rtcp-congestion-control-fee
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |V=2|P| FMT=11  |   PT = 205    |          length               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 SSRC of RTCP packet sender                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   SSRC of 1st RTP Stream                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          begin_seq            |          num_reports          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |R|ECN|  Arrival time offset    | ...                           .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// .                                                               .
// .                                                               .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   SSRC of nth RTP Stream                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          begin_seq            |          num_reports          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |R|ECN|  Arrival time offset    | ...                           |
// .                                                               .
// .                                                               .
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                 Report Timestamp (32 bits)                    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

var (
	errReportBlockLength   = errors.New("feedback report blocks must be at least 8 bytes")
	errIncorrectNumReports = errors.New("feedback report block contains less reports than num_reports")
	errMetricBlockLength   = errors.New("feedback report metric blocks must be exactly 2 bytes")
)

// ECN represents the two ECN bits
type ECN uint8

const (
	//nolint:misspell
	// ECNNonECT signals Non ECN-Capable Transport, Non-ECT
	ECNNonECT ECN = iota // 00

	//nolint:misspell
	// ECNECT1 signals ECN Capable Transport, ECT(0)
	ECNECT1 // 01

	//nolint:misspell
	// ECNECT0 signals ECN Capable Transport, ECT(1)
	ECNECT0 // 10

	// ECNCE signals ECN Congestion Encountered, CE
	ECNCE // 11
)

const (
	reportTimestampLength = 4
	reportBlockOffset     = 8
)

// CCFeedbackReport is a Congestion Control Feedback Report as defined in
// https://www.rfc-editor.org/rfc/rfc8888.html#name-rtcp-congestion-control-fee
type CCFeedbackReport struct {
	// SSRC of sender
	SenderSSRC uint32

	// Report Blocks
	ReportBlocks []CCFeedbackReportBlock

	// Basetime
	ReportTimestamp uint32
}

// DestinationSSRC returns an array of SSRC values that this packet refers to.
func (b CCFeedbackReport) DestinationSSRC() []uint32 {
	ssrcs := make([]uint32, len(b.ReportBlocks))
	for i, block := range b.ReportBlocks {
		ssrcs[i] = block.MediaSSRC
	}
	return ssrcs
}

// Len returns the length of the report in bytes. It is computed with native
// (int) arithmetic so that reports larger than 65535 bytes cannot wrap, even
// though the on-wire length fields are only 16 bits wide.
func (b *CCFeedbackReport) Len() int {
	n := 0
	for _, block := range b.ReportBlocks {
		n += block.len()
	}
	return reportBlockOffset + n + reportTimestampLength
}

// MarshalSize returns the size of the packet once marshaled.
func (b *CCFeedbackReport) MarshalSize() int {
	return b.Len()
}

// Header returns the Header associated with this packet.
func (b *CCFeedbackReport) Header() Header {
	return Header{
		Padding: false,
		Count:   FormatCCFB,
		Type:    TypeTransportSpecificFeedback,
		Length:  uint16(b.Len()/4 - 1),
	}
}

// Marshal encodes the Congestion Control Feedback Report in binary
func (b CCFeedbackReport) Marshal() ([]byte, error) {
	length := b.Len()
	// The RTCP header length field is 16 bits and holds the packet length in
	// 32-bit words minus one, so a packet must fit in 2^18 bytes.
	if length < 4 || length%4 != 0 || length/4-1 > math.MaxUint16 {
		return nil, errBadLength
	}

	header := b.Header()
	headerBuf, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	copy(buf[:headerLength], headerBuf)
	binary.BigEndian.PutUint32(buf[headerLength:], b.SenderSSRC)
	offset := reportBlockOffset
	for _, block := range b.ReportBlocks {
		blockBuf, err := block.marshal()
		if err != nil {
			return nil, err
		}
		copy(buf[offset:], blockBuf)
		offset += block.len()
	}

	binary.BigEndian.PutUint32(buf[offset:], b.ReportTimestamp)
	return buf, nil
}

func (b CCFeedbackReport) String() string {
	out := fmt.Sprintf("CCFB:\n\tHeader %v\n", b.Header())
	out += fmt.Sprintf("CCFB:\n\tSender SSRC %d\n", b.SenderSSRC)
	out += fmt.Sprintf("\tReport Timestamp %d\n", b.ReportTimestamp)
	out += "\tFeedback Reports \n"
	for _, report := range b.ReportBlocks {
		out += fmt.Sprintf("%v ", report)
	}
	out += "\n"
	return out
}

// Unmarshal decodes the Congestion Control Feedback Report from binary
func (b *CCFeedbackReport) Unmarshal(rawPacket []byte) error {
	// Clear any state inherited from a previous packet up front. Parsing then
	// proceeds into local variables and is committed only once the whole packet
	// validates, so a failed parse can never expose partial ReportBlocks.
	b.SenderSSRC = 0
	b.ReportTimestamp = 0
	b.ReportBlocks = []CCFeedbackReportBlock{}

	if len(rawPacket) < headerLength+ssrcLength+reportTimestampLength {
		return errPacketTooShort
	}

	var h Header
	if err := h.Unmarshal(rawPacket); err != nil {
		return err
	}
	if h.Type != TypeTransportSpecificFeedback {
		return errWrongType
	}

	senderSSRC := binary.BigEndian.Uint32(rawPacket[headerLength:])

	reportTimestampOffset := len(rawPacket) - reportTimestampLength
	reportTimestamp := binary.BigEndian.Uint32(rawPacket[reportTimestampOffset:])

	reportBlocks := []CCFeedbackReportBlock{}
	offset := reportBlockOffset
	for offset < reportTimestampOffset {
		var block CCFeedbackReportBlock
		if err := block.unmarshal(rawPacket[offset:reportTimestampOffset]); err != nil {
			return err
		}
		blockLength := block.len()
		if blockLength <= 0 || offset+blockLength > reportTimestampOffset {
			return errIncorrectNumReports
		}
		reportBlocks = append(reportBlocks, block)
		offset += blockLength
	}

	b.SenderSSRC = senderSSRC
	b.ReportTimestamp = reportTimestamp
	b.ReportBlocks = reportBlocks
	return nil
}

const (
	ssrcOffset          = 0
	beginSequenceOffset = 4
	numReportsOffset    = 6
	reportsOffset       = 8

	maxMetricBlocks = 16384
)

// CCFeedbackReportBlock is a Feedback Report Block
type CCFeedbackReportBlock struct {
	// SSRC of the RTP stream on which this block is reporting
	MediaSSRC     uint32
	BeginSequence uint16
	MetricBlocks  []CCFeedbackMetricBlock
}

// len returns the length of the report block in bytes. It is computed with
// native (int) arithmetic; the 16-bit num_reports field is only converted when
// the block header is written in marshal.
func (b *CCFeedbackReportBlock) len() int {
	n := len(b.MetricBlocks)
	if n%2 != 0 {
		n++
	}
	return reportsOffset + 2*n
}

func (b CCFeedbackReportBlock) String() string {
	out := fmt.Sprintf("\tReport Block Media SSRC %d\n", b.MediaSSRC)
	out += fmt.Sprintf("\tReport Begin Sequence Nr %d\n", b.BeginSequence)
	out += fmt.Sprintf("\tReport length %d\n\t", len(b.MetricBlocks))
	for i, block := range b.MetricBlocks {
		out += fmt.Sprintf("{nr: %d, rx: %v, ts: %v} ", b.BeginSequence+uint16(i), block.Received, block.ArrivalTimeOffset)
	}
	out += "\n"
	return out
}

// marshal encodes the Congestion Control Feedback Report Block in binary
func (b CCFeedbackReportBlock) marshal() ([]byte, error) {
	if len(b.MetricBlocks) > maxMetricBlocks {
		return nil, errTooManyReports
	}

	buf := make([]byte, b.len())
	binary.BigEndian.PutUint32(buf[ssrcOffset:], b.MediaSSRC)
	binary.BigEndian.PutUint16(buf[beginSequenceOffset:], b.BeginSequence)

	// num_reports is a 16-bit wire field: convert only when writing the header.
	numReportsField := uint16(0)
	if len(b.MetricBlocks) > 0 {
		numReportsField = uint16(len(b.MetricBlocks) - 1)
	}
	binary.BigEndian.PutUint16(buf[numReportsOffset:], numReportsField)

	for i, block := range b.MetricBlocks {
		metricBlock, err := block.marshal()
		if err != nil {
			return nil, err
		}
		copy(buf[reportsOffset+2*i:], metricBlock)
	}

	return buf, nil
}

// Unmarshal decodes the Congestion Control Feedback Report Block from binary
func (b *CCFeedbackReportBlock) unmarshal(rawPacket []byte) error {
	// Reset state so reusing a block for the next packet cannot inherit
	// MetricBlocks from a previous parse.
	b.MediaSSRC = 0
	b.BeginSequence = 0
	b.MetricBlocks = nil

	if len(rawPacket) < reportsOffset {
		return errReportBlockLength
	}
	b.MediaSSRC = binary.BigEndian.Uint32(rawPacket[:beginSequenceOffset])
	b.BeginSequence = binary.BigEndian.Uint16(rawPacket[beginSequenceOffset:numReportsOffset])
	numReportsField := int(binary.BigEndian.Uint16(rawPacket[numReportsOffset:]))
	if numReportsField == 0 {
		return nil
	}

	// Keep the sequence arithmetic in native int width so the 16-bit wire
	// values cannot wrap. The encoded range must stay inside the uint16
	// sequence space.
	if int(b.BeginSequence)+numReportsField > math.MaxUint16 {
		return errIncorrectNumReports
	}
	numReports := numReportsField + 1

	// Validate against the remaining input before allocating, so a hostile
	// num_reports can never trigger an unbounded allocation.
	if len(rawPacket) < reportsOffset+2*numReports {
		return errIncorrectNumReports
	}
	b.MetricBlocks = make([]CCFeedbackMetricBlock, numReports)
	for i := 0; i < numReports; i++ {
		var mb CCFeedbackMetricBlock
		offset := reportsOffset + 2*i
		if err := mb.unmarshal(rawPacket[offset : offset+metricBlockLength]); err != nil {
			return err
		}
		b.MetricBlocks[i] = mb
	}
	return nil
}

const (
	metricBlockLength = 2
)

// CCFeedbackMetricBlock is a Feedback Metric Block
type CCFeedbackMetricBlock struct {
	Received bool
	ECN      ECN

	// Offset in 1/1024 seconds before Report Timestamp
	ArrivalTimeOffset uint16
}

// Marshal encodes the Congestion Control Feedback Metric Block in binary
func (b CCFeedbackMetricBlock) marshal() ([]byte, error) {
	buf := make([]byte, 2)
	r := uint16(0)
	if b.Received {
		r = 1
	}
	dst, err := setNBitsOfUint16(0, 1, 0, r)
	if err != nil {
		return nil, err
	}
	dst, err = setNBitsOfUint16(dst, 2, 1, uint16(b.ECN))
	if err != nil {
		return nil, err
	}
	dst, err = setNBitsOfUint16(dst, 13, 3, b.ArrivalTimeOffset)
	if err != nil {
		return nil, err
	}

	binary.BigEndian.PutUint16(buf, dst)
	return buf, nil
}

// Unmarshal decodes the Congestion Control Feedback Metric Block from binary
func (b *CCFeedbackMetricBlock) unmarshal(rawPacket []byte) error {
	if len(rawPacket) != metricBlockLength {
		return errMetricBlockLength
	}
	b.Received = rawPacket[0]&0x80 != 0
	if !b.Received {
		b.ECN = ECNNonECT
		b.ArrivalTimeOffset = 0
		return nil
	}
	b.ECN = ECN(rawPacket[0] >> 5 & 0x03)
	b.ArrivalTimeOffset = binary.BigEndian.Uint16(rawPacket) & 0x1FFF
	return nil
}
