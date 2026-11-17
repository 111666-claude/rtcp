// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"cmp"
	"errors"
	"slices"
	"sync"
	"time"
)

const (
	// ntpEpochOffsetSeconds is the number of seconds between the NTP epoch
	// (1900-01-01) and the Unix epoch (1970-01-01).
	ntpEpochOffsetSeconds = 2208988800

	// compactNTPUnitsPerSecond is the resolution of the middle 32 bits of an
	// NTP timestamp, the 16.16 fixed point value used by LSR and DLSR:
	// 1/65536 seconds.
	compactNTPUnitsPerSecond = 1 << 16

	// totalLostBits is the width of the cumulative number of packets lost
	// field of a reception report block. It is a signed 24-bit value on the
	// wire, see RFC 3550 section 6.4.1.
	totalLostBits = 24
	totalLostMask = 1<<totalLostBits - 1
	totalLostSign = 1 << (totalLostBits - 1)
)

var (
	// ErrInvalidReportTime is returned by Observe when the supplied reception
	// time cannot be expressed as an NTP timestamp: it is the zero time, or it
	// lies before the NTP epoch of 1900-01-01.
	ErrInvalidReportTime = errors.New("rtcp: reception report time is outside the NTP epoch")

	// ErrDuplicateReceptionReport is returned by Observe when a block repeats
	// the last accepted block for its source SSRC field for field, including
	// the DLSR. Such a block is a duplicate and contributes nothing to the
	// window.
	ErrDuplicateReceptionReport = errors.New("rtcp: duplicate reception report")

	// ErrStaleReceptionReport is returned by Observe when a block is supplied
	// with a reception time earlier than the last accepted block for the same
	// source SSRC. The report is out of order and is ignored.
	ErrStaleReceptionReport = errors.New("rtcp: reception report arrived out of order")

	// ErrNilReceiverReport is returned by ObserveReceiverReport for a nil
	// ReceiverReport.
	ErrNilReceiverReport = errors.New("rtcp: nil receiver report")
)

// ReceiverReportSample is the quality summary for one source SSRC over the
// window between two consecutive accepted reception report blocks.
type ReceiverReportSample struct {
	// SSRC is the source the report block pertains to.
	SSRC uint32
	// ReceivedAt is the caller-supplied time at which the report block was
	// received.
	ReceivedAt time.Time
	// First is true when this is the first accepted block for SSRC. No window
	// precedes it, so the deltas and the loss rate are zero.
	First bool
	// Reset is true when the block's extended highest sequence number is lower
	// than the previous accepted block's, which indicates that the source
	// restarted its sequence numbering. The block starts a new baseline:
	// ExtendedHighestSequenceDelta, PacketsLost and LossRate are zero because
	// no window spans the restart.
	Reset bool
	// ExtendedHighestSequenceNumber is the extended highest sequence number
	// carried by the block: the 16-bit sequence number in the low half and the
	// wrap count in the high half.
	ExtendedHighestSequenceNumber uint32
	// ExtendedHighestSequenceDelta is how far the extended highest sequence
	// number advanced since the previous accepted block. It is zero on the
	// first block and after a reset.
	ExtendedHighestSequenceDelta uint32
	// CumulativePacketsLost is the cumulative number of packets lost carried
	// by the block, sign extended from its 24-bit wire representation.
	CumulativePacketsLost int64
	// PacketsLost is the change in the cumulative number of lost packets since
	// the previous accepted block. It is negative when duplicates or late
	// packets reduced the cumulative loss, and it handles the 24-bit counter
	// wrapping past its maximum. A change of more than 2^23 packets within one
	// window is indistinguishable from a negative change and is not
	// representable. PacketsLost is zero on the first block and after a reset.
	PacketsLost int64
	// LossRate is the fraction of the packets expected in the window that were
	// lost, in the range [0, 1]. It is zero on the first block, after a reset,
	// and when the window contains no expected packets.
	LossRate float64
	// Jitter is the interarrival jitter carried by the block.
	Jitter uint32
	// RTT is the round-trip time derived from the block's LSR and DLSR. It is
	// meaningful only when HasRTT is true.
	RTT time.Duration
	// HasRTT reports whether RTT could be computed. It is false when the block
	// carries no usable sender report reference (LSR is zero) and when LSR and
	// DLSR do not describe a non-negative round-trip time.
	HasRTT bool
}

// ReceiverReportWindow turns the reception report blocks of incoming RTCP
// receiver reports into per-source quality metrics for the most recent report
// window.
//
// A window is the interval between two consecutive accepted report blocks for
// the same source SSRC. State is kept independently per source, so interleaved
// reports about different streams never influence each other. A source is
// expected to be reported by a single peer: the loss and sequence number
// counters of two different receivers are not comparable, so when several
// peers report on the same source, keep one ReceiverReportWindow per peer. The
// caller feeds blocks in with Observe (or whole packets with
// ObserveReceiverReport) together with the local time at which the block
// arrived:
//
//	sample, err := window.Observe(block, arrival)
//
// and the resulting sample reports how the cumulative loss, the extended
// highest sequence number and the jitter changed since the previous block, the
// loss rate over the window, and the RTT derived from LSR and DLSR when those
// fields carry enough information.
//
// The meaning of every field of a sample is documented on ReceiverReportSample.
// Reports are ordered by the caller-supplied reception time. A block whose
// reception time is strictly earlier than that of the last accepted block for
// its source is out of order and ignored with ErrStaleReceptionReport; blocks
// read at the same instant are accepted in call order, so the later call
// closes the window. A block that is accepted later but carries a lower
// extended highest sequence number is treated as a source reset. A block that
// repeats the last accepted block field for field is ignored with
// ErrDuplicateReceptionReport; when a block is both stale and a duplicate, the
// staleness is reported. The first accepted block for a source only
// establishes the baseline. A reception time that is zero or precedes the NTP
// epoch is rejected with ErrInvalidReportTime. In every error case the state of
// the source is left untouched.
//
// RTT uses the compact NTP arithmetic of RFC 3550 section 6.4.1,
// RTT = A - LSR - DLSR, where A is the reception time. It wraps with the compact
// NTP clock, whose seconds field is 16 bits, so it is intended for reports that
// arrive shortly after the sender report they refer to.
//
// The zero value is ready to use. All methods are safe for concurrent use.
type ReceiverReportWindow struct {
	mu      sync.RWMutex
	streams map[uint32]*reportWindowStream
}

// reportWindowStream is the per-source state of a ReceiverReportWindow.
type reportWindowStream struct {
	// last is the most recently accepted report block.
	last ReceptionReport
	// lastAt is the reception time of last.
	lastAt time.Time
	// latest is the sample produced for last.
	latest ReceiverReportSample
}

// NewReceiverReportWindow returns an empty ReceiverReportWindow.
func NewReceiverReportWindow() *ReceiverReportWindow {
	return &ReceiverReportWindow{}
}

// Observe records one reception report block received at receivedAt and
// returns the sample for the window that the block closes.
//
// The returned error is one of ErrInvalidReportTime,
// ErrStaleReceptionReport or ErrDuplicateReceptionReport. On error the sample
// is the zero value, the state of the block's source is unchanged, and no
// window is closed. Calling Observe for an unknown source establishes the
// baseline and returns a sample with First set.
func (w *ReceiverReportWindow) Observe(block ReceptionReport, receivedAt time.Time) (ReceiverReportSample, error) {
	if !isValidReportTime(receivedAt) {
		return ReceiverReportSample{}, ErrInvalidReportTime
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	return w.observeLocked(block, receivedAt)
}

// observeLocked implements Observe. The caller must hold the write lock.
func (w *ReceiverReportWindow) observeLocked(block ReceptionReport, receivedAt time.Time) (ReceiverReportSample, error) {
	stream, ok := w.streams[block.SSRC]
	if !ok {
		if w.streams == nil {
			w.streams = make(map[uint32]*reportWindowStream)
		}
		stream = &reportWindowStream{}
		w.streams[block.SSRC] = stream

		sample := newReceiverReportSample(block, receivedAt)
		sample.First = true
		stream.record(block, receivedAt, sample)

		return sample, nil
	}

	// The caller's reception time defines arrival order. Anything that claims
	// to have arrived before the last accepted block is out of order, even if
	// its counters are newer.
	if receivedAt.Before(stream.lastAt) {
		return ReceiverReportSample{}, ErrStaleReceptionReport
	}

	// A duplicate carries exactly the same block, including the DLSR, which
	// advances with the receiver's clock for every new report.
	if block == stream.last {
		return ReceiverReportSample{}, ErrDuplicateReceptionReport
	}

	sample := newReceiverReportSample(block, receivedAt)

	// The extended highest sequence number advances by one for every new
	// highest sequence number and wraps with its 32-bit cycle count. A signed
	// interpretation therefore identifies a source reset, while an ordinary
	// wrap keeps a positive delta.
	sequenceDelta := block.LastSequenceNumber - stream.last.LastSequenceNumber
	if int32(sequenceDelta) < 0 { //nolint:gosec // G115 // the signed interpretation is what classifies the movement
		// The source restarted. The counters of the two blocks are not
		// comparable, so the restart only establishes a new baseline.
		sample.Reset = true
	} else {
		sample.ExtendedHighestSequenceDelta = sequenceDelta
		sample.PacketsLost = totalLostDelta(stream.last.TotalLost, block.TotalLost)
		sample.LossRate = windowLossRate(sample.PacketsLost, sample.ExtendedHighestSequenceDelta)
	}

	stream.record(block, receivedAt, sample)

	return sample, nil
}

// ObserveReceiverReport applies every block of report in order with the same
// reception time and returns the samples of the blocks that were accepted.
// Rejected blocks produce no sample; their errors are joined into the returned
// error. report must not be nil.
func (w *ReceiverReportWindow) ObserveReceiverReport(
	report *ReceiverReport,
	receivedAt time.Time,
) ([]ReceiverReportSample, error) {
	if report == nil {
		return nil, ErrNilReceiverReport
	}
	if !isValidReportTime(receivedAt) {
		return nil, ErrInvalidReportTime
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	samples := make([]ReceiverReportSample, 0, len(report.Reports))
	var errs []error
	for _, block := range report.Reports {
		sample, err := w.observeLocked(block, receivedAt)
		if err != nil {
			errs = append(errs, err)

			continue
		}
		samples = append(samples, sample)
	}

	return samples, errors.Join(errs...)
}

// Latest returns the most recent accepted sample for ssrc and whether the
// source is tracked.
func (w *ReceiverReportWindow) Latest(ssrc uint32) (ReceiverReportSample, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	stream, ok := w.streams[ssrc]
	if !ok {
		return ReceiverReportSample{}, false
	}

	return stream.latest, true
}

// Samples returns the most recent accepted sample of every tracked source in
// ascending SSRC order.
func (w *ReceiverReportWindow) Samples() []ReceiverReportSample {
	w.mu.RLock()
	defer w.mu.RUnlock()

	samples := make([]ReceiverReportSample, 0, len(w.streams))
	for _, stream := range w.streams {
		samples = append(samples, stream.latest)
	}
	slices.SortFunc(samples, func(left, right ReceiverReportSample) int {
		return cmp.Compare(left.SSRC, right.SSRC)
	})

	return samples
}

// Remove drops all state for ssrc. A later block for the same source starts a
// new baseline and is reported as First.
func (w *ReceiverReportWindow) Remove(ssrc uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.streams, ssrc)
}

// record stores block and its sample as the new state of the source.
func (s *reportWindowStream) record(block ReceptionReport, receivedAt time.Time, sample ReceiverReportSample) {
	s.last = block
	s.lastAt = receivedAt
	s.latest = sample
}

// newReceiverReportSample captures the absolute fields of block. The window
// dependent fields are filled in by Observe.
func newReceiverReportSample(block ReceptionReport, receivedAt time.Time) ReceiverReportSample {
	rtt, hasRTT := receptionReportRTT(block, receivedAt)

	return ReceiverReportSample{
		SSRC:                          block.SSRC,
		ReceivedAt:                    receivedAt,
		ExtendedHighestSequenceNumber: block.LastSequenceNumber,
		CumulativePacketsLost:         cumulativeTotalLost(block.TotalLost),
		Jitter:                        block.Jitter,
		RTT:                           rtt,
		HasRTT:                        hasRTT,
	}
}

// receptionReportRTT derives the round-trip time from the LSR and DLSR of a
// block and the local reception time, using the compact NTP arithmetic of
// RFC 3550 section 6.4.1:
//
//	RTT = A - LSR - DLSR
//
// LSR is the middle 32 bits of the NTP timestamp of an earlier sender report,
// so A is converted to the same 16.16 fixed point representation. The
// computation is modulo 2^32, which covers the wrap of the compact NTP clock.
// A zero LSR means the receiver has not seen a sender report yet and carries no
// RTT information. A value that puts A before the referenced sender report, or
// a DLSR larger than the time elapsed since it, is rejected rather than turned
// into a bogus duration.
func receptionReportRTT(block ReceptionReport, receivedAt time.Time) (time.Duration, bool) {
	if block.LastSenderReport == 0 {
		return 0, false
	}

	elapsed := compactNTP(receivedAt) - block.LastSenderReport

	// Interpret the modulo difference as signed: a negative value means the
	// reception time lies before the referenced sender report. Half a compact
	// NTP wrap is roughly nine hours, far beyond any real RTT.
	if int32(elapsed) < 0 { //nolint:gosec // G115 // the signed interpretation is the validity check
		return 0, false
	}

	// The receiver spent DLSR waiting before it sent the report. Its value
	// cannot exceed the time elapsed since the sender report it refers to.
	if elapsed < block.Delay {
		return 0, false
	}

	return compactNTPDuration(elapsed - block.Delay), true
}

// isValidReportTime reports whether t can be converted to a compact NTP
// timestamp: it must be after the NTP epoch and must not be the zero time.
func isValidReportTime(t time.Time) bool {
	return !t.IsZero() && t.Unix() >= -ntpEpochOffsetSeconds
}

// compactNTP converts t to the middle 32 bits of its NTP timestamp: the 16.16
// fixed point seconds value that LSR and DLSR use.
func compactNTP(t time.Time) uint32 {
	seconds := uint64(t.Unix() + ntpEpochOffsetSeconds)           //nolint:gosec // G115 // the low 16 bits are all that is used
	fraction := uint64(t.Nanosecond()) * compactNTPUnitsPerSecond //nolint:gosec // G115 // Nanosecond is in [0, 1e9)
	fraction /= uint64(time.Second)

	return uint32(seconds<<16) | uint32(fraction) //nolint:gosec // G115 // intentional truncation to compact NTP
}

// compactNTPDuration converts a 16.16 fixed point seconds value to a duration.
func compactNTPDuration(units uint32) time.Duration {
	nanos := uint64(units) * uint64(time.Second) / compactNTPUnitsPerSecond

	return time.Duration(nanos) //nolint:gosec // G115 // at most 2^48 ns fits in a duration
}

// totalLostDelta returns the signed change between two cumulative loss
// counters. The field is a signed 24-bit integer on the wire, so the difference
// is taken modulo 2^24 and sign extended. That makes the delta correct when the
// counter wraps past its maximum and negative when duplicates or late packets
// reduce the cumulative loss.
func totalLostDelta(previous, current uint32) int64 {
	return signedTotalLost((current - previous) & totalLostMask)
}

// cumulativeTotalLost returns the signed value carried by a cumulative loss
// counter.
func cumulativeTotalLost(lost uint32) int64 {
	return signedTotalLost(lost & totalLostMask)
}

// signedTotalLost sign extends a 24-bit two's complement value.
func signedTotalLost(value uint32) int64 {
	if value >= totalLostSign {
		return int64(value) - 1<<totalLostBits
	}

	return int64(value)
}

// windowLossRate returns the fraction of expected packets that were lost in a
// window. A window without expected packets, or one in which duplicates made
// the loss delta negative, has no derivable loss rate and reports zero. A loss
// delta larger than the expected count, which can only come from inconsistent
// counters, is clamped to one.
func windowLossRate(packetsLost int64, expected uint32) float64 {
	if expected == 0 || packetsLost <= 0 {
		return 0
	}

	rate := float64(packetsLost) / float64(expected)
	if rate > 1 {
		return 1
	}

	return rate
}
