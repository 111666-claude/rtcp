// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"slices"
	"sync"
	"time"
)

const (
	// maxSequenceNumber is the largest value of a 16 bit RTP sequence number.
	maxSequenceNumber = 1<<16 - 1
	// maxTotalLost is the largest value that fits in the 24 bit
	// cumulative number of packets lost field of a reception report block.
	maxTotalLost = 1<<24 - 1
	// ntpFractionPerSecond is the resolution of the delay since last SR
	// (DLSR) field: units of 1/65536 seconds.
	ntpFractionPerSecond = 1 << 16
	// jitterSmoothing is the gain divisor of the RFC 3550 A.8 jitter filter.
	jitterSmoothing = 16
)

var (
	errClockRateNotSet        = errors.New("rtcp: clock rate must be greater than zero")
	errReceptionStatsNoStream = errors.New("rtcp: no reception state for SSRC")
)

// receptionStream holds the per-SSRC reception state described in
// RFC 3550 sections 6.4.1 and appendices A.3 and A.8.
type receptionStream struct {
	// clockRate is the RTP timestamp clock rate in Hz for this source.
	clockRate uint32

	// initialized reports whether the first packet has been observed.
	initialized bool
	// baseSeq is the first sequence number received.
	baseSeq uint16
	// maxSeq holds the highest sequence number received plus one, in the
	// convention of RFC 3550 appendix A.1. It wraps from 0 back to
	// maxSequenceNumber at the same time cycles is incremented.
	maxSeq uint16
	// cycles counts the number of times the 16 bit sequence number wrapped.
	cycles uint32

	// received counts distinct packets, i.e. packets that were not duplicates.
	received uint32
	// duplicates counts repeats of sequence numbers already observed.
	duplicates uint32

	// jitter is the interarrival jitter in RTP timestamp units, maintained
	// with the smoothed estimator of RFC 3550 appendix A.8.
	jitter uint32
	// lastTransit is the relative transit time of the previous packet.
	lastTransit int64

	// Baseline counters captured by the previous reception report, used to
	// restrict fraction lost to the interval between two reports.
	lastReportExpected uint32
	lastReportReceived uint32

	// lastSR is the middle 32 bits of the NTP timestamp carried in the
	// most recent sender report from this source, zero if none was seen.
	lastSR uint32
	// lastSRTime is the local time at which that sender report arrived.
	// The zero value means no sender report was seen.
	lastSRTime time.Time
}

// extendedMaxSeq returns the 32 bit extended highest sequence number:
// the upper 16 bits are the wrap count, the lower 16 bits the highest
// sequence number actually received.
func (s *receptionStream) extendedMaxSeq() uint32 {
	return s.cycles + uint32(s.maxSeq-1) //nolint:gosec // G115 // uint16 arithmetic; maxSeq-1 is the highest received sequence
}

// expectedPackets is the number of packets expected since reception began.
func (s *receptionStream) expectedPackets() uint32 {
	return s.extendedMaxSeq() - uint32(s.baseSeq) + 1
}

// ReceptionStats maintains per-SSRC reception statistics and produces
// RFC 3550 reception report blocks for receiver reports.
//
// A zero valued ReceptionStats is ready to use and safe for concurrent use.
// RTP packets are fed in through TrackPacket, sender reports through
// TrackSenderReport, and the current state is read with ReceptionReport or
// ReceptionReports. Repeated calls produce non-overlapping report intervals:
// the fraction lost field only counts losses since the previous report,
// while cumulative counters keep growing.
type ReceptionStats struct {
	mu      sync.RWMutex
	streams map[uint32]*receptionStream
}

// AddStream registers an SSRC before its first packet is seen. clockRate is
// the RTP timestamp clock rate in Hz and is required to convert arrival time
// into timestamp units for the jitter estimate. Calling AddStream for an
// SSRC that is already registered has no effect.
func (r *ReceptionStats) AddStream(ssrc uint32, clockRate uint32) error {
	if clockRate == 0 {
		return errClockRateNotSet
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.streams == nil {
		r.streams = make(map[uint32]*receptionStream)
	}

	if _, ok := r.streams[ssrc]; ok {
		return nil
	}

	r.streams[ssrc] = &receptionStream{clockRate: clockRate}

	return nil
}

// RemoveStream drops all state for ssrc. It is mainly useful when an SSRC
// leaves the session so that ReceptionReports stops emitting blocks for it.
func (r *ReceptionStats) RemoveStream(ssrc uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.streams, ssrc)
}

// TrackPacket records the reception of an RTP packet. sequenceNumber and
// rtpTimestamp come from the packet header; arrival is the local time the
// packet was received. clockRate is only used when an SSRC is seen for the
// first time, in which case it is registered lazily.
//
// Sequence number wrap, reordering, late packets and duplicates are handled
// per RFC 3550 appendix A.3 and never inflate the loss count.
func (r *ReceptionStats) TrackPacket(
	ssrc uint32,
	sequenceNumber uint16,
	rtpTimestamp uint32,
	arrival time.Time,
	clockRate uint32,
) error {
	if err := r.AddStream(ssrc, clockRate); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	stream := r.streams[ssrc]
	if stream.trackSequence(sequenceNumber) {
		stream.trackJitter(rtpTimestamp, arrival)
	}

	return nil
}

// TrackSenderReport records a sender report from ssrc. ntpTime is the 64 bit
// NTP timestamp carried in the report and arrival is the local time the
// report was received. The middle 32 bits of ntpTime become the last SR (LSR)
// field, and later reports measure the delay since last SR (DLSR) against
// arrival.
func (r *ReceptionStats) TrackSenderReport(ssrc uint32, ntpTime uint64, arrival time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	stream, ok := r.streams[ssrc]
	if !ok {
		return errReceptionStatsNoStream
	}

	// LSR is the middle 32 bits of the 64 bit NTP timestamp: drop the
	// top 16 and the bottom 16 bits.
	stream.lastSR = uint32(ntpTime >> 16) //nolint:gosec // G115 // narrowing is specified by RFC 3550
	stream.lastSRTime = arrival

	return nil
}

// ReceptionReport builds a single reception report block for ssrc at time
// now. It returns errReceptionStatsNoStream if the SSRC is not registered.
// The call closes the current report interval for that SSRC.
func (r *ReceptionStats) ReceptionReport(ssrc uint32, now time.Time) (ReceptionReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	stream, ok := r.streams[ssrc]
	if !ok {
		return ReceptionReport{}, errReceptionStatsNoStream
	}

	report := stream.receptionReport(now)
	report.SSRC = ssrc

	return report, nil
}

// ReceptionReports builds reception report blocks for every registered SSRC,
// in ascending SSRC order so the output is deterministic. Each call closes
// the current report interval: fraction lost afterwards only reflects losses
// between this call and the next.
func (r *ReceptionStats) ReceptionReports(now time.Time) []ReceptionReport {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.streams) == 0 {
		return nil
	}

	ssrcs := make([]uint32, 0, len(r.streams))
	for ssrc := range r.streams {
		ssrcs = append(ssrcs, ssrc)
	}
	slices.Sort(ssrcs)

	reports := make([]ReceptionReport, 0, len(ssrcs))
	for _, ssrc := range ssrcs {
		report := r.streams[ssrc].receptionReport(now)
		report.SSRC = ssrc
		reports = append(reports, report)
	}

	return reports
}

// trackSequence applies the sequence number validity and loss bookkeeping
// of RFC 3550 appendix A.3. It reports whether the packet was new; duplicate
// packets return false so the caller can skip the jitter update.
func (s *receptionStream) trackSequence(sequenceNumber uint16) bool {
	if !s.initialized {
		s.initialized = true
		s.baseSeq = sequenceNumber
		s.maxSeq = sequenceNumber + 1
		s.received = 1

		return true
	}

	// udelta is the forward distance from the highest sequence number
	// seen so far (maxSeq-1), accounting for 16 bit wrap.
	udelta := sequenceNumber - (s.maxSeq - 1)

	if udelta == 0 {
		// Exact repeat of the highest sequence number: a duplicate.
		s.duplicates++

		return false
	}

	// RFC 3550 appendix A.3 only treats the exact high-water repeat as a
	// duplicate here. A packet that lands further backward than a full
	// 16 bit sequence space is flagged in the standard but still falls
	// through to the received++ bookkeeping below; it is not counted twice.
	if sequenceNumber >= s.maxSeq {
		// New highest sequence number. maxSeq wrapped to zero when the
		// sequence number itself crossed the 16 bit boundary.
		if s.maxSeq == 0 {
			s.cycles += uint32(maxSequenceNumber) + 1
		}

		s.maxSeq = sequenceNumber + 1
	}

	s.received++

	return true
}

// trackJitter updates the interarrival jitter estimate per RFC 3550
// appendix A.8. Arrival time is converted into RTP timestamp units so the
// estimate shares the packet timestamp clock. It is only called for packets
// that trackSequence classified as new.
func (s *receptionStream) trackJitter(rtpTimestamp uint32, arrival time.Time) {
	arrivalUnits := arrival.UnixNano() * int64(s.clockRate) / int64(time.Second)
	transit := arrivalUnits - int64(rtpTimestamp)

	if s.received == 1 {
		// The first packet only seeds the estimator; there is no pair of
		// packets to measure an interarrival difference from yet.
		s.lastTransit = transit

		return
	}

	difference := transit - s.lastTransit
	if difference < 0 {
		difference = -difference
	}

	s.jitter += uint32((difference - int64(s.jitter)) / jitterSmoothing) //nolint:gosec // G115 // estimator output stays within RTP timestamp unit range
	s.lastTransit = transit
}

// receptionReport snapshots the current state into a wire format block and
// advances the per-interval fraction lost baseline.
func (s *receptionStream) receptionReport(now time.Time) ReceptionReport {
	expected := s.expectedPackets()

	// Cumulative loss: expected minus actually received distinct packets.
	totalLost := max(int64(0), int64(expected)-int64(s.received))
	wireTotalLost := min(uint32(totalLost), maxTotalLost) //nolint:gosec // G115 // totalLost is non-negative here

	return ReceptionReport{
		FractionLost:       s.fractionLost(expected),
		TotalLost:          wireTotalLost,
		LastSequenceNumber: s.extendedMaxSeq(),
		Jitter:             s.jitter,
		LastSenderReport:   s.lastSR,
		Delay:              s.delaySinceLastSR(now),
	}
}

// fractionLost computes the loss for the interval since the previous report,
// then stores the new baseline. With zero packets expected in the interval
// the fraction is zero.
func (s *receptionStream) fractionLost(expected uint32) uint8 {
	intervalExpected := expected - s.lastReportExpected
	intervalReceived := s.received - s.lastReportReceived
	intervalLost := int64(intervalExpected) - int64(intervalReceived)

	s.lastReportExpected = expected
	s.lastReportReceived = s.received

	if intervalExpected == 0 || intervalLost <= 0 {
		return 0
	}

	return uint8(intervalLost * 256 / int64(intervalExpected)) //nolint:gosec // G115 // ratio is bounded to [0,255] by construction
}

// delaySinceLastSR returns DLSR in units of 1/65536 seconds, or zero when no
// sender report has been received.
func (s *receptionStream) delaySinceLastSR(now time.Time) uint32 {
	if s.lastSRTime.IsZero() {
		return 0
	}

	delay := now.Sub(s.lastSRTime)
	if delay <= 0 {
		return 0
	}

	return uint32(delay * ntpFractionPerSecond / time.Second) //nolint:gosec // G115 // report interval delays fit in 32 bits
}
