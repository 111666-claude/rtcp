// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"math"
	"math/bits"
	"sync"
	"time"
)

var (
	errMapperNilReport     = errors.New("rtcp: nil sender report")
	errMapperClockRateZero = errors.New("rtcp: clock rate must be non-zero")
	errMapperUnknownSSRC   = errors.New("rtcp: no clock rate declared for SSRC")
	errMapperNoAnchor      = errors.New("rtcp: no sender report anchor for SSRC")
	errMapperZeroNTP       = errors.New("rtcp: sender report has zero NTP timestamp")
	errMapperAmbiguousRTP  = errors.New("rtcp: RTP timestamp is half a wrap cycle from the anchor, direction is ambiguous")
	errMapperTimeOverflow  = errors.New("rtcp: RTP to wall clock conversion overflowed")
)

// ntpUnixEpochOffset is the number of seconds between the NTP epoch
// (1900-01-01) and the Unix epoch (1970-01-01).
const ntpUnixEpochOffset = 2208988800

// mapperResetThreshold is the backward RTP jump (in ticks) at or above which
// an incoming Sender Report is treated as a source reset rather than an
// out-of-order report. At 90 kHz this is roughly 3.3 hours of media time, far
// beyond any plausible RTCP reordering.
const mapperResetThreshold = 1 << 30

// AnchorInfo describes the Sender Report anchor that was used to resolve a
// wall clock time in SenderReportMapper.Map.
type AnchorInfo struct {
	// SSRC is the synchronization source the anchor belongs to.
	SSRC uint32
	// NTPTime is the wall clock time of the anchor, converted from the
	// Sender Report's NTP timestamp.
	NTPTime time.Time
	// NTPTimestamp is the raw NTP timestamp from the Sender Report.
	NTPTimestamp uint64
	// RTPTimestamp is the raw 32-bit RTP timestamp from the Sender Report.
	RTPTimestamp uint32
	// ExtendedRTPTimestamp is the anchor's RTP timestamp extended to 64 bits
	// by tracking 32-bit wraparound across consecutive Sender Reports.
	ExtendedRTPTimestamp uint64
	// ClockRate is the RTP clock rate declared for this SSRC.
	ClockRate uint32
}

type mapperAnchor struct {
	ntp      time.Time
	ntpRaw   uint64
	rtp      uint32
	extended uint64
}

type mapperStream struct {
	clockRate uint32
	anchor    mapperAnchor
	hasAnchor bool
}

// SenderReportMapper maintains one NTP/RTP anchor per SSRC, built from
// incoming RTCP Sender Reports, and resolves RTP timestamps to wall clock
// times. It is intended for receivers (e.g. RTP recorders merging multiple
// streams onto one timeline) that only learn the RTP-to-wallclock mapping
// from sparse Sender Reports.
//
// Usage: declare each SSRC's RTP clock rate once with SetClockRate, feed
// every received Sender Report to AddSenderReport, and call Map to resolve
// RTP timestamps.
//
// Policies:
//   - Wraparound: RTP timestamps are extended to 64 bits by interpreting each
//     new value within ±2^31 ticks of the current anchor (nearest cycle).
//   - Reordering: a Sender Report whose RTP timestamp falls slightly behind
//     the current anchor is stale and ignored; the anchor never moves
//     backward except on reset.
//   - Reset: a Sender Report whose RTP timestamp jumps backward by
//     mapperResetThreshold or more is treated as a source reset and becomes
//     the new anchor.
//   - Clock rate change: calling SetClockRate with a different rate for an
//     SSRC discards its anchor; Map then reports errMapperNoAnchor until the
//     next Sender Report arrives.
//
// SenderReportMapper is safe for concurrent use.
type SenderReportMapper struct {
	mu      sync.RWMutex
	streams map[uint32]*mapperStream
}

// NewSenderReportMapper returns an empty SenderReportMapper.
func NewSenderReportMapper() *SenderReportMapper {
	return &SenderReportMapper{streams: make(map[uint32]*mapperStream)}
}

// SetClockRate declares the RTP clock rate (e.g. 90000 for video, 48000 or
// 8000 for audio) for an SSRC. It must be called before AddSenderReport or
// Map for that SSRC. Declaring a different rate for an SSRC that already has
// one discards its anchor, because a mapping established under the old rate
// cannot be continued under the new one.
func (m *SenderReportMapper) SetClockRate(ssrc uint32, clockRate uint32) error {
	if clockRate == 0 {
		return errMapperClockRateZero
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	stream, ok := m.streams[ssrc]
	if !ok {
		m.streams[ssrc] = &mapperStream{clockRate: clockRate}

		return nil
	}
	if stream.clockRate != clockRate {
		stream.anchor = mapperAnchor{}
		stream.hasAnchor = false
	}
	stream.clockRate = clockRate

	return nil
}

// AddSenderReport records a Sender Report as the anchor for its SSRC. The
// SSRC's clock rate must have been declared with SetClockRate first. Reports
// with a zero NTP timestamp are rejected. Stale (out-of-order) reports are
// ignored: the most recent anchor always wins.
func (m *SenderReportMapper) AddSenderReport(sr *SenderReport) error {
	if sr == nil {
		return errMapperNilReport
	}
	if sr.NTPTime == 0 {
		return errMapperZeroNTP
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	stream, ok := m.streams[sr.SSRC]
	if !ok {
		return errMapperUnknownSSRC
	}

	ntp := ntpToTime(sr.NTPTime)
	if !stream.hasAnchor {
		stream.anchor = mapperAnchor{
			ntp:      ntp,
			ntpRaw:   sr.NTPTime,
			rtp:      sr.RTPTime,
			extended: uint64(sr.RTPTime),
		}
		stream.hasAnchor = true

		return nil
	}

	// Signed distance from the current anchor, resolving wraparound to the
	// nearest cycle.
	diff := int32(sr.RTPTime - uint32(stream.anchor.extended)) //nolint:gosec // G115: intentional wrap
	switch {
	case diff >= 0:
		// Newer (or duplicate) report: advance the anchor.
		stream.anchor = mapperAnchor{
			ntp:      ntp,
			ntpRaw:   sr.NTPTime,
			rtp:      sr.RTPTime,
			extended: uint64(int64(stream.anchor.extended) + int64(diff)), //nolint:gosec // G115
		}
	case -diff >= mapperResetThreshold:
		// Backward jump far beyond plausible reordering: source reset.
		// Accept the report as the new anchor.
		stream.anchor = mapperAnchor{
			ntp:      ntp,
			ntpRaw:   sr.NTPTime,
			rtp:      sr.RTPTime,
			extended: uint64(int64(stream.anchor.extended) + int64(diff)), //nolint:gosec // G115
		}
	default:
		// Stale out-of-order report: keep the current anchor.
	}

	return nil
}

// Map resolves an RTP timestamp to its wall clock time using the current
// anchor for the SSRC. It returns the resolved time together with the anchor
// that was used. An error is returned if no clock rate was declared for the
// SSRC, if no Sender Report has been received yet, if the timestamp is
// exactly half a wrap cycle from the anchor (ambiguous direction), or if the
// time computation overflows.
func (m *SenderReportMapper) Map(ssrc uint32, rtp uint32) (time.Time, AnchorInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stream, ok := m.streams[ssrc]
	if !ok {
		return time.Time{}, AnchorInfo{}, errMapperUnknownSSRC
	}
	if !stream.hasAnchor {
		return time.Time{}, AnchorInfo{}, errMapperNoAnchor
	}

	anchor := stream.anchor
	info := AnchorInfo{
		SSRC:                 ssrc,
		NTPTime:              anchor.ntp,
		NTPTimestamp:         anchor.ntpRaw,
		RTPTimestamp:         anchor.rtp,
		ExtendedRTPTimestamp: anchor.extended,
		ClockRate:            stream.clockRate,
	}

	// Signed tick distance from the anchor, nearest cycle.
	delta := int32(rtp - uint32(anchor.extended)) //nolint:gosec // G115: intentional wrap
	if delta == math.MinInt32 {
		// Exactly half a wrap cycle away: the timestamp could be equally
		// far in the past or the future, so no direction can be chosen.
		return time.Time{}, AnchorInfo{}, errMapperAmbiguousRTP
	}

	nanos, ok := scaleTicksToNanos(delta, stream.clockRate)
	if !ok {
		return time.Time{}, AnchorInfo{}, errMapperTimeOverflow
	}

	return anchor.ntp.Add(time.Duration(nanos)), info, nil
}

// scaleTicksToNanos converts a signed RTP tick delta to nanoseconds at the
// given clock rate, reporting overflow instead of wrapping.
func scaleTicksToNanos(delta int32, clockRate uint32) (int64, bool) {
	negative := delta < 0
	magnitude := uint64(-int64(delta))
	if !negative {
		magnitude = uint64(delta)
	}

	hi, lo := bits.Mul64(magnitude, uint64(time.Second))
	if hi != 0 {
		return 0, false
	}

	nanos := int64(lo / uint64(clockRate)) //nolint:gosec // G115: lo < 2^63 after the hi check
	if negative {
		nanos = -nanos
	}

	return nanos, true
}

// ntpToTime converts a 64-bit NTP timestamp (RFC 5905) to a wall clock time.
func ntpToTime(ntp uint64) time.Time {
	secs := ntp >> 32
	frac := ntp & 0xFFFFFFFF
	// nanos = frac * 1e9 / 2^32; frac * 1e9 < 2^62 so this cannot overflow.
	nanos := (frac * uint64(time.Second)) >> 32

	return time.Unix(int64(secs)-ntpUnixEpochOffset, int64(nanos)).UTC() //nolint:gosec // G115
}
