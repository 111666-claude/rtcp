// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"sync"
	"time"
)

// ntpEpochOffset is the number of seconds between the NTP epoch (1900) and
// the Unix epoch (1970).
const ntpEpochOffset = 2208988800

var (
	// ErrNoSenderReportReference is returned when a reception report has a
	// zero LSR, meaning the reporting peer has not received a sender report
	// yet. The report carries no RTT information and is ignored.
	ErrNoSenderReportReference = errors.New("rtcp: reception report has zero LSR")

	// ErrUnknownSenderReport is returned when no recorded sender report
	// matches the report's LSR: the sender report is unknown, has expired,
	// was evicted from the bounded history, or was already consumed by an
	// earlier (duplicate) report.
	ErrUnknownSenderReport = errors.New("rtcp: no recorded sender report matches LSR")

	// ErrNegativeRTT is returned when DLSR exceeds the time elapsed since the
	// referenced sender report, which would produce a negative RTT.
	ErrNegativeRTT = errors.New("rtcp: DLSR exceeds time since sender report")

	// ErrExcessiveRTT is returned when the computed RTT exceeds the
	// configured maximum, indicating a stale or corrupt report rather than a
	// genuine measurement.
	ErrExcessiveRTT = errors.New("rtcp: computed RTT exceeds maximum")
)

// RTTSample is a single round-trip time measurement derived from a
// reception report.
type RTTSample struct {
	// SSRC is the synchronization source the measurement belongs to: the
	// sender of the referenced sender report.
	SSRC uint32
	// RTT is the measured round-trip time.
	RTT time.Duration
}

// RTTCalculatorConfig configures an RTTCalculator. A zero field selects the
// documented default.
type RTTCalculatorConfig struct {
	// MaxHistory is the maximum number of sender reports retained per SSRC;
	// older sender reports are evicted. Default: 16.
	MaxHistory int
	// MaxSenderReportAge is the maximum age of a sender report for it to be
	// eligible for matching. Default: 5 minutes.
	MaxSenderReportAge time.Duration
	// MaxRTT is the largest RTT sample accepted; larger results are rejected
	// with ErrExcessiveRTT. Default: 10 seconds.
	MaxRTT time.Duration
}

const (
	defaultRTTMaxHistory         = 16
	defaultRTTMaxSenderReportAge = 5 * time.Minute
	defaultRTTMaxRTT             = 10 * time.Second
)

// senderReportRecord is a recorded outbound sender report.
type senderReportRecord struct {
	// lsr is the middle 32 bits of the report's NTP timestamp, the value a
	// peer echoes back in the LSR field of a reception report.
	lsr uint32
	// sentAt is the local time the report was sent.
	sentAt time.Time
}

// RTTCalculator computes round-trip time samples from incoming reception
// reports (RFC 3550 §6.4.1) by correlating them with previously sent sender
// reports. State is kept independently per sender SSRC. It is safe for
// concurrent use.
type RTTCalculator struct {
	mu                 sync.Mutex
	records            map[uint32][]senderReportRecord
	maxHistory         int
	maxSenderReportAge time.Duration
	maxRTT             time.Duration
}

// NewRTTCalculator returns an RTTCalculator. A nil config selects the
// defaults documented on RTTCalculatorConfig.
func NewRTTCalculator(config *RTTCalculatorConfig) *RTTCalculator {
	c := &RTTCalculator{
		records:            make(map[uint32][]senderReportRecord),
		maxHistory:         defaultRTTMaxHistory,
		maxSenderReportAge: defaultRTTMaxSenderReportAge,
		maxRTT:             defaultRTTMaxRTT,
	}
	if config == nil {
		return c
	}
	if config.MaxHistory > 0 {
		c.maxHistory = config.MaxHistory
	}
	if config.MaxSenderReportAge > 0 {
		c.maxSenderReportAge = config.MaxSenderReportAge
	}
	if config.MaxRTT > 0 {
		c.maxRTT = config.MaxRTT
	}

	return c
}

// RecordSenderReport records an outbound sender report sent at sentAt so
// that later reception reports referencing it can be matched. The caller
// supplies sentAt, keeping the calculator deterministic and testable.
func (c *RTTCalculator) RecordSenderReport(sr SenderReport, sentAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.prune(sr.SSRC, sentAt)
	records := append(c.records[sr.SSRC], senderReportRecord{
		lsr:    ntpMiddle32(sr.NTPTime),
		sentAt: sentAt,
	})
	if len(records) > c.maxHistory {
		records = records[len(records)-c.maxHistory:]
	}
	c.records[sr.SSRC] = records
}

// ProcessReceptionReport examines one reception report (from a Receiver
// Report or from the report blocks of a Sender Report) received at
// receivedAt. If the report references a recorded sender report, it returns
// the RTT sample A−LSR−DLSR computed in the 16.16 fixed-point seconds
// timebase, and consumes the sender report so a duplicate report cannot
// yield a second sample. Reports that carry no usable information are
// rejected with one of the exported errors and produce no sample.
func (c *RTTCalculator) ProcessReceptionReport(report ReceptionReport, receivedAt time.Time) (RTTSample, error) {
	if report.LastSenderReport == 0 {
		return RTTSample{}, ErrNoSenderReportReference
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.prune(report.SSRC, receivedAt)
	records := c.records[report.SSRC]
	match := -1
	for i := range records {
		if records[i].lsr == report.LastSenderReport {
			match = i // keep scanning: match the most recent record
		}
	}
	if match < 0 {
		return RTTSample{}, ErrUnknownSenderReport
	}
	record := records[match]

	// All arithmetic is mod 2^32 in the 16.16 fixed-point seconds timebase,
	// so a wrap of the middle-32 NTP value between the sender report and the
	// reception report is handled naturally.
	elapsed := ntpMiddle32FromTime(receivedAt) - record.lsr
	if uint64(report.Delay) > uint64(elapsed) {
		return RTTSample{}, ErrNegativeRTT
	}
	rtt := elapsed - report.Delay
	if uint64(rtt) > c.maxRTTUnits() {
		return RTTSample{}, ErrExcessiveRTT
	}

	// Consume the record only on success so that a duplicate report fails
	// with ErrUnknownSenderReport instead of producing a bogus sample.
	c.records[report.SSRC] = append(records[:match], records[match+1:]...)

	return RTTSample{
		SSRC: report.SSRC,
		RTT:  fixedPointToDuration(rtt),
	}, nil
}

// prune drops records for ssrc older than the configured maximum age,
// relative to the caller-supplied time now.
func (c *RTTCalculator) prune(ssrc uint32, now time.Time) {
	records := c.records[ssrc]
	kept := records[:0]
	for _, r := range records {
		if now.Sub(r.sentAt) <= c.maxSenderReportAge {
			kept = append(kept, r)
		}
	}
	c.records[ssrc] = kept
}

// maxRTTUnits returns the configured maximum RTT in 16.16 fixed-point
// seconds units.
func (c *RTTCalculator) maxRTTUnits() uint64 {
	return uint64(c.maxRTT) * 65536 / uint64(time.Second)
}

// ntpMiddle32 returns the middle 32 bits of a 64-bit NTP timestamp: the
// 16.16 fixed-point seconds value echoed in the LSR field.
func ntpMiddle32(ntp uint64) uint32 {
	return uint32(ntp >> 16) //nolint:gosec // G115: intentional truncation to the middle 32 bits
}

// ntpMiddle32FromTime converts t to the middle 32 bits of its NTP
// timestamp.
func ntpMiddle32FromTime(t time.Time) uint32 {
	secs := uint64(t.Unix() + ntpEpochOffset)                        //nolint:gosec // G115: valid for representable times
	frac := uint64(t.Nanosecond()) * (1 << 32) / uint64(time.Second) //nolint:gosec // G115: Nanosecond is in [0, 1e9)

	return ntpMiddle32(secs<<32 | frac)
}

// fixedPointToDuration converts a 16.16 fixed-point seconds value to a
// time.Duration.
func fixedPointToDuration(fixed uint32) time.Duration {
	return time.Duration(uint64(fixed) * uint64(time.Second) / 65536) //nolint:gosec // G115: result fits for accepted RTT values
}
