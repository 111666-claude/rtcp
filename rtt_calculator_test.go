// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// srAt builds a SenderReport whose NTPTime corresponds exactly to t.
func srAt(ssrc uint32, t time.Time) SenderReport {
	secs := uint64(t.Unix() + ntpEpochOffset)
	frac := uint64(t.Nanosecond()) * (1 << 32) / uint64(time.Second)

	return SenderReport{SSRC: ssrc, NTPTime: secs<<32 | frac}
}

// lsrOf returns the LSR value a peer would echo for sr.
func lsrOf(sr SenderReport) uint32 {
	return uint32(sr.NTPTime >> 16)
}

// fixedPoint converts whole seconds and a 16.16 fraction to 16.16 units.
func fixedPoint(seconds, fraction uint32) uint32 {
	return seconds*65536 + fraction
}

func TestRTTCalculatorSingleStream(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	// Received 1s after the SR; the peer held it for 0.5s (DLSR).
	// RTT = 1s - 0.5s = 500ms.
	sample, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
		Delay:            fixedPoint(0, 32768), // 0.5s
	}, t0.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), sample.SSRC)
	assert.Equal(t, 500*time.Millisecond, sample.RTT)
}

func TestRTTCalculatorSubSecondPrecision(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	// 250ms is an exact number of 16.16 units (16384).
	sr1 := srAt(1000, t0)
	c.RecordSenderReport(sr1, t0)
	sample, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr1),
	}, t0.Add(250*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, 250*time.Millisecond, sample.RTT)

	// 125ms RTT after subtracting a 125ms DLSR from a 250ms elapsed time.
	sr2 := srAt(1000, t0.Add(time.Second))
	c.RecordSenderReport(sr2, t0.Add(time.Second))
	sample, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr2),
		Delay:            fixedPoint(0, 8192), // 125ms
	}, t0.Add(time.Second+250*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, 125*time.Millisecond, sample.RTT)

	// One 16.16 unit is ~15.26us; results truncate to the nearest unit.
	// receivedAt is chosen so its LSR-domain value is exactly 16385 units
	// after the SR, giving floor(16385 * 1e9 / 65536) = 250015258ns.
	sr3 := srAt(1000, t0.Add(2*time.Second))
	c.RecordSenderReport(sr3, t0.Add(2*time.Second))
	sample, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr3),
	}, t0.Add(2*time.Second+250015259*time.Nanosecond))
	require.NoError(t, err)
	assert.Equal(t, 250015258*time.Nanosecond, sample.RTT)
}

func TestRTTCalculatorMultipleStreams(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	srA := srAt(1000, t0)
	srB := srAt(2000, t0.Add(time.Second))
	c.RecordSenderReport(srA, t0)
	c.RecordSenderReport(srB, t0.Add(time.Second))

	// A report for one SSRC must not match the other SSRC's sender report.
	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             2000,
		LastSenderReport: lsrOf(srA),
	}, t0.Add(2*time.Second))
	assert.ErrorIs(t, err, ErrUnknownSenderReport)

	sample, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             2000,
		LastSenderReport: lsrOf(srB),
	}, t0.Add(2*time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(2000), sample.SSRC)
	assert.Equal(t, time.Second, sample.RTT)

	sample, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(srA),
		Delay:            fixedPoint(0, 32768), // 0.5s
	}, t0.Add(2*time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(1000), sample.SSRC)
	assert.Equal(t, 1500*time.Millisecond, sample.RTT)
}

func TestRTTCalculatorWraparound(t *testing.T) {
	c := NewRTTCalculator(nil)

	// Pick a time whose middle-32 NTP value is 0xFFFF0000, so that one
	// second later the value wraps to 0x00000000.
	unix := int64(65535) - int64(ntpEpochOffset%65536) + 65536*40000
	t0 := time.Unix(unix, 0)
	require.Equal(t, uint32(0xFFFF0000), ntpMiddle32FromTime(t0))
	require.Equal(t, uint32(0x00000000), ntpMiddle32FromTime(t0.Add(time.Second)))

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	// Elapsed wraps to 1s; DLSR of 0.25s leaves an RTT of 750ms.
	sample, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
		Delay:            fixedPoint(0, 16384), // 0.25s
	}, t0.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, 750*time.Millisecond, sample.RTT)
}

func TestRTTCalculatorOutOfOrderReports(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr1 := srAt(1000, t0)
	sr2 := srAt(1000, t0.Add(2*time.Second))
	c.RecordSenderReport(sr1, t0)
	c.RecordSenderReport(sr2, t0.Add(2*time.Second))

	// The report for the newer SR arrives first.
	sample, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr2),
	}, t0.Add(3*time.Second))
	require.NoError(t, err)
	assert.Equal(t, time.Second, sample.RTT)

	// A late report for the older SR still matches.
	sample, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr1),
	}, t0.Add(3*time.Second))
	require.NoError(t, err)
	assert.Equal(t, 3*time.Second, sample.RTT)
}

func TestRTTCalculatorZeroLSR(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: 0,
	}, t0.Add(time.Second))
	assert.ErrorIs(t, err, ErrNoSenderReportReference)
}

func TestRTTCalculatorUnknownSenderReport(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	// No sender report recorded at all.
	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: 0x12345678,
	}, t0)
	assert.ErrorIs(t, err, ErrUnknownSenderReport)

	// A recorded sender report with a different LSR does not match.
	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)
	_, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr) + 1,
	}, t0.Add(time.Second))
	assert.ErrorIs(t, err, ErrUnknownSenderReport)
}

func TestRTTCalculatorDuplicateReport(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	report := ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
	}
	_, err := c.ProcessReceptionReport(report, t0.Add(time.Second))
	require.NoError(t, err)

	// The same report again must not produce a second sample.
	_, err = c.ProcessReceptionReport(report, t0.Add(time.Second))
	assert.ErrorIs(t, err, ErrUnknownSenderReport)
}

func TestRTTCalculatorNegativeDelay(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	// DLSR (2s) exceeds the time elapsed since the SR (1s).
	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
		Delay:            fixedPoint(2, 0),
	}, t0.Add(time.Second))
	assert.ErrorIs(t, err, ErrNegativeRTT)
}

func TestRTTCalculatorExcessiveRTT(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	// 20s exceeds the default 10s maximum.
	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
	}, t0.Add(20*time.Second))
	assert.ErrorIs(t, err, ErrExcessiveRTT)

	// A custom maximum is honored.
	c = NewRTTCalculator(&RTTCalculatorConfig{MaxRTT: 500 * time.Millisecond})
	c.RecordSenderReport(sr, t0)
	_, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
	}, t0.Add(time.Second))
	assert.ErrorIs(t, err, ErrExcessiveRTT)
}

func TestRTTCalculatorExpiredSenderReport(t *testing.T) {
	c := NewRTTCalculator(nil)
	t0 := time.Unix(1_700_000_000, 0)

	sr := srAt(1000, t0)
	c.RecordSenderReport(sr, t0)

	// Beyond the default 5 minute sender report age.
	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
	}, t0.Add(10*time.Minute))
	assert.ErrorIs(t, err, ErrUnknownSenderReport)

	// A custom age is honored.
	c = NewRTTCalculator(&RTTCalculatorConfig{MaxSenderReportAge: time.Minute})
	c.RecordSenderReport(sr, t0)
	_, err = c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr),
	}, t0.Add(2*time.Minute))
	assert.ErrorIs(t, err, ErrUnknownSenderReport)
}

func TestRTTCalculatorBoundedHistory(t *testing.T) {
	c := NewRTTCalculator(&RTTCalculatorConfig{MaxHistory: 2})
	t0 := time.Unix(1_700_000_000, 0)

	sr1 := srAt(1000, t0)
	sr2 := srAt(1000, t0.Add(time.Second))
	sr3 := srAt(1000, t0.Add(2*time.Second))
	c.RecordSenderReport(sr1, t0)
	c.RecordSenderReport(sr2, t0.Add(time.Second))
	c.RecordSenderReport(sr3, t0.Add(2*time.Second))

	// The oldest sender report was evicted.
	_, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr1),
	}, t0.Add(3*time.Second))
	assert.ErrorIs(t, err, ErrUnknownSenderReport)

	// The retained ones still match.
	sample, err := c.ProcessReceptionReport(ReceptionReport{
		SSRC:             1000,
		LastSenderReport: lsrOf(sr3),
	}, t0.Add(3*time.Second))
	require.NoError(t, err)
	assert.Equal(t, time.Second, sample.RTT)
}
