// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testClockRate uint32 = 90000

// observe feeds one packet to the stats with a regular 20 ms send interval,
// so an undisturbed stream has zero jitter.
func observe(t *testing.T, stats *ReceptionStats, ssrc uint32, seq uint16, arrival time.Time) {
	t.Helper()

	rtpTimestamp := uint32(arrival.UnixNano() * int64(testClockRate) / int64(time.Second)) //nolint:gosec // G115 // test timestamps stay well within uint32 range
	require.NoError(t, stats.TrackPacket(ssrc, seq, rtpTimestamp, arrival, testClockRate))
}

func TestReceptionStatsRejectsZeroClockRate(t *testing.T) {
	var stats ReceptionStats

	assert.ErrorIs(t, stats.AddStream(1, 0), errClockRateNotSet)
	assert.ErrorIs(t,
		stats.TrackPacket(1, 0, 0, time.Now(), 0),
		errClockRateNotSet,
	)
}

func TestReceptionStatsUnknownSSRC(t *testing.T) {
	var stats ReceptionStats

	_, err := stats.ReceptionReport(1, time.Now())
	assert.ErrorIs(t, err, errReceptionStatsNoStream)
	assert.ErrorIs(t,
		stats.TrackSenderReport(1, 0, time.Now()),
		errReceptionStatsNoStream,
	)
	assert.Nil(t, stats.ReceptionReports(time.Now()))
}

func TestReceptionStatsSingleStreamNoLoss(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range uint16(10) {
		observe(t, &stats, 5000, i, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	report, err := stats.ReceptionReport(5000, start.Add(200*time.Millisecond))
	require.NoError(t, err)

	assert.Equal(t, uint32(5000), report.SSRC)
	assert.Equal(t, uint8(0), report.FractionLost)
	assert.Equal(t, uint32(0), report.TotalLost)
	assert.Equal(t, uint32(9), report.LastSequenceNumber)
	assert.Equal(t, uint32(0), report.Jitter)
	assert.Equal(t, uint32(0), report.LastSenderReport)
	assert.Equal(t, uint32(0), report.Delay)
}

func TestReceptionStatsSequenceWrap(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Send 65534, 65535, 0, 1, 2 without any loss: wrapping must not look
	// like a burst of lost packets.
	for i, seq := range []uint16{65534, 65535, 0, 1, 2} {
		observe(t, &stats, 7, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	report, err := stats.ReceptionReport(7, start.Add(100*time.Millisecond))
	require.NoError(t, err)

	assert.Equal(t, uint32(0), report.TotalLost)
	assert.Equal(t, uint8(0), report.FractionLost)
	// Extended highest sequence: one cycle plus sequence number 2.
	assert.Equal(t, uint32(65536+2), report.LastSequenceNumber)
}

func TestReceptionStatsLossAcrossWrap(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// 65535 then 2: sequence numbers 0 and 1 are lost in the new cycle.
	for i, seq := range []uint16{65533, 65534, 65535, 2} {
		observe(t, &stats, 7, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	report, err := stats.ReceptionReport(7, start.Add(100*time.Millisecond))
	require.NoError(t, err)

	assert.Equal(t, uint32(2), report.TotalLost)
	assert.Equal(t, uint32(65536+2), report.LastSequenceNumber)
	// 2 lost of 6 expected in the first interval.
	assert.Equal(t, uint8(2*256/6), report.FractionLost)
}

func TestReceptionStatsReorderingLateAndDuplicates(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Arrival order: 0, 1, 2, 4, 3(late), 4(duplicate), 0(duplicate).
	arrivalOrder := []uint16{0, 1, 2, 4, 3, 4, 0}
	for i, seq := range arrivalOrder {
		observe(t, &stats, 9, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	report, err := stats.ReceptionReport(9, start.Add(200*time.Millisecond))
	require.NoError(t, err)

	assert.Equal(t, uint32(0), report.TotalLost)
	assert.Equal(t, uint8(0), report.FractionLost)
	assert.Equal(t, uint32(4), report.LastSequenceNumber)

	// A duplicate arriving after a report does not create loss either.
	observe(t, &stats, 9, 2, start.Add(220*time.Millisecond))
	report, err = stats.ReceptionReport(9, start.Add(240*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), report.TotalLost)
	assert.Equal(t, uint8(0), report.FractionLost)
}

func TestReceptionStatsFractionLostIntervals(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Interval 1: sequences 0..4, with 2 missing (2 and 3).
	for i, seq := range []uint16{0, 1, 4} {
		observe(t, &stats, 11, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	first, err := stats.ReceptionReport(11, start.Add(100*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), first.TotalLost)
	// 2 lost out of 5 expected.
	assert.Equal(t, uint8(2*256/5), first.FractionLost)

	// Interval 2: sequences 5..9 all arrive, so no loss in this interval
	// even though cumulative loss remains 2.
	for i, seq := range []uint16{5, 6, 7, 8, 9} {
		observe(t, &stats, 11, seq, start.Add(time.Duration(4+i)*20*time.Millisecond))
	}

	second, err := stats.ReceptionReport(11, start.Add(200*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), second.TotalLost)
	assert.Equal(t, uint8(0), second.FractionLost)

	// Interval 3: one more gap. Sequence 11 is skipped.
	observe(t, &stats, 11, 10, start.Add(200*time.Millisecond))
	observe(t, &stats, 11, 12, start.Add(240*time.Millisecond))

	third, err := stats.ReceptionReport(11, start.Add(260*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, uint32(3), third.TotalLost)
	// 1 lost out of 3 newly expected (10, 11, 12).
	assert.Equal(t, uint8(1*256/3), third.FractionLost)
}

func TestReceptionStatsLatePacketReducesCumulativeLoss(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, seq := range []uint16{0, 1, 4} {
		observe(t, &stats, 13, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	first, err := stats.ReceptionReport(13, start.Add(100*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), first.TotalLost)

	// The "lost" packets show up late; cumulative loss must drop back to 0.
	observe(t, &stats, 13, 2, start.Add(120*time.Millisecond))
	observe(t, &stats, 13, 3, start.Add(140*time.Millisecond))
	// A new high-water mark makes this a non-empty report interval, so the
	// fraction lost reflects the interval rather than the zero-expected
	// edge case of RFC 3550 appendix A.3.
	observe(t, &stats, 13, 5, start.Add(160*time.Millisecond))

	second, err := stats.ReceptionReport(13, start.Add(180*time.Millisecond))
	require.NoError(t, err)
	// Sequences 0..5 have all been observed, so cumulative loss is back to 0.
	assert.Equal(t, uint32(0), second.TotalLost)
	// Interval expected 1 (sequence 5), interval received 3, hence no loss.
	assert.Equal(t, uint8(0), second.FractionLost)
}

func TestReceptionStatsJitter(t *testing.T) {
	var stats ReceptionStats

	// Use a 1 Hz RTP clock so one timestamp unit equals one second, keeping
	// every value hand-checkable. All packets carry the same RTP timestamp,
	// so the transit difference is driven purely by arrival spacing.
	clockRate := uint32(1)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, stats.TrackPacket(21, 0, 1000, base, clockRate))
	// Arrives 10 s after the reference: transit = 10 - 1000, seeds the
	// estimator without updating jitter.
	require.NoError(t, stats.TrackPacket(21, 1, 1000, base.Add(10*time.Second), clockRate))

	stream := stats.streams[21]
	assert.Equal(t, uint32(0), stream.jitter)

	// One second later: D = 1, J = (1 - 0)/16 = 0 with integer division.
	require.NoError(t, stats.TrackPacket(21, 2, 1000, base.Add(11*time.Second), clockRate))
	assert.Equal(t, uint32(0), stream.jitter)

	// 17 s gap now: D = 17, J = 0 + (17 - 0)/16 = 1.
	require.NoError(t, stats.TrackPacket(21, 3, 1000, base.Add(28*time.Second), clockRate))
	assert.Equal(t, uint32(1), stream.jitter)

	// Another 17 s gap: D = 17 again, J = 1 + (17 - 1)/16 = 2.
	require.NoError(t, stats.TrackPacket(21, 4, 1000, base.Add(45*time.Second), clockRate))
	assert.Equal(t, uint32(2), stream.jitter)

	report, err := stats.ReceptionReport(21, base.Add(46*time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(2), report.Jitter)
}

func TestReceptionStatsJitterShrinkingIntervals(t *testing.T) {
	var stats ReceptionStats

	// 1 Hz clock. RTP timestamps advance 10 units per packet while arrivals
	// only advance 8 s, so transit shrinks on the third packet and D goes
	// negative, exercising the absolute-value branch of the estimator.
	clockRate := uint32(1)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, stats.TrackPacket(23, 0, 0, base, clockRate))
	require.NoError(t, stats.TrackPacket(23, 1, 10, base.Add(8*time.Second), clockRate))
	require.NoError(t, stats.TrackPacket(23, 2, 20, base.Add(16*time.Second), clockRate))

	stream := stats.streams[23]
	// D for the third packet: transit changes from -2 to -4, D = -2, |D| = 2.
	assert.Equal(t, uint32(0), stream.jitter) // 2/16 rounds down, never negative

	report, err := stats.ReceptionReport(23, base.Add(17*time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), report.Jitter)
}

func TestReceptionStatsJitterDuplicateIgnored(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clockRate := uint32(100)

	require.NoError(t, stats.TrackPacket(22, 0, 0, start, clockRate))
	require.NoError(t, stats.TrackPacket(22, 1, 100, start.Add(time.Second), clockRate))
	// A duplicate with a wild arrival time must neither move the estimate
	// nor the distinct packet count.
	require.NoError(t, stats.TrackPacket(22, 1, 100, start.Add(10*time.Second), clockRate))

	stream := stats.streams[22]
	assert.Equal(t, uint32(1), stream.duplicates)
	assert.Equal(t, uint32(2), stream.received)
	// Two distinct packets with perfectly matched spacing give D = 0.
	assert.Equal(t, uint32(0), stream.jitter)
}

func TestReceptionStatsLSRAndDLSR(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observe(t, &stats, 31, 0, start)

	// Before any SR, both fields are zero.
	report, err := stats.ReceptionReport(31, start.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), report.LastSenderReport)
	assert.Equal(t, uint32(0), report.Delay)

	// NTP timestamp 0x1122334455667788: LSR keeps the middle 32 bits.
	const ntpTime uint64 = 0x1122334455667788
	srArrival := start.Add(2 * time.Second)
	require.NoError(t, stats.TrackSenderReport(31, ntpTime, srArrival))

	report, err = stats.ReceptionReport(31, srArrival.Add(500*time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, uint32(0x33445566), report.LastSenderReport)
	// 0.5 s expressed in 1/65536 s units.
	assert.Equal(t, uint32(32768), report.Delay)

	// DLSR keeps growing; LSR stays the same until the next SR.
	report, err = stats.ReceptionReport(31, srArrival.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(0x33445566), report.LastSenderReport)
	assert.Equal(t, uint32(65536), report.Delay)

	// A clock that moves backwards must not produce a huge DLSR value.
	report, err = stats.ReceptionReport(31, srArrival.Add(-time.Second))
	require.NoError(t, err)
	assert.Equal(t, uint32(0), report.Delay)
}

func TestReceptionStatsMultipleSSRCIsolation(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// SSRC 1: clean stream 0..4. SSRC 2: 0, 1, 4 with two losses.
	for i := range uint16(5) {
		observe(t, &stats, 100, i, start.Add(time.Duration(i)*20*time.Millisecond))
	}
	for i, seq := range []uint16{0, 1, 4} {
		observe(t, &stats, 200, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}

	reports := stats.ReceptionReports(start.Add(200 * time.Millisecond))
	require.Len(t, reports, 2)

	// Deterministic ascending SSRC ordering.
	assert.Equal(t, uint32(100), reports[0].SSRC)
	assert.Equal(t, uint32(0), reports[0].TotalLost)
	assert.Equal(t, uint32(4), reports[0].LastSequenceNumber)

	assert.Equal(t, uint32(200), reports[1].SSRC)
	assert.Equal(t, uint32(2), reports[1].TotalLost)
	assert.Equal(t, uint32(4), reports[1].LastSequenceNumber)

	// Removing one SSRC leaves the other untouched.
	stats.RemoveStream(100)
	reports = stats.ReceptionReports(start.Add(220 * time.Millisecond))
	require.Len(t, reports, 1)
	assert.Equal(t, uint32(200), reports[0].SSRC)
	assert.Equal(t, uint32(2), reports[0].TotalLost)
}

func TestReceptionStatsMarshalRoundTrip(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, seq := range []uint16{0, 1, 2, 4} {
		observe(t, &stats, 0xdeadbeef, seq, start.Add(time.Duration(i)*20*time.Millisecond))
	}
	require.NoError(t,
		stats.TrackSenderReport(0xdeadbeef, 0x1122334455667788, start.Add(100*time.Millisecond)))

	block, err := stats.ReceptionReport(0xdeadbeef, start.Add(150*time.Millisecond))
	require.NoError(t, err)

	raw, err := block.Marshal()
	require.NoError(t, err)
	assert.Len(t, raw, receptionReportLength)

	var decoded ReceptionReport
	require.NoError(t, decoded.Unmarshal(raw))
	assert.Equal(t, block, decoded)

	// The generated blocks plug straight into a marshaled receiver report.
	rr := ReceiverReport{SSRC: 4242, Reports: stats.ReceptionReports(start.Add(160 * time.Millisecond))}
	rrRaw, err := rr.Marshal()
	require.NoError(t, err)

	packets, err := Unmarshal(rrRaw)
	require.NoError(t, err)
	decodedRR, ok := packets[0].(*ReceiverReport)
	require.True(t, ok)
	assert.Equal(t, rr.SSRC, decodedRR.SSRC)
	require.Len(t, decodedRR.Reports, 1)
	assert.Equal(t, rr.Reports[0], decodedRR.Reports[0])
}

func TestReceptionStatsLongRunningCounters(t *testing.T) {
	var stats ReceptionStats

	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Simulate roughly 2^32 sequence numbers: enough for the 16 bit counter
	// to wrap many times while the extended counter stays in uint32 range.
	const totalPackets uint32 = (1 << 20) * 3
	arrival := start
	for count := range totalPackets {
		seq := uint16(count) //nolint:gosec // G115 // truncation is the wrap behavior under test
		arrival = arrival.Add(time.Millisecond)
		rtpTimestamp := uint32(arrival.UnixNano() * int64(testClockRate) / int64(time.Second)) //nolint:gosec // G115 // test timestamps stay well within uint32 range
		require.NoError(t, stats.TrackPacket(55, seq, rtpTimestamp, arrival, testClockRate))
	}

	report, err := stats.ReceptionReport(55, arrival.Add(time.Millisecond))
	require.NoError(t, err)

	assert.Equal(t, uint32(0), report.TotalLost)
	assert.Equal(t, uint8(0), report.FractionLost)
	assert.Equal(t, totalPackets-1, report.LastSequenceNumber)

	// The extended sequence number itself survives a 32 bit wrap in the
	// wire field; marshal/unmarshal preserves whatever value it holds.
	raw, err := report.Marshal()
	require.NoError(t, err)
	var decoded ReceptionReport
	require.NoError(t, decoded.Unmarshal(raw))
	assert.Equal(t, report.LastSequenceNumber, decoded.LastSequenceNumber)
}

// FuzzReceptionStatsSequenceInvariants feeds arbitrary sequence number
// sequences through the tracker and checks that wrap, reordering and
// duplicates can never produce a spurious loss larger than the observed
// sequence space, and that report blocks always survive a marshal round trip.
func FuzzReceptionStatsSequenceInvariants(f *testing.F) {
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{0xff, 0x00, 0x01})
	f.Add([]byte{5, 3, 5, 0, 4, 3})

	f.Fuzz(func(t *testing.T, sequenceNumbers []byte) {
		if len(sequenceNumbers) == 0 {
			return
		}

		var stats ReceptionStats

		start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i, b := range sequenceNumbers {
			arrival := start.Add(time.Duration(i) * time.Millisecond)
			require.NoError(t,
				stats.TrackPacket(1, uint16(b), uint32(i), arrival, testClockRate))
		}

		report, err := stats.ReceptionReport(1, start.Add(time.Hour))
		require.NoError(t, err)

		// No sequence space larger than the one observed can be reported lost,
		// and the wire field never exceeds its 24 bit capacity.
		assert.LessOrEqual(t, int64(report.TotalLost), int64(maxTotalLost))
		assert.LessOrEqual(t, int64(report.TotalLost), int64(len(sequenceNumbers))+int64(maxSequenceNumber))
		assert.LessOrEqual(t, int64(report.FractionLost), int64(255))

		raw, err := report.Marshal()
		require.NoError(t, err)
		var decoded ReceptionReport
		require.NoError(t, decoded.Unmarshal(raw))
		assert.Equal(t, report, decoded)
	})
}
