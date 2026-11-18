// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The three fixtures below are complete XR packets (RFC 3611) captured from
// the monitoring path. Every fixture carries the 127 "unavailable" sentinel in
// at least one metric, and fixture C also carries values that RFC 3611 says a
// sender must never emit.
//
// Fixture A: one report for each of two participants. Participant 0x11111111
// has no voice-quality estimate at all, participant 0x22222222 has signed
// signal and noise levels.
func voipMetricsFixtureA() []byte {
	return []byte{
		// RTCP header: V=2, P=0, RC=0, PT=XR (207); 20 words.
		0x80, 0xCF, 0x00, 0x13,
		// Sender SSRC.
		0x0A, 0x0B, 0x0C, 0x0D,
		// Participant 0x11111111: every optional quality metric unavailable.
		0x07, 0x00, 0x00, 0x08,
		0x11, 0x11, 0x11, 0x11,
		0x00, 0x00, 0x00, 0x00, // loss, discard, burst, gap densities
		0x00, 0x00, 0x00, 0x00, // burst and gap durations
		0x00, 0x3C, 0x00, 0x14, // RTT 60 ms, end system delay 20 ms
		0x7F, 0x7F, 0x7F, 0x10, // signal -127, noise -127, RERL 127, Gmin 16
		0x7F, 0x7F, 0x7F, 0x7F, // R, ext R, MOS-LQ, MOS-CQ unavailable
		0x00, 0x00, 0x00, 0x28, // RX config 0, reserved 0, JB nominal 40 ms
		0x00, 0x50, 0x00, 0xC8, // JB max 80 ms, JB abs max 200 ms
		// Participant 0x22222222: signed levels and a valid MOS pair.
		0x07, 0x00, 0x00, 0x08,
		0x22, 0x22, 0x22, 0x22,
		0x08, 0x02, 0x0A, 0x01, // loss 8/256, discard 2/256, burst 10/256, gap 1/256
		0x00, 0x14, 0x03, 0xE8, // burst 20 ms, gap 1000 ms
		0x00, 0x4B, 0x00, 0x19, // RTT 75 ms, end system delay 25 ms
		0xF6, 0xDF, 0x2A, 0x10, // signal -10 dB, noise -33 dB, RERL 42 dB, Gmin 16
		0x5E, 0x00, 0x28, 0x1E, // R 94, ext R 0, MOS-LQ 40, MOS-CQ 30
		0xC4, 0x00, 0x00, 0x32, // RX config 0xC4, reserved 0, JB nominal 50 ms
		0x00, 0x64, 0x01, 0x2C, // JB max 100 ms, JB abs max 300 ms
	}
}

// Fixture B: a later capture in which the availability of fields changed and
// the two participants are reported in the opposite order.
func voipMetricsFixtureB() []byte {
	return []byte{
		0x80, 0xCF, 0x00, 0x13,
		0x0A, 0x0B, 0x0C, 0x0D,
		// Participant 0x22222222 first this time.
		0x07, 0x00, 0x00, 0x08,
		0x22, 0x22, 0x22, 0x22,
		0x10, 0x00, 0x00, 0x0F, // loss 16/256, discard 0, burst 0, gap 15/256
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x64, 0x00, 0x1E, // RTT 100 ms, end system delay 30 ms
		0x7F, 0x7F, 0x1E, 0x10, // signal and noise unavailable, RERL 30 dB
		0x50, 0x7F, 0x20, 0x7F, // R 80, ext R unavailable, MOS-LQ 32, MOS-CQ unavailable
		0x84, 0x00, 0x00, 0x3C, // RX config 0x84, reserved 0, JB nominal 60 ms
		0x00, 0x64, 0x00, 0xFA, // JB max 100 ms, JB abs max 250 ms
		// Participant 0x11111111 with a partial estimate this time.
		0x07, 0x00, 0x00, 0x08,
		0x11, 0x11, 0x11, 0x11,
		0x04, 0x01, 0x00, 0x00, // loss 4/256, discard 1/256
		0x00, 0x00, 0x00, 0x00,
		0x00, 0xC8, 0x00, 0x19, // RTT 200 ms, end system delay 25 ms
		0xE2, 0x7F, 0x7F, 0x10, // signal -30 dB, noise and RERL unavailable
		0x60, 0x40, 0x2D, 0x28, // R 96, ext R 64, MOS-LQ 45, MOS-CQ 40
		0xC0, 0x00, 0x00, 0x2D, // RX config 0xC0, reserved 0, JB nominal 45 ms
		0x00, 0x5A, 0x01, 0x2C, // JB max 90 ms, JB abs max 300 ms
	}
}

// Fixture C: a malformed capture. The first block has no source SSRC and the
// second one reports an R factor of 101, which is neither a valid 0 to 100
// value nor the 127 sentinel.
func voipMetricsFixtureC() []byte {
	return []byte{
		0x80, 0xCF, 0x00, 0x13,
		0x0A, 0x0B, 0x0C, 0x0D,
		// Missing SSRC of source.
		0x07, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x7F, 0x7F, 0x7F, 0x10,
		0x7F, 0x7F, 0x7F, 0x7F,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		// Participant 0x22222222 with an out of range R factor (101).
		0x07, 0x00, 0x00, 0x08,
		0x22, 0x22, 0x22, 0x22,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x7F, 0x7F, 0x7F, 0x10,
		0x65, 0x7F, 0x7F, 0x7F,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

func decodeVoIPMetricsFixture(t *testing.T, raw []byte) *ExtendedReport {
	t.Helper()

	packets, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Len(t, packets, 1)

	report, ok := packets[0].(*ExtendedReport)
	require.True(t, ok)

	return report
}

func TestVoIPMetricsFixturesDecodeAndRoundTrip(t *testing.T) {
	fixtures := map[string][]byte{
		"A": voipMetricsFixtureA(),
		"B": voipMetricsFixtureB(),
		"C": voipMetricsFixtureC(),
	}

	for name, raw := range fixtures {
		t.Run(name, func(t *testing.T) {
			report := decodeVoIPMetricsFixture(t, raw)
			assert.Equal(t, uint32(0x0A0B0C0D), report.SenderSSRC)
			require.Len(t, report.Reports, 2)

			for _, block := range report.Reports {
				_, ok := block.(*VoIPMetricsReportBlock)
				require.True(t, ok)
			}

			// The codec is unchanged by the timeline: fixtures decode and
			// re-encode byte for byte, even when they carry sentinel values.
			marshaled, err := report.Marshal()
			require.NoError(t, err)
			assert.Equal(t, raw, marshaled)
		})
	}
}

func TestVoIPMetricsSampleUnitsAndSentinels(t *testing.T) {
	report := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())
	blockA, ok := report.Reports[0].(*VoIPMetricsReportBlock)
	require.True(t, ok)
	blockB, ok := report.Reports[1].(*VoIPMetricsReportBlock)
	require.True(t, ok)

	captured := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	sampleA, err := NewVoIPMetricsSample(blockA, captured)
	require.NoError(t, err)

	assert.Equal(t, uint32(0x11111111), sampleA.SSRC)
	assert.Equal(t, captured, sampleA.Captured)

	// The 8 bit densities are fractions with the binary point at the left
	// edge, not percentages.
	assert.InDelta(t, 0.0, sampleA.LossRate, 1e-12)
	// Millisecond wire fields become durations.
	assert.Equal(t, 60*time.Millisecond, sampleA.RoundTripDelay)
	assert.Equal(t, 20*time.Millisecond, sampleA.EndSystemDelay)
	assert.Equal(t, 40*time.Millisecond, sampleA.JBNominal)
	assert.Equal(t, 80*time.Millisecond, sampleA.JBMaximum)
	assert.Equal(t, 200*time.Millisecond, sampleA.JBAbsMax)
	assert.Equal(t, uint8(16), sampleA.Gmin)
	assert.Equal(t, uint8(0x00), sampleA.RXConfig)

	// Every 127 sentinel is an unavailable estimate, not a measurement.
	assert.Nil(t, sampleA.SignalLevel)
	assert.Nil(t, sampleA.NoiseLevel)
	assert.Nil(t, sampleA.RERL)
	assert.Nil(t, sampleA.RFactor)
	assert.Nil(t, sampleA.ExtRFactor)
	assert.Nil(t, sampleA.MOSLQ)
	assert.Nil(t, sampleA.MOSCQ)

	sampleB, err := NewVoIPMetricsSample(blockB, captured)
	require.NoError(t, err)

	assert.InDelta(t, 8.0/256.0, sampleB.LossRate, 1e-12)
	assert.InDelta(t, 2.0/256.0, sampleB.DiscardRate, 1e-12)
	assert.InDelta(t, 10.0/256.0, sampleB.BurstDensity, 1e-12)
	assert.InDelta(t, 1.0/256.0, sampleB.GapDensity, 1e-12)
	assert.Equal(t, 20*time.Millisecond, sampleB.BurstDuration)
	assert.Equal(t, 1000*time.Millisecond, sampleB.GapDuration)
	assert.Equal(t, 75*time.Millisecond, sampleB.RoundTripDelay)

	// Signal and noise levels are signed dBm0 values.
	require.NotNil(t, sampleB.SignalLevel)
	assert.Equal(t, int8(-10), *sampleB.SignalLevel)
	require.NotNil(t, sampleB.NoiseLevel)
	assert.Equal(t, int8(-33), *sampleB.NoiseLevel)
	require.NotNil(t, sampleB.RERL)
	assert.Equal(t, uint8(42), *sampleB.RERL)

	// R factors stay integers in 0 to 100; zero is a real value, not absence.
	require.NotNil(t, sampleB.RFactor)
	assert.Equal(t, uint8(94), *sampleB.RFactor)
	require.NotNil(t, sampleB.ExtRFactor)
	assert.Equal(t, uint8(0), *sampleB.ExtRFactor)

	// MOS is encoded as MOS * 10 on the wire.
	require.NotNil(t, sampleB.MOSLQ)
	assert.InDelta(t, 4.0, *sampleB.MOSLQ, 1e-12)
	require.NotNil(t, sampleB.MOSCQ)
	assert.InDelta(t, 3.0, *sampleB.MOSCQ, 1e-12)

	assert.Equal(t, uint8(0xC4), sampleB.RXConfig)
	assert.Equal(t, 50*time.Millisecond, sampleB.JBNominal)
	assert.Equal(t, 100*time.Millisecond, sampleB.JBMaximum)
	assert.Equal(t, 300*time.Millisecond, sampleB.JBAbsMax)
}

func TestVoIPMetricsSampleRejectsInvalidBlocks(t *testing.T) {
	captured := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	valid := VoIPMetricsReportBlock{SSRC: 7, Gmin: 16}

	_, err := NewVoIPMetricsSample(nil, captured)
	assert.ErrorIs(t, err, errVoIPMetricsNilBlock)

	missingSSRC := valid
	missingSSRC.SSRC = 0
	_, err = NewVoIPMetricsSample(&missingSSRC, captured)
	assert.ErrorIs(t, err, errVoIPMetricsMissingSSRC)

	zeroGmin := valid
	zeroGmin.Gmin = 0
	_, err = NewVoIPMetricsSample(&zeroGmin, captured)
	assert.ErrorIs(t, err, errVoIPMetricsInvalidMetric)

	// 101 is neither a valid R factor nor the 127 sentinel.
	outOfRangeR := valid
	outOfRangeR.RFactor = 101
	_, err = NewVoIPMetricsSample(&outOfRangeR, captured)
	assert.ErrorIs(t, err, errVoIPMetricsInvalidMetric)

	outOfRangeExtR := valid
	outOfRangeExtR.ExtRFactor = 126
	_, err = NewVoIPMetricsSample(&outOfRangeExtR, captured)
	assert.ErrorIs(t, err, errVoIPMetricsInvalidMetric)

	// MOS must be 10 to 50 on the wire, or 127.
	outOfRangeMOSLQ := valid
	outOfRangeMOSLQ.MOSLQ = 51
	_, err = NewVoIPMetricsSample(&outOfRangeMOSLQ, captured)
	assert.ErrorIs(t, err, errVoIPMetricsInvalidMetric)

	outOfRangeMOSCQ := valid
	outOfRangeMOSCQ.MOSCQ = 9
	_, err = NewVoIPMetricsSample(&outOfRangeMOSCQ, captured)
	assert.ErrorIs(t, err, errVoIPMetricsInvalidMetric)
}

func TestVoIPMetricsTimelineTwoStreamsOutOfOrder(t *testing.T) {
	timeline, err := NewVoIPMetricsTimeline()
	require.NoError(t, err)

	first := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	second := first.Add(5 * time.Second)

	// Ingest the later capture first: queries must still be ordered by
	// capture time, not by arrival order.
	reportB := decodeVoIPMetricsFixture(t, voipMetricsFixtureB())
	stored, err := timeline.IngestExtendedReport(reportB, second)
	require.NoError(t, err)
	assert.Equal(t, 2, stored)

	reportA := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())
	stored, err = timeline.IngestExtendedReport(reportA, first)
	require.NoError(t, err)
	assert.Equal(t, 2, stored)

	assert.Equal(t, []uint32{0x11111111, 0x22222222}, timeline.Participants())
	assert.Equal(t, 2, timeline.Len(0x11111111))
	assert.Equal(t, 2, timeline.Len(0x22222222))

	window, err := timeline.Window(0x11111111, first, second)
	require.NoError(t, err)
	require.Len(t, window.Samples, 2)
	assert.Equal(t, first, window.Samples[0].Captured)
	assert.Equal(t, second, window.Samples[1].Captured)
	// Availability changes between the two captures.
	assert.Nil(t, window.Samples[0].SignalLevel)
	require.NotNil(t, window.Samples[1].SignalLevel)
	assert.Equal(t, int8(-30), *window.Samples[1].SignalLevel)
	assert.Nil(t, window.Samples[1].NoiseLevel)
	assert.InDelta(t, 4.0/256.0, window.Samples[1].LossRate, 1e-12)

	window, err = timeline.Window(0x22222222, first, second)
	require.NoError(t, err)
	require.Len(t, window.Samples, 2)
	assert.Equal(t, 8.0/256.0, window.Samples[0].LossRate)
	assert.Equal(t, 75*time.Millisecond, window.Samples[0].RoundTripDelay)
	require.NotNil(t, window.Samples[0].MOSCQ)
	assert.InDelta(t, 3.0, *window.Samples[0].MOSCQ, 1e-12)
	assert.Equal(t, 16.0/256.0, window.Samples[1].LossRate)
	require.NotNil(t, window.Samples[1].MOSLQ)
	assert.InDelta(t, 3.2, *window.Samples[1].MOSLQ, 1e-12)
	assert.Nil(t, window.Samples[1].MOSCQ)

	latest, err := timeline.Latest(0x22222222)
	require.NoError(t, err)
	assert.Equal(t, second, latest.Captured)

	// Window bounds are inclusive.
	window, err = timeline.Window(0x11111111, second, second)
	require.NoError(t, err)
	require.Len(t, window.Samples, 1)
	assert.Equal(t, second, window.Samples[0].Captured)
}

func TestVoIPMetricsTimelineWindowOutcomes(t *testing.T) {
	timeline, err := NewVoIPMetricsTimeline()
	require.NoError(t, err)

	first := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	second := first.Add(5 * time.Second)

	reportA := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())
	stored, err := timeline.IngestExtendedReport(reportA, first)
	require.NoError(t, err)
	assert.Equal(t, 2, stored)

	// A capture clock that moves backwards cannot describe a window.
	_, err = timeline.Window(0x11111111, second, first)
	assert.ErrorIs(t, err, errVoIPMetricsBackwardWindow)

	// A known participant with nothing in the requested range.
	_, err = timeline.Window(0x11111111, second, second)
	assert.ErrorIs(t, err, errVoIPMetricsEmptyWindow)

	// A participant that was never reported.
	_, err = timeline.Window(0x33333333, first, second)
	assert.ErrorIs(t, err, errVoIPMetricsUnknownSSRC)
	_, err = timeline.Latest(0x33333333)
	assert.ErrorIs(t, err, errVoIPMetricsUnknownSSRC)
	assert.Equal(t, 0, timeline.Len(0x33333333))
	assert.Zero(t, timeline.Evicted(0x33333333))
}

func TestVoIPMetricsTimelineRejectsInvalidReports(t *testing.T) {
	timeline, err := NewVoIPMetricsTimeline()
	require.NoError(t, err)

	captured := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	reportC := decodeVoIPMetricsFixture(t, voipMetricsFixtureC())

	// The first block has no SSRC, so nothing is stored.
	stored, err := timeline.IngestExtendedReport(reportC, captured)
	assert.ErrorIs(t, err, errVoIPMetricsMissingSSRC)
	assert.Zero(t, stored)
	assert.Empty(t, timeline.Participants())

	// The second block parses, but its out of range R factor is rejected.
	blockC, ok := reportC.Reports[1].(*VoIPMetricsReportBlock)
	require.True(t, ok)
	retained, err := timeline.Ingest(blockC, captured)
	assert.ErrorIs(t, err, errVoIPMetricsInvalidMetric)
	assert.False(t, retained)

	_, err = timeline.IngestExtendedReport(nil, captured)
	assert.ErrorIs(t, err, errVoIPMetricsNilReport)
}

func TestVoIPMetricsTimelineDeduplicatesRepeatedReports(t *testing.T) {
	timeline, err := NewVoIPMetricsTimeline()
	require.NoError(t, err)

	captured := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	report := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())

	stored, err := timeline.IngestExtendedReport(report, captured)
	require.NoError(t, err)
	assert.Equal(t, 2, stored)

	// The same XR arriving twice at the same capture time is one point.
	stored, err = timeline.IngestExtendedReport(report, captured)
	require.NoError(t, err)
	assert.Zero(t, stored)
	assert.Equal(t, 1, timeline.Len(0x11111111))

	// Ingesting the same capture time through a single block is a duplicate
	// as well.
	block, ok := report.Reports[0].(*VoIPMetricsReportBlock)
	require.True(t, ok)
	retained, err := timeline.Ingest(block, captured)
	require.NoError(t, err)
	assert.False(t, retained)

	window, err := timeline.Window(0x11111111, captured, captured)
	require.NoError(t, err)
	assert.Len(t, window.Samples, 1)
}

func TestVoIPMetricsTimelineBoundedHistory(t *testing.T) {
	const capacity = 3

	timeline, err := NewVoIPMetricsTimeline(WithVoIPMetricsMaxSamples(capacity))
	require.NoError(t, err)

	report := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())
	block, ok := report.Reports[0].(*VoIPMetricsReportBlock)
	require.True(t, ok)

	start := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	for index := range 5 {
		captured := start.Add(time.Duration(index) * time.Second)
		retained, ingestErr := timeline.Ingest(block, captured)
		require.NoError(t, ingestErr)
		assert.True(t, retained)
	}

	// Only the newest `capacity` samples survive.
	assert.Equal(t, capacity, timeline.Len(0x11111111))
	assert.Equal(t, uint64(2), timeline.Evicted(0x11111111))

	window, err := timeline.Window(0x11111111, start, start.Add(10*time.Second))
	require.NoError(t, err)
	require.Len(t, window.Samples, capacity)
	assert.Equal(t, start.Add(2*time.Second), window.Samples[0].Captured)
	assert.Equal(t, start.Add(4*time.Second), window.Samples[2].Captured)

	// A late report older than everything retained is evicted immediately.
	retained, err := timeline.Ingest(block, start.Add(500*time.Millisecond))
	require.NoError(t, err)
	assert.False(t, retained)
	assert.Equal(t, capacity, timeline.Len(0x11111111))
	assert.Equal(t, uint64(3), timeline.Evicted(0x11111111))
}

func TestVoIPMetricsTimelineParticipantLimit(t *testing.T) {
	timeline, err := NewVoIPMetricsTimeline(WithVoIPMetricsMaxSSRCs(1))
	require.NoError(t, err)

	report := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())
	captured := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

	first, ok := report.Reports[0].(*VoIPMetricsReportBlock)
	require.True(t, ok)
	second, ok := report.Reports[1].(*VoIPMetricsReportBlock)
	require.True(t, ok)

	retained, err := timeline.Ingest(first, captured)
	require.NoError(t, err)
	assert.True(t, retained)

	retained, err = timeline.Ingest(second, captured)
	assert.ErrorIs(t, err, errVoIPMetricsTooManySSRCs)
	assert.False(t, retained)

	// Freeing the slot lets the second participant in.
	timeline.Remove(first.SSRC)
	retained, err = timeline.Ingest(second, captured)
	require.NoError(t, err)
	assert.True(t, retained)
	assert.Equal(t, []uint32{second.SSRC}, timeline.Participants())
}

func TestVoIPMetricsTimelineRequiresPositiveCapacity(t *testing.T) {
	_, err := NewVoIPMetricsTimeline(WithVoIPMetricsMaxSamples(0))
	assert.ErrorIs(t, err, errVoIPMetricsCapacity)

	_, err = NewVoIPMetricsTimeline(WithVoIPMetricsMaxSSRCs(-1))
	assert.ErrorIs(t, err, errVoIPMetricsCapacity)
}

func TestVoIPMetricsTimelineReturnsCopies(t *testing.T) {
	timeline, err := NewVoIPMetricsTimeline()
	require.NoError(t, err)

	report := decodeVoIPMetricsFixture(t, voipMetricsFixtureA())
	block, ok := report.Reports[1].(*VoIPMetricsReportBlock)
	require.True(t, ok)
	captured := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)

	_, err = timeline.Ingest(block, captured)
	require.NoError(t, err)

	window, err := timeline.Window(block.SSRC, captured, captured)
	require.NoError(t, err)
	require.Len(t, window.Samples, 1)
	require.NotNil(t, window.Samples[0].SignalLevel)

	// Mutating a returned sample must not corrupt the stored history.
	*window.Samples[0].SignalLevel = 0
	latest, err := timeline.Latest(block.SSRC)
	require.NoError(t, err)
	require.NotNil(t, latest.SignalLevel)
	assert.Equal(t, int8(-10), *latest.SignalLevel)
}
