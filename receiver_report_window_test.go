// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testWindowStreamA uint32 = 0x11110001
	testWindowStreamB uint32 = 0x22220002
)

func windowTestBase() time.Time {
	return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
}

// dlsrUnits converts a duration to the 1/65536 second units of a DLSR field.
func dlsrUnits(d time.Duration) uint32 {
	return uint32(d * compactNTPUnitsPerSecond / time.Second) //nolint:gosec // G115 // test values are small
}

func mustObserve(t *testing.T, window *ReceiverReportWindow, block ReceptionReport, at time.Time) ReceiverReportSample {
	t.Helper()

	sample, err := window.Observe(block, at)
	require.NoError(t, err)

	return sample
}

// TestReceiverReportWindowTwoStreams feeds a fixed, interleaved receiver report
// sequence for two sources. It checks the per-window loss delta, loss rate,
// jitter, extended highest sequence number movement, RTT, 24-bit loss counter
// wraparound, 16-bit sequence number wraparound and a source reset, and that
// the state of the two sources never interferes.
func TestReceiverReportWindowTwoStreams(t *testing.T) {
	base := windowTestBase()

	var window ReceiverReportWindow

	steps := []struct {
		at    time.Time
		block ReceptionReport
		want  ReceiverReportSample
	}{
		{
			// Stream A starts just before both the 16-bit sequence number and
			// the 24-bit cumulative loss counter wrap.
			at: base,
			block: ReceptionReport{
				SSRC:               testWindowStreamA,
				TotalLost:          0xFFFFF8,
				LastSequenceNumber: 0x0000FFFE,
				Jitter:             10,
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamA,
				ReceivedAt:                    base,
				First:                         true,
				ExtendedHighestSequenceNumber: 0x0000FFFE,
				CumulativePacketsLost:         -8,
				Jitter:                        10,
			},
		},
		{
			at: base.Add(500 * time.Millisecond),
			block: ReceptionReport{
				SSRC:               testWindowStreamB,
				LastSequenceNumber: 0x00020000,
				Jitter:             7,
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamB,
				ReceivedAt:                    base.Add(500 * time.Millisecond),
				First:                         true,
				ExtendedHighestSequenceNumber: 0x00020000,
				CumulativePacketsLost:         0,
				Jitter:                        7,
			},
		},
		{
			// Both counters wrap: the loss delta is +10 even though the new
			// value is smaller, and the sequence number delta is +16 across
			// the 16-bit boundary. LSR/DLSR describe a 500 ms RTT.
			at: base.Add(time.Second),
			block: ReceptionReport{
				SSRC:               testWindowStreamA,
				TotalLost:          0x000002,
				LastSequenceNumber: 0x0001000E,
				Jitter:             12,
				LastSenderReport:   compactNTP(base),
				Delay:              dlsrUnits(500 * time.Millisecond),
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamA,
				ReceivedAt:                    base.Add(time.Second),
				ExtendedHighestSequenceNumber: 0x0001000E,
				CumulativePacketsLost:         2,
				ExtendedHighestSequenceDelta:  16,
				PacketsLost:                   10,
				LossRate:                      10.0 / 16.0,
				Jitter:                        12,
				RTT:                           500 * time.Millisecond,
				HasRTT:                        true,
			},
		},
		{
			at: base.Add(1500 * time.Millisecond),
			block: ReceptionReport{
				SSRC:               testWindowStreamB,
				TotalLost:          3,
				LastSequenceNumber: 0x00020010,
				Jitter:             9,
				LastSenderReport:   compactNTP(base.Add(time.Second)),
				Delay:              dlsrUnits(250 * time.Millisecond),
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamB,
				ReceivedAt:                    base.Add(1500 * time.Millisecond),
				ExtendedHighestSequenceNumber: 0x00020010,
				CumulativePacketsLost:         3,
				ExtendedHighestSequenceDelta:  16,
				PacketsLost:                   3,
				LossRate:                      3.0 / 16.0,
				Jitter:                        9,
				RTT:                           250 * time.Millisecond,
				HasRTT:                        true,
			},
		},
		{
			// A late packet lowers the cumulative loss by 3: the delta is
			// negative and no loss rate can be derived from it.
			at: base.Add(2 * time.Second),
			block: ReceptionReport{
				SSRC:               testWindowStreamA,
				TotalLost:          0xFFFFFF,
				LastSequenceNumber: 0x0001001E,
				Jitter:             14,
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamA,
				ReceivedAt:                    base.Add(2 * time.Second),
				ExtendedHighestSequenceNumber: 0x0001001E,
				CumulativePacketsLost:         -1,
				ExtendedHighestSequenceDelta:  16,
				PacketsLost:                   -3,
				Jitter:                        14,
			},
		},
		{
			// Stream B restarts its sequence numbering: the block is a new
			// baseline. The cumulative loss it carries is reported, but no
			// delta spans the restart.
			at: base.Add(2500 * time.Millisecond),
			block: ReceptionReport{
				SSRC:               testWindowStreamB,
				TotalLost:          4,
				LastSequenceNumber: 0x00000010,
				Jitter:             11,
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamB,
				ReceivedAt:                    base.Add(2500 * time.Millisecond),
				Reset:                         true,
				ExtendedHighestSequenceNumber: 0x00000010,
				CumulativePacketsLost:         4,
				Jitter:                        11,
			},
		},
		{
			// The 24-bit wrap from -1 recovers a positive delta of 4.
			at: base.Add(3 * time.Second),
			block: ReceptionReport{
				SSRC:               testWindowStreamA,
				TotalLost:          3,
				LastSequenceNumber: 0x0001003E,
				Jitter:             15,
				LastSenderReport:   compactNTP(base.Add(2 * time.Second)),
				Delay:              dlsrUnits(500 * time.Millisecond),
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamA,
				ReceivedAt:                    base.Add(3 * time.Second),
				ExtendedHighestSequenceNumber: 0x0001003E,
				CumulativePacketsLost:         3,
				ExtendedHighestSequenceDelta:  32,
				PacketsLost:                   4,
				LossRate:                      4.0 / 32.0,
				Jitter:                        15,
				RTT:                           500 * time.Millisecond,
				HasRTT:                        true,
			},
		},
		{
			at: base.Add(3500 * time.Millisecond),
			block: ReceptionReport{
				SSRC:               testWindowStreamB,
				TotalLost:          5,
				LastSequenceNumber: 0x00000020,
				Jitter:             13,
			},
			want: ReceiverReportSample{
				SSRC:                          testWindowStreamB,
				ReceivedAt:                    base.Add(3500 * time.Millisecond),
				ExtendedHighestSequenceNumber: 0x00000020,
				CumulativePacketsLost:         5,
				ExtendedHighestSequenceDelta:  16,
				PacketsLost:                   1,
				LossRate:                      1.0 / 16.0,
				Jitter:                        13,
			},
		},
	}

	for i, step := range steps {
		got := mustObserve(t, &window, step.block, step.at)
		assert.Equalf(t, step.want, got, "step %d (SSRC %#x)", i, step.block.SSRC)
	}

	samples := window.Samples()
	require.Len(t, samples, 2)
	assert.Equal(t, steps[len(steps)-2].want, samples[0])
	assert.Equal(t, steps[len(steps)-1].want, samples[1])

	latestA, ok := window.Latest(testWindowStreamA)
	require.True(t, ok)
	assert.Equal(t, steps[len(steps)-2].want, latestA)

	latestB, ok := window.Latest(testWindowStreamB)
	require.True(t, ok)
	assert.Equal(t, steps[len(steps)-1].want, latestB)
}

func TestReceiverReportWindowRTT(t *testing.T) {
	base := windowTestBase()
	const ssrc uint32 = 0xC0FFEE

	// Pick a sender report time whose compact NTP seconds field is just below
	// the 16-bit wrap so that the following arrival crosses it.
	senderSeconds := int64(0)
	for (senderSeconds+ntpEpochOffsetSeconds)&0xFFFF != 0xFFFE {
		senderSeconds++
	}
	senderTime := time.Unix(senderSeconds, 0).UTC()
	wrappedArrival := senderTime.Add(3 * time.Second)

	for _, test := range []struct {
		name      string
		block     ReceptionReport
		at        time.Time
		wantRTT   time.Duration
		wantHasRR bool
	}{
		{
			name:  "no sender report reference",
			block: ReceptionReport{SSRC: ssrc},
			at:    base.Add(time.Second),
		},
		{
			name:  "zero LSR with non-zero DLSR",
			block: ReceptionReport{SSRC: ssrc, Delay: dlsrUnits(time.Second)},
			at:    base.Add(time.Second),
		},
		{
			name: "ordinary",
			block: ReceptionReport{
				SSRC:             ssrc,
				LastSenderReport: compactNTP(base),
				Delay:            dlsrUnits(500 * time.Millisecond),
			},
			at:        base.Add(time.Second),
			wantRTT:   500 * time.Millisecond,
			wantHasRR: true,
		},
		{
			name: "DLSR equals elapsed time",
			block: ReceptionReport{
				SSRC:             ssrc,
				LastSenderReport: compactNTP(base),
				Delay:            dlsrUnits(time.Second),
			},
			at:        base.Add(time.Second),
			wantRTT:   0,
			wantHasRR: true,
		},
		{
			name: "DLSR exceeds elapsed time",
			block: ReceptionReport{
				SSRC:             ssrc,
				LastSenderReport: compactNTP(base),
				Delay:            dlsrUnits(1500 * time.Millisecond),
			},
			at: base.Add(time.Second),
		},
		{
			name: "reception before the sender report",
			block: ReceptionReport{
				SSRC:             ssrc,
				LastSenderReport: compactNTP(base.Add(2 * time.Second)),
			},
			at: base.Add(time.Second),
		},
		{
			name: "compact NTP seconds wrap",
			block: ReceptionReport{
				SSRC:             ssrc,
				LastSenderReport: compactNTP(senderTime),
				Delay:            dlsrUnits(time.Second),
			},
			at:        wrappedArrival,
			wantRTT:   2 * time.Second,
			wantHasRR: true,
		},
	} {
		var window ReceiverReportWindow

		sample := mustObserve(t, &window, test.block, test.at)
		assert.Equalf(t, test.wantHasRR, sample.HasRTT, "HasRTT %q", test.name)
		assert.Equalf(t, test.wantRTT, sample.RTT, "RTT %q", test.name)
	}
}

func TestReceiverReportWindowRejectsInvalidTime(t *testing.T) {
	base := windowTestBase()
	block := ReceptionReport{
		SSRC:               testWindowStreamA,
		TotalLost:          1,
		LastSequenceNumber: 1,
		LastSenderReport:   compactNTP(base),
		Delay:              dlsrUnits(100 * time.Millisecond),
	}

	for _, at := range []time.Time{
		{},
		time.Unix(-ntpEpochOffsetSeconds-1, 0),
	} {
		var window ReceiverReportWindow

		sample, err := window.Observe(block, at)
		assert.ErrorIs(t, err, ErrInvalidReportTime)
		assert.Equal(t, ReceiverReportSample{}, sample)

		_, ok := window.Latest(block.SSRC)
		assert.False(t, ok)
	}

	// The NTP epoch itself is representable.
	var window ReceiverReportWindow

	sample := mustObserve(t, &window, block, time.Unix(-ntpEpochOffsetSeconds, 0))
	assert.True(t, sample.First)
}

func TestReceiverReportWindowStaleAndDuplicate(t *testing.T) {
	base := windowTestBase()
	const ssrc uint32 = 0x1234

	var window ReceiverReportWindow

	first := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          0,
		LastSequenceNumber: 100,
		Jitter:             1,
	}
	firstSample := mustObserve(t, &window, first, base)

	newer := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          1,
		LastSequenceNumber: 101,
		Jitter:             2,
	}
	newerSample := mustObserve(t, &window, newer, base.Add(time.Second))
	assert.Equal(t, int64(1), newerSample.PacketsLost)
	assert.Equal(t, uint32(1), newerSample.ExtendedHighestSequenceDelta)
	assert.Equal(t, 1.0, newerSample.LossRate)
	assert.True(t, firstSample.First)

	// Out of order arrival time: ignored even though the counters are newer.
	outOfOrder := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          2,
		LastSequenceNumber: 102,
		Jitter:             3,
	}
	sample, err := window.Observe(outOfOrder, base.Add(500*time.Millisecond))
	assert.ErrorIs(t, err, ErrStaleReceptionReport)
	assert.Equal(t, ReceiverReportSample{}, sample)

	latest, ok := window.Latest(ssrc)
	require.True(t, ok)
	assert.Equal(t, newerSample, latest)

	// Exact repetition, including the DLSR: a duplicate.
	sample, err = window.Observe(newer, base.Add(2*time.Second))
	assert.ErrorIs(t, err, ErrDuplicateReceptionReport)
	assert.Equal(t, ReceiverReportSample{}, sample)

	latest, ok = window.Latest(ssrc)
	require.True(t, ok)
	assert.Equal(t, newerSample, latest)

	// Same counters but a different DLSR is a new report with an empty window.
	refreshed := newer
	refreshed.Delay = dlsrUnits(250 * time.Millisecond)
	refreshedSample := mustObserve(t, &window, refreshed, base.Add(2*time.Second))
	assert.Equal(t, int64(0), refreshedSample.PacketsLost)
	assert.Equal(t, uint32(0), refreshedSample.ExtendedHighestSequenceDelta)
	assert.Equal(t, 0.0, refreshedSample.LossRate)
	assert.False(t, refreshedSample.First)
	assert.False(t, refreshedSample.Reset)

	// Counters going backwards within a stream are a reset, not an error.
	reset := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          7,
		LastSequenceNumber: 5,
		Jitter:             4,
	}
	resetSample := mustObserve(t, &window, reset, base.Add(3*time.Second))
	assert.True(t, resetSample.Reset)
	assert.Equal(t, int64(7), resetSample.CumulativePacketsLost)
	assert.Equal(t, int64(0), resetSample.PacketsLost)
	assert.Equal(t, uint32(0), resetSample.ExtendedHighestSequenceDelta)
	assert.Equal(t, 0.0, resetSample.LossRate)
}

func TestReceiverReportWindowObserveReceiverReport(t *testing.T) {
	base := windowTestBase()

	blockA := ReceptionReport{
		SSRC:               testWindowStreamA,
		TotalLost:          2,
		LastSequenceNumber: 10,
		Jitter:             5,
	}
	blockB := ReceptionReport{
		SSRC:               testWindowStreamB,
		TotalLost:          1,
		LastSequenceNumber: 20,
		Jitter:             6,
	}

	_, err := (*ReceiverReportWindow)(nil).ObserveReceiverReport(nil, base)
	assert.ErrorIs(t, err, ErrNilReceiverReport)

	var window ReceiverReportWindow

	samples, err := window.ObserveReceiverReport(&ReceiverReport{Reports: []ReceptionReport{blockA, blockB, blockA}}, base)
	require.ErrorIs(t, err, ErrDuplicateReceptionReport)
	require.Len(t, samples, 2)
	assert.True(t, samples[0].First)
	assert.True(t, samples[1].First)
	assert.Equal(t, blockA.SSRC, samples[0].SSRC)
	assert.Equal(t, blockB.SSRC, samples[1].SSRC)

	// Every block rejected: no samples, and one joined error per block.
	var invalid ReceiverReportWindow

	samples, err = invalid.ObserveReceiverReport(
		&ReceiverReport{Reports: []ReceptionReport{blockA, blockB}},
		time.Time{},
	)
	assert.Empty(t, samples)
	assert.ErrorIs(t, err, ErrInvalidReportTime)

	_, ok := invalid.Latest(blockA.SSRC)
	assert.False(t, ok)
}

func TestReceiverReportWindowRemove(t *testing.T) {
	base := windowTestBase()

	window := NewReceiverReportWindow()
	block := ReceptionReport{
		SSRC:               testWindowStreamA,
		TotalLost:          1,
		LastSequenceNumber: 1,
	}

	sample := mustObserve(t, window, block, base)
	assert.True(t, sample.First)

	window.Remove(testWindowStreamA)

	_, ok := window.Latest(testWindowStreamA)
	assert.False(t, ok)
	assert.Empty(t, window.Samples())

	// After removal the source starts over with a fresh baseline.
	sample = mustObserve(t, window, block, base.Add(time.Second))
	assert.True(t, sample.First)
}

// TestReceiverReportWindowFromWire feeds real marshaled receiver reports
// through Unmarshal, so the window is verified against the wire format rather
// than struct literals.
func TestReceiverReportWindowFromWire(t *testing.T) {
	base := windowTestBase()

	reports := []ReceiverReport{
		{
			SSRC: 0x0A0A0A0A,
			Reports: []ReceptionReport{
				{
					SSRC:               testWindowStreamA,
					FractionLost:       0,
					TotalLost:          0,
					LastSequenceNumber: 0x0000FFFF,
					Jitter:             100,
				},
				{
					SSRC:               testWindowStreamB,
					TotalLost:          0,
					LastSequenceNumber: 0x00001000,
					Jitter:             200,
				},
			},
		},
		{
			SSRC: 0x0A0A0A0A,
			Reports: []ReceptionReport{
				{
					SSRC:               testWindowStreamA,
					FractionLost:       64,
					TotalLost:          4,
					LastSequenceNumber: 0x0001000F,
					Jitter:             110,
					LastSenderReport:   compactNTP(base),
					Delay:              dlsrUnits(125 * time.Millisecond),
				},
				{
					SSRC:               testWindowStreamB,
					FractionLost:       0,
					TotalLost:          0,
					LastSequenceNumber: 0x00001010,
					Jitter:             210,
				},
			},
		},
	}

	var window ReceiverReportWindow

	for i, report := range reports {
		data, err := report.Marshal()
		require.NoError(t, err)

		packets, err := Unmarshal(data)
		require.NoError(t, err)
		require.Len(t, packets, 1)

		decoded, ok := packets[0].(*ReceiverReport)
		require.True(t, ok)

		samples, err := window.ObserveReceiverReport(decoded, base.Add(time.Duration(i)*time.Second))
		require.NoError(t, err)
		require.Len(t, samples, 2)

		for _, sample := range samples {
			assert.Equal(t, i == 0, sample.First)
		}
	}

	samples := window.Samples()
	require.Len(t, samples, 2)

	// Stream A crossed the 16-bit sequence number boundary and its sender
	// report reference yields an RTT of 875 ms.
	assert.Equal(t, ReceiverReportSample{
		SSRC:                          testWindowStreamA,
		ReceivedAt:                    base.Add(time.Second),
		ExtendedHighestSequenceNumber: 0x0001000F,
		ExtendedHighestSequenceDelta:  16,
		CumulativePacketsLost:         4,
		PacketsLost:                   4,
		LossRate:                      4.0 / 16.0,
		Jitter:                        110,
		RTT:                           875 * time.Millisecond,
		HasRTT:                        true,
	}, samples[0])

	assert.Equal(t, ReceiverReportSample{
		SSRC:                          testWindowStreamB,
		ReceivedAt:                    base.Add(time.Second),
		ExtendedHighestSequenceNumber: 0x00001010,
		ExtendedHighestSequenceDelta:  16,
		PacketsLost:                   0,
		Jitter:                        210,
	}, samples[1])
}

func TestReceiverReportWindowSameInstantAndLossRate(t *testing.T) {
	base := windowTestBase()
	const ssrc uint32 = 0xBEEF

	var window ReceiverReportWindow

	start := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          0,
		LastSequenceNumber: 1000,
	}
	mustObserve(t, &window, start, base)

	// Blocks read at the same instant are accepted in call order; the second
	// one closes a window.
	first := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          1,
		LastSequenceNumber: 1001,
	}
	second := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          2,
		LastSequenceNumber: 1002,
	}
	sample := mustObserve(t, &window, first, base.Add(time.Second))
	assert.Equal(t, int64(1), sample.PacketsLost)

	sample = mustObserve(t, &window, second, base.Add(time.Second))
	assert.Equal(t, int64(1), sample.PacketsLost)
	assert.Equal(t, uint32(1), sample.ExtendedHighestSequenceDelta)
	assert.Equal(t, 1.0, sample.LossRate)

	// A window in which no new sequence number was received cannot have a loss
	// rate, even when the cumulative loss grew (duplicates of one packet).
	idle := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          5,
		LastSequenceNumber: 1002,
	}
	sample = mustObserve(t, &window, idle, base.Add(2*time.Second))
	assert.Equal(t, int64(3), sample.PacketsLost)
	assert.Equal(t, uint32(0), sample.ExtendedHighestSequenceDelta)
	assert.Equal(t, 0.0, sample.LossRate)

	// A loss delta larger than the number of expected packets is clamped.
	over := ReceptionReport{
		SSRC:               ssrc,
		TotalLost:          105,
		LastSequenceNumber: 1004,
	}
	sample = mustObserve(t, &window, over, base.Add(3*time.Second))
	assert.Equal(t, int64(100), sample.PacketsLost)
	assert.Equal(t, uint32(2), sample.ExtendedHighestSequenceDelta)
	assert.Equal(t, 1.0, sample.LossRate)
}
