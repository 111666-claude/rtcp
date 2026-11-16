// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeNTP builds a 64-bit NTP timestamp from whole seconds since the Unix
// epoch plus a fractional part in nanoseconds.
func makeNTP(unixSecs int64, nanos int64) uint64 {
	secs := uint64(unixSecs + ntpUnixEpochOffset) //nolint:gosec // G115: test values are positive
	frac := (uint64(nanos) << 32) / uint64(time.Second)

	return secs<<32 | frac
}

func TestSenderReportMapperKnownPair(t *testing.T) {
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(1111, 90000))

	ntp := makeNTP(1700000000, 500000000) // 1700000000.5 unix
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    1111,
		NTPTime: ntp,
		RTPTime: 100000,
	}))

	// The anchor itself resolves to its own NTP time.
	got, info, err := mapper.Map(1111, 100000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000000, 500000000).UTC(), got)
	assert.Equal(t, uint32(1111), info.SSRC)
	assert.Equal(t, uint32(100000), info.RTPTimestamp)
	assert.Equal(t, uint64(100000), info.ExtendedRTPTimestamp)
	assert.Equal(t, ntp, info.NTPTimestamp)
	assert.Equal(t, uint32(90000), info.ClockRate)
	assert.Equal(t, time.Unix(1700000000, 500000000).UTC(), info.NTPTime)

	// One second of media later.
	got, _, err = mapper.Map(1111, 100000+90000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000001, 500000000).UTC(), got)

	// Half a second of media before the anchor.
	got, _, err = mapper.Map(1111, 100000-45000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000000, 0).UTC(), got)

	// Sub-tick precision: 1 tick at 90 kHz is 11111 ns (truncated).
	got, _, err = mapper.Map(1111, 100000+1)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000000, 500000000+11111).UTC(), got)
}

func TestSenderReportMapperWraparound(t *testing.T) {
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(2222, 90000))

	// Anchor 16 ticks before the 32-bit wrap.
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    2222,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 0xFFFFFFF0,
	}))

	// 32 ticks after the anchor crosses the wrap boundary.
	want := time.Unix(1700000000, 0).UTC().Add(32 * time.Second / 90000)
	got, _, err := mapper.Map(2222, 0x10)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// A Sender Report sent after the wrap, 90 ticks (1 ms) of media later,
	// extends the anchor's cycle.
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    2222,
		NTPTime: makeNTP(1700000000, 1000000),
		RTPTime: 0x4A, // 0xFFFFFFF0 + 90 mod 2^32
	}))

	// Mapping stays continuous across the anchor update.
	got, info, err := mapper.Map(2222, 0x10)
	require.NoError(t, err)
	assert.WithinDuration(t, want, got, time.Microsecond)
	assert.Equal(t, uint64(0x10000004A), info.ExtendedRTPTimestamp)

	// The new anchor resolves to its own NTP time (within NTP precision).
	got, _, err = mapper.Map(2222, 0x4A)
	require.NoError(t, err)
	assert.WithinDuration(t, time.Unix(1700000000, 1000000).UTC(), got, time.Microsecond)
}

func TestSenderReportMapperDualStream(t *testing.T) {
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(100, 90000)) // video
	require.NoError(t, mapper.SetClockRate(200, 48000)) // audio

	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    100,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 900000,
	}))
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    200,
		NTPTime: makeNTP(1700000010, 0),
		RTPTime: 480000,
	}))

	// Each stream resolves against its own anchor and clock rate.
	video, infoV, err := mapper.Map(100, 900000+90000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000001, 0).UTC(), video)
	assert.Equal(t, uint32(90000), infoV.ClockRate)

	audio, infoA, err := mapper.Map(200, 480000+48000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000011, 0).UTC(), audio)
	assert.Equal(t, uint32(48000), infoA.ClockRate)

	// A new report on one stream must not disturb the other.
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    100,
		NTPTime: makeNTP(1700000100, 0),
		RTPTime: 900000 + 100*90000,
	}))
	audio, _, err = mapper.Map(200, 480000+48000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000011, 0).UTC(), audio)
}

func TestSenderReportMapperOutOfOrderReport(t *testing.T) {
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(3333, 90000))

	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    3333,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 500000,
	}))
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    3333,
		NTPTime: makeNTP(1700000010, 0),
		RTPTime: 500000 + 10*90000,
	}))

	// A stale report (small backward jump) is ignored.
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    3333,
		NTPTime: makeNTP(1700000005, 0),
		RTPTime: 500000 + 5*90000,
	}))

	got, info, err := mapper.Map(3333, 500000+10*90000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000010, 0).UTC(), got)
	assert.Equal(t, uint32(500000+10*90000), info.RTPTimestamp)
}

func TestSenderReportMapperReset(t *testing.T) {
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(4444, 90000))

	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    4444,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 0x80000000,
	}))

	// A backward jump far beyond reordering is a source reset: the report
	// becomes the new anchor.
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    4444,
		NTPTime: makeNTP(1700003600, 0),
		RTPTime: 1000,
	}))

	got, info, err := mapper.Map(4444, 1000+90000)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700003601, 0).UTC(), got)
	assert.Equal(t, uint32(1000), info.RTPTimestamp)
}

func TestSenderReportMapperClockRateChange(t *testing.T) {
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(5555, 90000))
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    5555,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 42,
	}))

	// Changing the clock rate discards the anchor.
	require.NoError(t, mapper.SetClockRate(5555, 48000))
	_, _, err := mapper.Map(5555, 42)
	require.ErrorIs(t, err, errMapperNoAnchor)

	// Re-declaring the same rate keeps a freshly established anchor.
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    5555,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 48000,
	}))
	require.NoError(t, mapper.SetClockRate(5555, 48000))
	got, _, err := mapper.Map(5555, 48000*2)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1700000001, 0).UTC(), got)
}

func TestSenderReportMapperErrors(t *testing.T) {
	mapper := NewSenderReportMapper()

	// Zero clock rate.
	require.ErrorIs(t, mapper.SetClockRate(1, 0), errMapperClockRateZero)

	// Report for an SSRC with no declared clock rate.
	require.ErrorIs(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    1,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 1,
	}), errMapperUnknownSSRC)

	// Nil report.
	require.ErrorIs(t, mapper.AddSenderReport(nil), errMapperNilReport)

	require.NoError(t, mapper.SetClockRate(1, 90000))

	// Zero NTP timestamp must not become an anchor.
	require.ErrorIs(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    1,
		NTPTime: 0,
		RTPTime: 1,
	}), errMapperZeroNTP)

	// Query before any anchor.
	_, _, err := mapper.Map(1, 1)
	require.ErrorIs(t, err, errMapperNoAnchor)

	// Query for an unknown SSRC.
	_, _, err = mapper.Map(999, 1)
	require.ErrorIs(t, err, errMapperUnknownSSRC)

	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    1,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 1000,
	}))

	// Exactly half a wrap cycle away: ambiguous direction.
	_, _, err = mapper.Map(1, 1000+0x80000000)
	require.ErrorIs(t, err, errMapperAmbiguousRTP)

	// Just inside the ambiguous point still resolves.
	_, _, err = mapper.Map(1, 1000+0x80000001)
	require.NoError(t, err)
}

func TestSenderReportMapperErrorValues(t *testing.T) {
	// Ensure the overflow guard is reachable in principle: the largest
	// representable delta at the smallest clock rate stays within int64
	// nanoseconds, so Map must succeed rather than wrap.
	mapper := NewSenderReportMapper()
	require.NoError(t, mapper.SetClockRate(7, 1))
	require.NoError(t, mapper.AddSenderReport(&SenderReport{
		SSRC:    7,
		NTPTime: makeNTP(1700000000, 0),
		RTPTime: 0,
	}))

	got, _, err := mapper.Map(7, math.MaxInt32)
	require.NoError(t, err)
	assert.Equal(t,
		time.Unix(1700000000, 0).UTC().Add(time.Duration(math.MaxInt32)*time.Second),
		got,
	)
}
