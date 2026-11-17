// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"math"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rembTestClock is a manually advanced clock for deterministic expiry and
// ordering tests.
type rembTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newREMBTestClock() *rembTestClock {
	return &rembTestClock{now: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)}
}

func (c *rembTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *rembTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = c.now.Add(d)
}

func (c *rembTestClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.now = t
}

// rembWirePacket marshals a REMB and unmarshals the datagram again, so the
// tracker is fed exactly what would arrive on the wire.
func rembWirePacket(t *testing.T, sender uint32, bitrate float32, ssrcs ...uint32) Packet {
	t.Helper()

	raw, err := Marshal([]Packet{&ReceiverEstimatedMaximumBitrate{
		SenderSSRC: sender,
		Bitrate:    bitrate,
		SSRCs:      ssrcs,
	}})
	require.NoError(t, err)

	pkts, err := Unmarshal(raw)
	require.NoError(t, err)
	require.Len(t, pkts, 1)

	return pkts[0]
}

func TestREMBTrackerSingleReport(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 8927168, 2222)))

	report, ok := tracker.Lookup(2222)
	require.True(t, ok)
	assert.Equal(t, uint32(2222), report.SSRC)
	assert.Equal(t, float32(8927168), report.Bitrate)
	assert.Equal(t, uint32(1111), report.SenderSSRC)
	assert.Equal(t, clock.Now(), report.ReportedAt)
	assert.Equal(t, 1, tracker.Len())

	_, ok = tracker.Lookup(3333)
	assert.False(t, ok)
	assert.Empty(t, tracker.Reports()[1:])
}

func TestREMBTrackerUpdatesEveryListedSSRC(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	pkt := rembWirePacket(t, 1111, 500000, 10, 20, 30)
	require.NoError(t, tracker.Update(pkt))

	for _, ssrc := range []uint32{10, 20, 30} {
		report, ok := tracker.Lookup(ssrc)
		require.True(t, ok, "ssrc %d", ssrc)
		assert.Equal(t, float32(500000), report.Bitrate)
		assert.Equal(t, uint32(1111), report.SenderSSRC)
	}

	// A later report for the same sources replaces the estimate.
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 250000, 10, 20)))

	assert.Equal(t, float32(250000), mustLookup(t, tracker, 10).Bitrate)
	assert.Equal(t, float32(250000), mustLookup(t, tracker, 20).Bitrate)
	assert.Equal(t, float32(500000), mustLookup(t, tracker, 30).Bitrate)
	assert.Equal(t, 3, tracker.Len())
}

func TestREMBTrackerReportsSortedBySSRC(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 1000, 300, 100, 200)))

	reports := tracker.Reports()
	require.Len(t, reports, 3)
	assert.Equal(t, []uint32{100, 200, 300}, []uint32{
		reports[0].SSRC,
		reports[1].SSRC,
		reports[2].SSRC,
	})
}

func TestREMBTrackerRejectsInvalidBitrates(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 400000, 42)))

	invalid := []float32{0, -1, float32(math.NaN()), float32(math.Inf(1)), float32(math.Inf(-1))}
	for _, bitrate := range invalid {
		clock.Advance(time.Second)
		err := tracker.Update(&ReceiverEstimatedMaximumBitrate{
			SenderSSRC: 1111,
			Bitrate:    bitrate,
			SSRCs:      []uint32{42},
		})
		require.ErrorIs(t, err, ErrInvalidREMBBitrate, "bitrate %v", bitrate)

		report, ok := tracker.Lookup(42)
		require.True(t, ok)
		assert.Equal(t, float32(400000), report.Bitrate)
	}

	// A REMB with a valid bitrate but no SSRCs is not an error and updates nothing.
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 900000)))
	assert.Equal(t, 1, tracker.Len())
}

func TestREMBTrackerMixedValidityStillAppliesGoodReports(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	err := tracker.Update(
		&ReceiverEstimatedMaximumBitrate{SenderSSRC: 1, Bitrate: -5, SSRCs: []uint32{1}},
		rembWirePacket(t, 2, 300000, 2),
	)
	require.ErrorIs(t, err, ErrInvalidREMBBitrate)

	assert.Equal(t, float32(300000), mustLookup(t, tracker, 2).Bitrate)
	_, ok := tracker.Lookup(1)
	assert.False(t, ok)
}

func TestREMBTrackerDuplicateSSRCInOneReport(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 750000, 77, 77, 77)))

	assert.Equal(t, 1, tracker.Len())
	assert.Equal(t, float32(750000), mustLookup(t, tracker, 77).Bitrate)
}

func TestREMBTrackerIgnoresOutOfOrderReports(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	newer := clock.Now()
	clock.Advance(10 * time.Second)
	newerReport := clock.Now()
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 900000, 5)))
	assert.Equal(t, newerReport, mustLookup(t, tracker, 5).ReportedAt)

	// A delayed report from before the stored one must not move state back.
	clock.Set(newer.Add(-5 * time.Second))
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 5)))

	report := mustLookup(t, tracker, 5)
	assert.Equal(t, float32(900000), report.Bitrate)
	assert.Equal(t, newerReport, report.ReportedAt)

	// Reports sharing one receipt time are ordered by arrival: the last
	// packet of the call wins for a given SSRC.
	clock.Advance(20 * time.Second)
	require.NoError(t, tracker.Update(
		rembWirePacket(t, 1111, 200000, 5),
		rembWirePacket(t, 2222, 800000, 5),
	))

	report = mustLookup(t, tracker, 5)
	assert.Equal(t, float32(800000), report.Bitrate)
	assert.Equal(t, uint32(2222), report.SenderSSRC)
}

func TestREMBTrackerExpiry(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerTTL(3*time.Second),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 1, 2)))

	clock.Advance(2 * time.Second)
	assert.Equal(t, 2, tracker.Len())
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 1)))

	// SSRC 1 was refreshed, SSRC 2 was not.
	clock.Advance(1500 * time.Millisecond)
	assert.Equal(t, 1, tracker.Len())
	assert.Len(t, tracker.Reports(), 1)
	_, ok := tracker.Lookup(2)
	assert.False(t, ok)
	assert.Equal(t, float32(300000), mustLookup(t, tracker, 1).Bitrate)

	// At exactly the TTL the report is expired.
	clock.Advance(1500 * time.Millisecond)
	_, ok = tracker.Lookup(1)
	assert.False(t, ok)
	assert.Equal(t, 0, tracker.Len())

	// Expire reclaims both entries: the eviction at the start of Update is
	// lazy and only runs when Update is called.
	assert.Equal(t, 2, tracker.Expire())
	assert.Equal(t, 0, tracker.Expire())
}

func TestREMBTrackerNonExpiringTTL(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerTTL(0),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 1)))
	clock.Advance(24 * time.Hour)

	assert.Equal(t, 1, tracker.Len())
	assert.Equal(t, float32(300000), mustLookup(t, tracker, 1).Bitrate)
}

func TestREMBTrackerUnboundedCapacity(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerCapacity(0),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 1, 2, 3)))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{1}}))

	assert.Equal(t, 2, tracker.Len())
	assert.Equal(t, []uint32{2, 3}, []uint32{tracker.Reports()[0].SSRC, tracker.Reports()[1].SSRC})
}

func TestREMBTrackerGoodbyeWithoutTombstone(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerTTL(0),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 4)))
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{4}}))
	_, ok := tracker.Lookup(4)
	assert.False(t, ok)

	// With reports that never expire there is no tombstone window, so the
	// sender itself may report the SSRC again immediately.
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 4)))
	assert.Equal(t, float32(100000), mustLookup(t, tracker, 4).Bitrate)
}

func TestREMBTrackerGoodbyeRemovesSource(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 7, 8)))
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{7}}))

	_, ok := tracker.Lookup(7)
	assert.False(t, ok)
	assert.Equal(t, float32(300000), mustLookup(t, tracker, 8).Bitrate)

	// Duplicate and unknown BYEs are no-ops.
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{7, 999}}))
	assert.Equal(t, 1, tracker.Len())
}

func TestREMBTrackerGoodbyeTombstoneBlocksSameSender(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerTTL(5*time.Second),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 7)))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{7}}))

	// An in-flight REMB from the departed sender cannot resurrect the source.
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 7)))
	_, ok := tracker.Lookup(7)
	assert.False(t, ok)

	// A different receiver reporting the same media SSRC is a fresh report.
	require.NoError(t, tracker.Update(rembWirePacket(t, 2222, 150000, 7)))
	report, ok := tracker.Lookup(7)
	require.True(t, ok)
	assert.Equal(t, uint32(2222), report.SenderSSRC)
	assert.Equal(t, float32(150000), report.Bitrate)

	// Once the tombstone TTL elapses the original sender may report again.
	clock.Advance(5 * time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 250000, 7)))
	assert.Equal(t, uint32(1111), mustLookup(t, tracker, 7).SenderSSRC)

	// A second BYE removes the source again.
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{7}}))
	_, ok = tracker.Lookup(7)
	assert.False(t, ok)
}

func TestREMBTrackerCapacityEvictsOldest(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerCapacity(2),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 10)))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 200000, 20)))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 300000, 30)))

	// The oldest report was evicted to keep the tracker bounded.
	assert.Equal(t, 2, tracker.Len())
	_, ok := tracker.Lookup(10)
	assert.False(t, ok)
	assert.Equal(t, float32(200000), mustLookup(t, tracker, 20).Bitrate)
	assert.Equal(t, float32(300000), mustLookup(t, tracker, 30).Bitrate)

	// Refreshing an existing SSRC does not evict anything.
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 400000, 20)))
	assert.Equal(t, 2, tracker.Len())
	assert.Equal(t, float32(400000), mustLookup(t, tracker, 20).Bitrate)

	// A multi-SSRC report is applied source by source, still bounded.
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 500000, 40, 50)))
	assert.Equal(t, 2, tracker.Len())
	assert.Equal(t, float32(500000), mustLookup(t, tracker, 40).Bitrate)
	assert.Equal(t, float32(500000), mustLookup(t, tracker, 50).Bitrate)
}

func TestREMBTrackerCapacityTieBreakIsDeterministic(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerCapacity(2),
	)

	// Equal timestamps: the largest SSRC is evicted first.
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 300, 100)))
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 200)))

	assert.Equal(t, 2, tracker.Len())
	_, ok := tracker.Lookup(300)
	assert.False(t, ok)
	assert.Equal(t, float32(100000), mustLookup(t, tracker, 100).Bitrate)
	assert.Equal(t, float32(100000), mustLookup(t, tracker, 200).Bitrate)
}

func TestREMBTrackerTombstonesAreBounded(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(
		WithREMBTrackerClock(clock.Now),
		WithREMBTrackerCapacity(2),
		WithREMBTrackerTTL(time.Minute),
	)

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 1, 2)))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{1}}))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{2}}))
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 3)))
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{3}}))

	// Three tombstones exceeded the capacity of two; the oldest (SSRC 1) was
	// dropped, so its sender can report it again while SSRC 2, tombstoned one
	// second later, stays shielded.
	clock.Advance(time.Second)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 200000, 1, 2)))
	assert.Equal(t, uint32(1111), mustLookup(t, tracker, 1).SenderSSRC)
	_, ok := tracker.Lookup(2)
	assert.False(t, ok)
}

func TestREMBTrackerRemoveAndReset(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 100000, 1, 2)))
	tracker.Remove(1)
	_, ok := tracker.Lookup(1)
	assert.False(t, ok)
	assert.Equal(t, float32(100000), mustLookup(t, tracker, 2).Bitrate)

	tracker.Reset()
	assert.Equal(t, 0, tracker.Len())
	assert.Empty(t, tracker.Reports())
	_, ok = tracker.Lookup(2)
	assert.False(t, ok)
}

func TestREMBTrackerAcceptsUnmarshaledDatagramAndIgnoresOthers(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	// A datagram holding an unrelated receiver report followed by a REMB is
	// decoded with Unmarshal and fed as a whole.
	rembRaw, err := rembWirePacket(t, 1111, 600000, 9).Marshal()
	require.NoError(t, err)
	rrRaw, err := (&ReceiverReport{}).Marshal()
	require.NoError(t, err)

	pkts, err := Unmarshal(append(rrRaw, rembRaw...))
	require.NoError(t, err)
	require.Len(t, pkts, 2)

	require.NoError(t, tracker.Update(pkts...))
	assert.Equal(t, float32(600000), mustLookup(t, tracker, 9).Bitrate)

	// Unrelated packets and nil values are harmless.
	require.NoError(t, tracker.Update(
		nil,
		&ReceiverReport{},
		(*ReceiverEstimatedMaximumBitrate)(nil),
		(*Goodbye)(nil),
	))
	assert.Equal(t, 1, tracker.Len())
}

func TestREMBTrackerMultiSenderPacketSequence(t *testing.T) {
	clock := newREMBTestClock()
	tracker := NewREMBTracker(WithREMBTrackerClock(clock.Now))

	// Two receivers report estimates for an audio and a video stream over
	// time; the newest accepted estimate per SSRC is the one visible.
	require.NoError(t, tracker.Update(
		rembWirePacket(t, 1111, 200000, 100), // audio receiver A
		rembWirePacket(t, 2222, 900000, 200), // video receiver B
	))

	clock.Advance(100 * time.Millisecond)
	require.NoError(t, tracker.Update(rembWirePacket(t, 2222, 1200000, 200, 201)))

	clock.Advance(100 * time.Millisecond)
	// An older video report arrives late; it must not win.
	clock.Set(clock.Now().Add(-time.Second))
	require.NoError(t, tracker.Update(rembWirePacket(t, 2222, 500000, 200)))
	clock.Advance(time.Second)

	// Receiver A now reports for both streams; that wins for 100 and 200.
	clock.Advance(100 * time.Millisecond)
	require.NoError(t, tracker.Update(rembWirePacket(t, 1111, 700000, 100, 200)))

	reports := tracker.Reports()
	require.Len(t, reports, 3)
	assert.Equal(t, []uint32{100, 200, 201}, []uint32{
		reports[0].SSRC, reports[1].SSRC, reports[2].SSRC,
	})
	for _, report := range reports {
		switch report.SSRC {
		case 201:
			// SSRC 201 was only ever reported by receiver B, so it keeps
			// both that estimate and its receipt time.
			assert.Equal(t, uint32(2222), report.SenderSSRC)
			assert.Equal(t, float32(1200000), report.Bitrate)
		default:
			assert.Equal(t, uint32(1111), report.SenderSSRC, "ssrc %d", report.SSRC)
			assert.Equal(t, float32(700000), report.Bitrate, "ssrc %d", report.SSRC)
			assert.Equal(t, clock.Now(), report.ReportedAt, "ssrc %d", report.SSRC)
		}
	}

	// The video receiver leaves; both of its streams are dropped.
	require.NoError(t, tracker.Update(&Goodbye{Sources: []uint32{201}}))
	assert.Equal(t, 2, tracker.Len())
}

func TestREMBTrackerConcurrentUse(t *testing.T) {
	// The default clock is used here: the test only checks that concurrent
	// readers and writers stay within the configured bound.
	tracker := NewREMBTracker(WithREMBTrackerCapacity(64))

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sender := uint32(1000 + i) //nolint:gosec // G115 // i is in [0,8)
			for j := range 100 {
				ssrc := uint32((i*100 + j) % 64) //nolint:gosec // G115 // bounded by the modulo
				_ = tracker.Update(rembWirePacket(t, sender, float32(100000+j), ssrc))
				_, _ = tracker.Lookup(ssrc)
				_ = tracker.Reports()
				_ = tracker.Len()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 100 {
			_ = tracker.Expire()
			tracker.Remove(0)
		}
	}()

	wg.Wait()

	require.LessOrEqual(t, tracker.Len(), 64)
}

func mustLookup(t *testing.T, tracker *REMBTracker, ssrc uint32) REMBReport {
	t.Helper()

	report, ok := tracker.Lookup(ssrc)
	require.True(t, ok, "ssrc %d not tracked", ssrc)

	return report
}
