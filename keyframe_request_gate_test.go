// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a manually advanced, injectable time source.
type fakeClock struct {
	mu sync.Mutex
	at time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{at: time.Unix(1, 0)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.at
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.at = c.at.Add(d)
}

func newTestGate(t *testing.T, cooldown time.Duration) (*KeyframeRequestGate, *fakeClock) {
	t.Helper()

	clock := newFakeClock()
	gate, err := NewKeyframeRequestGate(KeyframeRequestGateConfig{
		Cooldown: cooldown,
		Clock:    clock.now,
	})
	require.NoError(t, err)

	return gate, clock
}

func pli(mediaSSRC uint32, senderSSRC uint32) *PictureLossIndication {
	return &PictureLossIndication{SenderSSRC: senderSSRC, MediaSSRC: mediaSSRC}
}

func fir(mediaSSRC uint32, sequenceNumber uint8) *FullIntraRequest {
	return &FullIntraRequest{
		SenderSSRC: mediaSSRC,
		MediaSSRC:  mediaSSRC,
		FIR: []FIREntry{{
			SSRC:           mediaSSRC,
			SequenceNumber: sequenceNumber,
		}},
	}
}

// TestKeyframeRequestGatePLIMultiSubscriber drives a burst of twelve
// subscribers through the gate and checks exactly one forwarding decision per
// cooldown window, with every suppressed request counted on the coalesced
// event.
func TestKeyframeRequestGatePLIMultiSubscriber(t *testing.T) {
	const (
		subscribers = 12
		cooldown    = 100 * time.Millisecond
		mediaSSRC   = uint32(9000)
	)

	gate, clock := newTestGate(t, cooldown)

	// First request is forwarded immediately.
	emitted, err := gate.Process(pli(mediaSSRC, 1001))
	require.NoError(t, err)
	require.Equal(t, []KeyframeRequest{{
		Type:      KeyframeRequestPLI,
		MediaSSRC: mediaSSRC,
		Count:     1,
	}}, emitted)

	// The remaining eleven subscribers react inside the same window and must
	// not produce another forwarding decision.
	for sender := uint32(1002); sender <= 1000+subscribers; sender++ {
		emitted, err = gate.Process(pli(mediaSSRC, sender))
		require.NoError(t, err)
		assert.Empty(t, emitted)
	}

	pending, ok := gate.Pending(mediaSSRC)
	require.True(t, ok)
	assert.Equal(t, KeyframeRequestPLI, pending.Type)
	assert.Equal(t, subscribers-1, pending.Count)

	// Still inside the cooldown: nothing is due.
	clock.advance(cooldown - time.Millisecond)
	assert.Empty(t, gate.FlushDue())

	// Window elapsed: exactly one coalesced request carrying all eleven hits.
	clock.advance(time.Millisecond)
	assert.Equal(t, []KeyframeRequest{{
		Type:      KeyframeRequestPLI,
		MediaSSRC: mediaSSRC,
		Count:     subscribers - 1,
	}}, gate.FlushDue())
	_, ok = gate.Pending(mediaSSRC)
	assert.False(t, ok)

	// A fresh loss burst opens a new window. FlushDue restarted the cooldown
	// at the current instant, so a full cooldown must elapse first.
	clock.advance(cooldown)
	emitted, err = gate.Process(pli(mediaSSRC, 2001))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	assert.Equal(t, KeyframeRequestPLI, emitted[0].Type)
	assert.Equal(t, 1, emitted[0].Count)
}

// TestKeyframeRequestGateFIRMultiSubscriber verifies forwarding counts and the
// FIR sequence-number semantics across a subscriber burst, including uint8
// wraparound.
func TestKeyframeRequestGateFIRMultiSubscriber(t *testing.T) {
	const (
		subscribers = 12
		cooldown    = 50 * time.Millisecond
		mediaSSRC   = uint32(7000)
	)

	gate, clock := newTestGate(t, cooldown)

	// The first observed sequence number is always accepted.
	emitted, err := gate.Process(fir(mediaSSRC, 254))
	require.NoError(t, err)
	require.Equal(t, []KeyframeRequest{{
		Type:              KeyframeRequestFIR,
		MediaSSRC:         mediaSSRC,
		FIRSequenceNumber: 254,
		Count:             1,
	}}, emitted)

	// Increasing sequence numbers are newer even across the uint8 boundary.
	emitted, err = gate.Process(fir(mediaSSRC, 255))
	require.NoError(t, err)
	assert.Empty(t, emitted)
	emitted, err = gate.Process(fir(mediaSSRC, 0))
	require.NoError(t, err)
	assert.Empty(t, emitted)

	// Duplicates and out-of-order values are rejected deterministically.
	for _, stale := range []uint8{254, 255, 0} {
		_, err = gate.Process(fir(mediaSSRC, stale))
		assert.ErrorIs(t, err, ErrStaleFIRSequenceNumber)
	}

	pending, ok := gate.Pending(mediaSSRC)
	require.True(t, ok)
	// The pending event carries the newest accepted sequence number.
	assert.Equal(t, uint8(0), pending.FIRSequenceNumber)
	// Sequences 255 and 0 were accepted, 254 had opened the window.
	assert.Equal(t, 2, pending.Count)

	// Remaining subscribers keep coalescing with monotonically new sequences.
	for seq := uint8(1); seq <= 9; seq++ {
		_, err = gate.Process(fir(mediaSSRC, seq))
		require.NoError(t, err)
	}
	pending, ok = gate.Pending(mediaSSRC)
	require.True(t, ok)
	assert.Equal(t, uint8(9), pending.FIRSequenceNumber)
	assert.Equal(t, 11, pending.Count)

	clock.advance(cooldown)
	assert.Equal(t, []KeyframeRequest{{
		Type:              KeyframeRequestFIR,
		MediaSSRC:         mediaSSRC,
		FIRSequenceNumber: 9,
		Count:             11,
	}}, gate.FlushDue())

	// After the window the baseline still guards against replays.
	_, err = gate.Process(fir(mediaSSRC, 9))
	assert.ErrorIs(t, err, ErrStaleFIRSequenceNumber)
	// FlushDue restarted the cooldown at the current instant; a full window
	// must elapse before the next sequence number is forwarded.
	clock.advance(cooldown)
	emitted, err = gate.Process(fir(mediaSSRC, 10))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	assert.Equal(t, uint8(10), emitted[0].FIRSequenceNumber)
}

// TestKeyframeRequestGateFIRUpgradesPendingPLI verifies that an FIR received
// while a PLI is pending upgrades the coalesced event and carries its sequence
// number.
func TestKeyframeRequestGateFIRUpgradesPendingPLI(t *testing.T) {
	const mediaSSRC = uint32(4000)

	gate, clock := newTestGate(t, time.Second)

	emitted, err := gate.Process(pli(mediaSSRC, 1))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))

	_, err = gate.Process(pli(mediaSSRC, 2))
	require.NoError(t, err)
	_, err = gate.Process(fir(mediaSSRC, 7))
	require.NoError(t, err)

	pending, ok := gate.Pending(mediaSSRC)
	require.True(t, ok)
	assert.Equal(t, KeyframeRequestFIR, pending.Type)
	assert.Equal(t, uint8(7), pending.FIRSequenceNumber)
	assert.Equal(t, 2, pending.Count)

	clock.advance(time.Second)
	assert.Equal(t, []KeyframeRequest{{
		Type:              KeyframeRequestFIR,
		MediaSSRC:         mediaSSRC,
		FIRSequenceNumber: 7,
		Count:             2,
	}}, gate.FlushDue())

	// A later PLI does not downgrade an FIR.
	_, err = gate.Process(pli(mediaSSRC, 3))
	require.NoError(t, err)
	_, err = gate.Process(fir(mediaSSRC, 8))
	require.NoError(t, err)
	_, err = gate.Process(pli(mediaSSRC, 4))
	require.NoError(t, err)
	pending, ok = gate.Pending(mediaSSRC)
	require.True(t, ok)
	assert.Equal(t, KeyframeRequestFIR, pending.Type)
	assert.Equal(t, uint8(8), pending.FIRSequenceNumber)
	assert.Equal(t, 3, pending.Count)
}

// TestKeyframeRequestGateIndependentSSRCs verifies that gating decisions do not
// leak between media SSRCs and that output is ordered deterministically.
func TestKeyframeRequestGateIndependentSSRCs(t *testing.T) {
	gate, clock := newTestGate(t, time.Minute)

	_, err := gate.Process(pli(300, 1))
	require.NoError(t, err)
	_, err = gate.Process(pli(200, 1))
	require.NoError(t, err)
	_, err = gate.Process(pli(100, 1))
	require.NoError(t, err)

	// Each SSRC is within its own window, so all three are suppressed.
	for _, ssrc := range []uint32{100, 200, 300} {
		_, err = gate.Process(pli(ssrc, 2))
		require.NoError(t, err)
	}
	require.Equal(t, 3, gate.Len())

	clock.advance(time.Minute)
	assert.Equal(t, []KeyframeRequest{
		{Type: KeyframeRequestPLI, MediaSSRC: 100, Count: 1},
		{Type: KeyframeRequestPLI, MediaSSRC: 200, Count: 1},
		{Type: KeyframeRequestPLI, MediaSSRC: 300, Count: 1},
	}, gate.FlushDue())
}

// TestKeyframeRequestGateStaleFIRIsAtomic verifies that an FIR rejected for a
// duplicate or out-of-order entry modifies no state, including the state of the
// other entries carried in the same packet.
func TestKeyframeRequestGateStaleFIRIsAtomic(t *testing.T) {
	gate, _ := newTestGate(t, time.Minute)

	_, err := gate.Process(fir(100, 5))
	require.NoError(t, err)

	// Two entries: SSRC 100 replays 5 (stale), SSRC 200 would be new.
	badFIR := &FullIntraRequest{
		SenderSSRC: 500,
		MediaSSRC:  500,
		FIR: []FIREntry{
			{SSRC: 100, SequenceNumber: 5},
			{SSRC: 200, SequenceNumber: 1},
		},
	}
	_, err = gate.Process(badFIR)
	assert.ErrorIs(t, err, ErrStaleFIRSequenceNumber)
	assert.Equal(t, 1, gate.Len())
	_, ok := gate.Pending(200)
	assert.False(t, ok)

	// The same target SSRC repeated within one FIR packet is a duplicate and
	// rejected without creating a second entry.
	duplicatedSSRC := &FullIntraRequest{
		SenderSSRC: 500,
		MediaSSRC:  500,
		FIR: []FIREntry{
			{SSRC: 300, SequenceNumber: 1},
			{SSRC: 300, SequenceNumber: 2},
		},
	}
	_, err = gate.Process(duplicatedSSRC)
	assert.ErrorIs(t, err, ErrStaleFIRSequenceNumber)
	assert.Equal(t, 1, gate.Len())
}

// TestKeyframeRequestGateSenderSSRCChanges verifies that only the target media
// SSRC matters: feedback from different senders targeting the same media SSRC
// is coalesced into one forwarding decision.
func TestKeyframeRequestGateSenderSSRCChanges(t *testing.T) {
	const mediaSSRC = uint32(800)

	gate, clock := newTestGate(t, 10*time.Second)

	emitted, err := gate.Process(pli(mediaSSRC, 111))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	for _, sender := range []uint32{222, 333, 444} {
		emitted, err = gate.Process(pli(mediaSSRC, sender))
		require.NoError(t, err)
		assert.Empty(t, emitted)
	}
	require.Equal(t, 1, gate.Len())

	pending, ok := gate.Pending(mediaSSRC)
	require.True(t, ok)
	assert.Equal(t, 3, pending.Count)

	clock.advance(10 * time.Second)
	assert.Equal(t, 1, len(gate.FlushDue()))
}

// TestKeyframeRequestGateRebind verifies that Reset forgets a re-bound SSRC so
// its next request is forwarded immediately even inside the old window.
func TestKeyframeRequestGateRebind(t *testing.T) {
	const mediaSSRC = uint32(600)

	gate, _ := newTestGate(t, time.Hour)

	_, err := gate.Process(pli(mediaSSRC, 1))
	require.NoError(t, err)
	_, err = gate.Process(pli(mediaSSRC, 2))
	require.NoError(t, err)

	assert.True(t, gate.Reset(mediaSSRC))
	assert.False(t, gate.Reset(mediaSSRC))
	assert.Equal(t, 0, gate.Len())

	emitted, err := gate.Process(pli(mediaSSRC, 3))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	assert.Equal(t, 1, emitted[0].Count)

	// ResetAll forgets every state at once.
	_, err = gate.Process(pli(601, 1))
	require.NoError(t, err)
	_, err = gate.Process(pli(602, 1))
	require.NoError(t, err)
	require.Equal(t, 3, gate.Len())
	gate.ResetAll()
	assert.Equal(t, 0, gate.Len())

	// After a reset every SSRC starts a fresh window and is forwarded.
	emitted, err = gate.Process(pli(601, 2))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	assert.Equal(t, 1, emitted[0].Count)
}

// TestKeyframeRequestGateZeroCooldown verifies that a zero cooldown forwards
// every well-formed request immediately and retains no state.
func TestKeyframeRequestGateZeroCooldown(t *testing.T) {
	clock := newFakeClock()
	gate, err := NewKeyframeRequestGate(KeyframeRequestGateConfig{
		Cooldown: 0,
		Clock:    clock.now,
	})
	require.NoError(t, err)

	for i := range 5 {
		emitted, processErr := gate.Process(pli(42, uint32(i+1))) //nolint:gosec // G115: loop bound is a tiny constant
		require.NoError(t, processErr)
		require.Equal(t, 1, len(emitted))
		assert.Equal(t, 1, emitted[0].Count)
		// Coalescing is disabled, so FIR replays are accepted independently.
		firEmitted, firErr := gate.Process(fir(42, 1))
		require.NoError(t, firErr)
		require.Equal(t, 1, len(firEmitted))
		assert.Equal(t, uint8(1), firEmitted[0].FIRSequenceNumber)
	}
	assert.Equal(t, 0, gate.Len())
	assert.Empty(t, gate.FlushDue())
	assert.Equal(t, 0, gate.PurgeExpired())
}

// TestKeyframeRequestGateExpiryAndCapacity verifies lazy expiry cleanup and the
// bounded capacity, including deterministic idle eviction and the hard failure
// once every state holds a pending request.
func TestKeyframeRequestGateExpiryAndCapacity(t *testing.T) {
	t.Run("expired idle states are reclaimed", func(t *testing.T) {
		clock := newFakeClock()
		gate, newErr := NewKeyframeRequestGate(KeyframeRequestGateConfig{
			Cooldown:        time.Minute,
			MaxTrackedSSRCs: 2,
			Clock:           clock.now,
		})
		require.NoError(t, newErr)

		_, newErr = gate.Process(pli(10, 1))
		require.NoError(t, newErr)
		_, newErr = gate.Process(pli(20, 1))
		require.NoError(t, newErr)
		require.Equal(t, 2, gate.Len())

		clock.advance(time.Minute)
		assert.Equal(t, 2, gate.PurgeExpired())
		assert.Equal(t, 0, gate.Len())

		// Reclaimed slots accept new SSRCs again.
		_, newErr = gate.Process(pli(30, 1))
		require.NoError(t, newErr)
		assert.Equal(t, 1, gate.Len())
	})

	t.Run("oldest idle state is evicted at capacity", func(t *testing.T) {
		clock := newFakeClock()
		gate, newErr := NewKeyframeRequestGate(KeyframeRequestGateConfig{
			Cooldown:        time.Minute,
			MaxTrackedSSRCs: 2,
			Clock:           clock.now,
		})
		require.NoError(t, newErr)

		_, newErr = gate.Process(pli(10, 1))
		require.NoError(t, newErr)
		clock.advance(time.Second)
		_, newErr = gate.Process(pli(20, 1))
		require.NoError(t, newErr)

		// SSRC 10 is the oldest idle state and is deterministically evicted.
		emitted, newErr := gate.Process(pli(30, 1))
		require.NoError(t, newErr)
		require.Equal(t, 1, len(emitted))
		assert.Equal(t, 2, gate.Len())
		assert.False(t, gate.Reset(10))
		assert.True(t, gate.Reset(30))
	})

	t.Run("hard failure when every state holds a pending request", func(t *testing.T) {
		clock := newFakeClock()
		gate, newErr := NewKeyframeRequestGate(KeyframeRequestGateConfig{
			Cooldown:        time.Minute,
			MaxTrackedSSRCs: 2,
			Clock:           clock.now,
		})
		require.NoError(t, newErr)

		// Two active windows, each with a coalesced pending request.
		_, newErr = gate.Process(pli(10, 1))
		require.NoError(t, newErr)
		_, newErr = gate.Process(pli(20, 1))
		require.NoError(t, newErr)
		_, newErr = gate.Process(pli(10, 2))
		require.NoError(t, newErr)
		_, newErr = gate.Process(pli(20, 2))
		require.NoError(t, newErr)

		// Nothing is idle or expired, so a third SSRC cannot be admitted.
		_, newErr = gate.Process(pli(30, 1))
		assert.ErrorIs(t, newErr, ErrGateCapacityExceeded)
		assert.Equal(t, 2, gate.Len())

		// After two full windows the flushed, idle states are expired and
		// reclaimed lazily, so the previously rejected SSRC is now admitted.
		clock.advance(time.Minute)
		require.Equal(t, 2, len(gate.FlushDue()))
		clock.advance(time.Minute)
		emitted, newErr := gate.Process(pli(30, 1))
		require.NoError(t, newErr)
		require.Equal(t, 1, len(emitted))
		assert.Equal(t, 1, gate.Len())
	})
}

// TestKeyframeRequestGateBadInputs covers the deterministic rules for missing
// target SSRCs, unsupported packets and bad configuration.
func TestKeyframeRequestGateBadInputs(t *testing.T) {
	gate, _ := newTestGate(t, time.Minute)

	_, err := gate.Process(pli(0, 1))
	assert.ErrorIs(t, err, ErrMissingTargetSSRC)

	_, err = gate.Process(&FullIntraRequest{})
	assert.ErrorIs(t, err, ErrMissingTargetSSRC)

	_, err = gate.Process(&FullIntraRequest{FIR: []FIREntry{{SSRC: 0, SequenceNumber: 1}}})
	assert.ErrorIs(t, err, ErrMissingTargetSSRC)

	_, err = gate.Process(&ReceiverReport{})
	assert.ErrorIs(t, err, ErrUnsupportedFeedback)

	var nilPLI *PictureLossIndication
	_, err = gate.Process(nilPLI)
	assert.ErrorIs(t, err, ErrUnsupportedFeedback)

	var nilFIR *FullIntraRequest
	_, err = gate.Process(nilFIR)
	assert.ErrorIs(t, err, ErrUnsupportedFeedback)

	_, err = NewKeyframeRequestGate(KeyframeRequestGateConfig{Cooldown: -1})
	assert.ErrorIs(t, err, ErrInvalidCooldown)

	_, err = NewKeyframeRequestGate(KeyframeRequestGateConfig{MaxTrackedSSRCs: -1})
	assert.ErrorIs(t, err, ErrInvalidCapacity)
}

// TestKeyframeRequestGateDefaultClock verifies that a gate without an injected
// clock falls back to time.Now and still coalesces requests.
func TestKeyframeRequestGateDefaultClock(t *testing.T) {
	gate, err := NewKeyframeRequestGate(KeyframeRequestGateConfig{Cooldown: time.Minute})
	require.NoError(t, err)

	emitted, err := gate.Process(pli(700, 1))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	emitted, err = gate.Process(pli(700, 2))
	require.NoError(t, err)
	assert.Empty(t, emitted)
	assert.Equal(t, 1, gate.Len())
}

// TestKeyframeRequestGateProcessRaw verifies raw compound packets: PLI/FIR
// members are gated, other members ignored, and malformed input rejected.
func TestKeyframeRequestGateProcessRaw(t *testing.T) {
	gate, clock := newTestGate(t, time.Minute)

	pliPacket := pli(555, 999)
	pliData, err := pliPacket.Marshal()
	require.NoError(t, err)
	rrData, err := (&ReceiverReport{SSRC: 999}).Marshal()
	require.NoError(t, err)
	compound := append(append([]byte{}, rrData...), pliData...)

	emitted, err := gate.ProcessRaw(compound)
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	assert.Equal(t, uint32(555), emitted[0].MediaSSRC)

	// The PLI inside a second compound is coalesced.
	emitted, err = gate.ProcessRaw(compound)
	require.NoError(t, err)
	assert.Empty(t, emitted)
	pending, ok := gate.Pending(555)
	require.True(t, ok)
	assert.Equal(t, 1, pending.Count)

	// A malformed datagram is rejected.
	_, err = gate.ProcessRaw([]byte{0x80})
	assert.Error(t, err)

	// A gate-level rejection reached through the raw path is propagated.
	staleFIR, err := fir(556, 1).Marshal()
	require.NoError(t, err)
	_, err = gate.ProcessRaw(staleFIR)
	require.NoError(t, err)
	_, err = gate.ProcessRaw(staleFIR)
	assert.ErrorIs(t, err, ErrStaleFIRSequenceNumber)

	clock.advance(time.Minute)
	require.Equal(t, 1, len(gate.FlushDue()))
}

// TestKeyframeRequestGateDuePendingDeliveredFirst verifies that when a new
// request arrives after the window elapsed, the coalesced pending request is
// delivered and the incoming request opens the fresh window, so only one
// effective keyframe request is forwarded at the boundary.
func TestKeyframeRequestGateDuePendingDeliveredFirst(t *testing.T) {
	gate, clock := newTestGate(t, time.Minute)

	// Open a window and coalesce two suppressed PLIs into the pending event.
	_, err := gate.Process(pli(800, 1))
	require.NoError(t, err)
	_, err = gate.Process(pli(800, 2))
	require.NoError(t, err)
	_, err = gate.Process(pli(800, 3))
	require.NoError(t, err)

	// Once the window elapses the next input flushes the coalesced pending
	// event. Delivering it restarts the window, so the triggering request is
	// coalesced rather than producing a second keyframe request at the instant.
	clock.advance(time.Minute)
	emitted, err := gate.Process(pli(800, 4))
	require.NoError(t, err)
	require.Equal(t, 1, len(emitted))
	assert.Equal(t, 2, emitted[0].Count)

	// The triggering request now waits in the fresh window.
	pending, ok := gate.Pending(800)
	require.True(t, ok)
	assert.Equal(t, 1, pending.Count)
}

// TestKeyframeRequestGateFIRCapacityError verifies that FIR entry processing
// surfaces the bounded-capacity error instead of silently dropping the entry.
func TestKeyframeRequestGateFIRCapacityError(t *testing.T) {
	clock := newFakeClock()
	gate, err := NewKeyframeRequestGate(KeyframeRequestGateConfig{
		Cooldown:        time.Hour,
		MaxTrackedSSRCs: 1,
		Clock:           clock.now,
	})
	require.NoError(t, err)

	// One SSRC with a pending request fills the only slot.
	_, err = gate.Process(fir(900, 1))
	require.NoError(t, err)
	_, err = gate.Process(fir(900, 2))
	require.NoError(t, err)

	// A second, distinct target SSRC cannot be admitted.
	_, err = gate.Process(fir(901, 1))
	assert.ErrorIs(t, err, ErrGateCapacityExceeded)
	assert.Equal(t, 1, gate.Len())
}

// TestKeyframeRequestGateConcurrent verifies that concurrent input never
// produces more than one forwarding decision per SSRC per cooldown window.
func TestKeyframeRequestGateConcurrent(t *testing.T) {
	const (
		goroutines = 64
		ssrcs      = 4
	)

	gate, clock := newTestGate(t, time.Hour)

	var wg sync.WaitGroup
	for i := range goroutines {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mediaSSRC := uint32(1000 + n%ssrcs)
			_, processErr := gate.Process(pli(mediaSSRC, uint32(2000+n))) //nolint:gosec // G115: bounded test index
			assert.NoError(t, processErr)
		}(i)
	}
	wg.Wait()

	var immediate int
	for ssrc := uint32(1000); ssrc < 1000+ssrcs; ssrc++ {
		pending, ok := gate.Pending(ssrc)
		require.True(t, ok)
		immediate++
		assert.Equal(t, goroutines/ssrcs-1, pending.Count)
	}
	assert.Equal(t, ssrcs, immediate)
	assert.Equal(t, ssrcs, gate.Len())

	clock.advance(time.Hour)
	flushed := gate.FlushDue()
	assert.Equal(t, ssrcs, len(flushed))
}
