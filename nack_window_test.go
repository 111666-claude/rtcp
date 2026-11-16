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

// fakeClock is a manually advanced clock for deterministic NackWindow tests.
type fakeClock struct {
	t time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Unix(1_000, 0)}
}

func (c *fakeClock) now() time.Time {
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

func testWindow(t *testing.T, config NackWindowConfig) (*NackWindow, *fakeClock) {
	t.Helper()

	clock := newFakeClock()
	config.Now = clock.now

	window, err := NewNackWindow(config)
	require.NoError(t, err)

	return window, clock
}

func nackSequenceNumbers(packet *TransportLayerNack) []uint16 {
	if packet == nil {
		return nil
	}

	out := make([]uint16, 0)
	for i := range packet.Nacks {
		out = append(out, packet.Nacks[i].PacketList()...)
	}

	return out
}

func TestNackWindowInvalidConfig(t *testing.T) {
	base := NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      2,
		MaxWindowLength: 64,
	}

	for _, test := range []struct {
		name      string
		mutate    func(*NackWindowConfig)
		wantError error
	}{
		{"zero reorder wait", func(c *NackWindowConfig) { c.ReorderWait = 0 }, ErrInvalidNackReorderWait},
		{"negative reorder wait", func(c *NackWindowConfig) { c.ReorderWait = -time.Millisecond }, ErrInvalidNackReorderWait},
		{"zero max retries", func(c *NackWindowConfig) { c.MaxRetries = 0 }, ErrInvalidNackMaxRetries},
		{"zero window length", func(c *NackWindowConfig) { c.MaxWindowLength = 0 }, ErrInvalidNackWindowLength},
		{
			"window length above half the space",
			func(c *NackWindowConfig) { c.MaxWindowLength = 1 << 15 }, ErrInvalidNackWindowLength,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)

			_, err := NewNackWindow(config)
			assert.ErrorIs(t, err, test.wantError)
		})
	}

	// A nil clock is replaced by time.Now instead of failing.
	window, err := NewNackWindow(base)
	require.NoError(t, err)
	assert.NotNil(t, window)
}

func TestNackWindowReorderingWithholdsThenCancels(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      3,
		MaxWindowLength: 64,
	})

	// 0, 1, then jump to 3: gap on 2.
	window.AddPacket(100, 0)
	window.AddPacket(100, 1)
	window.AddPacket(100, 3)

	// Before the wait elapses nothing is reported.
	clock.advance(9 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks())

	// Late arrival within the wait cancels the pending request.
	window.AddPacket(100, 2)
	clock.advance(2 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks())

	// And nothing ever comes out for that gap later.
	clock.advance(time.Hour)
	assert.Empty(t, window.TransportLayerNacks())
}

func TestNackWindowRealLossReportedAndExpires(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      2,
		MaxWindowLength: 64,
	})

	window.AddPacket(100, 10)
	window.AddPacket(100, 12) // 11 is genuinely lost.

	clock.advance(10 * time.Millisecond)

	first := window.TransportLayerNacks()
	require.Len(t, first, 1)
	assert.Equal(t, uint32(100), first[0].MediaSSRC)
	assert.Equal(t, []uint16{11}, nackSequenceNumbers(first[0]))
	// No SenderSSRC configured: the caller is expected to fill it in.
	assert.Zero(t, first[0].SenderSSRC)

	// Retry: the same gap is reported again.
	clock.advance(10 * time.Millisecond)
	second := window.TransportLayerNacks()
	require.Len(t, second, 1)
	assert.Equal(t, []uint16{11}, nackSequenceNumbers(second[0]))

	// After MaxRetries the gap expires and is reclaimed.
	clock.advance(10 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks())
	clock.advance(time.Hour)
	assert.Empty(t, window.TransportLayerNacks())
}

func TestNackWindowWraparound(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      10,
		MaxWindowLength: 64,
	})

	window.AddPacket(100, 0xFFFE)
	window.AddPacket(100, 0x0000) // 0xFFFF missing across the wrap.

	clock.advance(10 * time.Millisecond)
	packets := window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Equal(t, []uint16{0xFFFF}, nackSequenceNumbers(packets[0]))

	// A late 0xFFFF arrives after the first report and cancels further retries.
	window.AddPacket(100, 0xFFFF)
	clock.advance(time.Hour)
	assert.Empty(t, window.TransportLayerNacks())
}

func TestNackWindowMultipleSSRC(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      3,
		MaxWindowLength: 64,
	})

	window.AddPacket(100, 5)
	window.AddPacket(100, 7) // gap 6
	window.AddPacket(200, 5)
	window.AddPacket(200, 9) // gaps 6, 7, 8

	clock.advance(10 * time.Millisecond)
	packets := window.TransportLayerNacks()
	require.Len(t, packets, 2)

	// SSRC order is deterministic.
	assert.Equal(t, uint32(100), packets[0].MediaSSRC)
	assert.Equal(t, []uint16{6}, nackSequenceNumbers(packets[0]))
	assert.Equal(t, uint32(200), packets[1].MediaSSRC)
	assert.Equal(t, []uint16{6, 7, 8}, nackSequenceNumbers(packets[1]))

	// Filling one SSRC's gap does not touch the other one.
	window.AddPacket(100, 6)
	clock.advance(10 * time.Millisecond)
	packets = window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Equal(t, uint32(200), packets[0].MediaSSRC)
	assert.Equal(t, []uint16{6, 7, 8}, nackSequenceNumbers(packets[0]))
}

func TestNackWindowLargeJumpEvictsOldestGaps(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      3,
		MaxWindowLength: 4,
	})

	// Jump over 10 sequence numbers; only the four newest gaps fit.
	window.AddPacket(100, 0)
	window.AddPacket(100, 11)

	state := window.streams[100]
	assert.Len(t, state.gaps, 4)
	assert.NotContains(t, state.gaps, uint16(1))
	for seq := uint16(7); seq <= 10; seq++ {
		assert.Contains(t, state.gaps, seq)
	}

	clock.advance(10 * time.Millisecond)
	packets := window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Equal(t, []uint16{7, 8, 9, 10}, nackSequenceNumbers(packets[0]))
}

func TestNackWindowDuplicatesAndReorderedPackets(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      3,
		MaxWindowLength: 64,
	})

	window.AddPacket(100, 0)
	window.AddPacket(100, 2) // gap 1
	window.AddPacket(100, 2) // duplicate of the newest
	window.AddPacket(100, 0) // duplicate of an older received packet

	clock.advance(9 * time.Millisecond)
	window.AddPacket(100, 1) // late, in-order fill
	window.AddPacket(100, 1) // duplicate of the just-filled packet
	clock.advance(2 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks())

	// An out-of-order packet older than the bitmap window is ignored and does
	// not register a gap.
	window.AddPacket(100, 3)
	var newest uint16 = 3
	stale := newest - 64
	window.AddPacket(100, stale)
	clock.advance(10 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks())
}

func TestNackWindowMergesGapsIntoNackPairs(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      3,
		MaxWindowLength: 128,
	})

	// Lose 100..117 but keep 118: gaps 100..117 span two NackPairs.
	window.AddPacket(100, 99)
	window.AddPacket(100, 118)

	clock.advance(10 * time.Millisecond)
	packets := window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Equal(t, NackPairsFromSequenceNumbers(
		[]uint16{
			100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
			111, 112, 113, 114, 115, 116, 117,
		}),
		packets[0].Nacks)

	// The produced feedback round-trips through the existing codec.
	data, err := packets[0].Marshal()
	require.NoError(t, err)

	var decoded TransportLayerNack
	require.NoError(t, decoded.Unmarshal(data))
	assert.Equal(t, packets[0].Nacks, decoded.Nacks)
}

func TestNackWindowSenderSSRC(t *testing.T) {
	clock := newFakeClock()

	window, err := NewNackWindow(NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      2,
		MaxWindowLength: 64,
		SenderSSRC:      0xCAFE,
		Now:             clock.now,
	})
	require.NoError(t, err)

	window.AddPacket(100, 0)
	window.AddPacket(100, 2)
	clock.advance(10 * time.Millisecond)

	packets := window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Equal(t, uint32(0xCAFE), packets[0].SenderSSRC)
	assert.Equal(t, uint32(100), packets[0].MediaSSRC)

	// A fully populated packet marshals and decodes unchanged.
	data, err := packets[0].Marshal()
	require.NoError(t, err)

	var decoded TransportLayerNack
	require.NoError(t, decoded.Unmarshal(data))
	assert.Equal(t, packets[0], &decoded)
}

func TestNackWindowRemoveAndReset(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      3,
		MaxWindowLength: 64,
	})

	window.AddPacket(100, 0)
	window.AddPacket(100, 2)
	window.AddPacket(200, 0)
	window.AddPacket(200, 2)

	window.RemoveSSRC(100)
	assert.NotContains(t, window.streams, uint32(100))
	assert.Contains(t, window.streams, uint32(200))

	window.Reset()
	assert.Empty(t, window.streams)

	// A removed SSRC can start tracking again from scratch.
	clock.advance(10 * time.Millisecond)
	window.AddPacket(100, 7)
	window.AddPacket(100, 9)
	clock.advance(10 * time.Millisecond)
	packets := window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Equal(t, []uint16{8}, nackSequenceNumbers(packets[0]))
}

func TestNackWindowBoundedMemory(t *testing.T) {
	const windowLen uint16 = 32

	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     time.Hour, // keep gaps pending during the run
		MaxRetries:      3,
		MaxWindowLength: windowLen,
	})

	window.AddPacket(100, 0)

	// A long steady stream must never let the per-SSRC state grow without
	// bound, even when jumps interleave with in-order packets.
	for seq := uint32(1); seq <= 100_000; seq++ {
		if seq%7 == 0 {
			// Periodic jump keeps the gap map populated.
			window.AddPacket(100, uint16(seq)+3)
			seq += 3
		} else {
			window.AddPacket(100, uint16(seq))
		}

		state := window.streams[100]
		assert.LessOrEqualf(t, len(state.gaps), int(windowLen),
			"gaps unbounded at seq %d", seq)
	}

	state := window.streams[100]
	assert.LessOrEqual(t, len(state.gaps), int(windowLen))
	// The bitmap never grew beyond its initial allocation.
	expectedWords := int(roundUpPowerOfTwo(windowLen) / 64)
	if expectedWords == 0 {
		expectedWords = 1
	}
	assert.Equal(t, expectedWords, len(state.bitmap.bits))

	// A final large jump fills the window with exactly windowLen pending gaps.
	last := state.end
	window.AddPacket(100, last+windowLen+1)
	assert.Len(t, state.gaps, int(windowLen))

	clock.advance(2 * time.Hour)
	packets := window.TransportLayerNacks()
	require.Len(t, packets, 1)
	assert.Len(t, nackSequenceNumbers(packets[0]), int(windowLen))

	// After MaxRetries the gaps expire and the map stays bounded/empty.
	clock.advance(time.Hour)
	for range window.maxRetries {
		_ = window.TransportLayerNacks()
	}
	assert.Empty(t, window.streams[100].gaps)
}

func TestNackWindowDeterministicFeedbackContent(t *testing.T) {
	// One scripted scenario exercising reordering, true loss, wraparound and
	// late recovery in a single sequence, with exact feedback checks per tick.
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     10 * time.Millisecond,
		MaxRetries:      2,
		MaxWindowLength: 64,
	})

	// Around the wrap: FFFE received, FFFF lost, 0001 received.
	window.AddPacket(42, 0xFFFE)
	window.AddPacket(42, 0x0001)

	clock.advance(5 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks()) // still inside reorder wait

	// 0000 arrives late (gap between FFFF and 0001 ordering: FFFF, 0000 both missing);
	// this only fills 0000.
	window.AddPacket(42, 0x0000)
	clock.advance(5 * time.Millisecond) // t = 10ms: FFFF is mature
	first := window.TransportLayerNacks()
	require.Len(t, first, 1)
	assert.Equal(t, []uint16{0xFFFF}, nackSequenceNumbers(first[0]))

	// FFFF never recovers: second report, then expiry.
	clock.advance(10 * time.Millisecond)
	second := window.TransportLayerNacks()
	require.Len(t, second, 1)
	assert.Equal(t, []uint16{0xFFFF}, nackSequenceNumbers(second[0]))

	clock.advance(10 * time.Millisecond)
	assert.Empty(t, window.TransportLayerNacks())
}

func TestNackWindowFuzzInvariants(t *testing.T) {
	window, clock := testWindow(t, NackWindowConfig{
		ReorderWait:     5 * time.Millisecond,
		MaxRetries:      2,
		MaxWindowLength: 16,
	})

	// Deterministic pseudo-random stream of packets across several SSRCs.
	seed := uint32(0x1234_5678)
	nextRand := func() uint32 {
		// xorshift32
		seed ^= seed << 13
		seed ^= seed >> 17
		seed ^= seed << 5

		return seed
	}

	nextSeq := map[uint32]uint16{}

	for range 5000 {
		ssrc := 100 + nextRand()%3
		seq := nextSeq[ssrc]

		// 70% forward progress, 20% repeat/backward, 10% jump.
		switch nextRand() % 10 {
		case 0, 1:
			seq -= uint16(nextRand() % 4) //nolint:gosec // G115
		case 8, 9:
			seq += uint16(nextRand()%20 + 2) //nolint:gosec // G115
		default:
			seq++
		}

		nextSeq[ssrc] = seq
		window.AddPacket(ssrc, seq)

		if nextRand()%3 == 0 {
			clock.advance(5 * time.Millisecond)
		}

		packets := window.TransportLayerNacks()
		for _, packet := range packets {
			assert.NotEmpty(t, packet.Nacks)
			assert.LessOrEqual(t, len(nackSequenceNumbers(packet)), int(window.maxWindowLength))

			for _, pair := range packet.Nacks {
				for _, lost := range pair.PacketList() {
					assert.Contains(t, window.streams[packet.MediaSSRC].gaps, lost)
				}
			}
		}

		for ssrc, state := range window.streams {
			assert.LessOrEqualf(t, len(state.gaps), int(window.maxWindowLength),
				"ssrc %d gap map exceeded window", ssrc)
		}
	}
}

func TestNackWindowConcurrentAccess(t *testing.T) {
	window, err := NewNackWindow(NackWindowConfig{
		ReorderWait:     time.Millisecond,
		MaxRetries:      2,
		MaxWindowLength: 32,
	})
	require.NoError(t, err)

	const goroutines = 8

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)

		go func(offset uint16) {
			defer wg.Done()

			for i := range uint16(500) {
				ssrc := uint32(100 + (i+offset)%4)
				window.AddPacket(ssrc, i+offset)
				_ = window.TransportLayerNacks()
			}
		}(uint16(g * 100))
	}

	wg.Wait()

	// State stays bounded after the concurrent run.
	for ssrc, state := range window.streams {
		assert.LessOrEqualf(t, len(state.gaps), int(window.maxWindowLength),
			"ssrc %d gap map exceeded window", ssrc)
	}
}
