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

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock {
	return &manualClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func cnamePacket(ssrc uint32, cname string) CompoundPacket {
	return CompoundPacket{&ReceiverReport{}, NewCNAMESourceDescription(ssrc, cname)}
}

func byePacket(reason string, ssrcs ...uint32) CompoundPacket {
	return CompoundPacket{&ReceiverReport{}, &Goodbye{Sources: ssrcs, Reason: reason}}
}

// roundTrip marshals and unmarshals a CompoundPacket so the directory is fed
// exactly what would arrive on the wire.
func roundTrip(t *testing.T, pkt CompoundPacket) CompoundPacket {
	t.Helper()

	raw, err := pkt.Marshal()
	require.NoError(t, err)

	var out CompoundPacket
	require.NoError(t, out.Unmarshal(raw))

	return out
}

func ssrcsOf(sources []SessionSource) []uint32 {
	out := make([]uint32, len(sources))
	for i, s := range sources {
		out[i] = s.SSRC
	}

	return out
}

func TestSessionDirectoryBasicMapping(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(WithSessionDirectoryClock(clock.Now))

	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	require.NoError(t, dir.Update(cnamePacket(2000, "alice")))
	require.NoError(t, dir.Update(cnamePacket(3000, "bob")))

	// Multiple media SSRCs of one participant share a CNAME.
	assert.Equal(t, []uint32{1000, 2000}, ssrcsOf(dir.Sources("alice")))
	assert.Equal(t, []uint32{3000}, ssrcsOf(dir.Sources("bob")))
	assert.Nil(t, dir.Sources("carol"))
	assert.Equal(t, []string{"alice", "bob"}, dir.CNAMEs())
	assert.Equal(t, 3, dir.Len())

	// Last update time comes from the injected clock.
	src, ok := dir.Lookup(1000)
	require.True(t, ok)
	assert.Equal(t, "alice", src.CNAME)
	assert.Equal(t, clock.Now(), src.UpdatedAt)

	_, ok = dir.Lookup(9999)
	assert.False(t, ok)

	// A refresh advances the update timestamp.
	clock.Advance(time.Second)
	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	src, ok = dir.Lookup(1000)
	require.True(t, ok)
	assert.Equal(t, clock.Now(), src.UpdatedAt)
}

func TestSessionDirectorySourceRebind(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(WithSessionDirectoryClock(clock.Now))

	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	// The same SSRC is later claimed by a different CNAME: latest wins.
	require.NoError(t, dir.Update(cnamePacket(1000, "bob")))

	assert.Nil(t, dir.Sources("alice"))
	assert.Equal(t, []uint32{1000}, ssrcsOf(dir.Sources("bob")))
	src, ok := dir.Lookup(1000)
	require.True(t, ok)
	assert.Equal(t, "bob", src.CNAME)
}

func TestSessionDirectorySSRCMigration(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(WithSessionDirectoryClock(clock.Now))

	// Alice sends audio and video under one CNAME.
	require.NoError(t, dir.Update(CompoundPacket{
		&ReceiverReport{},
		&SourceDescription{Chunks: []SourceDescriptionChunk{
			{Source: 1111, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: "alice"}}},
			{Source: 2222, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: "alice"}}},
		}},
	}))
	assert.Equal(t, []uint32{1111, 2222}, ssrcsOf(dir.Sources("alice")))

	// The camera restarts: the old video SSRC says goodbye and a new video
	// SSRC appears with the same CNAME.
	require.NoError(t, dir.Update(byePacket("camera restart", 2222)))
	require.NoError(t, dir.Update(cnamePacket(3333, "alice")))

	// The participant is still one CNAME with two media sources.
	assert.Equal(t, []uint32{1111, 3333}, ssrcsOf(dir.Sources("alice")))
	_, ok := dir.Lookup(2222)
	assert.False(t, ok)
}

func TestSessionDirectoryStaleSDESAfterBye(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(WithSessionDirectoryClock(clock.Now))

	require.NoError(t, dir.Update(cnamePacket(2222, "alice")))
	require.NoError(t, dir.Update(byePacket("", 2222)))

	// A delayed copy of the old SDES arrives out of order: it must not
	// resurrect the source it describes.
	require.NoError(t, dir.Update(cnamePacket(2222, "alice")))
	assert.Nil(t, dir.Sources("alice"))
	_, ok := dir.Lookup(2222)
	assert.False(t, ok)

	// The same SSRC reused for a different CNAME is a fresh binding.
	require.NoError(t, dir.Update(cnamePacket(2222, "mallory")))
	assert.Equal(t, []uint32{2222}, ssrcsOf(dir.Sources("mallory")))
}

func TestSessionDirectoryDuplicateAndUnknownBye(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(WithSessionDirectoryClock(clock.Now))

	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	require.NoError(t, dir.Update(byePacket("", 1000)))

	// Duplicate BYE and BYE for an unknown SSRC are no-ops.
	require.NoError(t, dir.Update(byePacket("", 1000)))
	require.NoError(t, dir.Update(byePacket("", 4242)))
	assert.Equal(t, 0, dir.Len())
	assert.Empty(t, dir.CNAMEs())

	// The tombstone from the first BYE is still in effect.
	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	assert.Equal(t, 0, dir.Len())
}

func TestSessionDirectoryEmptyAndMissingCNAME(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(WithSessionDirectoryClock(clock.Now))

	require.NoError(t, dir.Update(CompoundPacket{
		&ReceiverReport{},
		&SourceDescription{Chunks: []SourceDescriptionChunk{
			// Empty CNAME text: ignored.
			{Source: 1000, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: ""}}},
			// No CNAME item at all: ignored.
			{Source: 2000, Items: []SourceDescriptionItem{{Type: SDESName, Text: "Alice"}}},
		}},
	}))

	assert.Equal(t, 0, dir.Len())
	assert.Nil(t, dir.Sources(""))
	_, ok := dir.Lookup(1000)
	assert.False(t, ok)
	_, ok = dir.Lookup(2000)
	assert.False(t, ok)
}

func TestSessionDirectoryExpiry(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(
		WithSessionDirectoryClock(clock.Now),
		WithSessionDirectoryTTL(time.Minute),
	)

	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	clock.Advance(30 * time.Second)
	require.NoError(t, dir.Update(cnamePacket(2000, "alice")))

	// Queries skip expired sources lazily.
	clock.Advance(31 * time.Second) // 1000 is 61s old, 2000 is 31s old
	assert.Equal(t, []uint32{2000}, ssrcsOf(dir.Sources("alice")))
	_, ok := dir.Lookup(1000)
	assert.False(t, ok)
	assert.Equal(t, 1, dir.Len())

	// Expire reclaims the stale entry eagerly.
	assert.Equal(t, 1, dir.Expire())
	assert.Equal(t, 0, dir.Expire())

	clock.Advance(time.Minute)
	assert.Equal(t, 1, dir.Expire())
	assert.Equal(t, 0, dir.Len())
	assert.Empty(t, dir.CNAMEs())

	// Expired state is fully forgotten: the old SDES is accepted again.
	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	assert.Equal(t, []uint32{1000}, ssrcsOf(dir.Sources("alice")))
}

func TestSessionDirectoryCapacity(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(
		WithSessionDirectoryClock(clock.Now),
		WithSessionDirectoryCapacity(2),
	)

	require.NoError(t, dir.Update(cnamePacket(1000, "alice")))
	require.NoError(t, dir.Update(cnamePacket(2000, "bob")))

	// A new SSRC beyond capacity is dropped and reported.
	err := dir.Update(cnamePacket(3000, "carol"))
	assert.ErrorIs(t, err, errSessionDirectoryFull)
	assert.Equal(t, 2, dir.Len())
	assert.Nil(t, dir.Sources("carol"))

	// Updates to tracked SSRCs still apply at capacity.
	require.NoError(t, dir.Update(cnamePacket(1000, "alice2")))
	assert.Equal(t, []uint32{1000}, ssrcsOf(dir.Sources("alice2")))

	// Capacity is freed by BYE.
	require.NoError(t, dir.Update(byePacket("", 2000)))
	require.NoError(t, dir.Update(cnamePacket(3000, "carol")))
	assert.Equal(t, []uint32{3000}, ssrcsOf(dir.Sources("carol")))
}

func TestSessionDirectoryMultiParticipantTimeline(t *testing.T) {
	clock := newManualClock()
	dir := NewSessionDirectory(
		WithSessionDirectoryClock(clock.Now),
		WithSessionDirectoryTTL(60*time.Second),
	)

	update := func(pkt CompoundPacket) {
		t.Helper()
		require.NoError(t, dir.Update(roundTrip(t, pkt)))
	}

	// t=0: alice (audio+video) and bob (audio+video) join.
	update(CompoundPacket{
		&ReceiverReport{},
		&SourceDescription{Chunks: []SourceDescriptionChunk{
			{Source: 1111, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: "alice"}}},
			{Source: 2222, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: "alice"}}},
		}},
	})
	update(CompoundPacket{
		&ReceiverReport{},
		&SourceDescription{Chunks: []SourceDescriptionChunk{
			{Source: 3333, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: "bob"}}},
			{Source: 4444, Items: []SourceDescriptionItem{{Type: SDESCNAME, Text: "bob"}}},
		}},
	})
	assert.Equal(t, []string{"alice", "bob"}, dir.CNAMEs())

	// t=10s: alice's camera restarts. Her video SSRC migrates 2222 -> 5555.
	clock.Advance(10 * time.Second)
	update(CompoundPacket{
		&ReceiverReport{},
		NewCNAMESourceDescription(1111, "alice"),
		&Goodbye{Sources: []uint32{2222}, Reason: "camera restart"},
	})
	update(cnamePacket(5555, "alice"))
	assert.Equal(t, []uint32{1111, 5555}, ssrcsOf(dir.Sources("alice")))

	// t=20s: a delayed copy of alice's original SDES arrives out of order.
	// The migrated-away SSRC 2222 must stay gone.
	clock.Advance(10 * time.Second)
	update(cnamePacket(2222, "alice"))
	assert.Equal(t, []uint32{1111, 5555}, ssrcsOf(dir.Sources("alice")))

	// t=30s: SSRC collision — carol claims bob's audio SSRC 3333.
	clock.Advance(10 * time.Second)
	update(cnamePacket(3333, "carol"))
	assert.Equal(t, []uint32{4444}, ssrcsOf(dir.Sources("bob")))
	assert.Equal(t, []uint32{3333}, ssrcsOf(dir.Sources("carol")))

	// t=45s: bob refreshes his video source.
	clock.Advance(15 * time.Second)
	update(cnamePacket(4444, "bob"))

	// t=70s: alice's sources (last seen t=10s) hit the TTL and expire;
	// carol's and bob's refreshed bindings are still active.
	clock.Advance(25 * time.Second)
	assert.Nil(t, dir.Sources("alice"))
	assert.Equal(t, []uint32{4444}, ssrcsOf(dir.Sources("bob")))
	assert.Equal(t, []uint32{3333}, ssrcsOf(dir.Sources("carol")))

	// t=95s: carol's binding (t=30s) expires too; only bob's refreshed
	// video source (t=45s) remains.
	clock.Advance(25 * time.Second)
	assert.Equal(t, 3, dir.Expire())
	assert.Equal(t, []string{"bob"}, dir.CNAMEs())
	assert.Equal(t, []uint32{4444}, ssrcsOf(dir.Sources("bob")))
}

func TestSessionDirectoryConcurrentAccess(t *testing.T) {
	dir := NewSessionDirectory(
		WithSessionDirectoryTTL(time.Minute),
		WithSessionDirectoryCapacity(64),
	)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ssrc := uint32(i*10 + 1) //nolint:gosec // G115
			for j := 0; j < 100; j++ {
				assert.NoError(t, dir.Update(cnamePacket(ssrc, "alice")))
				assert.NoError(t, dir.Update(byePacket("", ssrc)))
				_ = dir.Sources("alice")
				_, _ = dir.Lookup(ssrc)
				_ = dir.CNAMEs()
				_ = dir.Len()
				_ = dir.Expire()
			}
		}(i)
	}
	wg.Wait()
}
