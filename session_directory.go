// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"sort"
	"sync"
	"time"
)

// SessionSource describes a single RTP source tracked by a SessionDirectory.
type SessionSource struct {
	// SSRC is the synchronization source identifier.
	SSRC uint32
	// CNAME is the canonical name (SDES CNAME) the source is currently bound to.
	CNAME string
	// UpdatedAt is the time the binding was last refreshed,
	// as reported by the directory's clock.
	UpdatedAt time.Time
}

// sessionTombstone records that a BYE was received for an SSRC. It protects
// against out-of-order SDES information arriving after the BYE: an SDES that
// would resurrect the exact SSRC/CNAME pair that was said goodbye to is
// treated as stale and ignored.
type sessionTombstone struct {
	cname string
	at    time.Time
}

// SessionDirectory tracks RTP session membership from received RTCP packets.
// It consumes the SourceDescription (SDES) and Goodbye (BYE) packets of
// incoming CompoundPackets and maintains the SSRC/CNAME mapping, so that all
// media SSRCs of a participant can be looked up by their CNAME — even when a
// source changes its SSRC mid-session (for example after a camera restart).
//
// All methods are safe for concurrent use. Time is taken from an injectable
// clock (see WithSessionDirectoryClock) so expiry can be tested deterministically.
//
// Update semantics are deterministic:
//   - SDES chunks without a CNAME item, or with an empty CNAME, are ignored.
//   - If an SSRC is already bound to a different CNAME, the latest SDES wins
//     and the source is rebound to the new CNAME.
//   - A BYE removes the source and records a tombstone. A later SDES repeating
//     the same SSRC/CNAME pair is considered stale (out-of-order old
//     information) and ignored; an SDES binding the SSRC to a different CNAME
//     is accepted as a fresh binding.
//   - A BYE for an unknown or already removed SSRC is a no-op, so duplicate
//     BYEs have no effect.
//   - When the directory is at capacity (see WithSessionDirectoryCapacity),
//     new SSRCs are dropped and Update returns errSessionDirectoryFull;
//     updates to already tracked SSRCs are still applied.
type SessionDirectory struct {
	mu      sync.RWMutex
	now     func() time.Time
	ttl     time.Duration
	maxSize int

	sources map[uint32]SessionSource
	byCNAME map[string]map[uint32]struct{}
	tombs   map[uint32]sessionTombstone
}

// SessionDirectoryOption configures a SessionDirectory.
type SessionDirectoryOption func(*SessionDirectory)

// WithSessionDirectoryClock injects the clock used for update timestamps and
// expiry. Defaults to time.Now.
func WithSessionDirectoryClock(now func() time.Time) SessionDirectoryOption {
	return func(d *SessionDirectory) {
		d.now = now
	}
}

// WithSessionDirectoryTTL sets how long a binding stays active without being
// refreshed by another SDES. A value <= 0 means bindings never expire.
func WithSessionDirectoryTTL(ttl time.Duration) SessionDirectoryOption {
	return func(d *SessionDirectory) {
		d.ttl = ttl
	}
}

// WithSessionDirectoryCapacity bounds the number of sources the directory
// tracks. A value <= 0 means unbounded.
func WithSessionDirectoryCapacity(maxSize int) SessionDirectoryOption {
	return func(d *SessionDirectory) {
		d.maxSize = maxSize
	}
}

// NewSessionDirectory creates an empty SessionDirectory.
func NewSessionDirectory(opts ...SessionDirectoryOption) *SessionDirectory {
	d := &SessionDirectory{
		now:     time.Now,
		sources: make(map[uint32]SessionSource),
		byCNAME: make(map[string]map[uint32]struct{}),
		tombs:   make(map[uint32]sessionTombstone),
	}
	for _, opt := range opts {
		opt(d)
	}

	return d
}

// Update consumes the SourceDescription and Goodbye packets of a received
// CompoundPacket and applies them to the directory. All other packet types
// are ignored. It returns errSessionDirectoryFull if at least one new source
// had to be dropped because the directory is at capacity; all other updates
// are still applied.
func (d *SessionDirectory) Update(pkt CompoundPacket) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.now()
	d.expireLocked(now)

	var err error
	for _, p := range pkt {
		switch p := p.(type) {
		case *SourceDescription:
			if d.applySDESLocked(p, now) {
				err = errSessionDirectoryFull
			}
		case *Goodbye:
			d.applyGoodbyeLocked(p, now)
		}
	}

	return err
}

// Sources returns the active (non-expired) sources bound to cname, ordered by
// SSRC. It returns nil if the CNAME has no active sources.
func (d *SessionDirectory) Sources(cname string) []SessionSource {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := d.now()
	var out []SessionSource
	for ssrc := range d.byCNAME[cname] {
		src, ok := d.sources[ssrc]
		if !ok || d.isExpired(src, now) {
			continue
		}
		out = append(out, src)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SSRC < out[j].SSRC })

	return out
}

// Lookup returns the current binding for ssrc, or false if the SSRC is not
// tracked (unknown, removed by BYE, or expired).
func (d *SessionDirectory) Lookup(ssrc uint32) (SessionSource, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	src, ok := d.sources[ssrc]
	if !ok || d.isExpired(src, d.now()) {
		return SessionSource{}, false
	}

	return src, true
}

// CNAMEs returns the canonical names that have at least one active source,
// in sorted order.
func (d *SessionDirectory) CNAMEs() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := d.now()
	out := make([]string, 0, len(d.byCNAME))
	for cname, ssrcs := range d.byCNAME {
		for ssrc := range ssrcs {
			if src, ok := d.sources[ssrc]; ok && !d.isExpired(src, now) {
				out = append(out, cname)

				break
			}
		}
	}
	sort.Strings(out)

	return out
}

// Len returns the number of active (non-expired) sources.
func (d *SessionDirectory) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := d.now()
	n := 0
	for _, src := range d.sources {
		if !d.isExpired(src, now) {
			n++
		}
	}

	return n
}

// Expire removes all bindings and tombstones whose TTL has elapsed and
// returns the number of sources removed. Expired entries are also skipped
// lazily by the query methods and before each Update; Expire reclaims their
// capacity eagerly.
func (d *SessionDirectory) Expire() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.expireLocked(d.now())
}

func (d *SessionDirectory) isExpired(src SessionSource, now time.Time) bool {
	return d.ttl > 0 && now.Sub(src.UpdatedAt) >= d.ttl
}

// applySDESLocked applies every CNAME item of the packet and reports whether
// at least one new source was dropped due to capacity.
func (d *SessionDirectory) applySDESLocked(sdes *SourceDescription, now time.Time) (dropped bool) {
	for _, chunk := range sdes.Chunks {
		for _, item := range chunk.Items {
			if item.Type != SDESCNAME || item.Text == "" {
				continue
			}
			if !d.bindLocked(chunk.Source, item.Text, now) {
				dropped = true
			}
		}
	}

	return dropped
}

// bindLocked binds ssrc to cname. It reports false only when the source is
// new and the directory is at capacity.
func (d *SessionDirectory) bindLocked(ssrc uint32, cname string, now time.Time) bool {
	if tomb, ok := d.tombs[ssrc]; ok {
		if tomb.cname == cname {
			// Stale, out-of-order SDES for a source that was said
			// goodbye to: ignore it.
			return true
		}
		// The SSRC was reused for a different CNAME: accept the fresh binding.
		delete(d.tombs, ssrc)
	}

	if existing, ok := d.sources[ssrc]; ok {
		if existing.CNAME != cname {
			d.removeFromIndexLocked(ssrc, existing.CNAME)
			d.addToIndexLocked(ssrc, cname)
		}
		d.sources[ssrc] = SessionSource{SSRC: ssrc, CNAME: cname, UpdatedAt: now}

		return true
	}

	if d.maxSize > 0 && len(d.sources) >= d.maxSize {
		return false
	}
	d.sources[ssrc] = SessionSource{SSRC: ssrc, CNAME: cname, UpdatedAt: now}
	d.addToIndexLocked(ssrc, cname)

	return true
}

func (d *SessionDirectory) applyGoodbyeLocked(bye *Goodbye, now time.Time) {
	for _, ssrc := range bye.Sources {
		src, ok := d.sources[ssrc]
		if !ok {
			// Unknown or already removed source: duplicate BYEs are no-ops.
			continue
		}
		d.removeFromIndexLocked(ssrc, src.CNAME)
		delete(d.sources, ssrc)
		d.tombs[ssrc] = sessionTombstone{cname: src.CNAME, at: now}
		d.evictTombstonesLocked()
	}
}

func (d *SessionDirectory) expireLocked(now time.Time) (expired int) {
	if d.ttl <= 0 {
		return 0
	}
	for ssrc, src := range d.sources {
		if d.isExpired(src, now) {
			d.removeFromIndexLocked(ssrc, src.CNAME)
			delete(d.sources, ssrc)
			expired++
		}
	}
	for ssrc, tomb := range d.tombs {
		if now.Sub(tomb.at) >= d.ttl {
			delete(d.tombs, ssrc)
		}
	}

	return expired
}

// evictTombstonesLocked keeps the tombstone table bounded by the configured
// capacity, evicting the oldest entries first (ties broken by SSRC so the
// result is deterministic).
func (d *SessionDirectory) evictTombstonesLocked() {
	if d.maxSize <= 0 {
		return
	}
	for len(d.tombs) > d.maxSize {
		var oldestSSRC uint32
		var oldest time.Time
		first := true
		for ssrc, tomb := range d.tombs {
			if first || tomb.at.Before(oldest) || (tomb.at.Equal(oldest) && ssrc < oldestSSRC) {
				first = false
				oldest = tomb.at
				oldestSSRC = ssrc
			}
		}
		delete(d.tombs, oldestSSRC)
	}
}

func (d *SessionDirectory) addToIndexLocked(ssrc uint32, cname string) {
	ssrcs, ok := d.byCNAME[cname]
	if !ok {
		ssrcs = make(map[uint32]struct{})
		d.byCNAME[cname] = ssrcs
	}
	ssrcs[ssrc] = struct{}{}
}

func (d *SessionDirectory) removeFromIndexLocked(ssrc uint32, cname string) {
	ssrcs, ok := d.byCNAME[cname]
	if !ok {
		return
	}
	delete(ssrcs, ssrc)
	if len(ssrcs) == 0 {
		delete(d.byCNAME, cname)
	}
}
