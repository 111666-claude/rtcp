// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"cmp"
	"errors"
	"math"
	"slices"
	"sync"
	"time"
)

const (
	// DefaultREMBTrackerTTL is how long a REMB report stays valid without
	// being refreshed by a newer report for the same media SSRC.
	DefaultREMBTrackerTTL = 10 * time.Second

	// DefaultREMBTrackerCapacity is the default upper bound on the number of
	// media SSRCs tracked and on the number of BYE tombstones retained.
	DefaultREMBTrackerCapacity = 1024
)

// ErrInvalidREMBBitrate is returned by REMBTracker.Update when a REMB carries
// a bitrate that is not positive and finite. Such a report is ignored and
// existing state is left untouched.
var ErrInvalidREMBBitrate = errors.New("rtcp: REMB bitrate must be positive and finite")

// REMBReport is the most recent receiver estimated maximum bitrate reported
// for one media SSRC.
type REMBReport struct {
	// SSRC is the media source the estimate applies to.
	SSRC uint32
	// Bitrate is the estimated maximum bitrate in bits per second.
	Bitrate float32
	// SenderSSRC is the SSRC of the feedback sender that reported the estimate.
	SenderSSRC uint32
	// ReportedAt is the local time at which the report was accepted, as read
	// from the tracker's clock.
	ReportedAt time.Time
}

// rembTombstone records that a media SSRC was removed by a Goodbye, so that an
// in-flight REMB from the sender that reported it cannot resurrect the source.
type rembTombstone struct {
	senderSSRC uint32
	at         time.Time
}

// REMBTracker tracks the latest receiver estimated maximum bitrate (REMB)
// reported for each media SSRC, so that a sender can look up the bitrate
// currently available to every stream it is sending.
//
// Received RTCP is fed in through Update, typically with the []Packet returned
// by Unmarshal. Only REMB and Goodbye packets are applied; every other packet
// type is ignored. A single REMB updates all media SSRCs it lists, and a
// Goodbye drops the reports of the sources that have left. The current state
// is read with Lookup or Reports.
//
// Time is read from an injectable clock (see WithREMBTrackerClock), so expiry
// is deterministic in tests. Expired reports are reported as absent by the
// query methods and are reclaimed by Update and Expire.
//
// Update semantics are deterministic:
//   - A REMB whose bitrate is zero, negative, NaN or infinite is rejected
//     with ErrInvalidREMBBitrate; its SSRCs are not updated.
//   - A REMB with an empty SSRC list updates nothing and is not an error.
//   - A media SSRC repeated inside one REMB is applied once.
//   - A report is stale when its receipt time is earlier than the receipt
//     time of the report already stored for that SSRC; a stale report never
//     replaces a newer one. Packets are applied in the order supplied, so
//     among several reports for the same SSRC read at the same instant the
//     last one wins.
//   - A Goodbye removes the reports of the SSRCs it lists and remembers the
//     sender of each removed report for the TTL. A later REMB for that SSRC
//     from the same sender is treated as an in-flight stale report and
//     ignored; a report from a different sender is accepted as a new receiver.
//     A Goodbye for an SSRC that is not tracked is a no-op.
//   - When the tracker is at capacity (see WithREMBTrackerCapacity), the
//     least recently reported SSRC is evicted to make room for a new one;
//     ties are resolved by evicting the numerically largest SSRC. Expired
//     entries are reclaimed before any live entry is evicted.
//
// All methods are safe for concurrent use.
type REMBTracker struct {
	mu       sync.RWMutex
	now      func() time.Time
	ttl      time.Duration
	capacity int

	reports map[uint32]REMBReport
	tombs   map[uint32]rembTombstone
}

// REMBTrackerOption configures a REMBTracker.
type REMBTrackerOption func(*REMBTracker)

// WithREMBTrackerClock injects the clock used for report timestamps and
// expiry. Defaults to time.Now. A nil clock is ignored.
func WithREMBTrackerClock(now func() time.Time) REMBTrackerOption {
	return func(t *REMBTracker) {
		if now != nil {
			t.now = now
		}
	}
}

// WithREMBTrackerTTL sets how long a report stays valid without being
// refreshed, and how long a Goodbye tombstone shields a removed SSRC. A value
// <= 0 means reports never expire and Goodbyes are not tombstoned.
func WithREMBTrackerTTL(ttl time.Duration) REMBTrackerOption {
	return func(t *REMBTracker) {
		t.ttl = ttl
	}
}

// WithREMBTrackerCapacity bounds the number of reports tracked and the number
// of Goodbye tombstones retained. A value <= 0 means unbounded. Bounds apply
// independently to the report and tombstone tables.
func WithREMBTrackerCapacity(capacity int) REMBTrackerOption {
	return func(t *REMBTracker) {
		t.capacity = capacity
	}
}

// NewREMBTracker creates an empty tracker with DefaultREMBTrackerTTL and
// DefaultREMBTrackerCapacity, overridden by any supplied options.
func NewREMBTracker(opts ...REMBTrackerOption) *REMBTracker {
	tracker := &REMBTracker{
		now:      time.Now,
		ttl:      DefaultREMBTrackerTTL,
		capacity: DefaultREMBTrackerCapacity,
		reports:  make(map[uint32]REMBReport),
		tombs:    make(map[uint32]rembTombstone),
	}

	for _, opt := range opts {
		opt(tracker)
	}

	return tracker
}

// Update consumes RTCP packets in arrival order and applies their REMB and
// Goodbye information. Packets of any other type, including nil packets, are
// ignored. All packets in one call are stamped with the same clock reading.
//
// Every valid report is applied even when another packet in the call is
// invalid; the returned error joins ErrInvalidREMBBitrate for each rejected
// REMB.
func (t *REMBTracker) Update(pkts ...Packet) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	t.expireLocked(now)

	return errors.Join(t.applyPacketsLocked(pkts, now)...)
}

func (t *REMBTracker) applyPacketsLocked(pkts []Packet, now time.Time) []error {
	var errs []error

	for _, pkt := range pkts {
		switch typed := pkt.(type) {
		case nil:
			continue
		case *ReceiverEstimatedMaximumBitrate:
			if typed == nil {
				continue
			}
			if err := t.applyREMBLocked(typed, now); err != nil {
				errs = append(errs, err)
			}
		case *Goodbye:
			if typed == nil {
				continue
			}
			t.applyGoodbyeLocked(typed, now)
		}
	}

	return errs
}

// applyREMBLocked stores the estimate for every listed media SSRC, skipping
// duplicates, tombstoned sources and stale reports.
func (t *REMBTracker) applyREMBLocked(pkt *ReceiverEstimatedMaximumBitrate, now time.Time) error {
	if !validREMBitrate(pkt.Bitrate) {
		return ErrInvalidREMBBitrate
	}

	seen := make(map[uint32]struct{}, len(pkt.SSRCs))
	for _, ssrc := range pkt.SSRCs {
		if _, ok := seen[ssrc]; ok {
			continue
		}
		seen[ssrc] = struct{}{}

		if t.ignoredLocked(ssrc, pkt.SenderSSRC, now) {
			continue
		}

		t.storeLocked(REMBReport{
			SSRC:       ssrc,
			Bitrate:    pkt.Bitrate,
			SenderSSRC: pkt.SenderSSRC,
			ReportedAt: now,
		})
	}

	return nil
}

// ignoredLocked reports whether a REMB for ssrc from sender must not be
// applied, either because a Goodbye tombstone is still active for the same
// sender or because the stored report was received after now.
func (t *REMBTracker) ignoredLocked(ssrc, sender uint32, now time.Time) bool {
	// Expired tombstones are dropped by expireLocked before any packet of an
	// Update call is applied, so an entry found here is still active.
	if tomb, ok := t.tombs[ssrc]; ok {
		return tomb.senderSSRC == sender
	}

	if existing, ok := t.reports[ssrc]; ok && now.Before(existing.ReportedAt) {
		return true
	}

	return false
}

// applyGoodbyeLocked removes the listed sources and remembers who last
// reported each of them, so an in-flight report from that sender cannot bring
// the source back.
func (t *REMBTracker) applyGoodbyeLocked(bye *Goodbye, now time.Time) {
	for _, ssrc := range bye.Sources {
		report, ok := t.reports[ssrc]
		if !ok {
			// Unknown or already removed source: duplicate BYEs are no-ops.
			continue
		}

		delete(t.reports, ssrc)

		if t.ttl > 0 {
			t.tombs[ssrc] = rembTombstone{senderSSRC: report.SenderSSRC, at: now}
			t.evictTombstonesLocked()
		}
	}
}

// storeLocked writes one report, evicting the least recently reported SSRC
// when a new SSRC would exceed the configured capacity.
func (t *REMBTracker) storeLocked(report REMBReport) {
	if _, ok := t.reports[report.SSRC]; !ok && t.capacity > 0 && len(t.reports) >= t.capacity {
		t.evictOldestReportLocked()
	}

	t.reports[report.SSRC] = report
}

// evictOldestReportLocked removes the report with the earliest receipt time.
// Ties are broken by evicting the numerically largest SSRC.
func (t *REMBTracker) evictOldestReportLocked() {
	var victim uint32
	var oldest time.Time
	first := true

	for ssrc, report := range t.reports {
		if first || report.ReportedAt.Before(oldest) ||
			(report.ReportedAt.Equal(oldest) && ssrc > victim) {
			victim = ssrc
			oldest = report.ReportedAt
			first = false
		}
	}

	if !first {
		delete(t.reports, victim)
	}
}

// evictTombstonesLocked keeps the tombstone table within capacity, removing
// the earliest entries first. Ties are broken by removing the largest SSRC.
func (t *REMBTracker) evictTombstonesLocked() {
	if t.capacity <= 0 {
		return
	}

	for len(t.tombs) > t.capacity {
		var victim uint32
		var oldest time.Time
		first := true

		for ssrc, tomb := range t.tombs {
			if first || tomb.at.Before(oldest) ||
				(tomb.at.Equal(oldest) && ssrc > victim) {
				victim = ssrc
				oldest = tomb.at
				first = false
			}
		}

		delete(t.tombs, victim)
	}
}

// Lookup returns the current report for ssrc. It returns false when the SSRC
// was never reported, was removed by a Goodbye, was evicted, or its report has
// expired. Lookup itself never refreshes the report timestamp.
func (t *REMBTracker) Lookup(ssrc uint32) (REMBReport, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	report, ok := t.reports[ssrc]
	if !ok || t.isExpired(report, t.now()) {
		return REMBReport{}, false
	}

	return report, true
}

// Reports returns all active reports ordered by SSRC. Expired reports are
// omitted. The returned slice is a copy and may be modified by the caller.
func (t *REMBTracker) Reports() []REMBReport {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := t.now()
	reports := make([]REMBReport, 0, len(t.reports))
	for _, report := range t.reports {
		if t.isExpired(report, now) {
			continue
		}
		reports = append(reports, report)
	}

	slices.SortFunc(reports, func(a, b REMBReport) int {
		return cmp.Compare(a.SSRC, b.SSRC)
	})

	return reports
}

// Len returns the number of active reports.
func (t *REMBTracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := t.now()
	active := 0
	for _, report := range t.reports {
		if !t.isExpired(report, now) {
			active++
		}
	}

	return active
}

// Expire removes expired reports and tombstones and returns the number of
// reports removed. Expired entries are also skipped lazily by the query
// methods and reclaimed at the start of each Update; Expire reclaims their
// memory eagerly.
func (t *REMBTracker) Expire() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.expireLocked(t.now())
}

// Remove drops all state for ssrc, including a Goodbye tombstone, so the SSRC
// can be tracked again immediately. It is useful when the local application
// knows a stream has ended and its SSRC may be reused.
func (t *REMBTracker) Remove(ssrc uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.reports, ssrc)
	delete(t.tombs, ssrc)
}

// Reset clears all reports and tombstones while keeping the tracker's clock,
// TTL and capacity configuration.
func (t *REMBTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.reports = make(map[uint32]REMBReport)
	t.tombs = make(map[uint32]rembTombstone)
}

func (t *REMBTracker) expireLocked(now time.Time) int {
	if t.ttl <= 0 {
		return 0
	}

	expired := 0
	for ssrc, report := range t.reports {
		if t.isExpired(report, now) {
			delete(t.reports, ssrc)
			expired++
		}
	}

	for ssrc, tomb := range t.tombs {
		if t.tombstoneExpired(tomb, now) {
			delete(t.tombs, ssrc)
		}
	}

	return expired
}

func (t *REMBTracker) isExpired(report REMBReport, now time.Time) bool {
	return t.ttl > 0 && !now.Before(report.ReportedAt.Add(t.ttl))
}

func (t *REMBTracker) tombstoneExpired(tomb rembTombstone, now time.Time) bool {
	return t.ttl <= 0 || !now.Before(tomb.at.Add(t.ttl))
}

// validREMBitrate reports whether a REMB estimate can be tracked. Zero,
// negative, NaN and infinite values are not usable bitrates.
func validREMBitrate(bitrate float32) bool {
	return bitrate > 0 && !math.IsInf(float64(bitrate), 0)
}
