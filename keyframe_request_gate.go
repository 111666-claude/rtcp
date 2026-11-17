// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"slices"
	"sync"
	"time"
)

const (
	// defaultKeyframeRequestGateCapacity is the default upper bound on the number
	// of per-media-SSRC states retained by a KeyframeRequestGate.
	defaultKeyframeRequestGateCapacity = 128
)

// Sentinel errors returned by the KeyframeRequestGate. They are wrapped, never
// recreated, so callers can use errors.Is to match them.
var (
	// ErrInvalidCooldown is returned when a negative cooldown is configured.
	ErrInvalidCooldown = errors.New("rtcp: keyframe request gate cooldown must not be negative")
	// ErrInvalidCapacity is returned when a negative capacity is configured.
	ErrInvalidCapacity = errors.New("rtcp: keyframe request gate capacity must not be negative")
	// ErrUnsupportedFeedback is returned by Process for packets that are neither
	// PictureLossIndication nor FullIntraRequest.
	ErrUnsupportedFeedback = errors.New("rtcp: keyframe request gate only accepts PLI and FIR feedback packets")
	// ErrMissingTargetSSRC is returned when a PLI or an FIR entry carries no
	// target media SSRC (zero).
	ErrMissingTargetSSRC = errors.New("rtcp: keyframe request is missing a target media SSRC")
	// ErrStaleFIRSequenceNumber is returned when an FIR sequence number is a
	// duplicate or an out-of-order value relative to the per-media-SSRC
	// sequence-number baseline.
	ErrStaleFIRSequenceNumber = errors.New("rtcp: FIR sequence number is a duplicate or out of order")
	// ErrGateCapacityExceeded is returned when no expired or idle state can be
	// reclaimed and the gate already tracks MaxTrackedSSRCs media SSRCs.
	ErrGateCapacityExceeded = errors.New("rtcp: keyframe request gate capacity exceeded")
)

// KeyframeRequestType identifies the feedback mechanism of a coalesced request.
type KeyframeRequestType uint8

const (
	// KeyframeRequestPLI is a Picture Loss Indication (RFC 4585, Section 6.3.1).
	KeyframeRequestPLI KeyframeRequestType = iota + 1
	// KeyframeRequestFIR is a Full Intra Request (RFC 5104, Section 3.5.1).
	KeyframeRequestFIR
)

// KeyframeRequest is a single keyframe request to forward towards an encoder.
// It may represent several incoming feedback packets coalesced during the
// configured cooldown window.
type KeyframeRequest struct {
	// Type is the feedback mechanism that should be forwarded.
	Type KeyframeRequestType
	// MediaSSRC is the target media SSRC the request applies to.
	MediaSSRC uint32
	// FIRSequenceNumber carries the FIR sequence number to forward. It is zero
	// for KeyframeRequestPLI.
	FIRSequenceNumber uint8
	// Count is the number of incoming requests coalesced into this one,
	// including the request that created it.
	Count int
}

// KeyframeRequestGateConfig configures a KeyframeRequestGate.
type KeyframeRequestGateConfig struct {
	// Cooldown is the window during which requests targeting the same media
	// SSRC are coalesced into a single forwarded request. A zero Cooldown
	// disables coalescing: every well-formed request is forwarded immediately
	// and no per-SSRC state is retained.
	Cooldown time.Duration
	// MaxTrackedSSRCs bounds the number of per-media-SSRC states kept by the
	// gate. Zero selects defaultKeyframeRequestGateCapacity.
	MaxTrackedSSRCs int
	// Clock is the injectable time source. When nil, time.Now is used.
	Clock func() time.Time
}

// KeyframeRequestGate coalesces PLI and FIR feedback packets that target the
// same media SSRC. When several subscribers react to the same loss burst, only
// one effective keyframe request per media SSRC is forwarded within the
// configured cooldown window; suppressed requests are counted and, once the
// window elapses, delivered as a single pending event.
//
// All methods are safe for concurrent use. State is keyed on the target media
// SSRC only, so changes of the feedback sender SSRC never produce a second
// forwarding decision. Use Reset or ResetAll when a media SSRC is re-bound and
// its state must be forgotten.
type KeyframeRequestGate struct {
	mu       sync.Mutex
	cooldown time.Duration
	capacity int
	clock    func() time.Time
	states   map[uint32]*keyframeRequestState
}

// keyframeRequestState is the per-media-SSRC gate state.
type keyframeRequestState struct {
	// lastEmittedAt is the time the last request was forwarded for this SSRC.
	lastEmittedAt time.Time
	// lastSeenAt is the time of the most recent accepted input for this SSRC.
	lastSeenAt time.Time
	// lastFIRSeq is the highest accepted FIR sequence number.
	lastFIRSeq uint8
	// hasFIRSeq reports whether an FIR sequence number was ever accepted.
	hasFIRSeq bool
	// pending holds the coalesced request waiting for the cooldown to elapse.
	pending *KeyframeRequest
}

// NewKeyframeRequestGate constructs a gate from the given configuration.
func NewKeyframeRequestGate(config KeyframeRequestGateConfig) (*KeyframeRequestGate, error) {
	if config.Cooldown < 0 {
		return nil, ErrInvalidCooldown
	}

	capacity := config.MaxTrackedSSRCs
	if capacity == 0 {
		capacity = defaultKeyframeRequestGateCapacity
	} else if capacity < 0 {
		return nil, ErrInvalidCapacity
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	return &KeyframeRequestGate{
		cooldown: config.Cooldown,
		capacity: capacity,
		clock:    clock,
		states:   make(map[uint32]*keyframeRequestState),
	}, nil
}

// Process consumes one PLI or FIR packet and returns the requests that must be
// forwarded immediately. A returned slice can contain more than one request
// when an earlier coalesced request for one of the packet's target SSRCs has
// become due. Requests suppressed by the cooldown are retained and delivered by
// FlushDue.
//
// Packets of any other type are rejected with ErrUnsupportedFeedback and leave
// the gate state untouched. A PLI without a media SSRC and an FIR containing an
// entry without a media SSRC are rejected with ErrMissingTargetSSRC. FIR
// entries with duplicate or out-of-order sequence numbers, including a target
// SSRC repeated within the same FIR packet, are rejected with
// ErrStaleFIRSequenceNumber; an FIR packet is validated before any state is
// modified, so a rejection changes nothing.
func (g *KeyframeRequestGate) Process(packet Packet) ([]KeyframeRequest, error) {
	switch feedback := packet.(type) {
	case *PictureLossIndication:
		if feedback == nil {
			return nil, ErrUnsupportedFeedback
		}
		if feedback.MediaSSRC == 0 {
			return nil, ErrMissingTargetSSRC
		}

		return g.processPLI(feedback.MediaSSRC)
	case *FullIntraRequest:
		if feedback == nil {
			return nil, ErrUnsupportedFeedback
		}
		if err := validateFIREntries(feedback); err != nil {
			return nil, err
		}

		return g.processFIR(feedback.FIR)
	default:
		return nil, ErrUnsupportedFeedback
	}
}

// ProcessRaw unmarshals one RTCP datagram, which may be a compound packet, and
// feeds every PLI and FIR packet it contains through the gate. Other packet
// types, such as the sender report and source description members of a regular
// compound, are ignored. A malformed datagram is rejected with the unmarshal
// error and leaves the gate state untouched.
func (g *KeyframeRequestGate) ProcessRaw(rawPacket []byte) ([]KeyframeRequest, error) {
	packets, err := Unmarshal(rawPacket)
	if err != nil {
		return nil, err
	}

	var emitted []KeyframeRequest
	for _, packet := range packets {
		switch packet.(type) {
		case *PictureLossIndication, *FullIntraRequest:
			requests, processErr := g.Process(packet)
			emitted = append(emitted, requests...)
			if processErr != nil {
				return emitted, processErr
			}
		default:
			// Non-feedback members of a compound packet carry no keyframe
			// request and are intentionally ignored.
		}
	}

	return emitted, nil
}

// FlushDue returns the coalesced requests whose cooldown window has elapsed and
// clears them from the gate. Expired idle states are reclaimed afterwards. The
// result is ordered by ascending media SSRC for deterministic output.
func (g *KeyframeRequestGate) FlushDue() []KeyframeRequest {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock()

	ssrcs := make([]uint32, 0, len(g.states))
	for ssrc := range g.states {
		ssrcs = append(ssrcs, ssrc)
	}
	slices.Sort(ssrcs)

	var emitted []KeyframeRequest
	for _, ssrc := range ssrcs {
		if request, ok := g.takeDueLocked(now, g.states[ssrc]); ok {
			emitted = append(emitted, request)
		}
	}
	g.purgeExpiredLocked(now)

	return emitted
}

// Pending returns a copy of the request currently waiting for the cooldown to
// elapse for the given media SSRC, if any.
func (g *KeyframeRequestGate) Pending(mediaSSRC uint32) (KeyframeRequest, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	state, ok := g.states[mediaSSRC]
	if !ok || state.pending == nil {
		return KeyframeRequest{}, false
	}

	return *state.pending, true
}

// PurgeExpired reclaims every idle state whose cooldown window has elapsed and
// returns the number of reclaimed states. States with a pending request are
// never reclaimed.
func (g *KeyframeRequestGate) PurgeExpired() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock()
	before := len(g.states)
	g.purgeExpiredLocked(now)

	return before - len(g.states)
}

// Reset forgets the state of one media SSRC, for example when the SSRC is
// re-bound to a new media source. It reports whether a state existed.
func (g *KeyframeRequestGate) Reset(mediaSSRC uint32) bool {
	g.mu.Lock()
	defer g.mu.Unlock()

	_, ok := g.states[mediaSSRC]
	delete(g.states, mediaSSRC)

	return ok
}

// ResetAll forgets every per-media-SSRC state.
func (g *KeyframeRequestGate) ResetAll() {
	g.mu.Lock()
	defer g.mu.Unlock()

	clear(g.states)
}

// Len returns the number of media SSRC states currently tracked.
func (g *KeyframeRequestGate) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	return len(g.states)
}

// processPLI handles a validated PLI.
func (g *KeyframeRequestGate) processPLI(mediaSSRC uint32) ([]KeyframeRequest, error) {
	// With a zero cooldown nothing is coalesced and no state is retained.
	if g.cooldown == 0 {
		return []KeyframeRequest{{
			Type:      KeyframeRequestPLI,
			MediaSSRC: mediaSSRC,
			Count:     1,
		}}, nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock()
	state, err := g.getOrCreateLocked(now, mediaSSRC)
	if err != nil {
		return nil, err
	}

	return g.acceptLocked(now, mediaSSRC, KeyframeRequestPLI, 0, state), nil
}

// processFIR handles a validated FIR packet with one or more entries.
func (g *KeyframeRequestGate) processFIR(entries []FIREntry) ([]KeyframeRequest, error) {
	// With a zero cooldown nothing is coalesced and no state, including the
	// sequence-number baseline, is retained.
	if g.cooldown == 0 {
		emitted := make([]KeyframeRequest, 0, len(entries))
		for _, entry := range entries {
			emitted = append(emitted, KeyframeRequest{
				Type:              KeyframeRequestFIR,
				MediaSSRC:         entry.SSRC,
				FIRSequenceNumber: entry.SequenceNumber,
				Count:             1,
			})
		}

		return emitted, nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.clock()

	// Validate every entry against both the current baselines and the other
	// entries of this packet before modifying any state, so a rejected FIR
	// packet has no effect. A target SSRC appearing twice is a duplicate by
	// definition and rejected deterministically.
	seen := make(map[uint32]struct{}, len(entries))
	for _, entry := range entries {
		if _, duplicated := seen[entry.SSRC]; duplicated {
			return nil, ErrStaleFIRSequenceNumber
		}
		seen[entry.SSRC] = struct{}{}
		if state, ok := g.states[entry.SSRC]; ok &&
			!firSequenceIsNewer(entry.SequenceNumber, state.lastFIRSeq, state.hasFIRSeq) {
			return nil, ErrStaleFIRSequenceNumber
		}
	}

	var emitted []KeyframeRequest
	for _, entry := range entries {
		state, err := g.getOrCreateLocked(now, entry.SSRC)
		if err != nil {
			return emitted, err
		}
		state.hasFIRSeq = true
		state.lastFIRSeq = entry.SequenceNumber
		emitted = append(
			emitted,
			g.acceptLocked(now, entry.SSRC, KeyframeRequestFIR, entry.SequenceNumber, state)...,
		)
	}

	return emitted, nil
}

// acceptLocked forwards a request immediately when the cooldown has elapsed,
// otherwise coalesces it into the state's pending request. A due pending
// request is delivered first, in packet order.
func (g *KeyframeRequestGate) acceptLocked(
	now time.Time,
	mediaSSRC uint32,
	requestType KeyframeRequestType,
	firSequenceNumber uint8,
	state *keyframeRequestState,
) []KeyframeRequest {
	state.lastSeenAt = now

	var emitted []KeyframeRequest
	if request, ok := g.takeDueLocked(now, state); ok {
		emitted = append(emitted, request)
	}

	if now.Sub(state.lastEmittedAt) >= g.cooldown {
		state.lastEmittedAt = now

		return append(emitted, KeyframeRequest{
			Type:              requestType,
			MediaSSRC:         mediaSSRC,
			FIRSequenceNumber: firSequenceNumber,
			Count:             1,
		})
	}

	if state.pending == nil {
		state.pending = &KeyframeRequest{
			Type:              requestType,
			MediaSSRC:         mediaSSRC,
			FIRSequenceNumber: firSequenceNumber,
		}
	}
	state.pending.Count++
	// An FIR is the stronger request: it upgrades a pending PLI and the
	// forwarded request carries the newest accepted FIR sequence number.
	if requestType == KeyframeRequestFIR {
		state.pending.Type = KeyframeRequestFIR
		state.pending.FIRSequenceNumber = firSequenceNumber
	}

	return emitted
}

// takeDueLocked returns and clears the pending request once its cooldown has
// elapsed and starts a new cooldown window.
func (g *KeyframeRequestGate) takeDueLocked(
	now time.Time,
	state *keyframeRequestState,
) (KeyframeRequest, bool) {
	if state.pending == nil || now.Sub(state.lastEmittedAt) < g.cooldown {
		return KeyframeRequest{}, false
	}

	request := *state.pending
	state.pending = nil
	state.lastEmittedAt = now
	state.lastSeenAt = now

	return request, true
}

// getOrCreateLocked returns the state for a media SSRC, creating it on first
// use. Expired idle states are only reclaimed when a new SSRC needs a slot;
// existing states are kept because they hold the FIR sequence-number baseline,
// even when their cooldown window has elapsed. If the capacity is still
// reached the oldest idle state is evicted, and ErrGateCapacityExceeded is
// returned when every tracked state holds a pending request.
func (g *KeyframeRequestGate) getOrCreateLocked(
	now time.Time,
	mediaSSRC uint32,
) (*keyframeRequestState, error) {
	if state, ok := g.states[mediaSSRC]; ok {
		state.lastSeenAt = now

		return state, nil
	}

	g.purgeExpiredLocked(now)
	if len(g.states) >= g.capacity && !g.evictIdleLocked() {
		return nil, ErrGateCapacityExceeded
	}

	state := &keyframeRequestState{lastSeenAt: now}
	g.states[mediaSSRC] = state

	return state, nil
}

// evictIdleLocked removes the oldest idle state, breaking ties by the smallest
// media SSRC so the choice is deterministic. States with pending requests are
// never evicted.
func (g *KeyframeRequestGate) evictIdleLocked() bool {
	var victimSSRC uint32
	var victim *keyframeRequestState

	for ssrc, state := range g.states {
		if state.pending != nil {
			continue
		}
		if victim == nil ||
			state.lastSeenAt.Before(victim.lastSeenAt) ||
			(state.lastSeenAt.Equal(victim.lastSeenAt) && ssrc < victimSSRC) {
			victimSSRC, victim = ssrc, state
		}
	}

	if victim == nil {
		return false
	}
	delete(g.states, victimSSRC)

	return true
}

// purgeExpiredLocked removes idle states whose cooldown window has fully
// elapsed since their last activity. With a zero cooldown every idle state is
// immediately reclaimable, which keeps the gate empty between inputs.
func (g *KeyframeRequestGate) purgeExpiredLocked(now time.Time) {
	for ssrc, state := range g.states {
		if state.pending == nil && now.Sub(state.lastSeenAt) >= g.cooldown {
			delete(g.states, ssrc)
		}
	}
}

// validateFIREntries checks that an FIR packet carries at least one entry and
// that every entry names a target media SSRC.
func validateFIREntries(packet *FullIntraRequest) error {
	if len(packet.FIR) == 0 {
		return ErrMissingTargetSSRC
	}
	for _, entry := range packet.FIR {
		if entry.SSRC == 0 {
			return ErrMissingTargetSSRC
		}
	}

	return nil
}

// firSequenceIsNewer applies the RFC 5104 8-bit wrapping sequence-number rule:
// the first observed sequence number is always accepted; afterwards a forward
// distance within half the sequence space is treated as newer, while equal
// (duplicate) and backward (out-of-order) values are rejected.
func firSequenceIsNewer(sequenceNumber, baseline uint8, hasBaseline bool) bool {
	if !hasBaseline {
		return true
	}

	return int8(sequenceNumber-baseline) > 0 //nolint:gosec // G115: modular 8-bit sequence space by RFC 5104 design
}
