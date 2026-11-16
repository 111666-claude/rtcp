// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"slices"
	"sync"
	"time"
)

// maxNackWindowLength is the largest supported tracking window. It stays below
// half of the 16-bit sequence number space so forward/backward distance between
// two sequence numbers stays unambiguous.
const maxNackWindowLength = 1<<15 - 1

// NackWindowConfig configures a NackWindow.
type NackWindowConfig struct {
	// ReorderWait is how long a missing sequence number is held back before it
	// is reported in a TransportLayerNack. A packet arriving within this delay
	// cancels the pending request.
	ReorderWait time.Duration

	// MaxRetries limits how many TransportLayerNack packets reference the same
	// missing sequence number. A gap is dropped once it has been reported this
	// many times, even if the packet never arrives.
	MaxRetries uint16

	// MaxWindowLength bounds how many missing sequence numbers are tracked per
	// SSRC. Gaps beyond the limit evict the oldest pending gaps. The receive
	// bitmap covering the window is rounded up to the next power of two and
	// never exceeds maxNackWindowLength entries.
	MaxWindowLength uint16

	// Now supplies the current time. When nil, time.Now is used. Injecting a
	// clock makes feedback timing deterministic in tests.
	Now func() time.Time

	// SenderSSRC is written into every produced TransportLayerNack as the SSRC
	// of the feedback sender. It may be left zero when the caller sets it per
	// compound packet instead.
	SenderSSRC uint32
}

// NackWindow tracks missing RTP sequence numbers per media SSRC and produces
// bounded TransportLayerNack feedback.
//
// A sequence number is not reported as lost the moment a jump is observed: the
// gap is kept pending for ReorderWait to absorb reordering. If the packet
// arrives while pending, the request is canceled. Once the wait elapses the
// gap is included in the next feedback, up to MaxRetries times; gaps that
// exhaust their retries or fall outside the bounded window are discarded.
//
// NackWindow is safe for concurrent use.
type NackWindow struct {
	mu sync.Mutex

	reorderWait     time.Duration
	maxRetries      uint16
	maxWindowLength uint16
	senderSSRC      uint32
	now             func() time.Time

	streams map[uint32]*nackStreamState
}

// nackStreamState holds the per-SSRC tracking state.
type nackStreamState struct {
	// end is the highest sequence number observed, in 16-bit space.
	end uint16
	// endExtended is the same point in the monotonic extended space.
	endExtended uint32

	// bitmap records received sequence numbers over the bounded window.
	bitmap *nackBitmap

	// gaps are the currently pending or retrying missing sequence numbers,
	// keyed by 16-bit sequence number.
	gaps map[uint16]*nackGap
}

// nackGap is one missing sequence number.
type nackGap struct {
	// extended is the sequence number in unwrapped 32-bit space, used for
	// stable ordering across 16-bit wraparound.
	extended uint32
	// firstSeen is when the gap was registered.
	firstSeen time.Time
	// retries is how many feedback packets have already included this gap.
	retries uint16
}

// nackBitmap is a power-of-two sized ring bitmap of received sequence numbers.
type nackBitmap struct {
	bits []uint64
	mask uint16
}

func newNackBitmap(size uint16) *nackBitmap {
	words := size / 64
	if words == 0 {
		words = 1
	}

	return &nackBitmap{
		bits: make([]uint64, words),
		mask: size - 1,
	}
}

func (b *nackBitmap) set(seq uint16) {
	pos := seq & b.mask
	b.bits[pos/64] |= 1 << (pos % 64)
}

func (b *nackBitmap) clear(seq uint16) {
	pos := seq & b.mask
	b.bits[pos/64] &^= 1 << (pos % 64)
}

func (b *nackBitmap) get(seq uint16) bool {
	pos := seq & b.mask

	return (b.bits[pos/64] & (1 << (pos % 64))) != 0
}

// NewNackWindow creates a NackWindow from the given configuration.
// It returns an error if the window parameters are invalid.
func NewNackWindow(config NackWindowConfig) (*NackWindow, error) {
	if config.ReorderWait <= 0 {
		return nil, ErrInvalidNackReorderWait
	}

	if config.MaxRetries == 0 {
		return nil, ErrInvalidNackMaxRetries
	}

	if config.MaxWindowLength == 0 || config.MaxWindowLength > maxNackWindowLength {
		return nil, ErrInvalidNackWindowLength
	}

	now := config.Now
	if now == nil {
		now = time.Now
	}

	return &NackWindow{
		reorderWait:     config.ReorderWait,
		maxRetries:      config.MaxRetries,
		maxWindowLength: config.MaxWindowLength,
		senderSSRC:      config.SenderSSRC,
		now:             now,
		streams:         make(map[uint32]*nackStreamState),
	}, nil
}

// AddPacket records a received RTP sequence number for a media SSRC at the
// window's current time. Repeating a sequence number already inside the window
// is a duplicate and has no effect; a late packet filling a pending gap
// cancels that gap before it is reported again.
func (w *NackWindow) AddPacket(mediaSSRC uint32, sequenceNumber uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()

	state, ok := w.streams[mediaSSRC]
	if !ok {
		w.streams[mediaSSRC] = w.newStreamState(sequenceNumber)

		return
	}

	diff := sequenceNumber - state.end
	switch {
	case diff == 0:
		// Duplicate of the highest sequence number seen so far.
		return
	case diff < 1<<15:
		// Forward jump (16-bit wraparound included): advance the window and
		// register every sequence number in between as a gap.
		w.advance(state, sequenceNumber, diff)
	default:
		// Older sequence number. A gap still tracked means the packet is a
		// valid late arrival; fill it regardless of bitmap-window distance.
		if _, ok := state.gaps[sequenceNumber]; ok {
			if state.end-sequenceNumber < state.bitmap.mask+1 {
				state.bitmap.set(sequenceNumber)
			}
			delete(state.gaps, sequenceNumber)

			return
		}

		// Unknown sequence number: either a duplicate still inside the
		// receive window or an expired packet. Both are no-ops.
		if state.end-sequenceNumber >= state.bitmap.mask+1 || state.bitmap.get(sequenceNumber) {
			return
		}

		// Older but inside the window and not received before: mark it.
		state.bitmap.set(sequenceNumber)
	}
}

func (w *NackWindow) newStreamState(seq uint16) *nackStreamState {
	bitmap := newNackBitmap(roundUpPowerOfTwo(w.maxWindowLength))
	bitmap.set(seq)

	return &nackStreamState{
		end:         seq,
		endExtended: uint32(seq),
		bitmap:      bitmap,
		gaps:        make(map[uint16]*nackGap),
	}
}

// advance moves the window end forward by diff steps, registering missing
// sequence numbers as pending gaps and clearing stale bitmap entries.
func (w *NackWindow) advance(state *nackStreamState, seq uint16, diff uint16) {
	now := w.now()

	for distance, missing := uint16(1), state.end+1; missing != seq; distance, missing = distance+1, missing+1 {
		// The slot may still hold a record from one window ago.
		state.bitmap.clear(missing)
		w.registerGap(state, missing, state.endExtended+uint32(distance), now)
	}

	state.bitmap.clear(seq)
	state.bitmap.set(seq)
	state.endExtended += uint32(diff)
	state.end = seq
}

// registerGap adds a missing sequence number, evicting the oldest pending gap
// when the bounded window is full.
func (w *NackWindow) registerGap(state *nackStreamState, seq uint16, extended uint32, now time.Time) {
	if len(state.gaps) >= int(w.maxWindowLength) {
		w.evictOldestGap(state)
	}

	state.gaps[seq] = &nackGap{
		extended:  extended,
		firstSeen: now,
	}
}

// evictOldestGap removes the pending gap with the smallest extended sequence
// number. Its bitmap slot is left clear so the sequence number remains
// observable as lost within the current window.
func (w *NackWindow) evictOldestGap(state *nackStreamState) {
	var oldest uint16
	var oldestExtended uint32

	first := true

	for seq, gap := range state.gaps {
		if first || gap.extended < oldestExtended {
			oldest = seq
			oldestExtended = gap.extended
			first = false
		}
	}

	if !first {
		delete(state.gaps, oldest)
	}
}

// TransportLayerNacks returns the TransportLayerNack packets currently due.
// Gaps younger than ReorderWait are withheld for reordering; mature gaps are
// reported until they reach MaxRetries, after which they expire. Late packets
// and window eviction may remove gaps before they are ever reported.
func (w *NackWindow) TransportLayerNacks() []*TransportLayerNack {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := w.now()
	nacks := make([]*TransportLayerNack, 0, len(w.streams))

	// Stable SSRC ordering keeps the output deterministic.
	ssrcs := make([]uint32, 0, len(w.streams))
	for ssrc := range w.streams {
		ssrcs = append(ssrcs, ssrc)
	}

	slices.Sort(ssrcs)

	for _, ssrc := range ssrcs {
		if nack := w.buildNack(ssrc, w.streams[ssrc], now); nack != nil {
			nacks = append(nacks, nack)
		}
	}

	return nacks
}

// buildNack produces one TransportLayerNack for a single SSRC, or nil when no
// gap is currently due.
func (w *NackWindow) buildNack(ssrc uint32, state *nackStreamState, now time.Time) *TransportLayerNack {
	type pending struct {
		seq      uint16
		extended uint32
	}

	mature := make([]pending, 0, len(state.gaps))

	for seq, gap := range state.gaps {
		if now.Sub(gap.firstSeen) < w.reorderWait {
			continue
		}

		if gap.retries >= w.maxRetries {
			// Retry budget exhausted: give up and reclaim the entry.
			delete(state.gaps, seq)

			continue
		}

		gap.retries++
		mature = append(mature, pending{seq: seq, extended: gap.extended})
	}

	if len(mature) == 0 {
		return nil
	}

	// Sort by extended sequence number so wraparound keeps a stable order and
	// NackPairsFromSequenceNumbers sees ascending 16-bit values per run.
	slices.SortFunc(mature, func(a, b pending) int {
		return int(a.extended) - int(b.extended) //nolint:gosec // G115
	})

	sequences := make([]uint16, len(mature))
	for i, entry := range mature {
		sequences[i] = entry.seq
	}

	return &TransportLayerNack{
		SenderSSRC: w.senderSSRC,
		MediaSSRC:  ssrc,
		Nacks:      NackPairsFromSequenceNumbers(sequences),
	}
}

// RemoveSSRC drops all tracking state for a media SSRC.
func (w *NackWindow) RemoveSSRC(mediaSSRC uint32) {
	w.mu.Lock()
	defer w.mu.Unlock()

	delete(w.streams, mediaSSRC)
}

// Reset clears all per-SSRC state.
func (w *NackWindow) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.streams = make(map[uint32]*nackStreamState)
}

// roundUpPowerOfTwo returns the smallest power of two greater than or equal
// to v. v must be in [1, maxNackWindowLength].
func roundUpPowerOfTwo(v uint16) uint16 {
	size := uint16(1)
	for size < v {
		size <<= 1
	}

	return size
}
