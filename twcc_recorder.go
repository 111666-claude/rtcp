// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"math"
	"slices"
	"sync"
	"time"
)

// TWCC timing units, see
// https://tools.ietf.org/html/draft-holmer-rmcat-transport-wide-cc-extensions-01#section-3.1.5
const (
	twccReferenceTimeTick = 64 * time.Millisecond
	twccDeltaTick         = 250 * time.Microsecond

	// twccMinFeedbackSize is the smallest size that can hold one feedback
	// packet with a single received symbol: 4 byte RTCP header, 16 bytes of
	// fixed TWCC fields, a 2 byte status chunk and a 2 byte large delta.
	twccMinFeedbackSize = packetChunkOffset + headerLength + 4

	// twccRunLengthMax is the 13 bit run-length field limit.
	twccRunLengthMax = (1 << 13) - 1

	// twccVectorCapacity is the number of symbols carried by one two-bit
	// status vector chunk.
	twccVectorCapacity = 7

	// DefaultTWCCMaxPacketSize limits a marshaled feedback packet to a size
	// that fits comfortably in a typical MTU.
	DefaultTWCCMaxPacketSize = 1200

	// DefaultTWCCMaxTrackedPackets bounds how many transport-wide sequence
	// numbers the recorder keeps between two feedback builds.
	DefaultTWCCMaxTrackedPackets = 1000
)

var (
	errTWCCPacketSizeTooSmall = errors.New("rtcp: max TWCC packet size must fit at least one feedback packet")
	errTWCCCapacityTooSmall   = errors.New("rtcp: TWCC recorder capacity must be greater than zero")
)

// TWCCRecorder builds transport-wide congestion control feedback
// (TransportLayerCC) from the transport-wide sequence numbers and arrival
// times of received RTP packets.
//
// The recorder keeps every recorded packet until the next successful call to
// BuildFeedbackPackets: ranges already reported are never reported again.
// Sequence numbers are 16 bit and wrap around; a bounded amount of
// reordering, duplicates and loss inside the 16 bit window is handled.
//
// TWCCRecorder is safe for concurrent use.
type TWCCRecorder struct {
	mu sync.Mutex

	senderSSRC uint32
	mediaSSRC  uint32

	maxPacketSize     int
	maxTrackedPackets int

	// packets maps the extended (unwrapped) transport-wide sequence number
	// to the packet arrival time.
	packets map[uint64]time.Time

	// baseExtSeq is the lowest extended sequence number that may still be
	// reported. It advances on every feedback build and cache eviction.
	baseExtSeq uint64

	// maxExtSeq is the highest extended sequence number seen so far.
	maxExtSeq uint64

	// initialized reports whether at least one packet was recorded.
	initialized bool

	// fbPktCount is the 8 bit feedback packet counter, wrapping modulo 256.
	fbPktCount uint8
}

// TWCCRecorderOption configures a TWCCRecorder.
type TWCCRecorderOption func(*TWCCRecorder)

// WithTWCCMaxPacketSize sets the upper bound of a single marshaled feedback
// packet. When more data is available it is split across several feedback
// packets, each carrying its own reference time. The value must be large
// enough to hold one symbol (24 bytes); marshaled packets are padded to a
// multiple of 4 bytes.
func WithTWCCMaxPacketSize(size int) TWCCRecorderOption {
	return func(r *TWCCRecorder) {
		r.maxPacketSize = size
	}
}

// WithTWCCMaxTrackedPackets limits how many sequence numbers are buffered
// between feedback builds. Once the capacity is reached the oldest buffered
// entries are evicted; evicted packets are never reported and the feedback
// base advances past them.
func WithTWCCMaxTrackedPackets(capacity int) TWCCRecorderOption {
	return func(r *TWCCRecorder) {
		r.maxTrackedPackets = capacity
	}
}

// NewTWCCRecorder creates a TWCCRecorder. senderSSRC is the SSRC of the
// feedback sender and mediaSSRC the SSRC of the media source the reported RTP
// packets belong to.
func NewTWCCRecorder(senderSSRC, mediaSSRC uint32, options ...TWCCRecorderOption) (*TWCCRecorder, error) {
	recorder := &TWCCRecorder{
		senderSSRC:        senderSSRC,
		mediaSSRC:         mediaSSRC,
		maxPacketSize:     DefaultTWCCMaxPacketSize,
		maxTrackedPackets: DefaultTWCCMaxTrackedPackets,
		packets:           make(map[uint64]time.Time),
	}

	for _, option := range options {
		option(recorder)
	}

	if recorder.maxPacketSize < twccMinFeedbackSize {
		return nil, errTWCCPacketSizeTooSmall
	}

	if recorder.maxTrackedPackets <= 0 {
		return nil, errTWCCCapacityTooSmall
	}

	return recorder, nil
}

// Record stores the arrival of an RTP packet carrying the given
// transport-wide sequence number.
//
// 16 bit sequence numbers are unwrapped against the most recently seen
// number. Duplicate sequence numbers keep their first arrival time. Packets
// whose range was already reported, or that were evicted from the cache, are
// ignored. When the cache is full the oldest entries are evicted.
func (r *TWCCRecorder) Record(sequenceNumber uint16, arrivalTime time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	extSeq := r.extendSequenceNumber(sequenceNumber)
	if r.initialized && extSeq < r.baseExtSeq {
		// The range this sequence number belongs to was already reported or
		// evicted, so it cannot be represented in a future feedback packet.
		return
	}

	if _, exists := r.packets[extSeq]; exists {
		// Duplicate: the first arrival time is the one that gets reported.
		return
	}

	if len(r.packets) >= r.maxTrackedPackets {
		r.evictOldest()
	}

	r.packets[extSeq] = arrivalTime
}

// extendSequenceNumber maps a raw 16 bit sequence number to an extended
// sequence number. The highest sequence number seen so far is the anchor; a
// raw number in the upper half of the 16 bit window relative to that anchor is
// treated as older (previous cycle) and one in the lower half as newer. This
// tolerates up to half a window of reordering and is independent of the order
// in which the packets were recorded.
func (r *TWCCRecorder) extendSequenceNumber(sequenceNumber uint16) uint64 {
	if !r.initialized {
		r.initialized = true
		r.baseExtSeq = uint64(sequenceNumber)
		r.maxExtSeq = uint64(sequenceNumber)

		return uint64(sequenceNumber)
	}

	anchorCycles := r.maxExtSeq &^ uint64(math.MaxUint16)
	anchorSeq := uint16(r.maxExtSeq) //nolint:gosec // G115 low 16 bits of the anchor

	extSeq := anchorCycles + uint64(sequenceNumber)

	// Forward distance from the anchor, wrapping modulo 2^16. The uint16
	// subtraction produces the wrapped distance directly.
	forward := sequenceNumber - anchorSeq
	switch {
	case forward == 0:
		// Same raw number as the anchor; keep the anchor's cycle.
	case forward < 1<<15:
		// Newer than the anchor, possibly crossing the 16 bit wrap.
		if sequenceNumber < anchorSeq {
			extSeq += 1 << 16
		}
	default:
		// More than half a window behind: an older sequence, possibly in the
		// cycle before the anchor's forward wrap.
		if sequenceNumber > anchorSeq {
			extSeq -= 1 << 16
		}
	}

	// The window base tracks the lowest sequence number still buffered so a
	// late, out-of-order packet below the first one seen is included.
	if extSeq < r.baseExtSeq {
		r.baseExtSeq = extSeq
	}

	if extSeq > r.maxExtSeq {
		r.maxExtSeq = extSeq
	}

	return extSeq
}

// evictOldest drops the oldest buffered entries and advances the base past
// them. A batch is removed to keep the amortized cost low.
func (r *TWCCRecorder) evictOldest() {
	keys := make([]uint64, 0, len(r.packets))
	for extSeq := range r.packets {
		keys = append(keys, extSeq)
	}

	slices.Sort(keys)

	drop := min(len(keys)/10+1, len(keys))

	for i := range drop {
		delete(r.packets, keys[i])
	}

	r.baseExtSeq = keys[drop-1] + 1
}

// Reset discards every recorded packet and all sequence-number state, leaving
// the recorder equivalent to a freshly constructed one apart from its
// configuration and SSRC values.
func (r *TWCCRecorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.packets = make(map[uint64]time.Time)
	r.baseExtSeq = 0
	r.maxExtSeq = 0
	r.initialized = false
	r.fbPktCount = 0
}

// BuildFeedbackPackets consumes the buffered arrivals and returns one or more
// sendable TransportLayerCC packets covering them. It returns no packet when
// nothing was recorded since the previous build.
//
// Every arrival is reported exactly once: a successful build advances the
// feedback base past the consumed range and clears the buffer. When the data
// does not fit into the configured maximum packet size, or an arrival delta
// cannot be encoded inside one packet (a gap larger than the signed 16 bit
// large-delta range), it is split across several packets, each with its own
// reference time and feedback packet counter.
func (r *TWCCRecorder) BuildFeedbackPackets() ([]*TransportLayerCC, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.packets) == 0 {
		return nil, nil //nolint:nilnil // no buffered data means no feedback
	}

	entries := r.snapshotEntries()

	builder := newTWCCFeedbackBuilder(r.senderSSRC, r.mediaSSRC, r.maxPacketSize, r.fbPktCount)
	if err := builder.build(r.baseExtSeq, entries); err != nil {
		return nil, err
	}

	// Commit: every buffered entry has now been reported.
	r.baseExtSeq = r.maxExtSeq + 1
	r.packets = make(map[uint64]time.Time)
	r.fbPktCount = builder.nextFbPktCount

	return builder.packets, nil
}

// twccEntry is one sequence number position in the feedback window.
type twccEntry struct {
	arrivalTime time.Time
	received    bool
}

// snapshotEntries materializes the buffered window, filling sequence number
// gaps with not-received entries. The returned slice is ordered by extended
// sequence number.
func (r *TWCCRecorder) snapshotEntries() []twccEntry {
	// The window never holds more than maxTrackedPackets entries, so the
	// difference fits comfortably in an int.
	count := int(r.maxExtSeq-r.baseExtSeq) + 1 //nolint:gosec // G115 bounded by recorder capacity
	entries := make([]twccEntry, 0, count)

	for extSeq := r.baseExtSeq; extSeq <= r.maxExtSeq; extSeq++ {
		arrivalTime, received := r.packets[extSeq]
		entries = append(entries, twccEntry{arrivalTime: arrivalTime, received: received})
	}

	return entries
}

// twccFeedbackBuilder accumulates one feedback window and splits it into
// TransportLayerCC packets according to the size and delta limits.
type twccFeedbackBuilder struct {
	senderSSRC    uint32
	mediaSSRC     uint32
	maxPacketSize int

	nextFbPktCount uint8
	packets        []*TransportLayerCC

	// State of the packet currently being filled.
	chunks         []PacketStatusChunk
	deltas         []*RecvDelta
	deltaBytes     int // encoded size of all deltas
	baseSequence   uint16
	statusCount    uint16
	pendingRun     *RunLengthChunk // open run-length chunk, if any
	pendingVector  []uint16        // buffered status vector symbols, if any
	vectorHasLarge bool

	// Reference timing of the open packet.
	hasReference    bool
	referenceTime   time.Time
	lastArrivalTime time.Time
}

// currentChunkBytes is the encoded size of every status chunk, including a
// run or vector still buffered and not yet appended to chunks.
func (b *twccFeedbackBuilder) currentChunkBytes() int {
	bytes := len(b.chunks) * packetStatusChunkLength
	if b.pendingRun != nil || len(b.pendingVector) > 0 {
		bytes += packetStatusChunkLength
	}

	return bytes
}

func newTWCCFeedbackBuilder(
	senderSSRC, mediaSSRC uint32, maxPacketSize int, fbPktCount uint8,
) *twccFeedbackBuilder {
	return &twccFeedbackBuilder{
		senderSSRC:     senderSSRC,
		mediaSSRC:      mediaSSRC,
		maxPacketSize:  maxPacketSize,
		nextFbPktCount: fbPktCount,
	}
}

// build encodes the ordered window into one or more feedback packets.
func (b *twccFeedbackBuilder) build(windowBase uint64, entries []twccEntry) error {
	b.baseSequence = uint16(windowBase) //nolint:gosec // G115 base is a 16 bit sequence number

	for _, entry := range entries {
		if b.statusCount == math.MaxUint16 {
			// The 16 bit packet status count field is full; the remainder
			// goes into a continuation packet.
			b.finalizePacket()
			b.baseSequence = b.packetBaseSequence()
		}

		if !entry.received {
			b.appendSymbol(TypeTCCPacketNotReceived)

			continue
		}

		if err := b.addReceived(entry.arrivalTime); err != nil {
			return err
		}
	}

	b.finalizePacket()

	return nil
}

// addReceived appends a received status symbol together with its arrival
// delta. The packet is split when adding it would exceed the size budget or
// when the delta against the previous received packet cannot be encoded.
func (b *twccFeedbackBuilder) addReceived(arrivalTime time.Time) error {
	deltaTicks := b.nextDeltaTicks(arrivalTime)

	overflow := b.hasReference && deltaOutOfLargeRange(deltaTicks)
	exceedsBudget := false

	if !overflow {
		_, deltaSize, err := deltaSymbol(deltaTicks)
		if err != nil {
			return err
		}

		exceedsBudget = b.paddedSize(b.currentChunkBytes()+b.deltaBytes+deltaSize) > b.maxPacketSize
	}

	if (overflow || exceedsBudget) && b.statusCount > 0 {
		// Close the current packet and start a new one anchored at this
		// arrival, whose delta is therefore zero. An empty packet always
		// accepts the first symbol, which guarantees forward progress even
		// for the smallest legal maxPacketSize.
		b.finalizePacket()
		b.baseSequence = b.packetBaseSequence()
		deltaTicks = b.nextDeltaTicks(arrivalTime)
	}

	symbol, deltaSize, err := deltaSymbol(deltaTicks)
	if err != nil {
		return err
	}

	b.appendSymbol(symbol)
	b.deltas = append(b.deltas, &RecvDelta{
		Type:  symbol,
		Delta: deltaTicks * int64(twccDeltaTick/time.Microsecond),
	})
	b.deltaBytes += deltaSize

	b.lastArrivalTime = arrivalTime
	b.hasReference = true

	return nil
}

// nextDeltaTicks computes the delta for an arrival against the open packet's
// timing. The first arrival of a packet anchors a 64ms-aligned reference
// time; its delta carries the sub-64ms remainder so no precision is lost to
// the reference time quantization.
func (b *twccFeedbackBuilder) nextDeltaTicks(arrivalTime time.Time) int64 {
	if b.hasReference {
		return arrivalDeltaTicks(b.lastArrivalTime, arrivalTime)
	}

	b.referenceTime = arrivalTime.Truncate(twccReferenceTimeTick)

	return arrivalDeltaTicks(b.referenceTime, arrivalTime)
}

// packetBaseSequence returns the base sequence number of a split continuation
// packet, i.e. the window base advanced by every symbol emitted so far.
func (b *twccFeedbackBuilder) packetBaseSequence() uint16 {
	emitted := uint64(0)
	for _, packet := range b.packets {
		emitted += uint64(packet.PacketStatusCount)
	}

	return uint16(uint64(b.packets[0].BaseSequenceNumber) + emitted) //nolint:gosec // G115
}

// appendSymbol encodes one status symbol, choosing between run-length chunks
// for repeated symbols and status vector chunks for mixed symbols.
func (b *twccFeedbackBuilder) appendSymbol(symbol uint16) {
	switch {
	case b.pendingRun != nil:
		b.appendToRun(symbol)
	case len(b.pendingVector) > 0:
		b.appendToVector(symbol)
	default:
		// The first symbol is buffered alone; a repetition becomes a run,
		// a different symbol starts a status vector.
		b.pendingVector = append(b.pendingVector, symbol)
		b.vectorHasLarge = symbol == TypeTCCPacketReceivedLargeDelta
	}

	b.statusCount++
}

// appendToRun grows the open run-length chunk, finalizing it when the symbol
// changes or the 13 bit run-length limit is reached.
func (b *twccFeedbackBuilder) appendToRun(symbol uint16) {
	if symbol == b.pendingRun.PacketStatusSymbol && b.pendingRun.RunLength < twccRunLengthMax {
		b.pendingRun.RunLength++

		return
	}

	// The run ended; store it.
	b.chunks = append(b.chunks, b.pendingRun)
	previousRun := b.pendingRun
	b.pendingRun = nil

	if symbol == previousRun.PacketStatusSymbol {
		// The 13 bit run-length limit was reached: start a fresh run.
		b.pendingRun = &RunLengthChunk{
			Type:               TypeTCCRunLengthChunk,
			PacketStatusSymbol: symbol,
			RunLength:          1,
		}

		return
	}

	// A different symbol starts a new buffered vector.
	b.pendingVector = append(b.pendingVector, symbol)
	b.vectorHasLarge = symbol == TypeTCCPacketReceivedLargeDelta
}

// appendToVector adds a symbol to the buffered status vector. A repeated lone
// symbol is converted into a run-length chunk instead.
func (b *twccFeedbackBuilder) appendToVector(symbol uint16) {
	if len(b.pendingVector) == 1 && b.pendingVector[0] == symbol && !b.vectorHasLarge {
		b.pendingVector = nil
		b.vectorHasLarge = false
		b.pendingRun = &RunLengthChunk{
			Type:               TypeTCCRunLengthChunk,
			PacketStatusSymbol: symbol,
			RunLength:          2,
		}

		return
	}

	b.pendingVector = append(b.pendingVector, symbol)
	if symbol == TypeTCCPacketReceivedLargeDelta {
		b.vectorHasLarge = true
	}

	if len(b.pendingVector) == twccVectorCapacity {
		b.flushVector()
	}
}

// flushVector encodes the buffered symbols as one status vector chunk. A
// vector without large deltas uses the compact one-bit symbol size.
func (b *twccFeedbackBuilder) flushVector() {
	if len(b.pendingVector) == 0 {
		return
	}

	symbolSize := uint16(TypeTCCSymbolSizeTwoBit)
	if !b.vectorHasLarge {
		symbolSize = TypeTCCSymbolSizeOneBit
	}

	symbols := make([]uint16, len(b.pendingVector))
	copy(symbols, b.pendingVector)

	b.chunks = append(b.chunks, &StatusVectorChunk{
		Type:       TypeTCCStatusVectorChunk,
		SymbolSize: symbolSize,
		SymbolList: symbols,
	})
	b.pendingVector = nil
	b.vectorHasLarge = false
}

// flushPending stores any run-length chunk or status vector still buffered.
func (b *twccFeedbackBuilder) flushPending() {
	if b.pendingRun != nil {
		b.chunks = append(b.chunks, b.pendingRun)
		b.pendingRun = nil

		return
	}

	b.flushVector()
}

// paddedSize returns the marshaled packet size once the 4 byte RTCP header
// and the fixed 16 byte TWCC header are prepended and the whole packet is
// padded to a multiple of 4.
func (b *twccFeedbackBuilder) paddedSize(payloadSize int) int {
	total := headerLength + packetChunkOffset + payloadSize

	return (total + 3) / 4 * 4
}

// finalizePacket closes and stores the packet currently being filled.
func (b *twccFeedbackBuilder) finalizePacket() {
	if b.statusCount == 0 {
		return
	}

	b.flushPending()

	unpadded := headerLength + packetChunkOffset +
		len(b.chunks)*packetStatusChunkLength + b.deltaBytes
	size := (unpadded + 3) / 4 * 4
	packet := &TransportLayerCC{
		Header: Header{
			// Padding is only set when alignment actually appends bytes;
			// otherwise the padding byte would overwrite the final delta.
			Padding: size != unpadded,
			Count:   FormatTCC,
			Type:    TypeTransportSpecificFeedback,
			Length:  uint16(size/4 - 1), //nolint:gosec // G115 bounded by maxPacketSize
		},
		SenderSSRC:         b.senderSSRC,
		MediaSSRC:          b.mediaSSRC,
		BaseSequenceNumber: b.baseSequence,
		PacketStatusCount:  b.statusCount,
		FbPktCount:         b.nextFbPktCount,
		PacketChunks:       b.chunks,
		RecvDeltas:         b.deltas,
	}
	if b.hasReference {
		packet.ReferenceTime = referenceTimeTicks(b.referenceTime)
	}

	b.packets = append(b.packets, packet)
	b.nextFbPktCount++

	// Reset per-packet state for the following packet.
	b.chunks = nil
	b.deltas = nil
	b.deltaBytes = 0
	b.statusCount = 0
	b.pendingRun = nil
	b.pendingVector = nil
	b.vectorHasLarge = false
	b.hasReference = false
}

// arrivalDeltaTicks returns the signed arrival delta in 250us ticks.
func arrivalDeltaTicks(previous, current time.Time) int64 {
	return current.Sub(previous).Nanoseconds() / int64(twccDeltaTick)
}

// referenceTimeTicks converts an arrival time to the 24 bit TWCC reference
// time in 64ms ticks.
func referenceTimeTicks(t time.Time) uint32 {
	ticks := uint64(t.UnixNano()) / uint64(twccReferenceTimeTick)

	return uint32(ticks) & 0xFFFFFF //nolint:gosec // G115 masked to 24 bits
}

// deltaSymbol selects small or large delta encoding and returns the encoded
// delta size in bytes.
func deltaSymbol(deltaTicks int64) (uint16, int, error) {
	switch {
	case deltaTicks >= 0 && deltaTicks <= (1<<8)-1:
		return TypeTCCPacketReceivedSmallDelta, 1, nil
	case deltaTicks >= -(1<<15) && deltaTicks <= (1<<15)-1:
		return TypeTCCPacketReceivedLargeDelta, 2, nil
	default:
		return 0, 0, errDeltaExceedLimit
	}
}

// deltaOutOfLargeRange reports whether deltaTicks cannot be encoded as a
// signed 16 bit large delta.
func deltaOutOfLargeRange(deltaTicks int64) bool {
	return deltaTicks < -(1<<15) || deltaTicks > (1<<15)-1
}
