// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"math"
)

// Reference time is a 24-bit unsigned counter in units of 64ms, transport
// sequence numbers are 16-bit unsigned counters.
const (
	tccReferenceTimeScale   = 64_000 // microseconds per reference time unit (64ms)
	tccReferenceTimeModulus = 1 << 24
	tccSequenceNumberSpace  = 1 << 16
	tccSequenceBreakpoint   = tccSequenceNumberSpace / 2
)

// Errors returned by the TWCC feedback interpreter.
var (
	errTCCInvalidFeedback  = errors.New("rtcp: invalid TWCC feedback packet")
	errTCCSymbolOutOfRange = errors.New("rtcp: TWCC packet contains a packet status symbol outside the valid range")
	errTCCDeltaMismatch    = errors.New("rtcp: TWCC receive deltas do not match the packet status symbols")
)

// TWCCPacketStatus describes what a feedback packet reports about one
// transport sequence number.
type TWCCPacketStatus uint8

const (
	// TWCCStatusNotReceived means the packet was reported as not received.
	TWCCStatusNotReceived TWCCPacketStatus = iota

	// TWCCStatusReceived means the packet was received and the feedback
	// carries a receive delta for it.
	TWCCStatusReceived

	// TWCCStatusReceivedWithoutDelta means the packet was reported as
	// received, but the feedback carries no receive delta for it.
	TWCCStatusReceivedWithoutDelta
)

// TWCCArrival is the interpreter's view of one transport sequence number.
type TWCCArrival struct {
	// SequenceNumber is the extended (unwrapped) transport sequence number,
	// which keeps increasing across 16-bit wrap-arounds.
	SequenceNumber int64

	// Status reports whether the sequence number was received.
	Status TWCCPacketStatus

	// ArrivalTime is the arrival time in microseconds on the timeline
	// established by the first processed feedback packet, whose reference
	// time maps to zero. It is zero when Status is not TWCCStatusReceived.
	ArrivalTime int64
}

// TWCCWindowStats summarizes the sequence numbers first observed while
// processing one feedback packet. Sequence numbers already observed in
// earlier feedback packets are never counted again.
type TWCCWindowStats struct {
	// PacketCount is the number of distinct sequence numbers first observed
	// in this feedback packet.
	PacketCount int

	// ReceivedCount is the number of those sequence numbers reported as
	// received, with or without a receive delta.
	ReceivedCount int

	// LostCount is the number of those sequence numbers reported as not
	// received.
	LostCount int

	// LossRate is LostCount divided by PacketCount. It is zero when
	// PacketCount is zero.
	LossRate float64

	// ArrivalIntervals holds the inter-arrival times in microseconds between
	// consecutive received packets that carry a delta, ordered by sequence
	// number. The first sample may span the boundary with the previous
	// feedback packet.
	ArrivalIntervals []int64

	// MeanArrivalInterval is the arithmetic mean of ArrivalIntervals. It is
	// NaN when ArrivalIntervals is empty.
	MeanArrivalInterval float64

	// StdDevArrivalInterval is the population standard deviation of
	// ArrivalIntervals. It is zero when fewer than two intervals are
	// available and NaN when ArrivalIntervals is empty.
	StdDevArrivalInterval float64

	// MeanIntervalDelta is MeanArrivalInterval minus the mean inter-arrival
	// time accumulated over all feedback packets processed before this one.
	// It is NaN when either side has no inter-arrival sample.
	MeanIntervalDelta float64
}

// TWCCLifetimeStats summarizes every feedback packet processed by an
// interpreter since it was created.
type TWCCLifetimeStats struct {
	// PacketCount is the number of distinct sequence numbers observed.
	PacketCount int

	// ReceivedCount is the number of observed sequence numbers reported as
	// received, with or without a receive delta.
	ReceivedCount int

	// LostCount is the number of observed sequence numbers reported as not
	// received.
	LostCount int

	// LossRate is LostCount divided by PacketCount. It is zero when
	// PacketCount is zero.
	LossRate float64

	// MeanArrivalInterval is the mean inter-arrival time in microseconds over
	// all received packets that carry a delta. It is NaN when no interval is
	// available.
	MeanArrivalInterval float64

	// StdDevArrivalInterval is the population standard deviation of the
	// inter-arrival times in microseconds. It is NaN when no interval is
	// available.
	StdDevArrivalInterval float64
}

// TWCCInterpretResult is the output of processing one TransportLayerCC
// packet.
type TWCCInterpretResult struct {
	// Arrivals lists every sequence number covered by the feedback packet in
	// transport sequence order, including sequence numbers already observed
	// in earlier feedback packets. Use SequenceNumber to tell them apart.
	Arrivals []TWCCArrival

	// Stats summarizes the sequence numbers first observed in this feedback
	// packet.
	Stats TWCCWindowStats
}

// TWCCInterpreter consumes TransportLayerCC feedback packets and turns them
// into per-sequence arrival information with window loss and inter-arrival
// statistics.
//
// The interpreter keeps the reference time and sequence number state needed
// to chain feedback packets together: 16-bit sequence numbers are unwrapped,
// 24-bit reference times are extended across wrap-arounds, receive deltas are
// accumulated into absolute arrival times, and overlapping reports are
// de-duplicated so that each sequence number is counted at most once.
//
// A TWCCInterpreter is not safe for concurrent use.
type TWCCInterpreter struct {
	sequenceUnwrapper tccSequenceUnwrapper

	initialized bool

	// baseTimeOffset is the absolute arrival time of the first packet's
	// reference time; exposed arrival times are relative to it.
	baseTimeOffset int64

	// lastReferenceTime is the extended 24-bit reference time of the latest
	// processed packet, in 64ms units.
	lastReferenceTime int64

	// lastArrivalTime is the absolute arrival time of the latest received
	// packet carrying a delta, in microseconds.
	lastArrivalTime int64
	hasLastArrival  bool

	// observed contains every extended sequence number already accounted for,
	// for overlap de-duplication.
	observed map[int64]struct{}

	// Cumulative counters and Welford inter-arrival statistics.
	totalPackets  int
	totalReceived int
	totalLost     int
	intervalCount int
	intervalMean  float64
	intervalM2    float64
}

// NewTWCCInterpreter creates a TWCCInterpreter with no baseline. The first
// processed feedback packet establishes the reference timeline.
func NewTWCCInterpreter() *TWCCInterpreter {
	return &TWCCInterpreter{}
}

// Stats returns the statistics accumulated over all feedback packets
// processed so far.
func (i *TWCCInterpreter) Stats() TWCCLifetimeStats {
	stats := TWCCLifetimeStats{
		PacketCount:           i.totalPackets,
		ReceivedCount:         i.totalReceived,
		LostCount:             i.totalLost,
		MeanArrivalInterval:   math.NaN(),
		StdDevArrivalInterval: math.NaN(),
	}
	if i.totalPackets > 0 {
		stats.LossRate = float64(i.totalLost) / float64(i.totalPackets)
	}
	if i.intervalCount > 0 {
		stats.MeanArrivalInterval = i.intervalMean
		stats.StdDevArrivalInterval = math.Sqrt(i.intervalM2 / float64(i.intervalCount))
	}

	return stats
}

// Process interprets one TransportLayerCC packet and returns the arrival
// state of every sequence number it covers plus the window statistics.
//
// Malformed packets, such as unknown chunk types, packet status symbols
// outside the valid range or receive deltas that do not match the status
// symbols, are reported as errors and leave the interpreter state unchanged.
func (i *TWCCInterpreter) Process(packet *TransportLayerCC) (*TWCCInterpretResult, error) {
	if packet == nil {
		return nil, errTCCInvalidFeedback
	}

	symbols, err := flattenTCCSymbols(packet)
	if err != nil {
		return nil, err
	}
	if err := validateTCCDeltas(packet, symbols); err != nil {
		return nil, err
	}

	// A packet covering no sequence numbers carries no arrival information
	// and neither establishes nor advances the reference timeline.
	if !i.initialized && len(symbols) == 0 {
		return emptyTCCResult(), nil
	}

	// Work on a shadow state so that a malformed packet never partially
	// mutates the interpreter.
	shadow := *i
	shadow.advanceReferenceTime(packet.ReferenceTime)

	result := shadow.interpretSymbols(packet, symbols)
	result.finalize(i.intervalMean, i.intervalCount > 0)

	*i = shadow

	return result, nil
}

// emptyTCCResult returns the result of processing a packet without reports.
func emptyTCCResult() *TWCCInterpretResult {
	return &TWCCInterpretResult{
		Stats: TWCCWindowStats{
			MeanArrivalInterval:   math.NaN(),
			StdDevArrivalInterval: math.NaN(),
			MeanIntervalDelta:     math.NaN(),
		},
	}
}

// advanceReferenceTime establishes or extends the reference timeline.
func (i *TWCCInterpreter) advanceReferenceTime(referenceTime uint32) {
	if !i.initialized {
		i.initialized = true
		i.observed = make(map[int64]struct{})
		i.lastReferenceTime = int64(referenceTime)
		i.baseTimeOffset = i.lastReferenceTime * tccReferenceTimeScale

		return
	}

	i.lastReferenceTime = i.unwrapReferenceTime(referenceTime)
}

// interpretSymbols walks every reported sequence number, reconstructs the
// arrival state and accumulates the window statistics.
func (i *TWCCInterpreter) interpretSymbols(packet *TransportLayerCC, symbols []uint16) *TWCCInterpretResult {
	result := emptyTCCResult()
	result.Arrivals = make([]TWCCArrival, 0, len(symbols))

	// Deltas within a packet are relative to that packet's reference time,
	// not to the previous packet's last arrival.
	runningTime := i.lastReferenceTime * tccReferenceTimeScale
	deltaIndex := 0
	maxSequenceNumber := int64(0)

	for index, symbol := range symbols {
		sequenceNumber := i.sequenceUnwrapper.unwrap(packet.BaseSequenceNumber + uint16(index)) //nolint:gosec // index is bounded by PacketStatusCount
		maxSequenceNumber = sequenceNumber

		arrival, deltaUsed, err := tccArrival(symbol, sequenceNumber, runningTime, i.baseTimeOffset, packet.RecvDeltas, deltaIndex)
		if err != nil {
			// validateTCCDeltas guarantees this cannot happen.
			return emptyTCCResult()
		}
		deltaIndex += deltaUsed
		runningTime += arrival.deltaUS

		i.accountFor(arrival.TWCCArrival, runningTime, result)
		result.Arrivals = append(result.Arrivals, arrival.TWCCArrival)
	}

	// De-duplication state stays bounded to one sequence number space.
	for sequenceNumber := range i.observed {
		if sequenceNumber < maxSequenceNumber-tccSequenceNumberSpace {
			delete(i.observed, sequenceNumber)
		}
	}

	return result
}

// tccDecodedArrival pairs the public arrival state with the receive delta
// consumed while decoding it.
type tccDecodedArrival struct {
	TWCCArrival
	deltaUS int64
}

// tccArrival builds the arrival state of one sequence number and reports how
// many receive deltas it consumed.
func tccArrival(symbol uint16, sequenceNumber, runningTime, baseTimeOffset int64, deltas []*RecvDelta, deltaIndex int) (tccDecodedArrival, int, error) {
	arrival := tccDecodedArrival{
		TWCCArrival: TWCCArrival{SequenceNumber: sequenceNumber},
	}

	switch symbol {
	case TypeTCCPacketNotReceived:
		arrival.Status = TWCCStatusNotReceived
	case TypeTCCPacketReceivedSmallDelta, TypeTCCPacketReceivedLargeDelta:
		if deltaIndex >= len(deltas) || deltas[deltaIndex] == nil || deltas[deltaIndex].Type != symbol {
			return arrival, 0, errTCCDeltaMismatch
		}
		arrival.deltaUS = deltas[deltaIndex].Delta
		arrival.Status = TWCCStatusReceived
		arrival.ArrivalTime = runningTime + arrival.deltaUS - baseTimeOffset

		return arrival, 1, nil
	case TypeTCCPacketReceivedWithoutDelta:
		arrival.Status = TWCCStatusReceivedWithoutDelta
	default:
		return arrival, 0, errTCCSymbolOutOfRange
	}

	return arrival, 0, nil
}

// accountFor updates the cumulative and window counters for a sequence number
// that was not already observed in an earlier feedback packet.
func (i *TWCCInterpreter) accountFor(arrival TWCCArrival, runningTime int64, result *TWCCInterpretResult) {
	if _, duplicated := i.observed[arrival.SequenceNumber]; duplicated {
		return
	}

	i.observed[arrival.SequenceNumber] = struct{}{}
	i.totalPackets++
	result.Stats.PacketCount++

	switch arrival.Status {
	case TWCCStatusNotReceived:
		i.totalLost++
		result.Stats.LostCount++
	case TWCCStatusReceived, TWCCStatusReceivedWithoutDelta:
		i.totalReceived++
		result.Stats.ReceivedCount++
	}

	if arrival.Status != TWCCStatusReceived {
		return
	}

	if i.hasLastArrival {
		interval := arrival.ArrivalTime - (i.lastArrivalTime - i.baseTimeOffset)
		result.Stats.ArrivalIntervals = append(result.Stats.ArrivalIntervals, interval)
		i.addInterval(float64(interval))
	}
	i.lastArrivalTime = runningTime
	i.hasLastArrival = true
}

// finalize fills in the derived window statistics.
func (r *TWCCInterpretResult) finalize(previousIntervalMean float64, hasPreviousInterval bool) {
	if r.Stats.PacketCount > 0 {
		r.Stats.LossRate = float64(r.Stats.LostCount) / float64(r.Stats.PacketCount)
	}
	if len(r.Stats.ArrivalIntervals) == 0 {
		return
	}

	r.Stats.MeanArrivalInterval = meanOfIntervals(r.Stats.ArrivalIntervals)
	r.Stats.StdDevArrivalInterval = stddevOfIntervals(r.Stats.ArrivalIntervals, r.Stats.MeanArrivalInterval)
	if hasPreviousInterval {
		r.Stats.MeanIntervalDelta = r.Stats.MeanArrivalInterval - previousIntervalMean
	}
}

// meanOfIntervals returns the arithmetic mean of inter-arrival times.
func meanOfIntervals(intervals []int64) float64 {
	var total int64
	for _, interval := range intervals {
		total += interval
	}

	return float64(total) / float64(len(intervals))
}

// stddevOfIntervals returns the population standard deviation of
// inter-arrival times.
func stddevOfIntervals(intervals []int64, mean float64) float64 {
	if len(intervals) < 2 {
		return 0
	}

	var squaredDifferences float64
	for _, interval := range intervals {
		difference := float64(interval) - mean
		squaredDifferences += difference * difference
	}

	return math.Sqrt(squaredDifferences / float64(len(intervals)))
}

// unwrapReferenceTime extends a 24-bit reference time onto the continuous
// timeline of previously processed packets, selecting the value nearest to
// the previous reference time.
func (i *TWCCInterpreter) unwrapReferenceTime(referenceTime uint32) int64 {
	previous := i.lastReferenceTime % tccReferenceTimeModulus
	if previous < 0 {
		previous += tccReferenceTimeModulus
	}

	shift := int64(referenceTime) - previous
	switch {
	case shift < -tccReferenceTimeModulus/2:
		shift += tccReferenceTimeModulus
	case shift > tccReferenceTimeModulus/2:
		shift -= tccReferenceTimeModulus
	}

	return i.lastReferenceTime + shift
}

// addInterval merges one inter-arrival sample into the cumulative Welford
// statistics.
func (i *TWCCInterpreter) addInterval(interval float64) {
	i.intervalCount++
	delta := interval - i.intervalMean
	i.intervalMean += delta / float64(i.intervalCount)
	i.intervalM2 += delta * (interval - i.intervalMean)
}

// tccSequenceUnwrapper extends 16-bit sequence numbers to monotonically
// increasing int64 values, following the same rules as the TWCC recorder.
type tccSequenceUnwrapper struct {
	initialized   bool
	lastUnwrapped int64
}

func (u *tccSequenceUnwrapper) unwrap(sequenceNumber uint16) int64 {
	if !u.initialized {
		u.initialized = true
		u.lastUnwrapped = int64(sequenceNumber)

		return u.lastUnwrapped
	}

	lastWrapped := uint16(u.lastUnwrapped) //nolint:gosec // G115
	delta := int64(sequenceNumber) - int64(lastWrapped)
	if tccIsNewer(sequenceNumber, lastWrapped) {
		if delta < 0 {
			delta += tccSequenceNumberSpace
		}
	} else if delta > 0 && u.lastUnwrapped+delta-tccSequenceNumberSpace >= 0 {
		delta -= tccSequenceNumberSpace
	}

	u.lastUnwrapped += delta

	return u.lastUnwrapped
}

// tccIsNewer reports whether value comes after previous in the 16-bit
// sequence number space. The half-space tie is broken by the numeric value.
func tccIsNewer(value, previous uint16) bool {
	if value-previous == tccSequenceBreakpoint {
		return value > previous
	}

	return value != previous && value-previous < tccSequenceBreakpoint
}

// flattenTCCSymbols expands the packet status chunks of a feedback packet
// into one status symbol per reported sequence number. The total number of
// symbols covered by the chunks must match PacketStatusCount exactly.
func flattenTCCSymbols(packet *TransportLayerCC) ([]uint16, error) {
	if tccSymbolCount(packet.PacketChunks) != int(packet.PacketStatusCount) {
		return nil, errTCCInvalidFeedback
	}

	symbols := make([]uint16, 0, packet.PacketStatusCount)
	for _, chunk := range packet.PacketChunks {
		switch typedChunk := chunk.(type) {
		case *RunLengthChunk:
			for range typedChunk.RunLength {
				symbols = append(symbols, typedChunk.PacketStatusSymbol)
			}
		case *StatusVectorChunk:
			symbols = append(symbols, typedChunk.SymbolList...)
		default:
			return nil, errTCCInvalidFeedback
		}
	}

	return symbols, nil
}

// tccSymbolCount returns the number of sequence numbers covered by the
// chunks, or -1 when a chunk has an unknown type.
func tccSymbolCount(chunks []PacketStatusChunk) (count int) {
	for _, chunk := range chunks {
		switch typedChunk := chunk.(type) {
		case *RunLengthChunk:
			count += int(typedChunk.RunLength)
		case *StatusVectorChunk:
			count += len(typedChunk.SymbolList)
		default:
			return -1
		}
	}

	return count
}

// validateTCCDeltas checks that every received-with-delta symbol has a
// receive delta of the matching type, and that no delta is left unused.
func validateTCCDeltas(packet *TransportLayerCC, symbols []uint16) error {
	deltaIndex := 0

	for _, symbol := range symbols {
		switch symbol {
		case TypeTCCPacketReceivedSmallDelta, TypeTCCPacketReceivedLargeDelta:
			if deltaIndex >= len(packet.RecvDeltas) || packet.RecvDeltas[deltaIndex] == nil {
				return errTCCDeltaMismatch
			}
			if packet.RecvDeltas[deltaIndex].Type != symbol {
				return errTCCDeltaMismatch
			}
			deltaIndex++
		case TypeTCCPacketNotReceived, TypeTCCPacketReceivedWithoutDelta:
		default:
			return errTCCSymbolOutOfRange
		}
	}

	if deltaIndex != len(packet.RecvDeltas) {
		return errTCCDeltaMismatch
	}

	return nil
}
