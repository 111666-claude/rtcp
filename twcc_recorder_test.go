// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"maps"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	twccTestSenderSSRC = 1111
	twccTestMediaSSRC  = 2222
)

// baseTime returns a fixed instant aligned to the 64ms TWCC reference time
// grid so that reconstructed arrival times compare exactly.
func baseTime() time.Time {
	return time.Unix(1000, 0).Truncate(twccReferenceTimeTick)
}

func at(ms int) time.Time {
	return baseTime().Add(time.Duration(ms) * time.Millisecond)
}

// att returns a time n 250us delta ticks after the aligned base, so arrivals
// and reconstructed arrivals compare exactly after delta quantization.
func att(ticks int) time.Time {
	return baseTime().Add(time.Duration(ticks) * twccDeltaTick)
}

// quantized returns the arrival time a TWCC packet can actually represent:
// the reference time is truncated to the 64ms grid and the remainder is
// carried by the first arrival delta, so sub-64ms offsets are preserved but
// the absolute instant is reconstructed from the encoded reference field.
func quantized(arrival time.Time) time.Time {
	reference := arrival.Truncate(twccReferenceTimeTick)
	remainder := arrival.Sub(reference).Nanoseconds() / int64(twccDeltaTick)

	return reference.Add(time.Duration(remainder) * twccDeltaTick)
}

// expandStatuses flattens the status chunks of a feedback packet into one
// symbol per sequence number position. Unused symbols in a trailing status
// vector are discarded.
func expandStatuses(t *testing.T, packet *TransportLayerCC) []uint16 {
	t.Helper()

	symbols := make([]uint16, 0, packet.PacketStatusCount)

	for _, chunk := range packet.PacketChunks {
		remaining := int(packet.PacketStatusCount) - len(symbols)
		if remaining == 0 {
			break
		}

		switch c := chunk.(type) {
		case *RunLengthChunk:
			count := min(int(c.RunLength), remaining)
			for range count {
				symbols = append(symbols, c.PacketStatusSymbol)
			}
		case *StatusVectorChunk:
			count := min(len(c.SymbolList), remaining)
			symbols = append(symbols, c.SymbolList[:count]...)
		default:
			require.Failf(t, "unexpected chunk type", "%T", chunk)

			return nil
		}
	}

	require.Len(t, symbols, int(packet.PacketStatusCount))

	return symbols
}

// roundTrip marshals and unmarshals every feedback packet and checks the size
// budget and header fields.
func roundTrip(t *testing.T, packets []*TransportLayerCC, maxSize int) []*TransportLayerCC {
	t.Helper()
	require.NotEmpty(t, packets)

	decoded := make([]*TransportLayerCC, 0, len(packets))

	for i, packet := range packets {
		raw, err := packet.Marshal()
		require.NoErrorf(t, err, "marshal packet %d", i)
		assert.LessOrEqualf(t, len(raw), maxSize, "packet %d exceeds size budget", i)
		assert.Lenf(t, raw, packet.MarshalSize(), "packet %d marshal size mismatch", i)
		// MarshalSize is bounded by the configured max packet size and fits
		// in the 16 bit RTCP length field.
		assert.Equalf(t, uint16(packet.MarshalSize()/4-1), packet.Header.Length, //nolint:gosec // G115
			"packet %d length field", i)

		var again TransportLayerCC
		require.NoErrorf(t, again.Unmarshal(raw), "unmarshal packet %d", i)
		assert.Equal(t, TypeTransportSpecificFeedback, again.Header.Type)
		assert.Equal(t, FormatTCC, again.Header.Count)
		assert.Equal(t, uint32(twccTestSenderSSRC), again.SenderSSRC)
		assert.Equal(t, uint32(twccTestMediaSSRC), again.MediaSSRC)

		decoded = append(decoded, &again)
	}

	return decoded
}

// reconstructArrivals rebuilds the arrival time of every received sequence
// number from the reference time and deltas of one feedback packet.
func reconstructArrivals(t *testing.T, packet *TransportLayerCC) map[uint16]time.Time {
	t.Helper()

	statuses := expandStatuses(t, packet)
	require.Len(t, packet.RecvDeltas, countReceived(statuses))

	reference := time.Unix(0, int64(packet.ReferenceTime)*int64(twccReferenceTimeTick))
	arrivals := make(map[uint16]time.Time)
	deltaIndex := 0
	elapsed := time.Duration(0)

	for offset, symbol := range statuses {
		seq := packet.BaseSequenceNumber + uint16(offset) //nolint:gosec // G115
		if symbol == TypeTCCPacketNotReceived {
			continue
		}

		elapsed += time.Duration(packet.RecvDeltas[deltaIndex].Delta) * time.Microsecond
		deltaIndex++
		arrivals[seq] = reference.Add(elapsed)
	}

	return arrivals
}

func countReceived(statuses []uint16) int {
	count := 0
	for _, symbol := range statuses {
		if symbol != TypeTCCPacketNotReceived {
			count++
		}
	}

	return count
}

// allStatuses concatenates the status symbols of all feedback packets.
func allStatuses(t *testing.T, packets []*TransportLayerCC) []uint16 {
	t.Helper()

	combined := make([]uint16, 0)
	for _, packet := range packets {
		combined = append(combined, expandStatuses(t, packet)...)
	}

	return combined
}

func TestTWCCRecorder_NewInvalidOptions(t *testing.T) {
	_, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC, WithTWCCMaxPacketSize(23))
	assert.ErrorIs(t, err, errTWCCPacketSizeTooSmall)

	_, err = NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC, WithTWCCMaxTrackedPackets(0))
	assert.ErrorIs(t, err, errTWCCCapacityTooSmall)

	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)
	assert.Equal(t, DefaultTWCCMaxPacketSize, recorder.maxPacketSize)
	assert.Equal(t, DefaultTWCCMaxTrackedPackets, recorder.maxTrackedPackets)
}

func TestTWCCRecorder_EmptyBuild(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	packets, err := recorder.BuildFeedbackPackets()
	assert.NoError(t, err)
	assert.Nil(t, packets)

	// A second empty build stays empty and does not advance the counter.
	packets, err = recorder.BuildFeedbackPackets()
	assert.NoError(t, err)
	assert.Nil(t, packets)
}

func TestTWCCRecorder_BasicRoundTrip(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// Sequence 0..6 with one loss at 3.
	arrivals := map[uint16]time.Time{
		0: at(0),
		1: at(10),
		2: at(20),
		4: at(40),
		5: at(50),
		6: at(60),
	}
	for seq, arrival := range arrivals {
		recorder.Record(seq, arrival)
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(0), packets[0].BaseSequenceNumber)
	assert.Equal(t, uint16(7), packets[0].PacketStatusCount)
	assert.Equal(t, uint8(0), packets[0].FbPktCount)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	reconstructed := reconstructArrivals(t, decoded[0])

	for seq, arrival := range arrivals {
		assert.Equalf(t, quantized(arrival), reconstructed[seq], "sequence %d arrival", seq)
	}

	statuses := expandStatuses(t, decoded[0])
	assert.Equal(t, TypeTCCPacketNotReceived, statuses[3])
	assert.Len(t, reconstructed, len(arrivals))
}

func TestTWCCRecorder_RunLengthEncoding(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	for seq := range uint16(10) {
		recorder.Record(seq, att(int(seq)*20))
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	require.Len(t, packets[0].PacketChunks, 1)

	run, ok := packets[0].PacketChunks[0].(*RunLengthChunk)
	require.True(t, ok)
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, run.PacketStatusSymbol)
	assert.Equal(t, uint16(10), run.RunLength)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	reconstructed := reconstructArrivals(t, decoded[0])
	for seq := range uint16(10) {
		assert.Equal(t, quantized(att(int(seq)*20)), reconstructed[seq])
	}
}

func TestTWCCRecorder_StatusVectorEncoding(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// Alternating received/lost produces a one-bit status vector.
	for seq := range uint16(8) {
		if seq%2 == 0 {
			recorder.Record(seq, att(int(seq)*20))
		}
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	require.Len(t, packets[0].PacketChunks, 1)

	vector, ok := packets[0].PacketChunks[0].(*StatusVectorChunk)
	require.True(t, ok)
	assert.Equal(t, uint16(TypeTCCSymbolSizeOneBit), vector.SymbolSize)
	assert.Len(t, vector.SymbolList, 7)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	statuses := expandStatuses(t, decoded[0])
	for offset, symbol := range statuses {
		want := TypeTCCPacketNotReceived
		if offset%2 == 0 {
			want = TypeTCCPacketReceivedSmallDelta
		}
		assert.Equalf(t, want, symbol, "offset %d", offset)
	}
}

func TestTWCCRecorder_ReorderingAndDuplicates(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// Arrival order differs from sequence order; seq 2 is duplicated. Each
	// sequence number keeps one fixed arrival time regardless of call order.
	order := []uint16{0, 1, 3, 2, 4, 2}
	arrivals := map[uint16]time.Time{
		0: att(0),
		1: att(40),
		2: att(80),
		3: att(120),
		4: att(160),
	}
	for _, seq := range order {
		recorder.Record(seq, arrivals[seq])
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	assert.Equal(t, uint16(5), decoded[0].PacketStatusCount)
	assert.Len(t, decoded[0].RecvDeltas, 5)

	reconstructed := reconstructArrivals(t, decoded[0])
	for seq, arrival := range arrivals {
		// The duplicate kept the first arrival time.
		assert.Equal(t, quantized(arrival), reconstructed[seq])
	}
}

func TestTWCCRecorder_ConsecutiveBuildsDoNotRepeat(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	recorder.Record(0, at(0))
	recorder.Record(1, at(10))

	first, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, uint8(0), first[0].FbPktCount)

	packets, err := recorder.BuildFeedbackPackets()
	assert.NoError(t, err)
	assert.Nil(t, packets)

	recorder.Record(2, at(20))
	recorder.Record(3, at(30))

	second, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, uint16(2), second[0].BaseSequenceNumber)
	assert.Equal(t, uint16(2), second[0].PacketStatusCount)
	assert.Equal(t, uint8(1), second[0].FbPktCount)

	decoded := roundTrip(t, second, DefaultTWCCMaxPacketSize)
	reconstructed := reconstructArrivals(t, decoded[0])
	assert.Equal(t, quantized(at(20)), reconstructed[2])
	assert.Equal(t, quantized(at(30)), reconstructed[3])
}

func TestTWCCRecorder_SplitsOnMaxPacketSize(t *testing.T) {
	const maxSize = 32
	recorder, err := NewTWCCRecorder(
		twccTestSenderSSRC, twccTestMediaSSRC, WithTWCCMaxPacketSize(maxSize),
	)
	require.NoError(t, err)

	const total = 30
	for seq := range uint16(total) {
		recorder.Record(seq, att(int(seq)*8))
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Greater(t, len(packets), 1)

	decoded := roundTrip(t, packets, maxSize)
	assert.Equal(t, uint8(0), decoded[0].FbPktCount)
	for i := 1; i < len(decoded); i++ {
		assert.Equal(t, uint8(i), decoded[i].FbPktCount)
	}

	// Bases continue where the previous packet ended.
	covered := 0
	for i, packet := range decoded {
		expectedBase := uint16(covered)
		assert.Equalf(t, expectedBase, packet.BaseSequenceNumber, "packet %d base", i)
		covered += int(packet.PacketStatusCount)
	}
	assert.Equal(t, total, covered)

	// No sequence number is lost or duplicated by the split.
	statuses := allStatuses(t, decoded)
	require.Len(t, statuses, total)
	for _, symbol := range statuses {
		assert.Equal(t, TypeTCCPacketReceivedSmallDelta, symbol)
	}

	// Arrival times survive the split.
	arrivals := make(map[uint16]time.Time)
	for _, packet := range decoded {
		maps.Copy(arrivals, reconstructArrivals(t, packet))
	}
	for seq := range uint16(total) {
		assert.Equal(t, quantized(att(int(seq)*8)), arrivals[seq])
	}

	// Buffer is consumed exactly once.
	again, err := recorder.BuildFeedbackPackets()
	assert.NoError(t, err)
	assert.Nil(t, again)
}

func TestTWCCRecorder_LargeTimeGapStartsNewPacket(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	recorder.Record(0, att(0))
	// A gap beyond the signed 16 bit large-delta range (8191.75ms).
	hugeGap := time.Duration((1<<15)+100) * twccDeltaTick
	recorder.Record(1, att(0).Add(hugeGap))
	recorder.Record(2, att(0).Add(hugeGap).Add(40*twccDeltaTick))

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 2)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	assert.Equal(t, uint16(1), decoded[0].PacketStatusCount)
	assert.Equal(t, uint16(1), decoded[1].BaseSequenceNumber)
	assert.Equal(t, uint16(2), decoded[1].PacketStatusCount)

	first := reconstructArrivals(t, decoded[0])
	second := reconstructArrivals(t, decoded[1])
	assert.Equal(t, quantized(att(0)), first[0])
	assert.Equal(t, quantized(att(0).Add(hugeGap)), second[1])
	assert.Equal(t, quantized(att(0).Add(hugeGap).Add(40*twccDeltaTick)), second[2])
}

func TestTWCCRecorder_NonMonotonicArrivalTimes(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// Arrival times move backwards; negative deltas must use large deltas.
	recorder.Record(0, at(100))
	recorder.Record(1, at(90))
	recorder.Record(2, at(95))

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	statuses := expandStatuses(t, decoded[0])
	assert.Equal(t, TypeTCCPacketReceivedLargeDelta, statuses[1])

	reconstructed := reconstructArrivals(t, decoded[0])
	assert.Equal(t, quantized(at(100)), reconstructed[0])
	assert.Equal(t, quantized(at(90)), reconstructed[1])
	assert.Equal(t, quantized(at(95)), reconstructed[2])
}

func TestTWCCRecorder_SmallAndLargeDeltaSelection(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	recorder.Record(0, at(0))
	recorder.Record(1, at(50))  // 50ms = 200 ticks, small delta
	recorder.Record(2, at(100)) // 50ms, small delta
	recorder.Record(3, at(200)) // 100ms = 400 ticks, large delta

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	statuses := expandStatuses(t, decoded[0])
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, statuses[0])
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, statuses[1])
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, statuses[2])
	assert.Equal(t, TypeTCCPacketReceivedLargeDelta, statuses[3])
	assert.Equal(t, int(TypeTCCPacketReceivedLargeDelta), int(decoded[0].RecvDeltas[3].Type))

	reconstructed := reconstructArrivals(t, decoded[0])
	assert.Equal(t, quantized(at(200)), reconstructed[3])
}

func TestTWCCRecorder_CapacityEviction(t *testing.T) {
	const capacity = 5
	recorder, err := NewTWCCRecorder(
		twccTestSenderSSRC, twccTestMediaSSRC, WithTWCCMaxTrackedPackets(capacity),
	)
	require.NoError(t, err)

	for seq := range uint16(10) {
		recorder.Record(seq, att(int(seq)*20))
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.NotEmpty(t, packets)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	statuses := allStatuses(t, decoded)

	// The base advanced past the evicted entries; only recent sequence
	// numbers are reported and every reported one was received.
	firstBase := decoded[0].BaseSequenceNumber
	assert.Greater(t, firstBase, uint16(0))
	assert.LessOrEqual(t, len(statuses), capacity)

	for _, symbol := range statuses {
		assert.Equal(t, TypeTCCPacketReceivedSmallDelta, symbol)
	}
}

func TestTWCCRecorder_ResetClearsAllState(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	recorder.Record(0, at(0))
	recorder.Record(1, at(10))
	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint8(1), recorder.fbPktCount)

	recorder.Reset()
	assert.False(t, recorder.initialized)
	assert.Equal(t, uint8(0), recorder.fbPktCount)
	assert.Empty(t, recorder.packets)

	// Sequence numbering restarts from zero and the feedback counter too.
	recorder.Record(0, at(0))
	packets, err = recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(0), packets[0].BaseSequenceNumber)
	assert.Equal(t, uint8(0), packets[0].FbPktCount)
}

func TestTWCCRecorder_SequenceNumberWrap(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// Build up to the wrap edge and cross it.
	recorder.Record(math.MaxUint16-1, at(0))
	recorder.Record(math.MaxUint16, at(10))
	recorder.Record(0, at(20))
	recorder.Record(1, at(30))

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(math.MaxUint16-1), packets[0].BaseSequenceNumber)
	assert.Equal(t, uint16(4), packets[0].PacketStatusCount)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	reconstructed := reconstructArrivals(t, decoded[0])
	assert.Equal(t, quantized(at(0)), reconstructed[math.MaxUint16-1])
	assert.Equal(t, quantized(at(10)), reconstructed[math.MaxUint16])
	assert.Equal(t, quantized(at(20)), reconstructed[0])
	assert.Equal(t, quantized(at(30)), reconstructed[1])

	// The next window after the wrap continues at sequence 2.
	recorder.Record(2, at(40))
	packets, err = recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(2), packets[0].BaseSequenceNumber)
}

func TestTWCCRecorder_FbPktCountWraps(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)
	recorder.fbPktCount = math.MaxUint8

	recorder.Record(0, at(0))
	first, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, first, 1)
	assert.Equal(t, uint8(math.MaxUint8), first[0].FbPktCount)

	recorder.Record(1, at(10))
	second, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, uint8(0), second[0].FbPktCount)
}

func TestTWCCRecorder_MinPacketSizeMakesProgress(t *testing.T) {
	// The smallest legal size must still emit valid packets for every symbol.
	recorder, err := NewTWCCRecorder(
		twccTestSenderSSRC, twccTestMediaSSRC, WithTWCCMaxPacketSize(twccMinFeedbackSize),
	)
	require.NoError(t, err)

	for seq := range uint16(6) {
		recorder.Record(seq, att(int(seq)*20))
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.NotEmpty(t, packets)

	decoded := roundTrip(t, packets, twccMinFeedbackSize)
	assert.Len(t, allStatuses(t, decoded), 6)
}

func TestTWCCRecorder_GapIsReportedAsNotReceived(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// Sequence 0 anchors the base; 1 and 2 are missing, 3 and 4 received.
	recorder.Record(0, at(0))
	recorder.Record(3, at(30))
	recorder.Record(4, at(40))

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(0), packets[0].BaseSequenceNumber)
	assert.Equal(t, uint16(5), packets[0].PacketStatusCount)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	statuses := expandStatuses(t, decoded[0])
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, statuses[0])
	assert.Equal(t, TypeTCCPacketNotReceived, statuses[1])
	assert.Equal(t, TypeTCCPacketNotReceived, statuses[2])
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, statuses[3])
	assert.Equal(t, TypeTCCPacketReceivedSmallDelta, statuses[4])
	// Not-received positions carry no delta.
	assert.Len(t, decoded[0].RecvDeltas, 3)

	// A recorder that only ever saw high sequence numbers starts its base at
	// the first sequence number observed; unknown lower numbers are not gaps.
	fresh, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)
	fresh.Record(3, at(0))
	fresh.Record(4, at(10))
	packets, err = fresh.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)
	assert.Equal(t, uint16(3), packets[0].BaseSequenceNumber)
	assert.Equal(t, uint16(2), packets[0].PacketStatusCount)
}

func TestTWCCRecorder_ConcurrentUse(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		defer close(done)
		for range 200 {
			recorder.Record(1, att(0))
			recorder.Reset()
		}
	}()

	for range 200 {
		recorder.Record(2, att(1))
		_, buildErr := recorder.BuildFeedbackPackets()
		assert.NoError(t, buildErr)
	}

	<-done
}

func TestTWCCRecorder_ReorderingWithinHalfWindow(t *testing.T) {
	recorder, err := NewTWCCRecorder(twccTestSenderSSRC, twccTestMediaSSRC)
	require.NoError(t, err)

	// A burst of reordering well within half the 16 bit window.
	order := []uint16{100, 110, 105, 101, 120, 102}
	arrivals := make(map[uint16]time.Time, len(order))
	for i, seq := range order {
		arrival := att(i * 20)
		arrivals[seq] = arrival
		recorder.Record(seq, arrival)
	}

	packets, err := recorder.BuildFeedbackPackets()
	require.NoError(t, err)
	require.Len(t, packets, 1)

	// The window spans every sequence number from the lowest (100) to the
	// highest (120), regardless of the interleaved arrival order.
	assert.Equal(t, uint16(100), packets[0].BaseSequenceNumber)
	assert.Equal(t, uint16(21), packets[0].PacketStatusCount)

	decoded := roundTrip(t, packets, DefaultTWCCMaxPacketSize)
	reconstructed := reconstructArrivals(t, decoded[0])
	for seq, arrival := range arrivals {
		assert.Equal(t, quantized(arrival), reconstructed[seq])
	}
}
