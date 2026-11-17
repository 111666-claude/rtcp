// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

// tccDelta builds a receive delta of the given symbol type.
func tccDelta(symbol uint16, deltaUS int64) *RecvDelta {
	return &RecvDelta{Type: symbol, Delta: deltaUS}
}

// tccVectorChunks wraps status symbols into status vector chunks, using one
// bit per symbol when every symbol is representable that way and two bits
// otherwise.
func tccVectorChunks(symbols []uint16) []PacketStatusChunk {
	twoBit := false
	for _, symbol := range symbols {
		if symbol > TypeTCCPacketReceivedSmallDelta {
			twoBit = true
		}
	}

	capacity := 14
	var symbolSize uint16 = TypeTCCSymbolSizeOneBit
	if twoBit {
		capacity = 7
		symbolSize = TypeTCCSymbolSizeTwoBit
	}

	chunks := []PacketStatusChunk{}
	for start := 0; start < len(symbols); start += capacity {
		end := min(start+capacity, len(symbols))
		chunks = append(chunks, &StatusVectorChunk{
			SymbolSize: symbolSize,
			SymbolList: append([]uint16{}, symbols[start:end]...),
		})
	}

	return chunks
}

// tccPacket builds a feedback packet from status symbols and receive deltas,
// which must be ordered exactly like the received-with-delta symbols.
func tccPacket(base uint16, refTime uint32, fbCount uint8, symbols []uint16, deltas []*RecvDelta) *TransportLayerCC {
	packet := &TransportLayerCC{
		Header:             Header{Count: FormatTCC, Type: TypeTransportSpecificFeedback},
		SenderSSRC:         1,
		MediaSSRC:          2,
		BaseSequenceNumber: base,
		PacketStatusCount:  uint16(len(symbols)), //nolint:gosec // test inputs fit in uint16
		ReferenceTime:      refTime,
		FbPktCount:         fbCount,
		PacketChunks:       tccVectorChunks(symbols),
		RecvDeltas:         deltas,
	}
	packet.Header.Length = uint16(packet.MarshalSize()/4 - 1) //nolint:gosec // test packets fit

	return packet
}

func TestTWCCInterpreter_SinglePacket(t *testing.T) {
	interpreter := NewTWCCInterpreter()
	packet := tccPacket(100, 1000, 0,
		[]uint16{
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketReceivedLargeDelta,
			TypeTCCPacketNotReceived,
			TypeTCCPacketReceivedSmallDelta,
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 10000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 5000),
			tccDelta(TypeTCCPacketReceivedLargeDelta, 8000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 2000),
		})

	result, err := interpreter.Process(packet)
	assert.NoError(t, err)
	assert.Len(t, result.Arrivals, 5)

	expectedArrivals := []TWCCArrival{
		{SequenceNumber: 100, Status: TWCCStatusReceived, ArrivalTime: 10000},
		{SequenceNumber: 101, Status: TWCCStatusReceived, ArrivalTime: 15000},
		{SequenceNumber: 102, Status: TWCCStatusReceived, ArrivalTime: 23000},
		{SequenceNumber: 103, Status: TWCCStatusNotReceived},
		{SequenceNumber: 104, Status: TWCCStatusReceived, ArrivalTime: 25000},
	}
	assert.Equal(t, expectedArrivals, result.Arrivals)

	assert.Equal(t, 5, result.Stats.PacketCount)
	assert.Equal(t, 4, result.Stats.ReceivedCount)
	assert.Equal(t, 1, result.Stats.LostCount)
	assert.InDelta(t, 0.2, result.Stats.LossRate, 1e-12)
	assert.Equal(t, []int64{5000, 8000, 2000}, result.Stats.ArrivalIntervals)
	assert.InDelta(t, 5000, result.Stats.MeanArrivalInterval, 1e-9)
	assert.InDelta(t, math.Sqrt(6e6), result.Stats.StdDevArrivalInterval, 1e-9)
	assert.True(t, math.IsNaN(result.Stats.MeanIntervalDelta))

	lifetime := interpreter.Stats()
	assert.Equal(t, 5, lifetime.PacketCount)
	assert.Equal(t, 4, lifetime.ReceivedCount)
	assert.Equal(t, 1, lifetime.LostCount)
	assert.InDelta(t, 0.2, lifetime.LossRate, 1e-12)
	assert.InDelta(t, 5000, lifetime.MeanArrivalInterval, 1e-9)
	assert.InDelta(t, math.Sqrt(6e6), lifetime.StdDevArrivalInterval, 1e-9)
}

func TestTWCCInterpreter_CrossPacketAndOverlap(t *testing.T) {
	interpreter := NewTWCCInterpreter()

	// First packet: sequences 0..3, reference time 100.
	first := tccPacket(0, 100, 0,
		[]uint16{
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketNotReceived,
			TypeTCCPacketReceivedSmallDelta,
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 20000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 10000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 5000),
		})
	firstResult, err := interpreter.Process(first)
	assert.NoError(t, err)
	assert.Equal(t, []TWCCArrival{
		{SequenceNumber: 0, Status: TWCCStatusReceived, ArrivalTime: 20000},
		{SequenceNumber: 1, Status: TWCCStatusReceived, ArrivalTime: 30000},
		{SequenceNumber: 2, Status: TWCCStatusNotReceived},
		{SequenceNumber: 3, Status: TWCCStatusReceived, ArrivalTime: 35000},
	}, firstResult.Arrivals)
	assert.Equal(t, []int64{10000, 5000}, firstResult.Stats.ArrivalIntervals)

	// Second packet overlaps sequences 2 and 3 and extends to 4..6. The
	// delta of the duplicated sequence 3 is negative, exercising large
	// negative deltas across packet boundaries.
	second := tccPacket(2, 101, 1,
		[]uint16{
			TypeTCCPacketNotReceived,        // sequence 2, duplicated
			TypeTCCPacketReceivedLargeDelta, // sequence 3, duplicated
			TypeTCCPacketReceivedSmallDelta, // sequence 4, new
			TypeTCCPacketNotReceived,        // sequence 5, new
			TypeTCCPacketReceivedSmallDelta, // sequence 6, new
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedLargeDelta, -29000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 7000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 3000),
		})
	secondResult, err := interpreter.Process(second)
	assert.NoError(t, err)
	assert.Len(t, secondResult.Arrivals, 5)
	assert.Equal(t, int64(2), secondResult.Arrivals[0].SequenceNumber)
	assert.Equal(t, TWCCStatusNotReceived, secondResult.Arrivals[0].Status)
	assert.Equal(t, int64(3), secondResult.Arrivals[1].SequenceNumber)
	assert.Equal(t, TWCCStatusReceived, secondResult.Arrivals[1].Status)
	// Re-reported arrival time is reconstructed from the second packet's own
	// reference time and delta.
	assert.Equal(t, int64(35000), secondResult.Arrivals[1].ArrivalTime)
	assert.Equal(t, []TWCCArrival{
		{SequenceNumber: 4, Status: TWCCStatusReceived, ArrivalTime: 42000},
		{SequenceNumber: 5, Status: TWCCStatusNotReceived},
		{SequenceNumber: 6, Status: TWCCStatusReceived, ArrivalTime: 45000},
	}, secondResult.Arrivals[2:])

	// Only the three previously unknown sequence numbers enter the window.
	assert.Equal(t, 3, secondResult.Stats.PacketCount)
	assert.Equal(t, 2, secondResult.Stats.ReceivedCount)
	assert.Equal(t, 1, secondResult.Stats.LostCount)
	assert.InDelta(t, 1.0/3.0, secondResult.Stats.LossRate, 1e-12)
	assert.Equal(t, []int64{7000, 3000}, secondResult.Stats.ArrivalIntervals)
	assert.InDelta(t, 5000, secondResult.Stats.MeanArrivalInterval, 1e-9)
	assert.InDelta(t, 2000, secondResult.Stats.StdDevArrivalInterval, 1e-9)
	// Previous lifetime mean was 7500us (10000 and 5000).
	assert.InDelta(t, -2500, secondResult.Stats.MeanIntervalDelta, 1e-9)

	lifetime := interpreter.Stats()
	assert.Equal(t, 7, lifetime.PacketCount)
	assert.Equal(t, 5, lifetime.ReceivedCount)
	assert.Equal(t, 2, lifetime.LostCount)
	assert.InDelta(t, 2.0/7.0, lifetime.LossRate, 1e-12)
	assert.InDelta(t, 6250, lifetime.MeanArrivalInterval, 1e-9)
	assert.InDelta(t, math.Sqrt(6687500), lifetime.StdDevArrivalInterval, 1e-9)

	// Re-processing the exact same packet must not count anything twice.
	repeatResult, err := interpreter.Process(second)
	assert.NoError(t, err)
	assert.Zero(t, repeatResult.Stats.PacketCount)
	assert.Empty(t, repeatResult.Stats.ArrivalIntervals)
	assert.True(t, math.IsNaN(repeatResult.Stats.MeanArrivalInterval))
	assert.Equal(t, lifetime, interpreter.Stats())
}

func TestTWCCInterpreter_SequenceNumberWrap(t *testing.T) {
	interpreter := NewTWCCInterpreter()

	first := tccPacket(math.MaxUint16-1, 10, 0,
		[]uint16{
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketNotReceived,
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 2000),
		})
	firstResult, err := interpreter.Process(first)
	assert.NoError(t, err)
	assert.Equal(t, []int64{65534, 65535, 65536},
		[]int64{
			firstResult.Arrivals[0].SequenceNumber,
			firstResult.Arrivals[1].SequenceNumber,
			firstResult.Arrivals[2].SequenceNumber,
		})

	second := tccPacket(1, 11, 1,
		[]uint16{
			TypeTCCPacketReceivedLargeDelta,
			TypeTCCPacketReceivedSmallDelta,
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedLargeDelta, 2000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 4000),
		})
	secondResult, err := interpreter.Process(second)
	assert.NoError(t, err)
	assert.Equal(t, []TWCCArrival{
		{SequenceNumber: 65537, Status: TWCCStatusReceived, ArrivalTime: 66000},
		{SequenceNumber: 65538, Status: TWCCStatusReceived, ArrivalTime: 70000},
	}, secondResult.Arrivals)
	// The first interval bridges the wrap: 66000 - 3000.
	assert.Equal(t, []int64{63000, 4000}, secondResult.Stats.ArrivalIntervals)
	assert.InDelta(t, 33500, secondResult.Stats.MeanArrivalInterval, 1e-9)
	assert.InDelta(t, 29500, secondResult.Stats.StdDevArrivalInterval, 1e-9)
}

func TestTWCCInterpreter_ReferenceTimeWrap(t *testing.T) {
	interpreter := NewTWCCInterpreter()

	first := tccPacket(0, tccReferenceTimeModulus-1, 0,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 63000)})
	firstResult, err := interpreter.Process(first)
	assert.NoError(t, err)
	assert.Equal(t, int64(63000), firstResult.Arrivals[0].ArrivalTime)

	// Reference time wraps from 0xFFFFFF to 2: the nearest extended value is
	// three ticks later.
	second := tccPacket(1, 2, 1,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 1000)})
	secondResult, err := interpreter.Process(second)
	assert.NoError(t, err)
	assert.Equal(t, int64(3*tccReferenceTimeScale+1000), secondResult.Arrivals[0].ArrivalTime)
	assert.Equal(t, []int64{130000}, secondResult.Stats.ArrivalIntervals)

	// Out-of-order feedback with an older wrapped reference time resolves one
	// tick before the second packet's reference time.
	third := tccPacket(2, 1, 2,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 500)})
	thirdResult, err := interpreter.Process(third)
	assert.NoError(t, err)
	assert.Equal(t, int64(2*tccReferenceTimeScale+500), thirdResult.Arrivals[0].ArrivalTime)
	assert.Equal(t, []int64{-64500}, thirdResult.Stats.ArrivalIntervals)
}

func TestTWCCInterpreter_ReferenceTimeReverseWrap(t *testing.T) {
	interpreter := NewTWCCInterpreter()

	// Start near the bottom of the 24-bit space.
	first := tccPacket(0, 1, 0,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 1000)})
	firstResult, err := interpreter.Process(first)
	assert.NoError(t, err)
	assert.Equal(t, int64(1000), firstResult.Arrivals[0].ArrivalTime)

	// An older feedback whose reference time is at the top of the space
	// resolves one modulus earlier instead of jumping forward.
	late := tccPacket(1, tccReferenceTimeModulus-1, 1,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 2000)})
	lateResult, err := interpreter.Process(late)
	assert.NoError(t, err)
	// -1 tick unwrapped, minus the 64000us baseline: -64000 + 2000 - 64000.
	assert.Equal(t, int64(-126000), lateResult.Arrivals[0].ArrivalTime)
	assert.Equal(t, []int64{-127000}, lateResult.Stats.ArrivalIntervals)
}

func TestTWCCInterpreter_ReorderedFeedback(t *testing.T) {
	interpreter := NewTWCCInterpreter()

	first := tccPacket(10, 100, 0,
		[]uint16{
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketReceivedSmallDelta,
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 10000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 5000),
		})
	_, err := interpreter.Process(first)
	assert.NoError(t, err)

	// Older feedback covering sequences 5..9 arrives late and must be placed
	// before the already observed sequences 10 and 11.
	lateSymbols := []uint16{
		TypeTCCPacketReceivedSmallDelta,
		TypeTCCPacketReceivedSmallDelta,
		TypeTCCPacketReceivedSmallDelta,
		TypeTCCPacketReceivedSmallDelta,
		TypeTCCPacketReceivedSmallDelta,
	}
	lateDeltas := []*RecvDelta{
		tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
		tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
		tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
		tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
		tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
	}
	late := tccPacket(5, 99, 1, lateSymbols, lateDeltas)
	lateResult, err := interpreter.Process(late)
	assert.NoError(t, err)
	assert.Equal(t, []int64{5, 6, 7, 8, 9}, []int64{
		lateResult.Arrivals[0].SequenceNumber,
		lateResult.Arrivals[1].SequenceNumber,
		lateResult.Arrivals[2].SequenceNumber,
		lateResult.Arrivals[3].SequenceNumber,
		lateResult.Arrivals[4].SequenceNumber,
	})
	assert.Equal(t, 5, lateResult.Stats.PacketCount)

	// Newer feedback resumes the forward sequence number space.
	resume := tccPacket(12, 101, 2,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 2000)})
	resumeResult, err := interpreter.Process(resume)
	assert.NoError(t, err)
	assert.Equal(t, int64(12), resumeResult.Arrivals[0].SequenceNumber)

	// Re-reporting a sequence number seen in the late packet counts nowhere.
	duplicate := tccPacket(7, 99, 3,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 1000)})
	duplicateResult, err := interpreter.Process(duplicate)
	assert.NoError(t, err)
	assert.Equal(t, int64(7), duplicateResult.Arrivals[0].SequenceNumber)
	assert.Zero(t, duplicateResult.Stats.PacketCount)

	assert.Equal(t, 8, interpreter.Stats().PacketCount)
}

func TestTWCCInterpreter_RunLengthAndWithoutDelta(t *testing.T) {
	interpreter := NewTWCCInterpreter()
	packet := &TransportLayerCC{
		Header:             Header{Count: FormatTCC, Type: TypeTransportSpecificFeedback},
		BaseSequenceNumber: 20,
		PacketStatusCount:  6,
		ReferenceTime:      7,
		PacketChunks: []PacketStatusChunk{
			&RunLengthChunk{PacketStatusSymbol: TypeTCCPacketReceivedSmallDelta, RunLength: 3},
			&RunLengthChunk{PacketStatusSymbol: TypeTCCPacketNotReceived, RunLength: 2},
			&RunLengthChunk{PacketStatusSymbol: TypeTCCPacketReceivedWithoutDelta, RunLength: 1},
		},
		RecvDeltas: []*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 4000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 6000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 2000),
		},
	}
	packet.Header.Length = uint16(packet.MarshalSize()/4 - 1) //nolint:gosec // test packet fits

	result, err := interpreter.Process(packet)
	assert.NoError(t, err)
	assert.Equal(t, []TWCCArrival{
		{SequenceNumber: 20, Status: TWCCStatusReceived, ArrivalTime: 4000},
		{SequenceNumber: 21, Status: TWCCStatusReceived, ArrivalTime: 10000},
		{SequenceNumber: 22, Status: TWCCStatusReceived, ArrivalTime: 12000},
		{SequenceNumber: 23, Status: TWCCStatusNotReceived},
		{SequenceNumber: 24, Status: TWCCStatusNotReceived},
		{SequenceNumber: 25, Status: TWCCStatusReceivedWithoutDelta},
	}, result.Arrivals)
	assert.Equal(t, 4, result.Stats.ReceivedCount)
	assert.Equal(t, 2, result.Stats.LostCount)
	assert.Equal(t, []int64{6000, 2000}, result.Stats.ArrivalIntervals)
}

type badTCCChunk struct{}

func (badTCCChunk) Marshal() ([]byte, error) { return []byte{0, 0}, nil }

func (badTCCChunk) Unmarshal([]byte) error { return nil }

//nolint:maintidx
func TestTWCCInterpreter_MalformedPacketsDoNotMutateState(t *testing.T) {
	interpreter := NewTWCCInterpreter()
	valid := tccPacket(0, 100, 0,
		[]uint16{TypeTCCPacketReceivedSmallDelta, TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 1000),
			tccDelta(TypeTCCPacketReceivedSmallDelta, 2000),
		})
	_, err := interpreter.Process(valid)
	assert.NoError(t, err)
	before := interpreter.Stats()

	tests := []struct {
		name   string
		packet *TransportLayerCC
		err    error
	}{
		{
			name: "nil packet",
			err:  errTCCInvalidFeedback,
		},
		{
			name: "unknown chunk type",
			packet: &TransportLayerCC{
				PacketStatusCount: 1,
				PacketChunks:      []PacketStatusChunk{badTCCChunk{}},
			},
			err: errTCCInvalidFeedback,
		},
		{
			name: "chunks cover fewer symbols than status count",
			packet: &TransportLayerCC{
				PacketStatusCount: 3,
				PacketChunks: []PacketStatusChunk{
					&RunLengthChunk{PacketStatusSymbol: TypeTCCPacketNotReceived, RunLength: 1},
				},
			},
			err: errTCCInvalidFeedback,
		},
		{
			name: "chunks cover more symbols than status count",
			packet: &TransportLayerCC{
				PacketStatusCount: 1,
				PacketChunks: []PacketStatusChunk{
					&RunLengthChunk{PacketStatusSymbol: TypeTCCPacketNotReceived, RunLength: 2},
				},
			},
			err: errTCCInvalidFeedback,
		},
		{
			name: "symbol outside valid range",
			packet: &TransportLayerCC{
				PacketStatusCount: 1,
				PacketChunks: []PacketStatusChunk{
					&RunLengthChunk{PacketStatusSymbol: 4, RunLength: 1},
				},
			},
			err: errTCCSymbolOutOfRange,
		},
		{
			name: "missing receive delta",
			packet: tccPacket(0, 100, 0,
				[]uint16{TypeTCCPacketReceivedSmallDelta}, nil),
			err: errTCCDeltaMismatch,
		},
		{
			name: "extra receive delta",
			packet: tccPacket(0, 100, 0,
				[]uint16{TypeTCCPacketNotReceived},
				[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 1000)}),
			err: errTCCDeltaMismatch,
		},
		{
			name: "delta type does not match symbol",
			packet: tccPacket(0, 100, 0,
				[]uint16{TypeTCCPacketReceivedSmallDelta},
				[]*RecvDelta{tccDelta(TypeTCCPacketReceivedLargeDelta, 1000)}),
			err: errTCCDeltaMismatch,
		},
		{
			name: "nil delta entry",
			packet: &TransportLayerCC{
				Header:             Header{Count: FormatTCC, Type: TypeTransportSpecificFeedback},
				BaseSequenceNumber: 0,
				PacketStatusCount:  1,
				ReferenceTime:      100,
				PacketChunks: []PacketStatusChunk{
					&RunLengthChunk{PacketStatusSymbol: TypeTCCPacketReceivedSmallDelta, RunLength: 1},
				},
				RecvDeltas: []*RecvDelta{nil},
			},
			err: errTCCDeltaMismatch,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, processErr := interpreter.Process(test.packet)
			assert.ErrorIs(t, processErr, test.err)
			assert.Nil(t, result)
			assert.Equal(t, before, interpreter.Stats())
		})
	}

	// The interpreter still accepts valid feedback after the malformed ones.
	after := tccPacket(2, 101, 1,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 3000)})
	afterResult, err := interpreter.Process(after)
	assert.NoError(t, err)
	assert.Equal(t, 1, afterResult.Stats.PacketCount)
	assert.Equal(t, before.PacketCount+1, interpreter.Stats().PacketCount)
}

func TestTWCCInterpreter_EmptyFirstPacketHasNoBaseline(t *testing.T) {
	interpreter := NewTWCCInterpreter()

	empty := &TransportLayerCC{ReferenceTime: 42}
	result, err := interpreter.Process(empty)
	assert.NoError(t, err)
	assert.Empty(t, result.Arrivals)
	assert.Zero(t, result.Stats.PacketCount)
	assert.True(t, math.IsNaN(result.Stats.MeanArrivalInterval))
	assert.Zero(t, interpreter.Stats().PacketCount)

	// The first non-empty packet still owns the baseline, so its arrival
	// times start at the first delta.
	packet := tccPacket(0, 42, 0,
		[]uint16{TypeTCCPacketReceivedSmallDelta},
		[]*RecvDelta{tccDelta(TypeTCCPacketReceivedSmallDelta, 9000)})
	packetResult, err := interpreter.Process(packet)
	assert.NoError(t, err)
	assert.Equal(t, int64(9000), packetResult.Arrivals[0].ArrivalTime)
}

func TestTWCCInterpreter_MarshalRoundTrip(t *testing.T) {
	original := tccPacket(372, 4567386, 64,
		[]uint16{
			TypeTCCPacketReceivedSmallDelta,
			TypeTCCPacketReceivedLargeDelta,
			TypeTCCPacketNotReceived,
			TypeTCCPacketNotReceived,
			TypeTCCPacketNotReceived,
			TypeTCCPacketNotReceived,
			TypeTCCPacketNotReceived,
			TypeTCCPacketReceivedWithoutDelta,
			TypeTCCPacketNotReceived,
			TypeTCCPacketNotReceived,
			TypeTCCPacketReceivedWithoutDelta,
			TypeTCCPacketReceivedWithoutDelta,
			TypeTCCPacketReceivedWithoutDelta,
			TypeTCCPacketReceivedWithoutDelta,
		},
		[]*RecvDelta{
			tccDelta(TypeTCCPacketReceivedSmallDelta, 52000),
			tccDelta(TypeTCCPacketReceivedLargeDelta, 0),
		})

	data, err := original.Marshal()
	assert.NoError(t, err)

	var decoded TransportLayerCC
	assert.NoError(t, decoded.Unmarshal(data))

	fromStruct, err := NewTWCCInterpreter().Process(original)
	assert.NoError(t, err)
	fromWire, err := NewTWCCInterpreter().Process(&decoded)
	assert.NoError(t, err)
	assert.Equal(t, fromStruct.Arrivals, fromWire.Arrivals)
	assert.Equal(t, fromStruct.Stats.PacketCount, fromWire.Stats.PacketCount)
	assert.Equal(t, fromStruct.Stats.ReceivedCount, fromWire.Stats.ReceivedCount)
	assert.Equal(t, fromStruct.Stats.LostCount, fromWire.Stats.LostCount)
	assert.Equal(t, fromStruct.Stats.LossRate, fromWire.Stats.LossRate)
	assert.Equal(t, fromStruct.Stats.ArrivalIntervals, fromWire.Stats.ArrivalIntervals)
	assert.Equal(t, fromStruct.Stats.MeanArrivalInterval, fromWire.Stats.MeanArrivalInterval)
	assert.Equal(t, fromStruct.Stats.StdDevArrivalInterval, fromWire.Stats.StdDevArrivalInterval)
	assert.True(t, math.IsNaN(fromWire.Stats.MeanIntervalDelta))

	assert.Len(t, fromWire.Arrivals, 14)
	assert.Equal(t, 7, fromWire.Stats.LostCount)
	assert.Equal(t, 7, fromWire.Stats.ReceivedCount)
	assert.InDelta(t, 0.5, fromWire.Stats.LossRate, 1e-12)
	assert.Equal(t, []int64{0}, fromWire.Stats.ArrivalIntervals)
	assert.Equal(t, TWCCStatusReceivedWithoutDelta, fromWire.Arrivals[7].Status)
	assert.Zero(t, fromWire.Arrivals[7].ArrivalTime)
	assert.Equal(t, int64(52000), fromWire.Arrivals[0].ArrivalTime)
	assert.Equal(t, int64(52000), fromWire.Arrivals[1].ArrivalTime)
}

func TestTWCCInterpreter_DecodedVectorFromSpec(t *testing.T) {
	// example2 in TestTransportLayerCC_Unmarshal, a receiver-produced packet.
	raw := []byte{
		0xaf, 0xcd, 0x0, 0x6,
		0xfa, 0x17, 0xfa, 0x17,
		0x19, 0x3d, 0xd8, 0xbb,
		0x1, 0x74, 0x0, 0xe,
		0x45, 0xb1, 0x5a, 0x40,
		0xd8, 0x0, 0xf0, 0xff,
		0xd0, 0x0, 0x0, 0x3,
	}
	var packet TransportLayerCC
	assert.NoError(t, packet.Unmarshal(raw))

	result, err := NewTWCCInterpreter().Process(&packet)
	assert.NoError(t, err)
	assert.Len(t, result.Arrivals, int(packet.PacketStatusCount))
	assert.Equal(t, int64(372), result.Arrivals[0].SequenceNumber)
	assert.Equal(t, int64(385), result.Arrivals[13].SequenceNumber)
	assert.Equal(t, 7, result.Stats.ReceivedCount)
	assert.Equal(t, 7, result.Stats.LostCount)
}
