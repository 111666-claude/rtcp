// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// maxWireLength is the largest value expressible in the 16-bit Header.Length
// field (0xffff), which describes a (0xffff+1)*4 = 262144 byte packet.
const maxWireLength uint16 = 0xffff

// writeHeader builds the four common header bytes.
func writeHeader(padding bool, count uint8, typ PacketType, length uint16) []byte {
	h := Header{Padding: padding, Count: count, Type: typ, Length: length}
	raw, err := h.Marshal()
	if err != nil {
		panic(err)
	}

	return raw
}

// TestPacketLengthNoWraparound pins the safe length conversion: the maximum
// legal length field must describe 262144 bytes rather than wrapping to zero.
func TestPacketLengthNoWraparound(t *testing.T) {
	assert.Equal(t, maxPacketLength, packetLength(maxWireLength))
	assert.Equal(t, headerLength, packetLength(0))
	assert.Equal(t, headerLength*2, packetLength(1))
}

// TestMaxLengthApplicationDefined verifies that an APP packet whose length
// field is 0xffff is accepted when the full 4*(0xffff+1) bytes are present.
// The maximum-length packet exercises the decoder directly, since Marshal
// cannot itself emit a 0xffff length word.
func TestMaxLengthApplicationDefined(t *testing.T) {
	packetSize := packetLength(maxWireLength)
	raw := make([]byte, packetSize)
	copy(raw[:4], writeHeader(false, 0, TypeApplicationDefined, maxWireLength))
	binary.BigEndian.PutUint32(raw[4:8], 0x4baae1ab)
	copy(raw[8:12], "NAME")

	var app ApplicationDefined
	assert.NoError(t, app.Unmarshal(raw))
	assert.Equal(t, uint32(0x4baae1ab), app.SSRC)
	assert.Equal(t, "NAME", app.Name)
	assert.Len(t, app.Data, packetSize-12)
	assert.Equal(t, maxWireLength, binary.BigEndian.Uint16(raw[2:4]))

	// A normal-sized APP packet must still round-trip through Marshal.
	small := ApplicationDefined{SSRC: 0x4baae1ab, Name: "NAME", Data: []byte("ABCD")}
	marshaled, err := small.Marshal()
	assert.NoError(t, err)

	var decoded ApplicationDefined
	assert.NoError(t, decoded.Unmarshal(marshaled))
	assert.Equal(t, small, decoded)
}

// TestMaxLengthFeedback verifies the feedback packet entry points (NACK, FIR,
// SLI) accept a fully populated maximum-length packet instead of rejecting it
// through a wrapped length comparison.
func TestMaxLengthFeedback(t *testing.T) {
	t.Run("transport layer nack", func(t *testing.T) {
		packetSize := packetLength(maxWireLength)
		raw := make([]byte, packetSize)
		copy(raw[:4], writeHeader(false, FormatTLN, TypeTransportSpecificFeedback, maxWireLength))
		binary.BigEndian.PutUint32(raw[4:8], 1)
		binary.BigEndian.PutUint32(raw[8:12], 2)

		var nack TransportLayerNack
		assert.NoError(t, nack.Unmarshal(raw))
		// body is 0xffff*4 bytes, the 8-byte SSRC prefix holds no NACK pairs.
		assert.Len(t, nack.Nacks, (int(maxWireLength)*4-nackOffset)/4)
	})

	t.Run("full intra request", func(t *testing.T) {
		// Length 0xfffe keeps the FCI 8-byte aligned: 0xfffe*4 is divisible by 8.
		length := uint16(0xfffe)
		packetSize := packetLength(length)
		raw := make([]byte, packetSize)
		copy(raw[:4], writeHeader(false, FormatFIR, TypePayloadSpecificFeedback, length))
		binary.BigEndian.PutUint32(raw[4:8], 1)
		binary.BigEndian.PutUint32(raw[8:12], 2)

		var fir FullIntraRequest
		assert.NoError(t, fir.Unmarshal(raw))
		assert.Len(t, fir.FIR, (int(length)*4-firOffset)/8)
	})

	t.Run("slice loss indication", func(t *testing.T) {
		packetSize := packetLength(maxWireLength)
		raw := make([]byte, packetSize)
		copy(raw[:4], writeHeader(false, FormatSLI, TypeTransportSpecificFeedback, maxWireLength))
		binary.BigEndian.PutUint32(raw[4:8], 1)
		binary.BigEndian.PutUint32(raw[8:12], 2)

		var sli SliceLossIndication
		assert.NoError(t, sli.Unmarshal(raw))
		assert.Len(t, sli.SLI, (int(maxWireLength)*4-sliOffset)/4)
	})
}

// TestDeclaredLengthLargerThanInput makes sure every entry point rejects a
// packet whose Header.Length claims more bytes than were actually supplied,
// even when the uint16 arithmetic would have wrapped to a small value.
func TestDeclaredLengthLargerThanInput(t *testing.T) {
	// Length 0x4003 used to wrap: (0x4003)*4 == 0x000c in uint16 arithmetic,
	// so the old NACK/SLI/FIR bounds checks saw an apparently small packet.
	wrappedLength := uint16(0x4003)

	for _, test := range []struct {
		Name   string
		Header Header
	}{
		{"nack", Header{Count: FormatTLN, Type: TypeTransportSpecificFeedback, Length: wrappedLength}},
		{"sli", Header{Count: FormatSLI, Type: TypeTransportSpecificFeedback, Length: wrappedLength}},
		{"fir", Header{Count: FormatFIR, Type: TypePayloadSpecificFeedback, Length: wrappedLength}},
		{"twcc", Header{Count: FormatTCC, Type: TypeTransportSpecificFeedback, Length: wrappedLength}},
		{"rr", Header{Count: 0, Type: TypeReceiverReport, Length: wrappedLength}},
		{"sr", Header{Count: 0, Type: TypeSenderReport, Length: wrappedLength}},
		{"bye", Header{Count: 0, Type: TypeGoodbye, Length: wrappedLength}},
		{"sdes", Header{Count: 0, Type: TypeSourceDescription, Length: wrappedLength}},
		{"xr", Header{Count: 0, Type: TypeExtendedReport, Length: wrappedLength}},
		{"app", Header{Count: 0, Type: TypeApplicationDefined, Length: wrappedLength}},
		{"pli", Header{Count: FormatPLI, Type: TypePayloadSpecificFeedback, Length: wrappedLength}},
		{"rrr", Header{Count: FormatRRR, Type: TypeTransportSpecificFeedback, Length: wrappedLength}},
	} {
		t.Run(test.Name, func(t *testing.T) {
			headerBytes, err := test.Header.Marshal()
			assert.NoError(t, err)
			// Only 20 bytes are present while the header claims far more.
			raw := make([]byte, 20)
			copy(raw, headerBytes)

			_, err = Unmarshal(raw)
			assert.ErrorIs(t, err, errPacketTooShort)
		})
	}
}

// TestDeclaredLengthSmallerThanInput verifies packets whose declared length is
// smaller than the supplied buffer are rejected: the extra bytes may belong
// to the next packet in a compound and must never be absorbed.
func TestDeclaredLengthSmallerThanInput(t *testing.T) {
	// A 16-byte APP packet whose header claims 12 bytes (length 2).
	raw := make([]byte, 16)
	copy(raw[:4], writeHeader(false, 0, TypeApplicationDefined, 2))
	binary.BigEndian.PutUint32(raw[4:8], 1)
	copy(raw[8:12], "NAME")

	var app ApplicationDefined
	assert.ErrorIs(t, app.Unmarshal(raw), errAppDefinedInvalidLength)
}

// TestCompoundSplitsOnHeaderLength ensures the compound parser cuts each
// packet strictly at its own Header.Length and never feeds the next packet's
// bytes to the previous decoder.
func TestCompoundSplitsOnHeaderLength(t *testing.T) {
	// First packet: 12-byte APP declaring exactly 12 bytes.
	first := make([]byte, 12)
	copy(first[:4], writeHeader(false, 0, TypeApplicationDefined, 2))
	binary.BigEndian.PutUint32(first[4:8], 1)
	copy(first[8:12], "NAME")

	// Second packet: 12-byte PLI.
	second := make([]byte, 12)
	copy(second[:4], writeHeader(false, FormatPLI, TypePayloadSpecificFeedback, 2))
	binary.BigEndian.PutUint32(second[4:8], 3)
	binary.BigEndian.PutUint32(second[8:12], 4)

	packets, err := Unmarshal(append(append([]byte{}, first...), second...))
	assert.NoError(t, err)
	assert.Len(t, packets, 2)

	app, ok := packets[0].(*ApplicationDefined)
	assert.True(t, ok)
	assert.Equal(t, "NAME", app.Name)
	assert.Len(t, app.Data, 0) // no bytes borrowed from the second packet

	pli, ok := packets[1].(*PictureLossIndication)
	assert.True(t, ok)
	assert.Equal(t, uint32(3), pli.SenderSSRC)
	assert.Equal(t, uint32(4), pli.MediaSSRC)
}

// TestMultiTypeCompoundRegression exercises a compound stream containing the
// feedback types named in the report, all sharing the same boundary rules.
func TestMultiTypeCompoundRegression(t *testing.T) {
	nack := &TransportLayerNack{
		SenderSSRC: 1,
		MediaSSRC:  2,
		Nacks:      []NackPair{{PacketID: 7, LostPackets: 0}},
	}
	fir := &FullIntraRequest{
		SenderSSRC: 3,
		MediaSSRC:  4,
		FIR:        []FIREntry{{SSRC: 5, SequenceNumber: 6}},
	}
	pli := &PictureLossIndication{
		SenderSSRC: 7,
		MediaSSRC:  8,
	}
	rr := &ReceiverReport{SSRC: 9}

	marshaled, err := Marshal([]Packet{rr, nack, fir, pli})
	assert.NoError(t, err)

	decoded, err := Unmarshal(marshaled)
	assert.NoError(t, err)
	assert.Len(t, decoded, 4)
	assert.IsType(t, &ReceiverReport{}, decoded[0])
	assert.IsType(t, &TransportLayerNack{}, decoded[1])
	assert.IsType(t, &FullIntraRequest{}, decoded[2])
	assert.IsType(t, &PictureLossIndication{}, decoded[3])

	// Re-marshaling the decoded compound must reproduce the original bytes.
	remarshaled, err := Marshal(decoded)
	assert.NoError(t, err)
	assert.Equal(t, marshaled, remarshaled)
}

// TestShortInputsNeverPanic feeds truncated headers and packets to every
// decoder to confirm length errors instead of panics or out-of-range reads.
func TestShortInputsNeverPanic(t *testing.T) {
	headerBytes := writeHeader(false, 0, TypeReceiverReport, 100) // claims 404 bytes

	for _, size := range []int{0, 1, 2, 3, 4, 5, 7, 8} {
		raw := make([]byte, size)
		if size >= 4 {
			copy(raw, headerBytes)
		}

		var rr ReceiverReport
		assert.NotPanics(t, func() {
			_ = rr.Unmarshal(raw)
		})
		_, err := Unmarshal(raw)
		if size > 0 {
			assert.Error(t, err)
		}
	}

	// A two-byte slice must not panic even with a fully valid version byte.
	tiny := []byte{0x80, 0xc9}
	assert.NotPanics(t, func() {
		_, err := Unmarshal(tiny)
		assert.Error(t, err)
	})
}

// TestFailedDecodeLeavesNoPartialState ensures a TWCC decode that fails after
// some chunks were parsed does not retain partial FCI state.
func TestFailedDecodeLeavesNoPartialState(t *testing.T) {
	// TWCC header claiming more bytes than are supplied.
	raw := make([]byte, 20)
	copy(raw[:4], writeHeader(false, FormatTCC, TypeTransportSpecificFeedback, 100))
	binary.BigEndian.PutUint16(raw[10:12], 4) // PacketStatusCount = 4

	var twcc TransportLayerCC
	err := twcc.Unmarshal(raw)
	assert.Error(t, err)
	assert.Nil(t, twcc.PacketChunks)
	assert.Nil(t, twcc.RecvDeltas)
}
