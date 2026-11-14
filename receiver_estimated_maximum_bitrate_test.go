// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

var _ Packet = (*ReceiverEstimatedMaximumBitrate)(nil) // assert is a Packet

func TestReceiverEstimatedMaximumBitrateMarshal(t *testing.T) {
	assert := assert.New(t)

	input := ReceiverEstimatedMaximumBitrate{
		SenderSSRC: 1,
		Bitrate:    8927168.0,
		SSRCs:      []uint32{1215622422},
	}

	expected := []byte{143, 206, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 82, 69, 77, 66, 1, 26, 32, 223, 72, 116, 237, 22}

	output, err := input.Marshal()
	assert.NoError(err)
	assert.Equal(expected, output)
}

func TestReceiverEstimatedMaximumBitrateUnmarshal(t *testing.T) {
	assert := assert.New(t)

	// Real data sent by Chrome while watching a 6Mb/s stream
	input := []byte{143, 206, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 82, 69, 77, 66, 1, 26, 32, 223, 72, 116, 237, 22}

	// mantissa = []byte{26 & 3, 32, 223} = []byte{2, 32, 223} = 139487
	// exp = 26 >> 2 = 6
	// bitrate = 139487 * 2^6 = 139487 * 64 = 8927168 = 8.9 Mb/s
	expected := ReceiverEstimatedMaximumBitrate{
		SenderSSRC: 1,
		Bitrate:    8927168,
		SSRCs:      []uint32{1215622422},
	}

	packet := ReceiverEstimatedMaximumBitrate{}
	err := packet.Unmarshal(input)
	assert.NoError(err)
	assert.Equal(expected, packet)
}

func TestReceiverEstimatedMaximumBitrateTruncate(t *testing.T) {
	assert := assert.New(t)

	input := []byte{143, 206, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0, 82, 69, 77, 66, 1, 26, 32, 223, 72, 116, 237, 22}

	// Make sure that we're interpreting the bitrate correctly.
	// For the above example, we have:

	// mantissa = 139487
	// exp = 6
	// bitrate = 8927168

	packet := ReceiverEstimatedMaximumBitrate{}
	err := packet.Unmarshal(input)
	assert.NoError(err)
	assert.Equal(float32(8927168), packet.Bitrate)

	// Just verify marshal produces the same input.
	output, err := packet.Marshal()
	assert.NoError(err)
	assert.Equal(input, output)

	// If we subtract the bitrate by 1, we'll round down a lower mantissa
	packet.Bitrate--

	// bitrate = 8927167
	// mantissa = 139486
	// exp = 6

	output, err = packet.Marshal()
	assert.NoError(err)
	assert.NotEqual(input, output)

	// Which if we actually unmarshal again, we'll find that it's actually decreased by 63 (which is exp)
	// mantissa = 139486
	// exp = 6
	// bitrate = 8927104

	err = packet.Unmarshal(output)
	assert.NoError(err)
	assert.Equal(float32(8927104), packet.Bitrate)
}

func TestReceiverEstimatedMaximumBitrateOverflow(t *testing.T) {
	assert := assert.New(t)

	// Marshal a packet with the maximum possible bitrate.
	packet := ReceiverEstimatedMaximumBitrate{
		Bitrate: math.MaxFloat32,
	}

	// mantissa = 262143 = 0x3FFFF
	// exp = 63

	expected := []byte{143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0, 255, 255, 255}

	output, err := packet.Marshal()
	assert.NoError(err)
	assert.Equal(expected, output)

	// mantissa = 262143
	// exp = 63
	// bitrate = 0xFFFFC00000000000

	err = packet.Unmarshal(output)
	assert.NoError(err)
	assert.Equal(math.Float32frombits(0x67FFFFC0), packet.Bitrate)

	// Make sure we marshal to the same result again.
	output, err = packet.Marshal()
	assert.NoError(err)
	assert.Equal(expected, output)

	// Finally, try unmarshalling one number higher than we used to be able to handle.
	input := []byte{143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0, 188, 0, 0}
	err = packet.Unmarshal(input)
	assert.NoError(err)
	assert.Equal(math.Float32frombits(0x62800000), packet.Bitrate)
}

func TestReceiverEstimatedMaximumBitrateString(t *testing.T) {
	assert := assert.New(t)

	// A mantissa of 128 (bitrate = 128 * 2^exp) covers the small-exponent
	// unit boundaries as well as exp 63, whose text representation used to
	// panic with an out-of-range index into the unit table.
	exponentCases := []struct {
		exp      uint8
		bitrate  float32
		expected string
	}{
		{0, 128, "ReceiverEstimatedMaximumBitrate 0 128.00 b/s"},
		{1, 256, "ReceiverEstimatedMaximumBitrate 0 256.00 b/s"},
		{6, 8192, "ReceiverEstimatedMaximumBitrate 0 8.19 Kb/s"},
		{7, 16384, "ReceiverEstimatedMaximumBitrate 0 16.38 Kb/s"},
		{63, 1.1805916e+21, "ReceiverEstimatedMaximumBitrate 0 1.18 Zb/s"},
	}

	for _, tc := range exponentCases {
		raw := []byte{143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 'R', 'E', 'M', 'B', 0, tc.exp << 2, 0, 128}

		var packet ReceiverEstimatedMaximumBitrate
		assert.NoError(packet.Unmarshal(raw))
		assert.Equal(tc.bitrate, packet.Bitrate)
		assert.Equal(tc.expected, packet.String())
	}

	// One value per SI unit: each unit has to be reachable exactly once,
	// none may be duplicated or skipped.
	unitCases := []struct {
		bitrate  float32
		expected string
	}{
		{1, "ReceiverEstimatedMaximumBitrate 0 1.00 b/s"},
		{1e3, "ReceiverEstimatedMaximumBitrate 0 1.00 Kb/s"},
		{1e6, "ReceiverEstimatedMaximumBitrate 0 1.00 Mb/s"},
		{1e9, "ReceiverEstimatedMaximumBitrate 0 1.00 Gb/s"},
		{1e12, "ReceiverEstimatedMaximumBitrate 0 1.00 Tb/s"},
		{1e15, "ReceiverEstimatedMaximumBitrate 0 1.00 Pb/s"},
		{1e18, "ReceiverEstimatedMaximumBitrate 0 1.00 Eb/s"},
		{1e21, "ReceiverEstimatedMaximumBitrate 0 1.00 Zb/s"},
		{1e24, "ReceiverEstimatedMaximumBitrate 0 1.00 Yb/s"},
	}
	expectedUnits := []string{"b", "Kb", "Mb", "Gb", "Tb", "Pb", "Eb", "Zb", "Yb"}
	seenUnits := make(map[string]bool)

	for i, tc := range unitCases {
		packet := ReceiverEstimatedMaximumBitrate{Bitrate: tc.bitrate}
		assert.Equal(tc.expected, packet.String())
		assert.False(seenUnits[expectedUnits[i]], "unit %s emitted twice", expectedUnits[i])
		seenUnits[expectedUnits[i]] = true
	}

	assert.Len(seenUnits, len(expectedUnits))

	// Zero never enters the conversion loop and stays in the base unit.
	zero := ReceiverEstimatedMaximumBitrate{}
	assert.Equal("ReceiverEstimatedMaximumBitrate 0 0.00 b/s", zero.String())

	// Values beyond the largest unit must not index past the unit table.
	// They are reported in Yb/s instead of panicking.
	for _, bitrate := range []float32{math.MaxFloat32, float32(math.Inf(1))} {
		packet := ReceiverEstimatedMaximumBitrate{Bitrate: bitrate}
		assert.NotPanics(func() {
			assert.Contains(packet.String(), "Yb/s")
		})
	}
}

func TestReceiverEstimatedMaximumBitrateStringDoesNotMutate(t *testing.T) {
	assert := assert.New(t)

	packet := ReceiverEstimatedMaximumBitrate{
		SenderSSRC: 1,
		Bitrate:    8927168.0,
		SSRCs:      []uint32{1215622422},
	}

	// String is a read-only view and must leave the packet untouched.
	before := packet
	_ = packet.String()
	assert.Equal(before, packet)

	// Textification must not change the binary serialization, and repeated
	// reads must keep producing the same bytes.
	raw, err := packet.Marshal()
	assert.NoError(err)

	_ = packet.String()
	_ = packet.String()

	rawAgain, err := packet.Marshal()
	assert.NoError(err)
	assert.Equal(raw, rawAgain)

	// The same holds after Unmarshal: textifying the decoded packet must not
	// alter its fields, and it still re-marshals to the original bytes.
	var decoded ReceiverEstimatedMaximumBitrate
	assert.NoError(decoded.Unmarshal(raw))

	decodedBefore := decoded
	_ = decoded.String()
	assert.Equal(decodedBefore, decoded)

	decodedRaw, err := decoded.Marshal()
	assert.NoError(err)
	assert.Equal(raw, decodedRaw)
}
