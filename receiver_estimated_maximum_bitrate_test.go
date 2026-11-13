// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"fmt"
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

	assert.Equal("ReceiverEstimatedMaximumBitrate 0 1.18 Zb/s", packet.String())
}

func TestReceiverEstimatedMaximumBitrateString(t *testing.T) {
	assert := assert.New(t)

	// Every unit in the table must be reachable exactly once, and values
	// beyond the largest unit must clamp to it instead of panicking.
	cases := []struct {
		name     string
		bitrate  float32
		expected string
	}{
		{"zero", 0, "ReceiverEstimatedMaximumBitrate 0 0.00 b/s"},
		{"sub-threshold", 999, "ReceiverEstimatedMaximumBitrate 0 999.00 b/s"},
		{"kilobit", 1e3, "ReceiverEstimatedMaximumBitrate 0 1.00 Kb/s"},
		{"megabit", 1e6, "ReceiverEstimatedMaximumBitrate 0 1.00 Mb/s"},
		{"gigabit", 1e9, "ReceiverEstimatedMaximumBitrate 0 1.00 Gb/s"},
		{"terabit", 1e12, "ReceiverEstimatedMaximumBitrate 0 1.00 Tb/s"},
		{"petabit", 1e15, "ReceiverEstimatedMaximumBitrate 0 1.00 Pb/s"},
		{"exabit", 1e18, "ReceiverEstimatedMaximumBitrate 0 1.00 Eb/s"},
		{"zettabit", 1e21, "ReceiverEstimatedMaximumBitrate 0 1.00 Zb/s"},
		{"beyond-zettabit", 1e24, "ReceiverEstimatedMaximumBitrate 0 1000.00 Zb/s"},
	}

	for _, c := range cases {
		packet := ReceiverEstimatedMaximumBitrate{Bitrate: c.bitrate}
		assert.Equal(c.expected, packet.String(), c.name)
	}

	// Abnormally large values must clamp to the largest unit, not panic.
	huge := ReceiverEstimatedMaximumBitrate{Bitrate: math.MaxFloat32}
	assert.Contains(huge.String(), "Zb/s")

	// A packet with the maximum wire exponent (63) and mantissa previously
	// panicked in String with an index out of range.
	maxPacket := []byte{143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0, 255, 255, 255}
	var decoded ReceiverEstimatedMaximumBitrate
	assert.NoError(decoded.Unmarshal(maxPacket))
	assert.Equal("ReceiverEstimatedMaximumBitrate 0 2417.84 Zb/s", decoded.String())

	// Small wire exponents must decode and stringify without going out of range.
	for _, exp := range []byte{0, 1, 6, 7} {
		input := []byte{143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0, exp << 2, 0, 1}
		var small ReceiverEstimatedMaximumBitrate
		assert.NoError(small.Unmarshal(input))
		assert.Equal(float32(uint32(1)<<exp), small.Bitrate)
		assert.Equal(
			fmt.Sprintf("ReceiverEstimatedMaximumBitrate 0 %.2f b/s", float32(uint32(1)<<exp)),
			small.String(),
		)
	}
}

func TestReceiverEstimatedMaximumBitrateStringDoesNotMutate(t *testing.T) {
	assert := assert.New(t)

	packet := ReceiverEstimatedMaximumBitrate{
		SenderSSRC: 1,
		Bitrate:    8927168.0,
		SSRCs:      []uint32{1215622422},
	}

	before, err := packet.Marshal()
	assert.NoError(err)

	first := packet.String()

	// Stringifying must not change the packet or its binary representation.
	after, err := packet.Marshal()
	assert.NoError(err)
	assert.Equal(before, after)
	assert.Equal(float32(8927168.0), packet.Bitrate)
	assert.Equal([]uint32{1215622422}, packet.SSRCs)

	// And it must be idempotent.
	assert.Equal(first, packet.String())
}
