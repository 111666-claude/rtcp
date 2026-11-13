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

// rembPacketBytes builds a raw REMB packet (no SSRCs) with the given
// 6-bit exponent and 18-bit mantissa.
func rembPacketBytes(exp, mantissa uint32) []byte {
	return []byte{
		143, 206, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 82, 69, 77, 66, 0,
		byte(exp<<2) | byte(mantissa>>16), //nolint:gosec // test values are bounded
		byte(mantissa >> 8),               //nolint:gosec // test values are bounded
		byte(mantissa),                    //nolint:gosec // test values are bounded
	}
}

func TestReceiverEstimatedMaximumBitrateString(t *testing.T) {
	assert := assert.New(t)

	// Exponent boundary cases, decoded through the binary path.
	for _, test := range []struct {
		name     string
		exp      uint32
		mantissa uint32
		expected string
	}{
		{"Exp0", 0, 500, "ReceiverEstimatedMaximumBitrate 0 500.00 b/s"},
		{"Exp1", 1, 750, "ReceiverEstimatedMaximumBitrate 0 1.50 Kb/s"},
		{"Exp6", 6, 139487, "ReceiverEstimatedMaximumBitrate 0 8.93 Mb/s"},
		{"Exp7", 7, 139487, "ReceiverEstimatedMaximumBitrate 0 17.85 Mb/s"},
		// 128 * 2^63 = 1.1806e21: previously panicked with index out of range.
		{"Exp63", 63, 128, "ReceiverEstimatedMaximumBitrate 0 1.18 Zb/s"},
		// Largest encodable bitrate: mantissa and exponent both maxed out.
		{"Exp63MaxMantissa", 63, 0x3FFFF, "ReceiverEstimatedMaximumBitrate 0 2.42 Yb/s"},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet := ReceiverEstimatedMaximumBitrate{}
			assert.NoError(packet.Unmarshal(rembPacketBytes(test.exp, test.mantissa)))
			assert.Equal(test.expected, packet.String())
		})
	}

	// Zero value must not divide or index anywhere.
	packet := ReceiverEstimatedMaximumBitrate{}
	assert.Equal("ReceiverEstimatedMaximumBitrate 0 0.00 b/s", packet.String())

	// Absurdly large values must clamp to the last unit, not run off the table.
	packet = ReceiverEstimatedMaximumBitrate{Bitrate: math.MaxFloat32}
	assert.Contains(packet.String(), " Yb/s")

	// Textification must not modify the packet, and must not affect
	// a subsequent serialization of the same packet.
	packet = ReceiverEstimatedMaximumBitrate{SenderSSRC: 1, Bitrate: 8927168.0, SSRCs: []uint32{1215622422}}
	before, err := packet.Marshal()
	assert.NoError(err)
	_ = packet.String()
	assert.Equal(float32(8927168.0), packet.Bitrate)
	after, err := packet.Marshal()
	assert.NoError(err)
	assert.Equal(before, after)
}
