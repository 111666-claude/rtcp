// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

var _ Packet = (*SliceLossIndication)(nil) // assert is a Packet

func TestSliceLossIndicationUnmarshal(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Data      []byte
		Want      SliceLossIndication
		WantError error
	}{
		{
			Name: "valid",
			Data: []byte{
				// SliceLossIndication: v=2, FMT=SLI, PSFB, len=3
				0x82, 0xce, 0x0, 0x3,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// media=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// first=0xAAA, number=0, picture=0x2C
				0x55, 0x50, 0x00, 0x2C,
			},
			Want: SliceLossIndication{
				SenderSSRC: 0x902f9e2e,
				MediaSSRC:  0x902f9e2e,
				SLI:        []SLIEntry{{0xaaa, 0, 0x2C}},
			},
		},
		{
			Name: "short report",
			Data: []byte{
				0x81, 0xce, 0x0, 0x2,
				// ssrc=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// report ends early
			},
			WantError: errPacketTooShort,
		},
		{
			Name: "only one ssrc",
			Data: []byte{
				0x82, 0xce, 0x0, 0x1,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errPacketTooShort,
		},
		{
			Name: "truncated header",
			Data: []byte{
				0x82, 0xce, 0x0,
			},
			WantError: errPacketTooShort,
		},
		{
			Name: "wrong type",
			Data: []byte{
				// v=2, p=0, count=1, SR, len=7
				0x81, 0xc8, 0x0, 0x7,
				// ssrc=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// ssrc=0xbc5e9a40
				0xbc, 0x5e, 0x9a, 0x40,
				// fracLost=0, totalLost=0
				0x0, 0x0, 0x0, 0x0,
				// lastSeq=0x46e1
				0x0, 0x0, 0x46, 0xe1,
				// jitter=273
				0x0, 0x0, 0x1, 0x11,
				// lsr=0x9f36432
				0x9, 0xf3, 0x64, 0x32,
				// delay=150137
				0x0, 0x2, 0x4a, 0x79,
			},
			WantError: errWrongType,
		},
		{
			Name: "wrong fmt",
			Data: []byte{
				// v=2, FMT=PLI, PSFB, len=2
				0x81, 0xce, 0x0, 0x2,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// media=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errWrongType,
		},
		{
			Name: "wrong version",
			Data: []byte{
				// v=1, FMT=SLI, PSFB, len=2
				0x42, 0xce, 0x0, 0x2,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// media=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errBadVersion,
		},
		{
			Name: "length declares less than two ssrcs",
			Data: []byte{
				// len=1 => 8 bytes, which cannot hold both SSRCs
				0x82, 0xce, 0x0, 0x1,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// media=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errBadLength,
		},
		{
			Name: "length beyond buffer",
			Data: []byte{
				// len=3 => 16 bytes, but only 12 are present
				0x82, 0xce, 0x0, 0x3,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// media=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errPacketTooShort,
		},
		{
			Name:      "nil",
			Data:      nil,
			WantError: errPacketTooShort,
		},
	} {
		var sli SliceLossIndication
		err := sli.Unmarshal(test.Data)
		assert.ErrorIsf(t, err, test.WantError, "Unmarshal %q", test.Name)
		if err != nil {
			continue
		}

		assert.Equalf(t, test.Want, sli, "Unmarshal %q rr", test.Name)
	}
}

func TestSliceLossIndicationUnmarshalDoesNotMutateOnError(t *testing.T) {
	original := SliceLossIndication{
		SenderSSRC: 1,
		MediaSSRC:  2,
		SLI:        []SLIEntry{{First: 3, Number: 4, Picture: 5}},
	}
	sli := original

	// Declares a legal PSFB/SLI header but the body is too short for two SSRCs.
	err := sli.Unmarshal([]byte{0x82, 0xce, 0x0, 0x1, 0x90, 0x2f, 0x9e, 0x2e})
	assert.ErrorIs(t, err, errPacketTooShort)
	assert.Equal(t, original, sli)

	// Declared length does not even cover the second SSRC.
	err = sli.Unmarshal([]byte{0x82, 0xce, 0x0, 0x1, 0x90, 0x2f, 0x9e, 0x2e, 0xbc, 0x5e, 0x9a, 0x40})
	assert.ErrorIs(t, err, errBadLength)
	assert.Equal(t, original, sli)

	// Wrong type must not touch the receiver either.
	err = sli.Unmarshal([]byte{0x81, 0xce, 0x0, 0x2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11})
	assert.ErrorIs(t, err, errWrongType)
	assert.Equal(t, original, sli)
}

func TestSliceLossIndicationMarshalHeader(t *testing.T) {
	sli := SliceLossIndication{
		SenderSSRC: 0x902f9e2e,
		MediaSSRC:  0xbc5e9a40,
		SLI:        []SLIEntry{{First: 0x1, Number: 0xAA, Picture: 0x1F}},
	}

	data, err := sli.Marshal()
	assert.NoError(t, err)

	// Second byte must be the Payload-Specific Feedback type (206 / 0xCE),
	// otherwise the top-level dispatcher routes it to RawPacket.
	assert.Equal(t, byte(TypePayloadSpecificFeedback), data[1])
	assert.Equal(t, uint8(FormatSLI), data[0]&0x1F)
	assert.Equal(t, uint16(3), binary.BigEndian.Uint16(data[2:4]))
	assert.Equal(t, sli.MarshalSize(), len(data))
	assert.Equal(t, uint16((sli.MarshalSize()/4)-1), sli.Header().Length)
}

func TestSliceLossIndicationRoundTrip(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Report    SliceLossIndication
		WantError error
	}{
		{
			Name: "valid",
			Report: SliceLossIndication{
				SenderSSRC: 0x902f9e2e,
				MediaSSRC:  0x902f9e2e,
				SLI:        []SLIEntry{{1, 0xAA, 0x1F}, {1034, 0x05, 0x6}},
			},
		},
		{
			Name: "empty",
			Report: SliceLossIndication{
				SenderSSRC: 0x902f9e2e,
				MediaSSRC:  0xbc5e9a40,
			},
		},
	} {
		data, err := test.Report.Marshal()
		assert.ErrorIsf(t, err, test.WantError, "Marshal %q", test.Name)
		if err != nil {
			continue
		}

		var decoded SliceLossIndication
		assert.NoErrorf(t, decoded.Unmarshal(data), "Unmarshal %q", test.Name)
		assert.Equalf(t, test.Report, decoded, "%q sli round trip mismatch", test.Name)
	}
}

func TestSliceLossIndicationTotalUnmarshal(t *testing.T) {
	sli := SliceLossIndication{
		SenderSSRC: 0x902f9e2e,
		MediaSSRC:  0xbc5e9a40,
		SLI:        []SLIEntry{{First: 0xAAA, Number: 0x2, Picture: 0x2C}},
	}
	data, err := sli.Marshal()
	assert.NoError(t, err)

	packets, err := Unmarshal(data)
	assert.NoError(t, err)
	assert.Len(t, packets, 1)

	decoded, ok := packets[0].(*SliceLossIndication)
	assert.True(t, ok, "expected *SliceLossIndication, got %T", packets[0])
	assert.Equal(t, sli, *decoded)
}

func TestSliceLossIndicationUnmarshalMaxLength(t *testing.T) {
	rawPacket := make([]byte, 4*(0xFFFF+1))
	rawPacket[0] = 0x82
	rawPacket[1] = 0xce
	rawPacket[2] = 0xff
	rawPacket[3] = 0xff

	var sli SliceLossIndication
	err := sli.Unmarshal(rawPacket)
	assert.NoError(t, err)
	assert.Len(t, sli.SLI, 0xFFFF-sliLength)
}
