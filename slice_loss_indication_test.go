// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
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
				// SliceLossIndication (v=2, FMT=2, PT=PSFB=206, len=3)
				0x82, 0xce, 0x0, 0x3,
				// sender=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// media=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// sli First=0xAAA, Number=0, Picture=0x2C
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
				0x82, 0xce, 0x0, 0x2,
				// ssrc=0x902f9e2e
				0x90, 0x2f, 0x9e, 0x2e,
				// report ends early
			},
			WantError: errPacketTooShort,
		},
		{
			Name: "missing media ssrc",
			Data: []byte{
				// header declares only sender+media SSRCs (len=2) but
				// the packet ends after the sender SSRC
				0x82, 0xce, 0x0, 0x2,
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errPacketTooShort,
		},
		{
			Name: "declared length too small",
			Data: []byte{
				// len=1 only covers the sender SSRC, no room for media SSRC
				0x82, 0xce, 0x0, 0x1,
				0x90, 0x2f, 0x9e, 0x2e,
				0x90, 0x2f, 0x9e, 0x2e,
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
				// v=2, FMT=1 (PLI), PT=PSFB=206, len=2
				0x81, 0xce, 0x0, 0x2,
				0x90, 0x2f, 0x9e, 0x2e,
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errWrongType,
		},
		{
			Name: "transport specific feedback type",
			Data: []byte{
				// v=2, FMT=2, PT=RTPFB=205, len=2: SLI is PSFB, not RTPFB
				0x82, 0xcd, 0x0, 0x2,
				0x90, 0x2f, 0x9e, 0x2e,
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errWrongType,
		},
		{
			Name: "bad version",
			Data: []byte{
				// v=1, FMT=2, PT=PSFB=206, len=2
				0x42, 0xce, 0x0, 0x2,
				0x90, 0x2f, 0x9e, 0x2e,
				0x90, 0x2f, 0x9e, 0x2e,
			},
			WantError: errBadVersion,
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
			// a failed Unmarshal must not leave partial state behind
			assert.Equalf(t, SliceLossIndication{}, sli, "Unmarshal %q modified receiver on error", test.Name)

			continue
		}

		assert.Equalf(t, test.Want, sli, "Unmarshal %q rr", test.Name)
	}
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
			Name: "no entries",
			Report: SliceLossIndication{
				SenderSSRC: 0x902f9e2e,
				MediaSSRC:  0xbc5e9a40,
				SLI:        []SLIEntry{},
			},
		},
	} {
		data, err := test.Report.Marshal()
		assert.ErrorIsf(t, err, test.WantError, "Marshal %q", test.Name)
		if err != nil {
			continue
		}

		// the marshaled packet must be announced as Payload-Specific Feedback (RFC 4585)
		assert.Equalf(t, byte(TypePayloadSpecificFeedback), data[1], "Marshal %q packet type", test.Name)
		assert.Equalf(t, test.Report.MarshalSize(), len(data), "MarshalSize %q", test.Name)
		assert.Equalf(t, test.Report.Header().Length, (uint16(len(data))/4)-1, "Header length %q", test.Name)

		var decoded SliceLossIndication
		assert.NoErrorf(t, decoded.Unmarshal(data), "Unmarshal %q", test.Name)
		assert.Equalf(t, test.Report, decoded, "%q sli round trip mismatch", test.Name)
	}
}

func TestSliceLossIndicationDispatch(t *testing.T) {
	report := SliceLossIndication{
		SenderSSRC: 0x902f9e2e,
		MediaSSRC:  0x902f9e2e,
		SLI:        []SLIEntry{{1, 0xAA, 0x1F}},
	}

	data, err := report.Marshal()
	assert.NoError(t, err)

	packets, err := Unmarshal(data)
	assert.NoError(t, err)
	assert.Len(t, packets, 1)

	decoded, ok := packets[0].(*SliceLossIndication)
	assert.True(t, ok, "expected Unmarshal to dispatch to *SliceLossIndication, got %T", packets[0])
	assert.Equal(t, report, *decoded)
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
