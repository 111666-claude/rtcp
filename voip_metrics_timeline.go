// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

const (
	// voipMetricsUnavailable is the RFC 3611 section 4.7 sentinel for metrics
	// that the sender had no estimate for.
	voipMetricsUnavailable = 127

	// defaultVoIPMetricsSamplesPerSSRC bounds the history kept for one source,
	// and defaultVoIPMetricsSSRCs bounds the number of tracked sources.
	defaultVoIPMetricsSamplesPerSSRC = 64
	defaultVoIPMetricsSSRCs          = 32

	// voipMetricsFractionScale converts the 8 bit fixed point rates of
	// RFC 3611 into fractions: the binary point sits at the left edge.
	voipMetricsFractionScale = 256
	// voipMetricsMOSScale converts the integer MOS encoding (MOS * 10) to the
	// 1.0 to 5.0 MOS scale.
	voipMetricsMOSScale = 10
)

var (
	errVoIPMetricsNilBlock       = errors.New("rtcp: nil VoIP metrics report block")
	errVoIPMetricsNilReport      = errors.New("rtcp: nil extended report")
	errVoIPMetricsMissingSSRC    = errors.New("rtcp: VoIP metrics report block has no source SSRC")
	errVoIPMetricsInvalidMetric  = errors.New("rtcp: VoIP metrics report block has an out of range metric")
	errVoIPMetricsUnknownSSRC    = errors.New("rtcp: no VoIP metrics recorded for SSRC")
	errVoIPMetricsBackwardWindow = errors.New("rtcp: VoIP metrics window ends before it starts")
	errVoIPMetricsEmptyWindow    = errors.New("rtcp: VoIP metrics window contains no samples")
	errVoIPMetricsTooManySSRCs   = errors.New("rtcp: VoIP metrics timeline participant limit reached")
	errVoIPMetricsCapacity       = errors.New("rtcp: VoIP metrics timeline capacity must be greater than zero")
)

// VoIPMetricsSample is one VoIP Metrics report block (RFC 3611, section 4.7)
// converted to unit normalised values.
//
// The wire format mixes several encodings:
//
//   - LossRate, DiscardRate, BurstDensity and GapDensity are 8 bit fixed point
//     fractions with the binary point at the left edge. They are exposed as
//     fractions in [0, 255/256], not as percentages.
//   - BurstDuration, GapDuration, RoundTripDelay, EndSystemDelay and the three
//     jitter buffer delays are milliseconds on the wire and time.Duration here.
//   - SignalLevel and NoiseLevel are signed dBm0 values; RERL and Gmin are dB
//     and a packet count respectively. See the individual fields.
//   - RFactor, ExtRFactor, MOSLQ and MOSCQ use the sentinel 127 for
//     "unavailable"; every other sentinel use is described per field.
//
// Metrics that can be unavailable are pointers. A nil pointer means the sender
// reported the RFC 3611 "unavailable" sentinel (127); it does not mean zero.
type VoIPMetricsSample struct {
	// SSRC identifies the source stream the report describes.
	SSRC uint32
	// Captured is the local time at which the report block was received. It is
	// the ordering key of the timeline, independent of arrival order.
	Captured time.Time

	// LossRate is the fraction of expected packets lost since reception began,
	// after error protection, in [0, 255/256]. Duplicates and discarded
	// packets are excluded.
	LossRate float64
	// DiscardRate is the fraction of expected packets discarded by the jitter
	// buffer (late, early, under-run or overflow), in [0, 255/256]. It
	// currently excludes duplicate discards.
	DiscardRate float64
	// BurstDensity is the fraction of expected packets lost or discarded
	// during burst periods, in [0, 255/256].
	BurstDensity float64
	// GapDensity is the fraction of expected packets lost or discarded during
	// inter-burst gaps, in [0, 255/256].
	GapDensity float64

	// BurstDuration is the mean burst length, in milliseconds.
	BurstDuration time.Duration
	// GapDuration is the mean gap length, in milliseconds.
	GapDuration time.Duration

	// RoundTripDelay is the most recent round trip delay measured between the
	// RTP interfaces, in milliseconds.
	RoundTripDelay time.Duration
	// EndSystemDelay is the estimated sending side encoding plus receiving
	// side jitter buffer, decoding and playout delay, in milliseconds.
	EndSystemDelay time.Duration

	// SignalLevel is the speech level relative to 0 dBm0 in dB, as a signed
	// two's complement value. It is nil when the sender reported 127
	// ("unavailable").
	SignalLevel *int8
	// NoiseLevel is the silence period noise level relative to 0 dBm0 in dB,
	// as a signed two's complement value. It is nil when the sender reported
	// 127 ("unavailable").
	NoiseLevel *int8
	// RERL is the residual echo return loss in dB. It is nil when the sender
	// reported 127 ("unavailable").
	RERL *uint8
	// Gmin is the gap threshold used for burst and gap detection, in packets.
	// RFC 3611 requires a non-zero value that stays constant for the session.
	Gmin uint8

	// RFactor is the RTP segment R factor in [0, 100]. It is nil when the
	// sender reported 127 ("unavailable").
	RFactor *uint8
	// ExtRFactor is the external network segment R factor in [0, 100]. It is
	// nil when the sender reported 127 ("unavailable").
	ExtRFactor *uint8
	// MOSLQ is the estimated listening quality MOS in [1.0, 5.0], without
	// delay effects. It is nil when the sender reported 127 ("unavailable").
	MOSLQ *float64
	// MOSCQ is the estimated conversational quality MOS in [1.0, 5.0],
	// including delay effects. It is nil when the sender reported 127
	// ("unavailable").
	MOSCQ *float64

	// RXConfig is the raw receiver configuration byte: PLC in the top two bits,
	// JBA in the next two and the JB adjustment rate in the low four.
	RXConfig uint8
	// JBNominal is the current nominal jitter buffer delay in milliseconds.
	JBNominal time.Duration
	// JBMaximum is the current maximum jitter buffer delay in milliseconds.
	JBMaximum time.Duration
	// JBAbsMax is the absolute maximum jitter buffer delay in milliseconds
	// reachable by an adaptive buffer.
	JBAbsMax time.Duration
}

// NewVoIPMetricsSample converts a VoIP Metrics report block into a sample
// captured at the given local time.
//
// A block without a source SSRC (SSRC zero) is rejected with
// errVoIPMetricsMissingSSRC. Values that RFC 3611 does not allow are rejected
// with errVoIPMetricsInvalidMetric rather than silently clamped: the R and
// external R factors must be in [0, 100] or the sentinel 127, both MOS fields
// must be in [10, 50] or 127, and Gmin must be non-zero. The sentinel 127 for
// signal level, noise level, RERL, the R factors and the MOS fields is valid
// and is represented by a nil pointer.
func NewVoIPMetricsSample(block *VoIPMetricsReportBlock, captured time.Time) (VoIPMetricsSample, error) {
	if block == nil {
		return VoIPMetricsSample{}, errVoIPMetricsNilBlock
	}
	if block.SSRC == 0 {
		return VoIPMetricsSample{}, errVoIPMetricsMissingSSRC
	}
	if block.Gmin == 0 {
		return VoIPMetricsSample{}, fmt.Errorf("%w: Gmin is zero", errVoIPMetricsInvalidMetric)
	}
	if err := validateRFactor("R factor", block.RFactor); err != nil {
		return VoIPMetricsSample{}, err
	}
	if err := validateRFactor("external R factor", block.ExtRFactor); err != nil {
		return VoIPMetricsSample{}, err
	}
	if err := validateMOS("MOS-LQ", block.MOSLQ); err != nil {
		return VoIPMetricsSample{}, err
	}
	if err := validateMOS("MOS-CQ", block.MOSCQ); err != nil {
		return VoIPMetricsSample{}, err
	}

	return VoIPMetricsSample{
		SSRC:           block.SSRC,
		Captured:       captured,
		LossRate:       float64(block.LossRate) / voipMetricsFractionScale,
		DiscardRate:    float64(block.DiscardRate) / voipMetricsFractionScale,
		BurstDensity:   float64(block.BurstDensity) / voipMetricsFractionScale,
		GapDensity:     float64(block.GapDensity) / voipMetricsFractionScale,
		BurstDuration:  time.Duration(block.BurstDuration) * time.Millisecond,
		GapDuration:    time.Duration(block.GapDuration) * time.Millisecond,
		RoundTripDelay: time.Duration(block.RoundTripDelay) * time.Millisecond,
		EndSystemDelay: time.Duration(block.EndSystemDelay) * time.Millisecond,
		SignalLevel:    optionalSignalLevel(block.SignalLevel),
		NoiseLevel:     optionalSignalLevel(block.NoiseLevel),
		RERL:           optionalByte(block.RERL),
		Gmin:           block.Gmin,
		RFactor:        optionalByte(block.RFactor),
		ExtRFactor:     optionalByte(block.ExtRFactor),
		MOSLQ:          optionalMOS(block.MOSLQ),
		MOSCQ:          optionalMOS(block.MOSCQ),
		RXConfig:       block.RXConfig,
		JBNominal:      time.Duration(block.JBNominal) * time.Millisecond,
		JBMaximum:      time.Duration(block.JBMaximum) * time.Millisecond,
		JBAbsMax:       time.Duration(block.JBAbsMax) * time.Millisecond,
	}, nil
}

func validateRFactor(name string, value uint8) error {
	if value <= 100 || value == voipMetricsUnavailable {
		return nil
	}

	return fmt.Errorf("%w: %s is %d, want 0 to 100 or 127", errVoIPMetricsInvalidMetric, name, value)
}

func validateMOS(name string, value uint8) error {
	if (value >= 10 && value <= 50) || value == voipMetricsUnavailable {
		return nil
	}

	return fmt.Errorf("%w: %s is %d, want 10 to 50 or 127", errVoIPMetricsInvalidMetric, name, value)
}

// optionalByte maps the 8 bit "unavailable" sentinel to nil. All other values,
// including zero, are real measurements.
func optionalByte(value uint8) *uint8 {
	if value == voipMetricsUnavailable {
		return nil
	}
	out := value

	return &out
}

// optionalSignalLevel maps the 8 bit "unavailable" sentinel to nil and keeps
// the remaining values as signed dBm0 levels.
func optionalSignalLevel(value uint8) *int8 {
	if value == voipMetricsUnavailable {
		return nil
	}
	out := int8(value) //nolint:gosec // G115 // the wire field is a signed 8 bit level

	return &out
}

// optionalMOS scales the integer MOS encoding (MOS * 10) and maps the
// "unavailable" sentinel to nil.
func optionalMOS(value uint8) *float64 {
	if value == voipMetricsUnavailable {
		return nil
	}
	out := float64(value) / voipMetricsMOSScale

	return &out
}

// clonePtr duplicates an optional value so that callers of the timeline cannot
// mutate samples the timeline still owns.
func clonePtr[T any](value *T) *T {
	if value == nil {
		return nil
	}
	out := *value

	return &out
}

func (s *VoIPMetricsSample) clone() VoIPMetricsSample {
	out := *s
	out.SignalLevel = clonePtr(s.SignalLevel)
	out.NoiseLevel = clonePtr(s.NoiseLevel)
	out.RERL = clonePtr(s.RERL)
	out.RFactor = clonePtr(s.RFactor)
	out.ExtRFactor = clonePtr(s.ExtRFactor)
	out.MOSLQ = clonePtr(s.MOSLQ)
	out.MOSCQ = clonePtr(s.MOSCQ)

	return out
}

// VoIPMetricsWindow is the part of one participant's timeline that falls
// inside the requested capture time range, in ascending capture time order.
type VoIPMetricsWindow struct {
	// SSRC is the participant the window was queried for.
	SSRC uint32
	// From and To are the requested, inclusive capture time bounds.
	From time.Time
	To   time.Time
	// Samples are the matching samples, oldest capture time first.
	Samples []VoIPMetricsSample
}

// VoIPMetricsTimeline stores VoIP Metrics report blocks per SSRC in capture
// time order and serves bounded time windows from them.
//
// Ingestion is keyed by SSRC and capture time. A second report for the same
// SSRC with the same capture time is a duplicate and is ignored, so
// retransmitted or looped back XR packets do not create a second point.
// Reports may arrive out of order: every query returns samples ordered by
// capture time, never by insertion order.
//
// The history is bounded per SSRC. Once the per-SSRC capacity is reached the
// oldest sample is evicted, so a late report older than everything retained is
// accepted only into an eviction. Evicted counts those removals. Adding a new
// participant beyond the participant limit fails with
// errVoIPMetricsTooManySSRCs until Remove frees a slot.
//
// A VoIPMetricsTimeline is safe for concurrent use.
type VoIPMetricsTimeline struct {
	mu sync.Mutex

	maxSamplesPerSSRC int
	maxSSRCs          int
	series            map[uint32]*voipMetricsSeries
}

type voipMetricsSeries struct {
	// samples is ordered by Captured and has at most maxSamplesPerSSRC entries.
	samples []VoIPMetricsSample
	evicted uint64
}

// VoIPMetricsTimelineOption configures a VoIPMetricsTimeline.
type VoIPMetricsTimelineOption func(*VoIPMetricsTimeline)

// WithVoIPMetricsMaxSamples sets how many samples are retained for each SSRC.
// Older samples are evicted first. The value must be greater than zero.
func WithVoIPMetricsMaxSamples(count int) VoIPMetricsTimelineOption {
	return func(t *VoIPMetricsTimeline) {
		t.maxSamplesPerSSRC = count
	}
}

// WithVoIPMetricsMaxSSRCs sets how many participants are tracked. Ingesting a
// report for a further participant fails with errVoIPMetricsTooManySSRCs. The
// value must be greater than zero.
func WithVoIPMetricsMaxSSRCs(count int) VoIPMetricsTimelineOption {
	return func(t *VoIPMetricsTimeline) {
		t.maxSSRCs = count
	}
}

// NewVoIPMetricsTimeline creates an empty timeline with bounded storage.
func NewVoIPMetricsTimeline(options ...VoIPMetricsTimelineOption) (*VoIPMetricsTimeline, error) {
	timeline := &VoIPMetricsTimeline{
		maxSamplesPerSSRC: defaultVoIPMetricsSamplesPerSSRC,
		maxSSRCs:          defaultVoIPMetricsSSRCs,
		series:            make(map[uint32]*voipMetricsSeries),
	}
	for _, option := range options {
		option(timeline)
	}
	if timeline.maxSamplesPerSSRC <= 0 || timeline.maxSSRCs <= 0 {
		return nil, errVoIPMetricsCapacity
	}

	return timeline, nil
}

// Ingest converts block and stores it under the block's SSRC at captured.
//
// It reports whether the sample is retained. The result is false without an
// error when the sample duplicates an existing capture time for that SSRC, or
// when the timeline is full and the sample is so old that it is evicted
// immediately. Invalid blocks return an error and store nothing. Reaching the
// participant limit is an error.
func (t *VoIPMetricsTimeline) Ingest(block *VoIPMetricsReportBlock, captured time.Time) (bool, error) {
	sample, err := NewVoIPMetricsSample(block, captured)
	if err != nil {
		return false, err
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	series, ok := t.series[sample.SSRC]
	if !ok {
		if len(t.series) >= t.maxSSRCs {
			return false, fmt.Errorf("%w: %d participants", errVoIPMetricsTooManySSRCs, t.maxSSRCs)
		}
		series = &voipMetricsSeries{}
		t.series[sample.SSRC] = series
	}

	index, found := slices.BinarySearchFunc(series.samples, sample, func(left, right VoIPMetricsSample) int {
		return left.Captured.Compare(right.Captured)
	})
	if found {
		return false, nil
	}

	series.samples = slices.Insert(series.samples, index, sample)
	evicted := len(series.samples) - t.maxSamplesPerSSRC
	if evicted > 0 {
		series.samples = slices.Delete(series.samples, 0, evicted)
		series.evicted += uint64(evicted)
	}

	// The new sample is retained unless it was itself the oldest entry and the
	// capacity forced it out again.
	return index >= evicted, nil
}

// IngestExtendedReport stores every VoIP Metrics report block carried by xr at
// the given capture time and returns how many samples were retained.
// Duplicates and evicted samples are not counted. Non VoIP Metrics blocks are
// ignored. The first invalid block stops ingestion and is reported with its
// block index wrapped in the error.
func (t *VoIPMetricsTimeline) IngestExtendedReport(xr *ExtendedReport, captured time.Time) (int, error) {
	if xr == nil {
		return 0, errVoIPMetricsNilReport
	}

	stored := 0
	for index, block := range xr.Reports {
		metrics, ok := block.(*VoIPMetricsReportBlock)
		if !ok {
			continue
		}
		retained, err := t.Ingest(metrics, captured)
		if err != nil {
			return stored, fmt.Errorf("rtcp: report block %d: %w", index, err)
		}
		if retained {
			stored++
		}
	}

	return stored, nil
}

// Window returns the samples for ssrc whose capture time lies in [from, to],
// oldest first. Bounds are inclusive.
//
// It returns errVoIPMetricsBackwardWindow when to is before from (the capture
// clock cannot move backwards across a window), errVoIPMetricsUnknownSSRC when
// no report was ever stored for ssrc, and errVoIPMetricsEmptyWindow when the
// SSRC is known but the range holds no samples.
func (t *VoIPMetricsTimeline) Window(ssrc uint32, from, to time.Time) (VoIPMetricsWindow, error) {
	window := VoIPMetricsWindow{SSRC: ssrc, From: from, To: to}

	if to.Before(from) {
		return window, errVoIPMetricsBackwardWindow
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	series, ok := t.series[ssrc]
	if !ok {
		return window, errVoIPMetricsUnknownSSRC
	}

	start, _ := slices.BinarySearchFunc(series.samples, from, func(sample VoIPMetricsSample, bound time.Time) int {
		return sample.Captured.Compare(bound)
	})
	window.Samples = make([]VoIPMetricsSample, 0, len(series.samples)-start)
	for index := start; index < len(series.samples); index++ {
		if series.samples[index].Captured.After(to) {
			break
		}
		window.Samples = append(window.Samples, series.samples[index].clone())
	}
	if len(window.Samples) == 0 {
		return window, errVoIPMetricsEmptyWindow
	}

	return window, nil
}

// Latest returns the most recently captured sample for ssrc, regardless of the
// order in which reports arrived. It returns errVoIPMetricsUnknownSSRC when no
// report was ever stored for ssrc.
func (t *VoIPMetricsTimeline) Latest(ssrc uint32) (VoIPMetricsSample, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	series, ok := t.series[ssrc]
	if !ok || len(series.samples) == 0 {
		return VoIPMetricsSample{}, errVoIPMetricsUnknownSSRC
	}
	latest := series.samples[len(series.samples)-1]

	return latest.clone(), nil
}

// Participants returns the SSRCs with stored samples, in ascending order.
func (t *VoIPMetricsTimeline) Participants() []uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()

	participants := make([]uint32, 0, len(t.series))
	for ssrc := range t.series {
		participants = append(participants, ssrc)
	}
	slices.Sort(participants)

	return participants
}

// Len returns the number of retained samples for ssrc, or zero if the SSRC is
// unknown.
func (t *VoIPMetricsTimeline) Len(ssrc uint32) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	series, ok := t.series[ssrc]
	if !ok {
		return 0
	}

	return len(series.samples)
}

// Evicted returns how many samples were dropped for ssrc because the per-SSRC
// capacity was exceeded, or zero if the SSRC is unknown.
func (t *VoIPMetricsTimeline) Evicted(ssrc uint32) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	series, ok := t.series[ssrc]
	if !ok {
		return 0
	}

	return series.evicted
}

// Remove forgets everything recorded for ssrc, freeing its participant slot.
func (t *VoIPMetricsTimeline) Remove(ssrc uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.series, ssrc)
}
