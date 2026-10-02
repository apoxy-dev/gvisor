// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package bbr is BBRv3 congestion control for the netstack TCP sender.
// It follows Google BBRv3 commit 90210de4 and draft-ietf-ccwg-bbr-03.
package bbr

import (
	"math"
	"math/rand/v2"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// States of BBRv3.
const (
	StateStartup = iota
	StateDrain
	StateProbeBWDown
	StateProbeBWCruise
	StateProbeBWRefill
	StateProbeBWUp
	StateProbeRTT
)

// Constants of the reference. Gains are fixed point with BBR_UNIT=256.
const (
	bbrScale             = 256
	bbrUnit              = float64(bbrScale)
	betaNumerator        = 180
	lossThreshNumerator  = 5
	headroomCutNumerator = 38
	startupPacingGain    = 710.0 / bbrUnit // BBR_UNIT*277/100 + 1
	startupCwndGain      = 2.0
	drainPacingGain      = 88.0 / bbrUnit // BBR_UNIT*1000/2885
	probeUpGain          = 1.25
	probeDownGain        = 232.0 / bbrUnit // BBR_UNIT*91/100
	cruiseGain           = 1.0
	probeBWCwndGain      = 2.0
	// probeUpCwndGain is the cwnd gain in ProbeBW:UP, so that cwnd does not stop the probe.
	probeUpCwndGain  = 2.25
	probeRTTCwndGain = 0.5

	beta         = float64(betaNumerator) / bbrUnit // 1 - floor(BBR_UNIT*30/100)/BBR_UNIT
	headroom     = float64(bbrScale-headroomCutNumerator) / bbrUnit
	lossThresh   = float64(lossThreshNumerator) / bbrUnit
	pacingMargin = 0.01 // Pace at 99% of the model bandwidth.

	ecnAlphaGain = 1.0 / 16
	ecnFactor    = 85.0 / bbrUnit // floor(BBR_UNIT/3)/BBR_UNIT
	ecnThresh    = 0.5
	ecnMaxRTT    = 5 * time.Millisecond
	// startupFullECNCount is the number of high-CE rounds that end Startup (bbr_full_ecn_cnt).
	startupFullECNCount = 2

	minRTTFilterLen  = 10 * time.Second
	probeRTTInterval = 5 * time.Second
	probeRTTDuration = 200 * time.Millisecond

	fullBwThresh = 1.25 // Less than 25% growth ...
	fullBwCount  = 3    // ... in 3 rounds fills the pipe.
	// fullLossCount loss events in one round above lossThresh end Startup (full_loss_cnt).
	fullLossCount = 6

	maxBwFilterLen  = 2 // Max-bw filter length in probe cycles.
	probeRandRounds = 2 // Random start value of rounds_since_probe: [0, 2).

	extraAckedWinRTTs         = 5
	extraAckedResetThreshPkts = 1 << 20
	extraAckedMaxInterval     = 100 * time.Millisecond
	maxSendQuantum            = 64 << 10
	minSendQuantumPkts        = 2
)

// ACK phases (BBR.ack_phase): the ProbeBW phase in which the ACKed data was sent.
const (
	acksInit = iota
	acksRefilling
	acksProbeStarting
	acksProbeFeedback
	acksProbeStopping
)

// Sender is the sender interface of BBR. tcp.SimSender implements it.
type Sender interface {
	MSS() int
	CwndPkts() int
	SetCwndPkts(int)
	SetPacingRateBps(int64)
	SRTT() time.Duration
	Now() time.Duration
	InRecovery() bool
	LocalPort() uint16
	SetSsthresh(int)
	Seed() uint64
	ECNLowLatency() bool
	MarkAppLimited()
}

// BBR is one connection's BBRv3 state.
type BBR struct {
	s   Sender
	rng *rand.Rand

	state     int
	stateTime time.Duration // Entry time of the current state.

	// Model: bandwidth.
	maxBwFilter [maxBwFilterLen]int64 // Windowed max buckets in bits/s.
	cycleCount  int
	bwLatest    int64 // Max delivery rate in the current loss round.
	bwLo        int64 // Short-term bound. math.MaxInt64 is not set.
	fullBw      int64
	fullBwCount int
	// startupEcnRounds counts the Startup rounds in sequence with a CE fraction above ecnThresh.
	startupEcnRounds int
	filledPipe       bool
	// pacingBps is the last pacing rate. It only increases until the pipe is full.
	pacingBps int64

	// ACK aggregation. extraAcked is a max filter with two slots of 5 rounds, 1 round in Startup.
	ackEpochStart       time.Duration
	ackEpochAcked       int64
	extraAcked          [2]int64
	extraAckedWinRounds int
	extraAckedWinIdx    int

	// cwnd is the congestion window in bytes (BBRSetCwnd).
	// priorCwnd is the last good cwnd (BBRSaveCwnd, BBRRestoreCwnd).
	cwnd        int64
	priorCwnd   int64
	initialCwnd int64

	// Model: RTT. probeRTTMin is the 5 s minimum that schedules ProbeRTT.
	// minRTT is the 10 s minimum of the path model.
	minRTT            time.Duration
	minRTTTime        time.Duration
	probeRTTMin       time.Duration
	probeRTTMinTime   time.Duration
	probeRTTExpired   bool
	probeRTTDone      time.Duration // End of the ProbeRTT hold, 0 if not holding.
	probeRTTRoundDone bool          // A full round passed at the reduced window.

	// Model: inflight bounds in bytes. math.MaxInt64 is not set.
	inflightHi     int64
	inflightLo     int64
	inflightLatest int64 // Max delivered volume of a sample in this loss round.

	// Round tracking.
	nextRoundDelivered int64
	roundStart         bool
	roundCount         int64

	// Two packet-timed clocks, as in tcp_bbr.c. roundStart is for ECN alpha and full bandwidth.
	// lossRoundStart is for the lower bounds after loss.
	lossRoundDelivered int64
	lossRoundStart     bool
	lossInRound        bool
	ecnInRound         bool
	lossEventsRound    int
	lostBytesRound     int64
	prevLostBytes      int64
	ceBytesRound       int64
	ackedBytesRound    int64
	ecnAlpha           float64
	ecnEligible        bool

	// ProbeBW cycling.
	probeWait        time.Duration // Time in CRUISE before the next probe.
	cycleStart       time.Duration // Start of the current cycle (DOWN entry).
	roundsInPhase    int64
	roundsSinceProbe int64
	// probeUpRounds, probeUpAcks and probeUpCnt grow inflight_hi in UP:
	// one MSS per probeUpCnt bytes ACKed. The slope doubles each round.
	probeUpRounds int64
	probeUpAcks   int64
	probeUpCnt    int64
	// fullBwNow is BBR.full_bw_now. It is reset for each UP. filledPipe stays set.
	fullBwNow bool
	// ackPhase is BBR.ack_phase. It advances the max-bw filter one round after DOWN starts.
	ackPhase int
	// bwProbeSamples is BBR.bw_probe_samples. Loss stops a probe at most one time.
	bwProbeSamples bool
	// probeStartDelivered is C.delivered at REFILL entry.
	// Loss of data sent before the probe does not stop the probe.
	probeStartDelivered int64
	prevProbeTooHigh    bool
	stoppedRiskyProbe   bool

	// lastSample is the latest rate sample.
	lastSample tcp.SimRateSample

	idleRestart bool

	// Model bounds saved at the start of recovery, for undo after a spurious recovery.
	recoverySnapshot bool
	undoBwLo         int64
	undoInflightLo   int64
	undoInflightHi   int64
}

var _ tcp.SimCC = (*BBR)(nil)
var _ tcp.SimCCWithUndo = (*BBR)(nil)
var _ tcp.SimCCWithIdleRestart = (*BBR)(nil)
var _ tcp.SimCCWithLossProbeRecovery = (*BBR)(nil)

// New creates a BBRv3 instance for one connection.
func New(s Sender) *BBR {
	now := s.Now()
	b := &BBR{
		s: s,
		// The port gives each flow a different random stream.
		rng:        rand.New(rand.NewPCG(s.Seed(), 0xBB3<<32|uint64(s.LocalPort()))),
		state:      StateStartup,
		bwLo:       math.MaxInt64,
		inflightHi: math.MaxInt64,
		inflightLo: math.MaxInt64,
		probeUpCnt: math.MaxInt64,
		ecnAlpha:   1, // Alpha starts at 1.
		// As bbr_init: the first loss round ends when data sent after the first delivery is ACKed.
		lossRoundDelivered: 1,
		ackEpochStart:      now,
	}
	b.stateTime = now
	if srtt := s.SRTT(); srtt > 0 {
		b.minRTT = srtt
		b.minRTTTime = now
		b.probeRTTMin = srtt
		b.probeRTTMinTime = now
	}
	b.initialCwnd = int64(s.CwndPkts()) * int64(s.MSS())
	b.cwnd = b.initialCwnd
	b.initPacingRate()
	return b
}

// initPacingRate is BBRInitPacingRate. It paces the initial window over the SRTT, or over 1 ms.
func (b *BBR) initPacingRate() {
	srtt := b.s.SRTT()
	if srtt <= 0 {
		srtt = time.Millisecond
	}
	nominalBps := float64(8*b.initialCwnd) / srtt.Seconds()
	rate := int64(startupPacingGain * nominalBps)
	b.pacingBps = rate
	b.s.SetPacingRateBps(rate)
}

// Register registers BBR in the netstack TCP as "bbr".
func Register() {
	tcp.RegisterSimCC("bbr", func(h tcp.SimSender) tcp.SimCC { return New(h) })
}

// tcp.SimCC interface.

// Update does nothing. BBR uses OnAck.
func (b *BBR) Update(packetsAcked int, rtt time.Duration) {}

// HandleLossDetected sets ssthresh to cwnd, because recovery sets cwnd from ssthresh.
// BBR responds to loss through bw_lo.
func (b *BBR) HandleLossDetected() {
	b.saveCwnd()
	b.saveRecoveryModel()
	b.s.SetSsthresh(b.s.CwndPkts())
}

// HandleRTOExpired is BBROnEnterRTO. It sets cwnd to one packet.
func (b *BBR) HandleRTOExpired() {
	// The caller clears Outstanding after this call, so set the sender cwnd here.
	b.saveCwnd()
	b.saveRecoveryModel()
	b.resetFullBW()
	if !b.isProbingBandwidth() && b.inflightLo == math.MaxInt64 {
		b.inflightLo = b.cwnd
		if b.priorCwnd > b.inflightLo {
			b.inflightLo = b.priorCwnd
		}
	}
	b.cwnd = int64(b.s.MSS())
	b.s.SetCwndPkts(1)
}

// PostRecovery restores cwnd after recovery (BBRRestoreCwnd).
func (b *BBR) PostRecovery() {
	b.restoreCwnd()
	b.applyCwnd()
	b.recoverySnapshot = false
}

// UndoRecovery is bbr_undo_cwnd. It restores the model and cwnd after a spurious recovery.
func (b *BBR) UndoRecovery() {
	b.resetFullBW()
	b.lossInRound = false
	if b.recoverySnapshot {
		if b.undoBwLo > b.bwLo {
			b.bwLo = b.undoBwLo
		}
		if b.undoInflightLo > b.inflightLo {
			b.inflightLo = b.undoInflightLo
		}
		if b.undoInflightHi > b.inflightHi {
			b.inflightHi = b.undoInflightHi
		}
	}
	b.restoreCwnd()
	b.applyCwnd()
}

// HandleRestartFromIdle handles CA_EVENT_TX_START before a new flight from an empty pipe.
func (b *BBR) HandleRestartFromIdle() {
	now := b.s.Now()
	b.idleRestart = true
	b.resetAckAggregationEpoch(now)
	if b.inProbeBW() {
		// After an idle period, pace at the model bandwidth, not at an old UP or DOWN gain.
		b.setPacingWithGain(cruiseGain)
		return
	}
	if b.state == StateProbeRTT && b.probeRTTDone != 0 && now >= b.probeRTTDone {
		// The idle period drained the pipe and completed the hold. Exit ProbeRTT now.
		b.probeRTTMinTime = now
		b.probeRTTExpired = false
		b.exitProbeRTT(now)
		b.applyCwnd()
	}
}

// HandleLossProbeRecovery handles CA_EVENT_TLP_RECOVERY. It records one lost packet
// and, during a probe, applies the loss rate test.
func (b *BBR) HandleLossProbeRecovery(ev tcp.SimLossProbeRecovery) {
	b.noteLoss(ev.LostBytesCum, b.lastSample.Delivered)
	if !b.bwProbeSamples {
		return
	}
	lost := ev.LostBytes
	if lost <= 0 {
		lost = int64(b.s.MSS())
	}
	rs := tcp.SimRateSample{
		LostBytes:    lost,
		TxInflight:   b.inflightLatest + lost,
		IsAppLimited: ev.IsAppLimited,
	}
	if b.lossRateTooHigh(rs) {
		b.handleInflightTooHigh(rs, b.s.Now())
	}
}

func (b *BBR) saveRecoveryModel() {
	if b.recoverySnapshot {
		return
	}
	b.recoverySnapshot = true
	b.undoBwLo = b.bwLo
	b.undoInflightLo = b.inflightLo
	b.undoInflightHi = b.inflightHi
}

// saveCwnd and restoreCwnd are BBRSaveCwnd and BBRRestoreCwnd.
func (b *BBR) saveCwnd() {
	if !b.s.InRecovery() && b.state != StateProbeRTT {
		b.priorCwnd = b.cwnd
	} else if b.cwnd > b.priorCwnd {
		b.priorCwnd = b.cwnd
	}
}

func (b *BBR) restoreCwnd() {
	if b.priorCwnd > b.cwnd {
		b.cwnd = b.priorCwnd
	}
}

// OnAck processes one delivery rate sample.
func (b *BBR) OnAck(rs tcp.SimRateSample) {
	b.lastSample = rs
	b.updateRound(rs)
	b.updateLossECN(rs)
	b.updateBwModel(rs)
	b.updateAckAggregation(rs)
	b.updateMinRTT(rs)
	b.updateStateMachine(rs)
	b.boundLower()
	b.setPacing()
	b.setCwnd()
}

// Model updates.

func (b *BBR) updateRound(rs tcp.SimRateSample) {
	b.roundStart = false
	// Like Linux, only a valid rate sample advances the round.
	if rs.Interval <= 0 {
		return
	}
	// A round ends when data sent at or after the round marker is ACKed.
	if rs.PriorDelivered >= 0 && rs.PriorDelivered >= b.nextRoundDelivered {
		b.nextRoundDelivered = rs.Delivered
		b.roundStart = true
		b.roundCount++
		b.roundsInPhase++
		if b.filledPipe && b.roundsSinceProbe < math.MaxInt64 {
			b.roundsSinceProbe++
		}
	}
}

func (b *BBR) updateLossECN(rs tcp.SimRateSample) {
	b.lossRoundStart = false

	// LostBytesCum counts loss when it is marked. The first mark starts a new loss round.
	b.noteLoss(rs.LostBytesCum, rs.Delivered)

	// BBRUpdateLatestDeliverySignals: the delivery floors if this loss round has congestion.
	validSample := rs.PriorDelivered >= 0 && rs.DeliveryRateBps > 0 && rs.AckedBytes > 0
	deliveredVolume := sampleDeliveredVolume(rs)
	if validSample {
		if rs.DeliveryRateBps > b.bwLatest {
			b.bwLatest = rs.DeliveryRateBps
		}
		if deliveredVolume > b.inflightLatest {
			b.inflightLatest = deliveredVolume
		}
		if rs.PriorDelivered >= b.lossRoundDelivered {
			b.lossRoundDelivered = rs.Delivered
			b.lossRoundStart = true
		}
	}

	// ECN applies only on a low-latency ECN path with a min RTT of 5 ms or less.
	if b.roundStart && !b.ecnEligible && b.s.ECNLowLatency() &&
		b.minRTT > 0 && b.minRTT <= ecnMaxRTT {
		b.ecnEligible = true
	}
	b.ackedBytesRound += rs.AckedBytes
	if b.ecnEligible && rs.ECE {
		b.ceBytesRound += rs.AckedBytes
		b.ecnInRound = true
	}
	if b.roundStart && b.ecnEligible && b.ackedBytesRound > 0 {
		// Update ECN alpha one time per round.
		ceFrac := float64(b.ceBytesRound) / float64(b.ackedBytesRound)
		// The conversions stop FMA fusion, so that all platforms get the same result.
		b.ecnAlpha = float64((1-ecnAlphaGain)*b.ecnAlpha) + float64(ecnAlphaGain*ceFrac)
	}
}

func (b *BBR) noteLoss(lostBytesCum, delivered int64) {
	if lostBytesCum <= b.prevLostBytes {
		return
	}
	if !b.lossInRound {
		b.lossRoundDelivered = delivered
	}
	b.lossInRound = true
	if b.lossEventsRound < 0xf {
		b.lossEventsRound++
	}
	b.lostBytesRound += lostBytesCum - b.prevLostBytes
	b.prevLostBytes = lostBytesCum
}

func sampleDeliveredVolume(rs tcp.SimRateSample) int64 {
	if rs.DeliveredBytes > 0 {
		return rs.DeliveredBytes
	}
	if rs.PriorDelivered >= 0 {
		// Test samples can omit DeliveredBytes.
		return rs.Delivered - rs.PriorDelivered
	}
	return 0
}

// advanceLatestDeliverySignals is bbr_advance_latest_delivery_signals.
// An ACK of a TLP repair keeps the filter.
func (b *BBR) advanceLatestDeliverySignals(rs tcp.SimRateSample) {
	if !b.lossRoundStart || rs.IsAckingTLPRetransmit {
		return
	}
	b.bwLatest = rs.DeliveryRateBps
	b.inflightLatest = sampleDeliveredVolume(rs)
}

func (b *BBR) updateBwModel(rs tcp.SimRateSample) {
	if rs.DeliveryRateBps <= 0 {
		return
	}
	// App-limited samples can only increase the filter.
	if !rs.IsAppLimited || rs.DeliveryRateBps > b.maxBw() {
		if rs.DeliveryRateBps > b.maxBwFilter[1] {
			b.maxBwFilter[1] = rs.DeliveryRateBps
		}
	}
}

// resetAckAggregationEpoch starts a new ACK aggregation interval.
func (b *BBR) resetAckAggregationEpoch(now time.Duration) {
	b.ackEpochStart = now
	b.ackEpochAcked = 0
}

// updateAckAggregation is bbr_update_ack_aggregation in bytes.
func (b *BBR) updateAckAggregation(rs tcp.SimRateSample) {
	if rs.AckedBytes <= 0 || rs.PriorDelivered < 0 || rs.Interval <= 0 {
		return
	}

	if b.roundStart {
		b.extraAckedWinRounds++
		window := extraAckedWinRTTs
		if !b.filledPipe {
			window = 1
		}
		if b.extraAckedWinRounds >= window {
			b.extraAckedWinRounds = 0
			b.extraAckedWinIdx ^= 1
			b.extraAcked[b.extraAckedWinIdx] = 0
		}
	}

	now := rs.Now
	if now == 0 {
		now = b.s.Now()
	}
	if now < b.ackEpochStart {
		b.resetAckAggregationEpoch(now)
	}
	elapsed := now - b.ackEpochStart
	expected := b.bw() / 8 * int64(elapsed) / int64(time.Second)
	resetThreshold := int64(extraAckedResetThreshPkts) * int64(b.s.MSS())
	if b.ackEpochAcked <= expected || b.ackEpochAcked+rs.AckedBytes >= resetThreshold {
		b.resetAckAggregationEpoch(now)
		expected = 0
	}
	b.ackEpochAcked += rs.AckedBytes
	extra := b.ackEpochAcked - expected
	if extra > b.cwnd {
		extra = b.cwnd
	}
	if extra > b.extraAcked[b.extraAckedWinIdx] {
		b.extraAcked[b.extraAckedWinIdx] = extra
	}
}

func (b *BBR) maxExtraAcked() int64 {
	if b.extraAcked[1] > b.extraAcked[0] {
		return b.extraAcked[1]
	}
	return b.extraAcked[0]
}

func (b *BBR) ackAggregationCwnd() int64 {
	extra := b.maxExtraAcked()
	maxExtra := b.bw() / 8 * int64(extraAckedMaxInterval) / int64(time.Second)
	if extra > maxExtra {
		extra = maxExtra
	}
	return extra
}

// advanceMaxBwFilter moves the max-bw filter to the next cycle.
// An empty current bucket does not remove the older sample.
func (b *BBR) advanceMaxBwFilter() {
	if b.maxBwFilter[1] == 0 {
		return
	}
	b.cycleCount++
	b.maxBwFilter[0] = b.maxBwFilter[1]
	b.maxBwFilter[1] = 0
}

func min64(a, c int64) int64 {
	if a < c {
		return a
	}
	return c
}

// fixedMulFloor is value * numerator >> BBR_SCALE, as in tcp_bbr.c.
func fixedMulFloor(value int64, numerator int64) int64 {
	return value * numerator / bbrScale
}

func (b *BBR) maxBw() int64 {
	m := b.maxBwFilter[0]
	if b.maxBwFilter[1] > m {
		m = b.maxBwFilter[1]
	}
	return m
}

// bw is the model bandwidth: the max filter, limited by bw_lo.
func (b *BBR) bw() int64 {
	bw := b.maxBw()
	if b.bwLo < bw {
		bw = b.bwLo
	}
	return bw
}

func (b *BBR) updateMinRTT(rs tcp.SimRateSample) {
	now := rs.Now
	if now == 0 {
		now = b.s.Now()
	}
	b.probeRTTExpired = b.probeRTTMin > 0 && now-b.probeRTTMinTime > probeRTTInterval
	if rs.RTT <= 0 {
		return
	}

	// The 5 s filter schedules ProbeRTT. After it expires, the next good sample starts a new window.
	if b.probeRTTMin == 0 || rs.RTT < b.probeRTTMin ||
		(b.probeRTTExpired && !rs.IsAckDelayed) {
		b.probeRTTMin = rs.RTT
		b.probeRTTMinTime = now
	}

	// The 10 s model changes when the 5 s minimum is as good, or when the model expires.
	minExpired := b.minRTT > 0 && now-b.minRTTTime > minRTTFilterLen
	if b.minRTT == 0 || b.probeRTTMin <= b.minRTT || minExpired {
		b.minRTT = b.probeRTTMin
		b.minRTTTime = b.probeRTTMinTime
	}
}

// bdpBytesAt is ceil(gain * BDP) at bw, in full packets.
func (b *BBR) bdpBytesAt(gain float64, bw int64) int64 {
	if b.minRTT == 0 || bw == 0 {
		return b.initialCwnd
	}
	bdp := float64(bw) / 8 * b.minRTT.Seconds()
	bytes := float64(gain * bdp)
	mss := float64(b.s.MSS())
	return int64(math.Ceil(bytes/mss)) * int64(b.s.MSS())
}

// bdpBytes is gain * BDP at the model bandwidth.
func (b *BBR) bdpBytes(gain float64) int64 {
	return b.bdpBytesAt(gain, b.bw())
}

// tsoSegsGoal is the send quantum in packets: about 1 ms of data, more at low RTT, max 64 KiB.
func (b *BBR) tsoSegsGoal() int64 {
	bytes := b.pacingBps / 8 / 1024
	if b.minRTT > 0 {
		r := uint64(b.minRTT.Microseconds()) >> 9
		if r < 63 {
			bytes += int64(maxSendQuantum) >> r
		}
	}
	if bytes > maxSendQuantum {
		bytes = maxSendQuantum
	}
	segs := bytes / int64(b.s.MSS())
	if segs < minSendQuantumPkts {
		segs = minSendQuantumPkts
	}
	return segs
}

// quantizationBudget adds three send quanta and a floor of 4 packets.
// ProbeBW:UP adds two packets.
func (b *BBR) quantizationBudget(inflight int64) int64 {
	mss := int64(b.s.MSS())
	if offload := 3 * b.tsoSegsGoal() * mss; inflight < offload {
		inflight = offload
	}
	if minPipe := int64(4) * mss; inflight < minPipe {
		inflight = minPipe
	}
	if b.state == StateProbeBWUp {
		inflight += 2 * mss
	}
	return inflight
}

func (b *BBR) inflightBytesAt(gain float64, bw int64) int64 {
	return b.quantizationBudget(b.bdpBytesAt(gain, bw))
}

func (b *BBR) targetInflightBytes() int64 {
	target := b.inflightBytesAt(1.0, b.bw())
	if b.cwnd < target {
		target = b.cwnd
	}
	return target
}

// State machine.

func (b *BBR) updateStateMachine(rs tcp.SimRateSample) {
	now := b.s.Now()

	// Close the loss round before the state transitions.
	if b.lossRoundStart {
		b.adaptLowerBounds()
	}

	// Startup exit checks.
	if b.state == StateStartup {
		b.checkFullPipe(rs)
		if b.filledPipe {
			b.enter(StateDrain, now)
			// Congestion from Startup must not become a short-term bound in Drain.
			b.resetCongestionSignals()
		}
	}

	if b.state == StateDrain {
		if rs.InflightBytes <= b.inflightBytesAt(1.0, b.maxBw()) {
			b.startProbeBWDown(now)
		}
	}

	// Enter ProbeRTT when the 5 s filter expires, but not on the first ACK after idle.
	if b.state != StateProbeRTT && b.minRTT != 0 &&
		b.probeRTTExpired && !b.idleRestart {
		b.saveCwnd()
		b.enter(StateProbeRTT, now)
		b.probeRTTDone = 0
		b.probeRTTRoundDone = false
		b.ackPhase = acksProbeStopping
		b.nextRoundDelivered = rs.Delivered
	}

	// After the pipe is full, adapt the long-term model on each ACK in all states.
	if b.filledPipe {
		b.checkFullBwReached(rs)
		b.adaptLongTermModel(rs, now)
	}

	switch b.state {
	case StateProbeBWDown:
		// Leave DOWN when inflight is at or below the target with headroom.
		if rs.InflightBytes <= b.inflightWithHeadroom() &&
			rs.InflightBytes <= b.inflightBytesAt(1.0, b.maxBw()) {
			b.enterCruise(now)
		} else if b.timeToProbeBW(now) {
			// The queue of another flow can stop the drain. Probe when the wait expires.
			b.enterRefill(now)
		}
	case StateProbeBWCruise:
		if b.timeToProbeBW(now) {
			b.enterRefill(now)
		}
	case StateProbeBWRefill:
		// After one round of REFILL, start UP.
		if b.roundStart && b.roundsInPhase >= 1 {
			b.startProbeBWUp(now)
		}
	case StateProbeBWUp:
		if b.isTimeToGoDown(rs) {
			b.startProbeBWDown(now)
		}
	case StateProbeRTT:
		// Samples in ProbeRTT are app-limited.
		b.s.MarkAppLimited()
		cap := b.probeRTTCwndBytes()
		if b.probeRTTDone == 0 && rs.InflightBytes <= cap {
			// Inflight is at the cap. Hold for probeRTTDuration and one round (probe_rtt_round_done).
			b.probeRTTDone = now + probeRTTDuration
			b.probeRTTRoundDone = false
			b.nextRoundDelivered = rs.Delivered
		}
		if b.probeRTTDone != 0 && b.roundStart {
			b.probeRTTRoundDone = true
		}
		if b.probeRTTDone != 0 && b.probeRTTRoundDone && now >= b.probeRTTDone {
			// The hold is complete. Schedule the next ProbeRTT.
			b.probeRTTMinTime = now
			b.probeRTTExpired = false
			b.exitProbeRTT(now)
		}
	}

	if b.lossRoundStart {
		// Start the next loss round with this sample, after the state transitions.
		b.lossInRound = false
		b.ecnInRound = false
		b.lossEventsRound = 0
		b.lostBytesRound = 0
		b.bwLatest = 0
		b.inflightLatest = 0
		b.advanceLatestDeliverySignals(rs)
	}
	if b.roundStart {
		// The ECN counters use the packet-timed round.
		b.ceBytesRound = 0
		b.ackedBytesRound = 0
	}
	// As tcp_bbr.c, clear idle restart after the first ACK that delivers data.
	if sampleDeliveredVolume(rs) > 0 {
		b.idleRestart = false
	}
}

func (b *BBR) enter(state int, now time.Duration) {
	b.state = state
	b.stateTime = now
	b.roundsInPhase = 0
}

// enterRefill starts a bandwidth probe. It releases the short-term bounds and resets the probe counters.
func (b *BBR) enterRefill(now time.Duration) {
	b.enter(StateProbeBWRefill, now)
	b.bwLo = math.MaxInt64
	b.inflightLo = math.MaxInt64
	b.probeUpRounds = 0
	b.probeUpAcks = 0
	b.stoppedRiskyProbe = false
	b.ackPhase = acksRefilling
	b.bwProbeSamples = false
	b.probeStartDelivered = b.lastSample.Delivered
}

// startProbeBWUp is BBRStartProbeBW_UP. It starts the full-bw estimator again from the latest rate.
func (b *BBR) startProbeBWUp(now time.Duration) {
	b.ackPhase = acksProbeStarting
	b.bwProbeSamples = true
	b.enter(StateProbeBWUp, now)
	b.resetFullBW()
	b.fullBw = b.lastSample.DeliveryRateBps
	b.raiseInflightHiSlope()
}

func (b *BBR) startProbeBWDown(now time.Duration) {
	b.resetCongestionSignals()
	b.enter(StateProbeBWDown, now)
	b.cycleStart = now
	// Random probe delay: 0-1 rounds and 2-3 s.
	b.roundsSinceProbe = b.rng.Int64N(probeRandRounds)
	b.probeWait = 2*time.Second + time.Duration(b.rng.Int64N(int64(time.Second)))
	// inflight_hi does not grow outside UP.
	b.probeUpCnt = math.MaxInt64
	// The max-bw filter advances one round from now (ACKS_PROBE_STOPPING).
	b.ackPhase = acksProbeStopping
}

func (b *BBR) enterCruise(now time.Duration) {
	if b.inflightLo != math.MaxInt64 && b.inflightHi < b.inflightLo {
		b.inflightLo = b.inflightHi
	}
	b.enter(StateProbeBWCruise, now)
}

func (b *BBR) resetCongestionSignals() {
	b.lossInRound = false
	b.ecnInRound = false
	b.lossEventsRound = 0
	b.lostBytesRound = 0
	b.bwLatest = 0
	b.inflightLatest = 0
}

func (b *BBR) exitProbeRTT(now time.Duration) {
	b.restoreCwnd()
	b.bwLo = math.MaxInt64
	b.inflightLo = math.MaxInt64
	if b.filledPipe {
		b.startProbeBWDown(now)
		b.enterCruise(now)
	} else {
		b.enter(StateStartup, now)
	}
}

func (b *BBR) checkFullPipe(rs tcp.SimRateSample) {
	if b.filledPipe {
		return
	}
	// High loss or ECN also ends Startup.
	if b.lossRoundStart && b.lossEventsRound >= fullLossCount &&
		b.s.InRecovery() && b.lossRateTooHigh(rs) {
		b.handleQueueTooHighInStartup()
		return
	}
	if b.roundStart {
		// ECN exit needs two high-CE rounds in sequence (bbr_full_ecn_cnt).
		if b.ecnEligible && b.ackedBytesRound > 0 &&
			float64(b.ceBytesRound)/float64(b.ackedBytesRound) >= ecnThresh {
			b.startupEcnRounds++
			if b.startupEcnRounds >= startupFullECNCount {
				b.handleQueueTooHighInStartup()
				return
			}
		} else {
			b.startupEcnRounds = 0
		}
	}
	if rs.IsAppLimited {
		return
	}
	b.checkFullBwReached(rs)
}

// handleQueueTooHighInStartup is bbr_handle_queue_too_high_in_startup.
// It ends Startup and sets inflight_hi from the BDP or the latest delivered volume.
func (b *BBR) handleQueueTooHighInStartup() {
	b.filledPipe = true
	hi := b.inflightBytesAt(1.0, b.maxBw())
	if b.inflightLatest > hi {
		hi = b.inflightLatest
	}
	b.inflightHi = hi
}

// resetFullBW is BBRResetFullBW.
func (b *BBR) resetFullBW() {
	b.fullBw = 0
	b.fullBwCount = 0
	b.fullBwNow = false
}

// checkFullBwReached is BBRCheckFullBWReached: 3 rounds with less than 25% growth set full_bw_now.
func (b *BBR) checkFullBwReached(rs tcp.SimRateSample) {
	if b.fullBwNow || rs.IsAppLimited {
		return
	}
	if rs.DeliveryRateBps >= int64(float64(b.fullBw)*fullBwThresh) {
		// Bandwidth still grows. Start again from this sample.
		b.resetFullBW()
		b.fullBw = rs.DeliveryRateBps
		return
	}
	if !b.roundStart {
		return
	}
	b.fullBwCount++
	b.fullBwNow = b.fullBwCount >= fullBwCount
	if b.fullBwNow {
		b.filledPipe = true
	}
}

func (b *BBR) timeToProbeBW(now time.Duration) bool {
	if now-b.cycleStart > b.probeWait {
		return true
	}
	// For Reno coexistence, probe after the rounds that Reno needs to grow one BDP, max 63.
	inflightPkts := b.inflightBytesAt(1.0, b.bw()) / int64(b.s.MSS())
	if cwndPkts := b.cwnd / int64(b.s.MSS()); cwndPkts < inflightPkts {
		inflightPkts = cwndPkts
	}
	renoRounds := inflightPkts
	if renoRounds > 63 {
		renoRounds = 63
	}
	return b.roundsSinceProbe >= renoRounds && renoRounds > 0
}

// lossRateTooHigh is the loss part of IsInflightTooHigh: lost > tx_in_flight * LossThresh.
func (b *BBR) lossRateTooHigh(rs tcp.SimRateSample) bool {
	return rs.TxInflight > 0 &&
		rs.LostBytes > fixedMulFloor(rs.TxInflight, lossThreshNumerator)
}

// ecnTooHigh is the ECN part of IsInflightTooHigh, for this rate sample.
func (b *BBR) ecnTooHigh(rs tcp.SimRateSample) bool {
	return b.ecnEligible && rs.DeliveredBytes > 0 &&
		rs.DeliveredCEBytes > int64(ecnThresh*float64(rs.DeliveredBytes))
}

// inflightTooHigh is IsInflightTooHigh. It also stops the upward adaptation.
func (b *BBR) inflightTooHigh(rs tcp.SimRateSample) bool {
	return b.lossRateTooHigh(rs) || b.ecnTooHigh(rs)
}

// probeTooHigh reports whether a too-high sample is from data sent in the current probe.
// It is true at most one time per probe.
func (b *BBR) probeTooHigh(rs tcp.SimRateSample) bool {
	if !b.bwProbeSamples {
		return false
	}
	if rs.PriorDelivered < b.probeStartDelivered {
		return false
	}
	return b.ecnTooHigh(rs) || b.lossRateTooHigh(rs)
}

func (b *BBR) handleInflightTooHigh(rs tcp.SimRateSample, now time.Duration) {
	b.prevProbeTooHigh = true
	b.bwProbeSamples = false // React one time per probe.
	// An app-limited sample ends the probe but does not set inflight_hi.
	if !rs.IsAppLimited {
		// inflight_longterm = max(tx_in_flight, beta * target).
		infl := rs.TxInflight
		if infl == 0 {
			infl = rs.InflightBytes
		}
		target := fixedMulFloor(b.targetInflightBytes(), betaNumerator)
		hi := infl
		if target > hi {
			hi = target
		}
		b.inflightHi = hi
	}
	if b.state == StateProbeBWUp {
		b.startProbeBWDown(now)
	}
}

func (b *BBR) inProbeBW() bool {
	switch b.state {
	case StateProbeBWDown, StateProbeBWCruise, StateProbeBWRefill, StateProbeBWUp:
		return true
	}
	return false
}

func (b *BBR) isProbingBandwidth() bool {
	return b.state == StateStartup || b.state == StateProbeBWRefill || b.state == StateProbeBWUp
}

// adaptLongTermModel is BBRAdaptLongTermModel. It runs on each ACK after the pipe is full.
func (b *BBR) adaptLongTermModel(rs tcp.SimRateSample, now time.Duration) {
	if b.ackPhase == acksProbeStarting && b.roundStart {
		// Data sent in the probe is now ACKed.
		b.ackPhase = acksProbeFeedback
	}
	if b.ackPhase == acksProbeStopping && b.roundStart {
		// End of samples from the bandwidth probe.
		b.ackPhase = acksInit
		b.bwProbeSamples = false
		if b.inProbeBW() && !rs.IsAppLimited {
			b.advanceMaxBwFilter()
		}
		// A probe that stopped at inflight_hi without high loss refills now.
		if b.inProbeBW() && b.stoppedRiskyProbe && !b.prevProbeTooHigh {
			b.enterRefill(now)
			return
		}
	}
	if b.inflightTooHigh(rs) {
		if b.probeTooHigh(rs) {
			b.handleInflightTooHigh(rs, now)
		}
		return
	}
	// The loss and ECN rate is safe. Increase the upper bound.
	if b.inflightHi == math.MaxInt64 {
		return
	}
	if rs.TxInflight > b.inflightHi {
		b.inflightHi = rs.TxInflight
	}
	if b.state == StateProbeBWUp {
		b.probeInflightHiUpward(rs)
	}
}

// isTimeToGoDown is BBRIsTimeToGoDown.
func (b *BBR) isTimeToGoDown(rs tcp.SimRateSample) bool {
	if b.prevProbeTooHigh && rs.InflightBytes >= b.inflightHi {
		b.stoppedRiskyProbe = true
		b.prevProbeTooHigh = false
		return true
	}
	if rs.IsCwndLimited && b.cwnd >= b.inflightHi {
		// inflight_hi limits the bandwidth. This plateau does not fill the pipe.
		b.resetFullBW()
		b.fullBw = rs.DeliveryRateBps
		return false
	}
	if b.fullBwNow {
		b.prevProbeTooHigh = false
		return true
	}
	return false
}

// raiseInflightHiSlope is BBRRaiseInflightLongtermSlope. The growth doubles each UP round.
func (b *BBR) raiseInflightHiSlope() {
	growth := int64(1) << b.probeUpRounds // Packets per cwnd of ACKs.
	if b.probeUpRounds < 30 {
		b.probeUpRounds++
	}
	cnt := b.cwnd / growth
	if cnt < int64(b.s.MSS()) {
		cnt = int64(b.s.MSS())
	}
	b.probeUpCnt = cnt
}

// probeInflightHiUpward is BBRProbeInflightLongtermUpward.
// It grows inflight_hi only when cwnd is full and at inflight_hi.
func (b *BBR) probeInflightHiUpward(rs tcp.SimRateSample) {
	if b.inflightHi == math.MaxInt64 || b.inflightHi <= 0 {
		return
	}
	if !rs.IsCwndLimited || b.cwnd < b.inflightHi {
		return
	}
	b.probeUpAcks += rs.AckedBytes
	if b.probeUpAcks >= b.probeUpCnt {
		delta := b.probeUpAcks / b.probeUpCnt
		b.probeUpAcks -= delta * b.probeUpCnt
		b.inflightHi += delta * int64(b.s.MSS())
	}
	if b.roundStart {
		b.raiseInflightHiSlope()
	}
}

// adaptLowerBounds cuts the short-term bounds one time per loss round. It does not run during a probe.
func (b *BBR) adaptLowerBounds() {
	// Startup, REFILL and UP are probes (bbr_is_probing_bandwidth).
	if b.isProbingBandwidth() {
		return
	}
	ecnCut := b.ecnEligible && b.ecnAlpha > 0 && b.ecnInRound
	ecnInflightLo := int64(math.MaxInt64)

	// ECN cuts only inflight_lo. Loss and ECN cuts do not add.
	if ecnCut {
		if b.inflightLo == math.MaxInt64 {
			b.inflightLo = int64(b.s.CwndPkts()) * int64(b.s.MSS())
		}
		scale := 1 - float64(b.ecnAlpha*ecnFactor)
		ecnInflightLo = int64(float64(b.inflightLo) * scale)
	}

	if b.lossInRound {
		if b.bwLo == math.MaxInt64 {
			b.bwLo = b.maxBw()
		}
		latest := b.bwLatest
		cut := fixedMulFloor(b.bwLo, betaNumerator)
		if latest > cut {
			b.bwLo = latest
		} else {
			b.bwLo = cut
		}
		if b.inflightLo == math.MaxInt64 {
			b.inflightLo = int64(b.s.CwndPkts()) * int64(b.s.MSS())
		}
		latestIn := b.inflightLatest
		cutIn := fixedMulFloor(b.inflightLo, betaNumerator)
		if latestIn > cutIn {
			b.inflightLo = latestIn
		} else {
			b.inflightLo = cutIn
		}
	}
	if ecnInflightLo < b.inflightLo {
		b.inflightLo = ecnInflightLo
	}
}

func (b *BBR) boundLower() {
	// The floor of bw_lo is 1, as in the reference.
	if b.bwLo != math.MaxInt64 && b.bwLo < 1 {
		b.bwLo = 1
	}
}

// Outputs.

func (b *BBR) pacingGain() float64 {
	switch b.state {
	case StateStartup:
		return startupPacingGain
	case StateDrain:
		return drainPacingGain
	case StateProbeBWDown:
		return probeDownGain
	case StateProbeBWUp:
		return probeUpGain
	default:
		return cruiseGain
	}
}

func (b *BBR) cwndGain() float64 {
	switch b.state {
	case StateStartup, StateDrain:
		return startupCwndGain
	case StateProbeRTT:
		return probeRTTCwndGain
	case StateProbeBWUp:
		return probeUpCwndGain
	default:
		return probeBWCwndGain
	}
}

func (b *BBR) setPacing() {
	b.setPacingWithGain(b.pacingGain())
}

func (b *BBR) setPacingWithGain(gain float64) {
	bw := b.bw()
	if bw <= 0 {
		return
	}
	rate := int64(gain * float64(bw) * (1 - pacingMargin))
	if rate < 8000 {
		rate = 8000
	}
	// Until the pipe is full, the pacing rate only increases (bbr_set_pacing_rate).
	if !b.filledPipe && rate < b.pacingBps {
		return
	}
	b.pacingBps = rate
	b.s.SetPacingRateBps(rate)
}

func (b *BBR) inflightWithHeadroom() int64 {
	if b.inflightHi == math.MaxInt64 {
		return math.MaxInt64
	}
	// Subtract the truncated 38/256 cut, as the reference does.
	return b.inflightHi - fixedMulFloor(b.inflightHi, headroomCutNumerator)
}

func (b *BBR) probeRTTCwndBytes() int64 {
	c := b.bdpBytes(probeRTTCwndGain)
	if min := int64(4 * b.s.MSS()); c < min {
		c = min
	}
	return c
}

// maxInflightBytes is BBR.max_inflight: cwnd_gain * BDP plus extra_acked, then the quantization budget.
func (b *BBR) maxInflightBytes() int64 {
	inflight := b.bdpBytes(b.cwndGain()) + b.ackAggregationCwnd()
	return b.quantizationBudget(inflight)
}

// setCwnd is BBRSetCwnd. cwnd grows by the ACKed data, and the model caps it after the pipe is full.
func (b *BBR) setCwnd() {
	acked := b.lastSample.AckedBytes
	maxInflight := b.maxInflightBytes()
	if b.filledPipe {
		b.cwnd += acked
		if b.cwnd > maxInflight {
			b.cwnd = maxInflight
		}
	} else if b.cwnd < maxInflight || b.lastSample.Delivered < b.initialCwnd {
		b.cwnd += acked
	}
	b.applyCwnd()
}

// applyCwnd applies the floors and caps of BBRBoundCwndForProbeRTT and BBRBoundCwndForModel.
func (b *BBR) applyCwnd() {
	mss := int64(b.s.MSS())
	minPipe := 4 * mss
	if b.cwnd < minPipe {
		b.cwnd = minPipe
	}
	if b.state == StateProbeRTT {
		if c := b.probeRTTCwndBytes(); b.cwnd > c {
			b.cwnd = c
		}
	}
	// Caps: inflight_hi in DOWN, REFILL and UP, with headroom in CRUISE and ProbeRTT, and inflight_lo.
	bound := int64(math.MaxInt64)
	switch b.state {
	case StateProbeBWDown, StateProbeBWRefill, StateProbeBWUp:
		bound = b.inflightHi
	case StateProbeBWCruise, StateProbeRTT:
		bound = b.inflightWithHeadroom()
	}
	if b.inflightLo < bound {
		bound = b.inflightLo
	}
	if bound < minPipe {
		bound = minPipe
	}
	if b.cwnd > bound {
		b.cwnd = bound
	}
	b.s.SetCwndPkts(int(b.cwnd / mss))
}
