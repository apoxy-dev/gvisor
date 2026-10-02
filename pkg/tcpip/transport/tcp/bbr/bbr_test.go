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

package bbr

import (
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// fakeSender drives BBR without netstack.
type fakeSender struct {
	now             time.Duration
	mss             int
	cwnd            int
	ssthresh        int
	pacing          int64
	inflight        int64
	srtt            time.Duration
	ecnLow          bool
	recovery        bool
	appLimitedMarks int
}

func (f *fakeSender) MSS() int                 { return f.mss }
func (f *fakeSender) CwndPkts() int            { return f.cwnd }
func (f *fakeSender) SetCwndPkts(c int)        { f.cwnd = c }
func (f *fakeSender) SetPacingRateBps(r int64) { f.pacing = r }
func (f *fakeSender) SRTT() time.Duration      { return f.srtt }
func (f *fakeSender) Now() time.Duration       { return f.now }
func (f *fakeSender) InRecovery() bool         { return f.recovery }
func (f *fakeSender) LocalPort() uint16        { return 40001 }
func (f *fakeSender) SetSsthresh(v int)        { f.ssthresh = v }
func (f *fakeSender) Seed() uint64             { return 42 }
func (f *fakeSender) ECNLowLatency() bool      { return f.ecnLow }
func (f *fakeSender) MarkAppLimited()          { f.appLimitedMarks++ }

const mss = 1448

// stateName returns the name of a state.
func stateName(s int) string {
	switch s {
	case StateStartup:
		return "Startup"
	case StateDrain:
		return "Drain"
	case StateProbeBWDown:
		return "ProbeBW:DOWN"
	case StateProbeBWCruise:
		return "ProbeBW:CRUISE"
	case StateProbeBWRefill:
		return "ProbeBW:REFILL"
	case StateProbeBWUp:
		return "ProbeBW:UP"
	case StateProbeRTT:
		return "ProbeRTT"
	}
	return "?"
}

// trace sends the ACK samples of a steady flow at rateBps and rtt for dur.
func trace(b *BBR, f *fakeSender, rateBps int64, rtt time.Duration, dur time.Duration) {
	step := 10 * time.Millisecond
	bytesPerStep := rateBps / 8 * int64(step) / int64(time.Second)
	for elapsed := time.Duration(0); elapsed < dur; elapsed += step {
		f.now += step
		f.inflight = rateBps / 8 * int64(rtt) / int64(time.Second)
		delivered := b.lastSample.Delivered + bytesPerStep
		// The ACKed data was sent one RTT ago, when delivered was one inflight lower.
		prior := delivered - f.inflight
		if prior < 0 {
			prior = 0
		}
		b.OnAck(tcp.SimRateSample{
			Now:             f.now,
			AckedBytes:      bytesPerStep,
			Delivered:       delivered,
			DeliveredBytes:  delivered - prior,
			PriorDelivered:  prior,
			DeliveryRateBps: rateBps,
			RTT:             rtt,
			Interval:        step,
			InflightBytes:   f.inflight,
		})
	}
}

func newTestBBR() (*BBR, *fakeSender) {
	f := &fakeSender{mss: mss, cwnd: 10, srtt: 40 * time.Millisecond}
	return New(f), f
}

func TestStartupExitOnPlateau(t *testing.T) {
	b, f := newTestBBR()
	rtt := 40 * time.Millisecond
	// Growing bandwidth: stays in Startup.
	rate := int64(10e6)
	for i := 0; i < 6; i++ {
		trace(b, f, rate, rtt, rtt)
		rate = rate * 2
	}
	if b.state != StateStartup {
		t.Fatalf("left Startup during growth (state=%s)", stateName(b.state))
	}
	// Plateau: less than 25% growth for 3 rounds. Expect Drain, then ProbeBW.
	for i := 0; i < 10; i++ {
		trace(b, f, rate, rtt, rtt)
	}
	if b.state == StateStartup || b.state == StateDrain {
		t.Fatalf("did not exit Startup after plateau (state=%s)", stateName(b.state))
	}
	if !b.filledPipe {
		t.Fatal("filledPipe not set")
	}
}

func TestInvalidRecoverySamplesDoNotAdvanceRound(t *testing.T) {
	b, f := newTestBBR()
	b.nextRoundDelivered = 10_000
	b.fullBw = 10e6
	b.fullBwCount = 2
	b.lastSample.Delivered = 20_000

	// Linux sets interval_us=-1 for a retransmission sample shorter than min_rtt.
	// The tcp package sends a zero Interval with the prior-delivered value.
	for i := 0; i < 4; i++ {
		f.now += time.Millisecond
		b.OnAck(tcp.SimRateSample{
			Now:             f.now,
			AckedBytes:      mss,
			Delivered:       b.lastSample.Delivered + mss,
			DeliveredBytes:  mss,
			PriorDelivered:  20_000 + int64(i*mss),
			DeliveryRateBps: 0,
			Interval:        0,
		})
	}

	if b.roundStart {
		t.Fatal("invalid retransmission sample started a packet-timed round")
	}
	if b.roundCount != 0 {
		t.Fatalf("invalid retransmission samples advanced %d rounds, want 0", b.roundCount)
	}
	if b.fullBwCount != 2 || b.filledPipe {
		t.Fatalf("invalid samples changed full-bw detector: count=%d filled=%v, want 2/false",
			b.fullBwCount, b.filledPipe)
	}
}

func TestMaxBwFilterWindow(t *testing.T) {
	b, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(b, f, 100e6, rtt, 500*time.Millisecond)
	if got := b.maxBw(); got < 95e6 {
		t.Fatalf("maxBw %.1f Mbps, want ~100", float64(got)/1e6)
	}
	// Close the high-rate cycle, then collect a low-rate cycle.
	// The high-rate cycle stays in the filter until the low-rate cycle closes.
	b.advanceMaxBwFilter()
	trace(b, f, 20e6, rtt, 100*time.Millisecond)
	if got := b.maxBw(); got < 95e6 {
		t.Fatalf("one advance should retain the old bucket (got %.1f)", float64(got)/1e6)
	}
	b.advanceMaxBwFilter()
	trace(b, f, 20e6, rtt, 100*time.Millisecond)
	if got := b.maxBw(); got > 25e6 {
		t.Fatalf("stale bandwidth survived two advances: %.1f Mbps", float64(got)/1e6)
	}
}

func TestRTOInstallsLiveOnePacketCwndAndRestores(t *testing.T) {
	b, f := newTestBBR()
	b.state = StateProbeBWCruise
	b.cwnd = 20 * int64(mss)
	f.cwnd = 20
	b.bwLo = 50e6
	f.recovery = true // gVisor enters RTORecovery before this call.

	b.HandleRTOExpired()
	if f.cwnd != 1 || b.cwnd != int64(mss) {
		t.Fatalf("RTO cwnd live/private = %d/%d bytes, want 1 packet/%d bytes", f.cwnd, b.cwnd, mss)
	}
	if b.bwLo != 50e6 {
		t.Fatalf("RTO cleared bw_lo: got %d, want 50Mbps retained", b.bwLo)
	}
	if want := 20 * int64(mss); b.inflightLo != want {
		t.Fatalf("RTO inflight_lo = %d, want prior cwnd %d", b.inflightLo, want)
	}

	f.recovery = false
	b.PostRecovery()
	if f.cwnd != 20 {
		t.Fatalf("RTO exit restored cwnd %d packets, want 20", f.cwnd)
	}
}

func TestSpuriousRecoveryUndoRestoresModel(t *testing.T) {
	b, f := newTestBBR()
	b.state = StateProbeBWCruise
	b.cwnd, f.cwnd = 20*int64(mss), 20
	b.bwLo, b.inflightLo, b.inflightHi = 80e6, 300_000, 400_000
	b.HandleLossDetected()

	b.bwLo, b.inflightLo, b.inflightHi = 40e6, 150_000, 200_000
	b.cwnd, f.cwnd = 5*int64(mss), 5
	b.UndoRecovery()
	if b.bwLo != 80e6 || b.inflightLo != 300_000 || b.inflightHi != 400_000 {
		t.Fatalf("undo bounds = %d/%d/%d, want 80000000/300000/400000",
			b.bwLo, b.inflightLo, b.inflightHi)
	}
	if f.cwnd != 20 {
		t.Fatalf("undo cwnd %d packets, want 20", f.cwnd)
	}
}

func TestMinRTTWindowExpiry(t *testing.T) {
	b, f := newTestBBR()
	// The RTT is 20 ms, then another flow increases it to 80 ms.
	trace(b, f, 50e6, 20*time.Millisecond, 300*time.Millisecond)
	if b.minRTT != 20*time.Millisecond {
		t.Fatalf("minRTT %v, want 20ms", b.minRTT)
	}
	trace(b, f, 50e6, 80*time.Millisecond, 11*time.Second)
	if b.minRTT < 70*time.Millisecond {
		t.Fatalf("stale min RTT %v survived the 10s window", b.minRTT)
	}
}

func TestProbeRTTScheduling(t *testing.T) {
	b, f := newTestBBR()
	rtt := 30 * time.Millisecond
	// Reach steady state.
	trace(b, f, 50e6, rtt, 2*time.Second)
	if b.state == StateStartup {
		t.Fatal("still in startup after 2s of steady samples")
	}
	// The min RTT does not decrease, so ProbeRTT must start after about 5 s.
	sawProbeRTT := false
	for i := 0; i < 60; i++ {
		trace(b, f, 50e6, rtt, 100*time.Millisecond)
		if b.state == StateProbeRTT {
			sawProbeRTT = true
			// Inflight drains below the ProbeRTT cap.
			f.inflight = 2 * mss
		}
	}
	if !sawProbeRTT {
		t.Fatal("no ProbeRTT within 6s")
	}
	// After the ProbeRTT hold at low inflight, the state must go back to ProbeBW.
	for i := 0; i < 50 && b.state == StateProbeRTT; i++ {
		f.now += 10 * time.Millisecond
		f.inflight = 2 * mss
		delivered := b.lastSample.Delivered + mss
		b.OnAck(tcp.SimRateSample{
			Now: f.now, AckedBytes: mss, Delivered: delivered,
			PriorDelivered:  delivered - f.inflight,
			DeliveryRateBps: 50e6, RTT: rtt, Interval: 10 * time.Millisecond,
			InflightBytes: f.inflight,
		})
	}
	if b.state == StateProbeRTT {
		t.Fatal("stuck in ProbeRTT")
	}
}

func TestLossResponseMath(t *testing.T) {
	b, f := newTestBBR()
	rtt := 30 * time.Millisecond
	trace(b, f, 80e6, rtt, 2*time.Second)
	if b.state == StateProbeBWRefill || b.state == StateProbeBWUp {
		trace(b, f, 80e6, rtt, time.Second)
	}
	pre := b.bw()
	// One loss round: delivery rate halves, ten segments marked lost.
	f.now += 10 * time.Millisecond
	b.OnAck(tcp.SimRateSample{
		Now: f.now, AckedBytes: mss, Delivered: b.lastSample.Delivered + mss,
		DeliveryRateBps: 40e6, RTT: rtt, Interval: 10 * time.Millisecond,
		InflightBytes: f.inflight, LostBytesCum: 10 * mss,
	})
	// Complete the round so adaptLowerBounds runs.
	trace(b, f, 40e6, rtt, 2*rtt)
	if b.bwLo == math.MaxInt64 {
		t.Fatal("bw_lo not set after loss round")
	}
	// bw_lo must respect the beta=0.7 floor against the latest rate.
	if b.bwLo < int64(0.69*float64(pre)) && b.bwLo < 40e6 {
		t.Fatalf("bw_lo %.1f cut below both beta*bw (%.1f) and latest (40)",
			float64(b.bwLo)/1e6, 0.7*float64(pre)/1e6)
	}
	if b.bw() > b.bwLo {
		t.Fatal("model bw not bounded by bw_lo")
	}
}

func TestPacingGainsPerState(t *testing.T) {
	b, _ := newTestBBR()
	cases := []struct {
		state int
		gain  float64
	}{
		{StateStartup, startupPacingGain},
		{StateDrain, drainPacingGain},
		{StateProbeBWDown, probeDownGain},
		{StateProbeBWCruise, 1.0},
		{StateProbeBWRefill, 1.0},
		{StateProbeBWUp, 1.25},
		{StateProbeRTT, 1.0},
	}
	for _, c := range cases {
		b.state = c.state
		if g := b.pacingGain(); math.Abs(g-c.gain) > 1e-9 {
			t.Errorf("state %s pacing gain %v, want %v", stateName(c.state), g, c.gain)
		}
	}
	b.state = StateProbeRTT
	if g := b.cwndGain(); g != probeRTTCwndGain {
		t.Errorf("ProbeRTT cwnd gain %v, want %v", g, probeRTTCwndGain)
	}
	// cwnd_gain is 2.25 in ProbeBW:UP and 2.0 in the other ProbeBW states.
	b.state = StateProbeBWUp
	if g := b.cwndGain(); g != probeUpCwndGain {
		t.Errorf("ProbeBW:UP cwnd gain %v, want %v", g, probeUpCwndGain)
	}
	b.state = StateProbeBWCruise
	if g := b.cwndGain(); g != probeBWCwndGain {
		t.Errorf("ProbeBW:CRUISE cwnd gain %v, want %v", g, probeBWCwndGain)
	}
}

func TestGoogleFixedPointConstants(t *testing.T) {
	cases := []struct {
		name      string
		got, want float64
	}{
		{"startup", startupPacingGain, 710.0 / 256.0},
		{"drain", drainPacingGain, 88.0 / 256.0},
		{"down", probeDownGain, 232.0 / 256.0},
		{"loss multiplier", beta, 180.0 / 256.0},
		{"loss threshold", lossThresh, 5.0 / 256.0},
		{"usable headroom", headroom, 218.0 / 256.0},
		{"ECN factor", ecnFactor, 85.0 / 256.0},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s=%v, want exact fixed-point value %v", c.name, c.got, c.want)
		}
	}

	// The reference subtracts floor(38*v/256). Here that gives 219, and floor(218*v/256) gives 218.
	b, _ := newTestBBR()
	b.inflightHi = 257
	if got := b.inflightWithHeadroom(); got != 219 {
		t.Errorf("fixed-point headroom(257)=%d, want 219", got)
	}
	if got := fixedMulFloor(257, lossThreshNumerator); got != 5 {
		t.Errorf("fixed-point loss threshold(257)=%d, want 5", got)
	}
}

func TestAckAggregationAndQuantizationBudget(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeBWCruise
	b.maxBwFilter[0] = 100e6
	b.minRTT = 40 * time.Millisecond
	b.cwnd = 400 * int64(mss)
	f.cwnd = 400

	// At 100 Mbps, 10 ms is 125000 expected bytes. 200000 bytes in the epoch
	// plus 50000 ACKed bytes gives 125000 bytes of aggregation.
	b.ackEpochStart = 0
	b.ackEpochAcked = 200_000
	f.now = 10 * time.Millisecond
	b.updateAckAggregation(tcp.SimRateSample{
		Now: f.now, AckedBytes: 50_000, PriorDelivered: 1, Interval: 10 * time.Millisecond,
	})
	if got := b.maxExtraAcked(); got != 125_000 {
		t.Fatalf("extra_acked=%d, want 125000", got)
	}

	b.extraAcked = [2]int64{}
	withoutAggregation := b.maxInflightBytes()
	b.extraAcked[0] = 10 * int64(mss)
	withAggregation := b.maxInflightBytes()
	if got := withAggregation - withoutAggregation; got != 10*int64(mss) {
		t.Fatalf("ACK aggregation raised max_inflight by %d, want %d", got, 10*mss)
	}

	base := 100 * int64(mss)
	b.state = StateProbeBWCruise
	if got := b.quantizationBudget(base); got != base {
		t.Fatalf("CRUISE quantization=%d, want unchanged %d", got, base)
	}
	b.state = StateProbeBWUp
	if got := b.quantizationBudget(base); got != base+2*int64(mss) {
		t.Fatalf("UP quantization=%d, want base+2MSS=%d", got, base+2*int64(mss))
	}

	b.state = StateProbeBWCruise
	b.minRTT = 13 * time.Millisecond
	if got := b.bdpBytesAt(1, 7e6); got != 8*int64(mss) {
		t.Fatalf("rounded BDP=%d, want 8 packets=%d", got, 8*mss)
	}
}

func TestIdleRestartResetsEpochAndUsesCruisePacing(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeBWUp
	b.maxBwFilter[0] = 100e6
	b.ackEpochStart = time.Second
	b.ackEpochAcked = 12345
	f.now = 5 * time.Second

	b.HandleRestartFromIdle()
	if !b.idleRestart {
		t.Fatal("idleRestart not latched")
	}
	if b.ackEpochStart != f.now || b.ackEpochAcked != 0 {
		t.Fatalf("ACK epoch not reset: start=%v acked=%d", b.ackEpochStart, b.ackEpochAcked)
	}
	wantPacing := int64(float64(100e6) * (1 - pacingMargin))
	if f.pacing != wantPacing {
		t.Fatalf("idle restart pacing=%d, want gain-1 pacing %d", f.pacing, wantPacing)
	}

	// The first delivered sample sees idleRestart set. Then idleRestart clears.
	f.now += 10 * time.Millisecond
	b.OnAck(tcp.SimRateSample{
		Now: f.now, AckedBytes: mss, Delivered: mss, DeliveredBytes: mss,
		PriorDelivered: 0, DeliveryRateBps: 100e6, RTT: 40 * time.Millisecond,
		Interval: 10 * time.Millisecond,
	})
	if b.idleRestart {
		t.Fatal("idleRestart survived the first delivered ACK")
	}
}

func TestIdleRestartCanCompleteProbeRTTBeforeTransmit(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeRTT
	b.maxBwFilter[0] = 100e6
	b.cwnd = 4 * int64(mss)
	b.priorCwnd = 30 * int64(mss)
	f.cwnd = 4
	f.now = time.Second
	b.probeRTTDone = f.now - time.Millisecond

	b.HandleRestartFromIdle()
	if b.state != StateProbeBWCruise {
		t.Fatalf("idle restart left state=%s, want ProbeBW:CRUISE", stateName(b.state))
	}
	if f.cwnd != 30 {
		t.Fatalf("idle ProbeRTT exit restored cwnd=%d, want 30", f.cwnd)
	}
}

func TestIdleRestartRefreshesExpiredProbeRTTWindow(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeBWCruise
	b.maxBwFilter[0] = 100e6
	b.minRTT = 30 * time.Millisecond
	b.probeRTTMin = 30 * time.Millisecond
	b.minRTTTime = 0
	b.probeRTTMinTime = 0
	b.cycleStart = 6 * time.Second
	b.probeWait = time.Hour
	b.roundsSinceProbe = -1 << 30
	b.idleRestart = true
	f.now = 6 * time.Second

	b.OnAck(tcp.SimRateSample{
		Now: f.now, AckedBytes: mss, Delivered: mss, DeliveredBytes: mss,
		PriorDelivered: 0, DeliveryRateBps: 100e6, RTT: 35 * time.Millisecond,
		Interval: 10 * time.Millisecond,
	})
	if b.state == StateProbeRTT {
		t.Fatal("idle restart entered ProbeRTT instead of using the naturally drained RTT sample")
	}
	if b.probeRTTMin != 35*time.Millisecond || b.probeRTTMinTime != f.now {
		t.Fatalf("probe_rtt_min refresh=%v at %v, want 35ms at %v",
			b.probeRTTMin, b.probeRTTMinTime, f.now)
	}
	if b.idleRestart {
		t.Fatal("idle restart latch did not clear after delivered ACK")
	}
}

func TestInflightTooHighAbortsProbe(t *testing.T) {
	b, f := newTestBBR()
	rtt := 30 * time.Millisecond
	trace(b, f, 80e6, rtt, 3*time.Second)
	// Force UP with a sample that lost more than 2% of its transmit-time inflight.
	b.enter(StateProbeBWUp, f.now)
	// As REFILL entry sets it. Move the probe mark back, so that this sample is from the probe.
	b.bwProbeSamples, b.probeStartDelivered = true, 0
	f.now += 10 * time.Millisecond
	b.OnAck(tcp.SimRateSample{
		Now: f.now, AckedBytes: mss, Delivered: b.lastSample.Delivered + mss,
		DeliveryRateBps: 80e6, RTT: rtt, Interval: 10 * time.Millisecond,
		InflightBytes: f.inflight,
		TxInflight:    f.inflight, LostBytes: int64(0.1 * float64(f.inflight)),
	})
	if b.state == StateProbeBWUp {
		t.Fatal("PROBE_UP survived loss above the 2% threshold")
	}
	if b.inflightHi == math.MaxInt64 {
		t.Fatal("inflight_hi not capped after loss abort")
	}
}

func TestRiskyProbeStopsAtPriorInflightHiAndReprobes(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeBWUp
	b.inflightHi = 100_000
	b.prevProbeTooHigh = true
	rs := tcp.SimRateSample{InflightBytes: 100_000}
	if !b.isTimeToGoDown(rs) {
		t.Fatal("probe did not stop at inflight_hi learned from prior excessive feedback")
	}
	if !b.stoppedRiskyProbe || b.prevProbeTooHigh {
		t.Fatalf("risky-probe flags stopped/previous = %v/%v, want true/false",
			b.stoppedRiskyProbe, b.prevProbeTooHigh)
	}

	b.startProbeBWDown(f.now)
	b.roundStart = true
	b.ackPhase = acksProbeStopping
	b.adaptLongTermModel(tcp.SimRateSample{DeliveryRateBps: 50e6}, f.now)
	if b.state != StateProbeBWRefill {
		t.Fatalf("safe stopped probe entered %s, want immediate REFILL", stateName(b.state))
	}
}

func BenchmarkOnAck(b *testing.B) {
	bbr, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(bbr, f, 1e9, rtt, time.Second)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		bbr.OnAck(steadySample(bbr, f, 1e9, rtt, 10*time.Microsecond))
	}
}
