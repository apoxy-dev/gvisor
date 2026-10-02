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

// Conformance tests: scripted rate samples check the model against draft-ietf-ccwg-bbr-03.
// The tests log the measured and the expected values.

import (
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// steadySample builds one steady-state rate sample and advances fake time.
func steadySample(b *BBR, f *fakeSender, rateBps int64, rtt, step time.Duration) tcp.SimRateSample {
	f.now += step
	f.inflight = rateBps / 8 * int64(rtt) / int64(time.Second)
	delivered := b.lastSample.Delivered + rateBps/8*int64(step)/int64(time.Second)
	prior := delivered - f.inflight
	if prior < 0 {
		prior = 0
	}
	return tcp.SimRateSample{
		Now:             f.now,
		AckedBytes:      rateBps / 8 * int64(step) / int64(time.Second),
		Delivered:       delivered,
		DeliveredBytes:  delivered - prior,
		PriorDelivered:  prior,
		DeliveryRateBps: rateBps,
		RTT:             rtt,
		Interval:        step,
		InflightBytes:   f.inflight,
	}
}

// Filter windows.

// The max-bw filter holds the current and the previous ProbeBW cycle.
// Time alone does not remove a sample. Only the end of the next probe cycle does.
func TestMaxBwFilterDecayTiming(t *testing.T) {
	b, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(b, f, 100e6, rtt, 4*time.Second) // Reach ProbeBW with a full model.
	if b.state == StateStartup || b.state == StateDrain {
		t.Fatalf("not in ProbeBW after 4s (state=%s)", stateName(b.state))
	}
	// Close the high-rate cycle, stay in CRUISE, and move the probe timer far out.
	b.advanceMaxBwFilter()
	b.enter(StateProbeBWCruise, f.now)
	b.ackPhase = acksInit
	b.cycleStart = f.now
	b.probeWait = time.Hour
	b.roundsSinceProbe = -1 << 30 // Stop the Reno-rounds trigger.
	b.probeRTTMinTime = f.now     // Stop ProbeRTT.

	stepStart := f.now
	for elapsed := time.Duration(0); elapsed < 1500*time.Millisecond; elapsed += 10 * time.Millisecond {
		b.OnAck(steadySample(b, f, 20e6, rtt, 10*time.Millisecond))
	}
	if got := b.maxBw(); got < 95e6 {
		t.Fatalf("wall clock evicted prior probe-cycle sample after %v: %.1f Mbps", f.now-stepStart, float64(got)/1e6)
	}
	b.advanceMaxBwFilter()
	if got := b.maxBw(); got > 25e6 {
		t.Errorf("old bandwidth survived low-rate probe-cycle turnover: %.1f Mbps", float64(got)/1e6)
	}
	t.Logf("held 100Mbps for %v without a cycle boundary; decayed to %.1fMbps at explicit turnover",
		f.now-stepStart, float64(b.maxBw())/1e6)
}

// A 5 s minimum RTT schedules ProbeRTT and a 10 s minimum is the path model.
// The end of the 5 s filter must not remove the 10 s model.
func TestSeparateProbeRTTAndMinRTTWindows(t *testing.T) {
	b, f := newTestBBR()
	f.now = 10 * time.Millisecond
	b.updateMinRTT(tcp.SimRateSample{Now: f.now, RTT: 20 * time.Millisecond})
	if b.minRTT != 20*time.Millisecond {
		t.Fatalf("minRTT %v after low sample, want 20ms", b.minRTT)
	}
	lowTime := b.minRTTTime

	f.now = lowTime + probeRTTInterval + time.Millisecond
	b.updateMinRTT(tcp.SimRateSample{Now: f.now, RTT: 80 * time.Millisecond})
	if !b.probeRTTExpired {
		t.Fatal("five-second probe_rtt_min window did not expire")
	}
	if b.probeRTTMin != 80*time.Millisecond {
		t.Fatalf("probeRTTMin=%v after refresh, want 80ms", b.probeRTTMin)
	}
	if b.minRTT != 20*time.Millisecond {
		t.Fatalf("five-second scheduler expiry replaced ten-second minRTT with %v", b.minRTT)
	}

	f.now = lowTime + minRTTFilterLen + time.Millisecond
	b.updateMinRTT(tcp.SimRateSample{Now: f.now, RTT: 80 * time.Millisecond})
	if b.minRTT != 80*time.Millisecond {
		t.Fatalf("expired ten-second minRTT=%v, want current probeRTTMin 80ms", b.minRTT)
	}
	t.Logf("probe scheduler refreshed at 5s; path-model minimum held for 10s")
}

// ProbeBW cycle order and timing.

func TestProbeBWCycleSequence(t *testing.T) {
	b, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(b, f, 100e6, rtt, 3*time.Second)

	// Record the state sequence over 20 s of steady ProbeBW.
	var seq []int
	var times []time.Duration
	last := -1
	refillEnter, upEnter := time.Duration(0), time.Duration(0)
	var probeWaitDur []time.Duration
	var refillRounds []int64
	for elapsed := time.Duration(0); elapsed < 20*time.Second; elapsed += 5 * time.Millisecond {
		b.OnAck(steadySample(b, f, 100e6, rtt, 5*time.Millisecond))
		if b.state != last {
			seq = append(seq, b.state)
			times = append(times, f.now)
			switch b.state {
			case StateProbeBWRefill:
				refillEnter = f.now
				if b.cycleStart != 0 {
					probeWaitDur = append(probeWaitDur, f.now-b.cycleStart)
				}
			case StateProbeBWUp:
				upEnter = f.now
				_ = upEnter
				if refillEnter != 0 {
					refillRounds = append(refillRounds, int64((f.now-refillEnter)/rtt))
				}
			}
			last = b.state
		}
	}

	// Check the order DOWN, CRUISE, REFILL, UP, DOWN.
	// At 1 BDP of steady inflight, DOWN goes to CRUISE, not to REFILL.
	next := map[int]int{
		StateProbeBWDown:   StateProbeBWCruise,
		StateProbeBWCruise: StateProbeBWRefill,
		StateProbeBWRefill: StateProbeBWUp,
		StateProbeBWUp:     StateProbeBWDown,
	}
	names := ""
	for _, s := range seq {
		names += stateName(s) + " "
	}
	t.Logf("state sequence: %s", names)
	for i := 0; i+1 < len(seq); i++ {
		cur, nxt := seq[i], seq[i+1]
		if cur == StateStartup || cur == StateDrain || nxt == StateProbeRTT || cur == StateProbeRTT {
			continue // Other tests check the entry path and ProbeRTT.
		}
		if want := next[cur]; nxt != want {
			t.Errorf("transition %s -> %s at t=%v, want -> %s",
				stateName(cur), stateName(nxt), times[i+1], stateName(want))
		}
	}

	// The probe clock starts at DOWN entry. The interval is 2-3 s or the Reno-rounds bound,
	// whichever is first. At this BDP, the Reno-rounds bound is about 1.24-1.26 s.
	for _, d := range probeWaitDur {
		t.Logf("DOWN-entry to REFILL %v (probe interval; wall range 2-3s, Reno-rounds bound about 1.25s)", d)
		if d < 1150*time.Millisecond || d > 3200*time.Millisecond {
			t.Errorf("probe interval %v outside [1.15s, 3.2s]", d)
		}
	}
	// REFILL lasts one packet-timed round.
	for _, r := range refillRounds {
		t.Logf("refill lasted ~%d rounds", r)
		if r < 1 || r > 2 {
			t.Errorf("REFILL lasted ~%d rounds, want 1", r)
		}
	}
	if len(probeWaitDur) == 0 || len(refillRounds) == 0 {
		t.Fatal("did not observe complete probe cycles in 20s")
	}
}

// The pacing rate must be gain * bw * (1 - margin) in each phase.
func TestPacingRatePerPhaseExact(t *testing.T) {
	b, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(b, f, 100e6, rtt, 3*time.Second)
	gains := map[int]float64{
		StateProbeBWDown:   probeDownGain,
		StateProbeBWCruise: 1.0,
		StateProbeBWRefill: 1.0,
		StateProbeBWUp:     1.25,
	}
	for state, gain := range gains {
		// Set the phase and calculate the outputs directly, because OnAck can leave the phase.
		b.state = state
		b.setPacing()
		want := int64(gain * float64(b.bw()) * (1 - pacingMargin))
		if f.pacing != want {
			t.Errorf("%s: pacing %d, want %d (= %.2f * bw * 0.99)", stateName(state), f.pacing, want, gain)
		}
		t.Logf("%s: pacing %.2f Mbps = %.2f * bw(%.2f Mbps) * 0.99", stateName(state),
			float64(f.pacing)/1e6, gain, float64(b.bw())/1e6)
	}
	// The ProbeBW target includes measured ACK aggregation and the reference
	// quantization budget.
	b.state = StateProbeBWCruise
	b.inflightHi, b.inflightLo = math.MaxInt64, math.MaxInt64
	wantCwnd := int(b.maxInflightBytes() / int64(mss))
	b.setCwnd()
	if f.cwnd != wantCwnd {
		t.Errorf("ProbeBW cwnd %d pkts, want max_inflight %d", f.cwnd, wantCwnd)
	}
}

// Loss response.

// betaCut applies the fixed point beta of the reference.
func betaCut(v int64) int64 { return fixedMulFloor(v, betaNumerator) }

func ecnCut(v int64) int64 { return int64((1 - ecnFactor) * float64(v)) }

func TestLossResponseTable(t *testing.T) {
	const maxI = int64(math.MaxInt64)
	cases := []struct {
		name    string
		state   int
		bwLo    int64 // Before.
		inflLo  int64
		latest  int64 // bwLatest of this round.
		latestI int64 // inflightLatest of this round.
		loss    bool
		wantBw  int64 // After.
		wantIn  int64
	}{
		{
			// First loss: bw_lo starts at max_bw, then is cut to max(latest, beta*bw_lo).
			// inflight_lo starts at the 10-packet cwnd (bbr_init_lower_bounds), then is cut by beta.
			name: "first-loss-beta-cut", state: StateProbeBWCruise,
			bwLo: maxI, inflLo: maxI, latest: 40e6, latestI: 1_000, loss: true,
			wantBw: betaCut(100e6), wantIn: betaCut(10 * int64(mss)),
		},
		{
			// Latest is above the beta floor: bw_lo is latest, with no deeper cut.
			name: "latest-dominates", state: StateProbeBWCruise,
			bwLo: 80e6, inflLo: 200_000, latest: 75e6, latestI: 190_000, loss: true,
			wantBw: 75e6, wantIn: 190_000,
		},
		{
			// Bounds that are set are cut by beta again.
			name: "latched-compounds", state: StateProbeBWCruise,
			bwLo: 50e6, inflLo: 150_000, latest: 10e6, latestI: 10_000, loss: true,
			wantBw: betaCut(50e6), wantIn: betaCut(150_000),
		},
		{
			// No cut in REFILL.
			name: "no-cut-in-refill", state: StateProbeBWRefill,
			bwLo: 50e6, inflLo: 150_000, latest: 10e6, latestI: 10_000, loss: true,
			wantBw: 50e6, wantIn: 150_000,
		},
		{
			// No loss in the round: no cut.
			name: "no-loss-no-cut", state: StateProbeBWCruise,
			bwLo: 50e6, inflLo: 150_000, latest: 10e6, latestI: 10_000, loss: false,
			wantBw: 50e6, wantIn: 150_000,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, _ := newTestBBR()
			// Fixed model: max_bw 100 Mbps, min_rtt 20ms -> BDP 250000 B.
			b.maxBwFilter[0] = 100e6
			b.minRTT = 20 * time.Millisecond
			b.state = c.state
			b.bwLo, b.inflightLo = c.bwLo, c.inflLo
			b.bwLatest, b.inflightLatest = c.latest, c.latestI
			b.lossInRound = c.loss
			b.adaptLowerBounds()
			if b.bwLo != c.wantBw {
				t.Errorf("bw_lo = %d, want %d", b.bwLo, c.wantBw)
			}
			if b.inflightLo != c.wantIn {
				t.Errorf("inflight_lo = %d, want %d", b.inflightLo, c.wantIn)
			}
			t.Logf("bw_lo %d -> %d, inflight_lo %d -> %d", c.bwLo, b.bwLo, c.inflLo, b.inflightLo)
		})
	}
}

// Loss above 2% in UP stops the probe and sets inflight_hi from the transmit-time inflight,
// with a floor of beta*BDP.
func TestProbeAbortSetsInflightHi(t *testing.T) {
	b, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(b, f, 100e6, rtt, 3*time.Second)
	b.enter(StateProbeBWUp, f.now)
	// As REFILL entry sets it. Move the probe mark back, so that this sample is from the probe.
	b.bwProbeSamples, b.probeStartDelivered = true, 0
	s := steadySample(b, f, 100e6, rtt, 10*time.Millisecond)
	s.TxInflight = f.inflight
	s.LostBytes = int64(0.03 * float64(f.inflight)) // 3% is above the 2% threshold.
	b.OnAck(s)
	if b.state == StateProbeBWUp {
		t.Fatal("UP survived 3% loss")
	}
	if b.state != StateProbeBWDown {
		t.Errorf("probe abort entered %s, want ProbeBW:DOWN", stateName(b.state))
	}
	target := b.targetInflightBytes()
	wantHi := fixedMulFloor(target, betaNumerator)
	if f.inflight > wantHi {
		wantHi = f.inflight
	}
	if b.inflightHi != wantHi {
		t.Errorf("inflight_hi = %d, want %d (max(inflight, beta*BDP))", b.inflightHi, wantHi)
	}
	t.Logf("inflight_hi latched at %d (inflight=%d, beta*BDP=%d)",
		b.inflightHi, f.inflight, fixedMulFloor(target, betaNumerator))
}

// An app-limited sample with high loss does not lower inflight_hi, but it uses
// the feedback of the probe, marks the probe as risky and leaves UP.
func TestAppLimitedHighLossStopsProbeWithoutCut(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeBWUp
	b.minRTT = 20 * time.Millisecond
	b.maxBwFilter[0] = 100e6
	b.inflightHi = 300_000
	b.bwProbeSamples = true
	b.probeStartDelivered = 0
	b.lastSample.Delivered = 100_000
	s := tcp.SimRateSample{
		Now:             f.now,
		AckedBytes:      mss,
		Delivered:       101_448,
		DeliveredBytes:  mss,
		PriorDelivered:  50_000,
		DeliveryRateBps: 50e6,
		TxInflight:      200_000,
		LostBytes:       10_000,
		IsAppLimited:    true,
	}
	b.adaptLongTermModel(s, f.now)
	if b.state != StateProbeBWDown || !b.prevProbeTooHigh || b.bwProbeSamples {
		t.Fatalf("app-limited high loss did not stop/consume probe: state=%s risky=%v samples=%v",
			stateName(b.state), b.prevProbeTooHigh, b.bwProbeSamples)
	}
	if b.inflightHi != 300_000 {
		t.Fatalf("app-limited high loss cut inflight_hi to %d, want unchanged 300000", b.inflightHi)
	}
}

// ECN response.

// Alpha is the EWMA alpha' = (1-g)*alpha + g*ce_frac with g = 1/16, one time per round.
func TestECNAlphaEWMA(t *testing.T) {
	b, f := newTestBBR()
	rtt := 4 * time.Millisecond
	f.ecnLow = true
	trace(b, f, 50e6, rtt, time.Second)
	if !b.ecnEligible {
		t.Fatal("shallow precise-ECN route with 4ms min_rtt did not become eligible")
	}

	// One round with a known CE fraction, closed by one sample.
	// Check alpha' with the same float order as the code.
	alpha0 := b.ecnAlpha
	b.ackedBytesRound, b.ceBytesRound = 900, 400
	closing := steadySample(b, f, 50e6, rtt, 10*time.Millisecond)
	closing.AckedBytes = 100
	closing.ECE = true // 400+100 CE of 900+100 acked -> ce_frac 0.5
	closing.Delivered = b.lastSample.Delivered + 100
	closing.PriorDelivered = b.nextRoundDelivered // Force the end of a round.
	b.OnAck(closing)
	const ceFrac = 0.5
	want := float64((1-ecnAlphaGain)*alpha0) + float64(ecnAlphaGain*ceFrac)
	if math.Abs(b.ecnAlpha-want) > 1e-12 {
		t.Errorf("alpha after round = %.6f, want %.6f = (1-1/16)*%.6f + (1/16)*%.2f",
			b.ecnAlpha, want, alpha0, ceFrac)
	}
	t.Logf("alpha %.4f -> %.4f (ce_frac %.2f, gain 1/16, predicted %.4f)", alpha0, b.ecnAlpha, ceFrac, want)

	// More high-CE rounds move alpha nearer to the fraction.
	prev := b.ecnAlpha
	for r := 0; r < 3; r++ {
		b.ackedBytesRound, b.ceBytesRound = 900, 400
		s := steadySample(b, f, 50e6, rtt, 10*time.Millisecond)
		s.AckedBytes, s.ECE = 100, true
		s.Delivered = b.lastSample.Delivered + 100
		s.PriorDelivered = b.nextRoundDelivered
		b.OnAck(s)
		if b.ecnAlpha <= prev || b.ecnAlpha > ceFrac {
			t.Errorf("round %d: alpha %.4f not converging monotonically toward %.2f (prev %.4f)",
				r, b.ecnAlpha, ceFrac, prev)
		}
		prev = b.ecnAlpha
	}
	t.Logf("alpha converging: %.4f after 4 half-CE rounds", b.ecnAlpha)
}

// bbr_reset_congestion_signals resets the loss round, but ECN alpha uses the packet-timed round.
// A ProbeBW transition must not cut the alpha interval.
func TestCongestionResetPreservesECNAlphaRound(t *testing.T) {
	b, _ := newTestBBR()
	b.lossInRound, b.ecnInRound = true, true
	b.lossEventsRound, b.lostBytesRound = 3, 12_000
	b.bwLatest, b.inflightLatest = 50e6, 100_000
	b.ackedBytesRound, b.ceBytesRound = 10_000, 4_000
	b.resetCongestionSignals()
	if b.lossInRound || b.ecnInRound || b.lossEventsRound != 0 ||
		b.lostBytesRound != 0 || b.bwLatest != 0 || b.inflightLatest != 0 {
		t.Fatal("loss-round congestion signals survived reset")
	}
	if b.ackedBytesRound != 10_000 || b.ceBytesRound != 4_000 {
		t.Fatalf("ECN alpha round was truncated: acked=%d ce=%d",
			b.ackedBytesRound, b.ceBytesRound)
	}
}

func TestECNEligibilityAndSampleThreshold(t *testing.T) {
	cases := []struct {
		name string
		low  bool
		rtt  time.Duration
		want bool
	}{
		{"ordinary-ecn", false, 4 * time.Millisecond, false},
		{"rtt-too-large", true, 20 * time.Millisecond, false},
		{"shallow-low-rtt", true, 4 * time.Millisecond, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, f := newTestBBR()
			f.ecnLow, b.minRTT, b.roundStart = c.low, c.rtt, true
			b.updateLossECN(tcp.SimRateSample{AckedBytes: 100, ECE: true})
			if b.ecnEligible != c.want {
				t.Fatalf("ecnEligible=%v, want %v", b.ecnEligible, c.want)
			}
		})
	}
	b, _ := newTestBBR()
	b.ecnEligible = true
	if !b.ecnTooHigh(tcp.SimRateSample{DeliveredBytes: 1000, DeliveredCEBytes: 501}) {
		t.Fatal("sample above 50% CE did not trip ECN gate")
	}
	if b.ecnTooHigh(tcp.SimRateSample{DeliveredBytes: 1000, DeliveredCEBytes: 500}) {
		t.Fatal("sample exactly at 50% CE tripped strict threshold")
	}
}

// ECN cuts only inflight_lo. With loss and ECN together, the lower of the two cuts applies.
// The cuts do not add, and ECN does not cut bw_lo.
func TestECNAndLossIndependentLowerBounds(t *testing.T) {
	b, _ := newTestBBR()
	b.state = StateProbeBWCruise
	b.ecnEligible = true
	b.ecnAlpha = 1
	b.lossInRound = true
	b.bwLatest = 10e6
	b.inflightLatest = 10_000
	b.ecnInRound = true
	b.ceBytesRound, b.ackedBytesRound = 500, 1000
	b.bwLo, b.inflightLo = 100e6, 300_000
	b.adaptLowerBounds()
	wantBw := betaCut(100e6)
	wantIn := ecnCut(300_000)
	if b.bwLo != wantBw {
		t.Errorf("bw_lo = %d, want loss-only cut %d", b.bwLo, wantBw)
	}
	if b.inflightLo != wantIn {
		t.Errorf("inflight_lo = %d, want min(loss=%d, ecn=%d) = %d",
			b.inflightLo, betaCut(300_000), wantIn, wantIn)
	}
	t.Logf("loss+ECN: bw_lo=%d (loss only), inflight_lo=%d (min independent candidates)", b.bwLo, b.inflightLo)
}

// The lower bounds use a separate loss round. A loss in the middle of a round
// cuts the model only after data sent after the loss is ACKed.
func TestLowerBoundsWaitForIndependentLossRound(t *testing.T) {
	b, f := newTestBBR()
	b.filledPipe = true
	b.state = StateProbeBWCruise
	b.maxBwFilter[0] = 100e6
	b.minRTT = 20 * time.Millisecond
	b.minRTTTime = f.now
	b.probeWait = time.Hour
	b.roundsSinceProbe = -1 << 30
	b.nextRoundDelivered = math.MaxInt64 // The packet-timed round is not used here.
	b.lossRoundDelivered = 10_000
	b.bwLo, b.inflightLo = 100e6, 100_000

	ack := func(delivered, prior, rate, lostCum int64) {
		f.now += 10 * time.Millisecond
		b.OnAck(tcp.SimRateSample{
			Now:             f.now,
			AckedBytes:      10_000,
			Delivered:       delivered,
			DeliveredBytes:  delivered - prior,
			PriorDelivered:  prior,
			DeliveryRateBps: rate,
			RTT:             20 * time.Millisecond,
			Interval:        10 * time.Millisecond,
			InflightBytes:   100_000,
			TxInflight:      100_000,
			LostBytesCum:    lostCum,
		})
	}

	// The first mark moves the loss-round marker to C.delivered=20,000.
	ack(20_000, 9_000, 80e6, mss)
	ack(30_000, 19_999, 70e6, mss)
	if b.bwLo != 100e6 || b.inflightLo != 100_000 {
		t.Fatalf("bounds cut before a full post-loss flight: bw_lo=%d inflight_lo=%d", b.bwLo, b.inflightLo)
	}

	// This sample was sent at the loss marker, so it ends the loss round.
	// The 80 Mbps rate floor is above beta*100 Mbps.
	ack(40_000, 20_000, 60e6, mss)
	if b.bwLo != 80e6 {
		t.Fatalf("bw_lo=%d after loss round, want latest delivery floor 80000000", b.bwLo)
	}
	if b.inflightLo != betaCut(100_000) {
		t.Fatalf("inflight_lo=%d after loss round, want beta cut %d", b.inflightLo, betaCut(100_000))
	}
	t.Logf("loss at delivered=20000: held bounds for a full flight, then cut to %.1fMbps/%dB",
		float64(b.bwLo)/1e6, b.inflightLo)
}

// Startup exit.

// TestStartupExitOnPlateau checks the plateau exit. These tests check the gains,
// the loss exit and the exit during growth.
func TestStartupGainsAndDrain(t *testing.T) {
	b, f := newTestBBR()
	rtt := 40 * time.Millisecond
	rate := int64(20e6)
	trace(b, f, rate, rtt, 2*rtt)
	if b.state != StateStartup {
		t.Fatalf("left startup too early")
	}
	// Startup gain 710/256 and cwnd gain 2.0.
	wantPacing := int64(startupPacingGain * float64(b.bw()) * (1 - pacingMargin))
	if f.pacing != wantPacing {
		t.Errorf("startup pacing %d, want %d (710/256 * bw * 0.99)", f.pacing, wantPacing)
	}
	// Before the pipe is full, cwnd grows by the ACKed data and the model does not cut it.
	// extra_acked can move the target on the same ACK, so cwnd is within one ACK of max_inflight.
	target := int(b.maxInflightBytes() / int64(mss))
	ackPkts := int(rate/8*int64(10*time.Millisecond)/int64(time.Second))/mss + 1
	if f.cwnd < target-ackPkts || f.cwnd > target+ackPkts {
		t.Errorf("startup cwnd %d, want within one ACK of max_inflight [%d, %d]",
			f.cwnd, target-ackPkts, target+ackPkts)
	}
	// Force the plateau exit. Drain uses the gain 88/256.
	for i := 0; i < 12 && b.state == StateStartup; i++ {
		trace(b, f, rate, rtt, rtt)
	}
	if b.state == StateDrain {
		wantDrain := int64(drainPacingGain * float64(b.bw()) * (1 - pacingMargin))
		if f.pacing != wantDrain {
			t.Errorf("drain pacing %d, want %d (88/256 * bw * 0.99)", f.pacing, wantDrain)
		}
		t.Logf("drain pacing %.2f Mbps = 88/256 * bw(%.2f) * 0.99", float64(f.pacing)/1e6, float64(b.bw())/1e6)
	} else {
		// Drain can end in one OnAck when inflight is 1 BDP. ProbeBW is then correct.
		t.Logf("drain completed inline (state=%s); inflight already <= BDP", stateName(b.state))
	}
}

func TestStartupExitOnLoss(t *testing.T) {
	b, f := newTestBBR()
	rtt := 40 * time.Millisecond
	trace(b, f, 20e6, rtt, 2*rtt) // Start a round.
	if b.state != StateStartup {
		t.Fatal("left startup prematurely")
	}
	// A round with fullLossCount or more loss events, closed by a sample
	// that lost more than 2% of its transmit-time inflight.
	b.lossInRound = true
	b.lossEventsRound = fullLossCount
	f.recovery = true
	s := steadySample(b, f, 20e6, rtt, rtt)
	s.TxInflight = f.inflight
	s.LostBytes = int64(0.05 * float64(f.inflight))
	b.OnAck(s)
	if b.state == StateStartup {
		t.Fatalf("startup survived %d loss events at 5%% lost bytes", fullLossCount)
	}
	if b.inflightHi == math.MaxInt64 {
		t.Fatal("loss-based startup exit did not initialize inflight_hi")
	}
	wantFloor := b.inflightBytesAt(1.0, b.maxBw())
	if b.inflightHi < wantFloor || b.inflightHi < b.inflightLatest {
		t.Fatalf("startup inflight_hi=%d below model/latest floors %d/%d",
			b.inflightHi, wantFloor, b.inflightLatest)
	}
	t.Logf("loss-based startup exit -> %s with inflight_hi=%d", stateName(b.state), b.inflightHi)
}

// One loss in Startup must not set the short-term bounds or decrease pacing.
// Startup is a probe, and the pacing rate only increases until the pipe is full.
func TestStartupSingleLossKeepsRamping(t *testing.T) {
	b, f := newTestBBR()
	rtt := 40 * time.Millisecond
	rate := int64(10e6)
	var maxPacing int64
	for round := 0; round < 24 && b.state == StateStartup; round++ {
		trace(b, f, rate, rtt, rtt)
		if !b.filledPipe && f.pacing < maxPacing {
			t.Fatalf("round %d: pacing dropped %.2f -> %.2f Mbps before full pipe",
				round, float64(maxPacing)/1e6, float64(f.pacing)/1e6)
		}
		if f.pacing > maxPacing {
			maxPacing = f.pacing
		}
		if round == 2 {
			// One loss event in the ramp, just before the round ends.
			b.lossInRound = true
			b.lossEventsRound = 1
			b.lostBytesRound = int64(mss)
		}
		if round >= 3 && b.state == StateStartup {
			if b.bwLo != math.MaxInt64 {
				t.Fatalf("round %d: bw_lo engaged at %.2f Mbps by a single startup loss", round, float64(b.bwLo)/1e6)
			}
			if b.inflightLo != math.MaxInt64 {
				t.Fatalf("round %d: inflight_lo engaged (%d bytes) by a single startup loss", round, b.inflightLo)
			}
		}
		if rate < 100e6 {
			rate = rate * 13 / 10
			if rate > 100e6 {
				rate = 100e6
			}
		}
	}
	if b.state == StateStartup {
		t.Fatal("never exited startup on the 100 Mbps plateau")
	}
	if got := b.maxBw(); got < 90e6 {
		t.Errorf("startup exited with maxBw %.2f Mbps, want >= 90 (premature exit)", float64(got)/1e6)
	}
	t.Logf("startup exit -> %s at maxBw %.2f Mbps, peak pacing %.2f Mbps (loss at round 2 ignored)",
		stateName(b.state), float64(b.maxBw())/1e6, float64(maxPacing)/1e6)
}

// BBRSetCwnd grows cwnd by the ACKed data and decreases it to the target only after the pipe is full.
// On a low-BDP path, the first ACK must not cut cwnd to the 4-packet floor.
func TestCwndGrowByAckedControlLaw(t *testing.T) {
	b, f := newTestBBR()
	rate := int64(100e3) // 100 Kbps, 200 ms: BDP is about 1.7 packets, much less than IW.
	rtt := 200 * time.Millisecond

	b.OnAck(steadySample(b, f, rate, rtt, 10*time.Millisecond))
	if f.cwnd < 10 {
		t.Fatalf("first ACK cut cwnd to %d pkts (initial window 10): pre-full-pipe snap-down", f.cwnd)
	}
	t.Logf("first cold-model ACK: cwnd %d pkts (target would be %d pkts)",
		f.cwnd, int(b.maxInflightBytes()/int64(mss)))

	// Before the pipe is full, cwnd must never decrease.
	prev := f.cwnd
	steps := 0
	for i := 0; i < 500 && !b.filledPipe; i++ {
		b.OnAck(steadySample(b, f, rate, rtt, 10*time.Millisecond))
		if b.filledPipe {
			break // This ACK filled the pipe. A decrease is correct now.
		}
		if f.cwnd < prev {
			t.Fatalf("step %d: cwnd decreased %d -> %d pkts before full pipe", i, prev, f.cwnd)
		}
		prev = f.cwnd
		steps++
	}
	if !b.filledPipe {
		t.Fatal("100 Kbps plateau never declared the pipe full")
	}
	t.Logf("pipe full after %d steps with cwnd held at %d pkts (never below 10)", steps, prev)

	// After the pipe is full, the model target decreases cwnd.
	b.OnAck(steadySample(b, f, rate, rtt, 10*time.Millisecond))
	want := int(b.maxInflightBytes() / int64(mss))
	if want < 4 {
		want = 4
	}
	if f.cwnd != want {
		t.Errorf("post-full-pipe cwnd %d pkts, want snap to max_inflight %d", f.cwnd, want)
	}
	t.Logf("post-full-pipe snap: cwnd %d pkts (max_inflight %d pkts)", f.cwnd, want)
}

func TestStartupNoExitWhileGrowing(t *testing.T) {
	b, f := newTestBBR()
	rtt := 40 * time.Millisecond
	rate := int64(5e6)
	// 30% growth each round: no plateau.
	for i := 0; i < 10; i++ {
		trace(b, f, rate, rtt, rtt)
		rate = rate * 13 / 10
	}
	if b.state != StateStartup {
		t.Fatalf("exited startup during sustained 30%%/round growth (state=%s)", stateName(b.state))
	}
	if b.filledPipe {
		t.Fatal("filledPipe set during growth")
	}
	t.Logf("still in startup after 10 growing rounds (rate now %.1f Mbps)", float64(rate)/1e6)
}

// ProbeRTT.

func TestProbeRTTClampDurationAndRefresh(t *testing.T) {
	b, f := newTestBBR()
	rtt := 30 * time.Millisecond
	trace(b, f, 50e6, rtt, 2*time.Second)

	// Run until the ProbeRTT filter expires.
	scheduleTime := b.probeRTTMinTime
	entered := time.Duration(0)
	for elapsed := time.Duration(0); elapsed < 8*time.Second && entered == 0; elapsed += 10 * time.Millisecond {
		b.OnAck(steadySample(b, f, 50e6, rtt, 10*time.Millisecond))
		if b.state == StateProbeRTT {
			entered = f.now
		}
	}
	if entered == 0 {
		t.Fatal("no ProbeRTT entry within 8s of steady min_rtt")
	}
	staleness := entered - scheduleTime
	t.Logf("ProbeRTT entered with probe_rtt_min staleness %v (interval %v)", staleness, probeRTTInterval)
	if staleness < probeRTTInterval {
		t.Errorf("entered ProbeRTT at staleness %v, before the %v interval", staleness, probeRTTInterval)
	}

	// Drain inflight below the cap. Calculate the cap on each ACK, because
	// min_rtt can decrease during the hold.
	holdStart := time.Duration(0)
	var exitAt time.Duration
	lowRTT := rtt - 10*time.Millisecond
	sawRefresh := false
	for i := 0; i < 200 && b.state == StateProbeRTT; i++ {
		f.now += 10 * time.Millisecond
		f.inflight = 2 * mss
		delivered := b.lastSample.Delivered + mss
		s := tcp.SimRateSample{
			Now: f.now, AckedBytes: mss, Delivered: delivered,
			PriorDelivered:  delivered - f.inflight,
			DeliveryRateBps: 50e6, RTT: rtt, Interval: 10 * time.Millisecond,
			InflightBytes: f.inflight,
		}
		// In the hold, send one lower RTT sample. It must go into the filter.
		if holdStart != 0 && !sawRefresh {
			s.RTT = lowRTT
			sawRefresh = true
		}
		b.OnAck(s)
		if b.state == StateProbeRTT {
			wantPkts := int(b.probeRTTCwndBytes() / int64(mss))
			if wantPkts < 4 {
				wantPkts = 4
			}
			if f.cwnd != wantPkts {
				t.Fatalf("ProbeRTT cwnd %d pkts, want clamp %d (max(0.5*BDP, 4 MSS))", f.cwnd, wantPkts)
			}
		}
		if holdStart == 0 && b.probeRTTDone != 0 {
			holdStart = f.now
		}
	}
	exitAt = f.now
	if b.state == StateProbeRTT {
		t.Fatal("never exited ProbeRTT")
	}
	// Exit restores the cwnd from before ProbeRTT (BBRRestoreCwnd).
	clampPkts := int(b.probeRTTCwndBytes() / int64(mss))
	if f.cwnd < 2*clampPkts {
		t.Errorf("cwnd %d pkts after ProbeRTT exit, want restored well above the %d-pkt clamp", f.cwnd, clampPkts)
	}
	if holdStart == 0 {
		t.Fatal("hold never started (inflight below cap not detected)")
	}
	held := exitAt - holdStart
	t.Logf("held %v at reduced window (want >= %v + 1 round)", held, probeRTTDuration)
	if held < probeRTTDuration {
		t.Errorf("ProbeRTT hold %v shorter than the %v minimum", held, probeRTTDuration)
	}
	if b.minRTT != lowRTT {
		t.Errorf("lower RTT sample during ProbeRTT not absorbed: min_rtt %v, want %v", b.minRTT, lowRTT)
	}
	if f.appLimitedMarks == 0 {
		t.Fatal("ProbeRTT did not mark its low-rate samples application-limited")
	}
	// Exit schedules the next ProbeRTT and keeps the time of the 10 s min_rtt sample.
	if exitAt-b.probeRTTMinTime > 50*time.Millisecond {
		t.Errorf("probeRTTMinTime not refreshed at ProbeRTT exit (age %v)", exitAt-b.probeRTTMinTime)
	}
}

// App-limited samples.

// App-limited samples must not decrease the filter. As in bbr_update_bw,
// an app-limited sample above the max increases it.
func TestAppLimitedSamples(t *testing.T) {
	b, f := newTestBBR()
	rtt := 20 * time.Millisecond
	trace(b, f, 80e6, rtt, time.Second)
	base := b.maxBw()
	if base < 75e6 {
		t.Fatalf("model did not reach 80 Mbps (%.1f)", float64(base)/1e6)
	}

	// 1. Low app-limited samples do not change the filter.
	// Use only 0.5 s, so that the filter stays in the same cycle.
	for i := 0; i < 50; i++ {
		s := steadySample(b, f, 5e6, rtt, 10*time.Millisecond)
		s.IsAppLimited = true
		b.OnAck(s)
	}
	if got := b.maxBw(); got < base {
		t.Errorf("app-limited 5 Mbps samples lowered max_bw: %.1f -> %.1f Mbps",
			float64(base)/1e6, float64(got)/1e6)
	}
	t.Logf("after low app-limited: max_bw %.1f Mbps (was %.1f)", float64(b.maxBw())/1e6, float64(base)/1e6)

	// 2. A higher app-limited sample increases the filter.
	s := steadySample(b, f, 120e6, rtt, 10*time.Millisecond)
	s.IsAppLimited = true
	b.OnAck(s)
	if got := b.maxBw(); got < 120e6 {
		t.Errorf("app-limited sample above max did not raise the filter (got %.1f Mbps, reference raises)",
			float64(got)/1e6)
	}

	// 3. A higher sample that is not app-limited increases it more.
	s2 := steadySample(b, f, 150e6, rtt, 10*time.Millisecond)
	b.OnAck(s2)
	if got := b.maxBw(); got < 150e6 {
		t.Errorf("non-app-limited 150 Mbps sample did not raise the filter (got %.1f)", float64(got)/1e6)
	}
	t.Logf("filter raised: %.1f -> %.1f -> %.1f Mbps", float64(base)/1e6, 120.0, float64(b.maxBw())/1e6)
}
