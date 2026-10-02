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

package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const testMSS = 1000

// rateSim records the rate samples.
type rateSim struct{ samples []SimRateSample }

func (*rateSim) HandleLossDetected()       {}
func (*rateSim) HandleRTOExpired()         {}
func (*rateSim) Update(int, time.Duration) {}
func (*rateSim) PostRecovery()             {}
func (r *rateSim) OnAck(rs SimRateSample)  { r.samples = append(r.samples, rs) }

// newClockSender returns a sender with a manual clock that is 1 s after the start.
func newClockSender(t testing.TB, pacingBps int64, sim SimCC) (*sender, *faketime.ManualClock) {
	t.Helper()
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{Clock: clock})
	t.Cleanup(stk.Destroy)
	s := &sender{ep: &Endpoint{stack: stk}}
	s.MaxPayloadSize = testMSS
	s.ccsim = &ccsimSenderState{wrap: &ccsimWrapper{s: s, sim: sim, pacingBps: pacingBps}}
	s.ccsim.pacingTimer.init(clock, func() {})
	t.Cleanup(s.ccsim.pacingTimer.cleanup)
	clock.Advance(time.Second)
	return s, clock
}

func TestRateSampleInterval(t *testing.T) {
	type op struct {
		at   time.Duration // Time from the first op.
		send int           // Segments to send.
		ack  int           // Oldest segments to ACK.
	}
	cases := []struct {
		name          string
		ops           []op
		wantInterval  time.Duration
		wantDelivered int64
	}{
		{
			// The ACK phase is 1 ms. The send phase starts at the send of the newest ACKed segment.
			name:         "ack compression",
			ops:          []op{{at: 0, send: 1}, {at: 10 * time.Millisecond, send: 1}, {at: 20 * time.Millisecond, ack: 1}, {at: 20 * time.Millisecond, send: 1}, {at: 21 * time.Millisecond, ack: 2}},
			wantInterval: 20 * time.Millisecond, wantDelivered: 2 * testMSS,
		},
		{
			name:         "ack clock",
			ops:          []op{{at: 0, send: 1}, {at: 10 * time.Millisecond, send: 1}, {at: 20 * time.Millisecond, ack: 1}, {at: 20 * time.Millisecond, send: 1}, {at: 30 * time.Millisecond, ack: 1}, {at: 40 * time.Millisecond, ack: 1}},
			wantInterval: 20 * time.Millisecond, wantDelivered: 2 * testMSS,
		},
		{
			name:         "empty pipe starts new intervals",
			ops:          []op{{at: 0, send: 1}, {at: 20 * time.Millisecond, ack: 1}, {at: 50 * time.Millisecond, send: 2}, {at: 70 * time.Millisecond, ack: 2}},
			wantInterval: 20 * time.Millisecond, wantDelivered: 2 * testMSS,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sim := &rateSim{}
			s, clock := newClockSender(t, 0, sim)
			s.ep.mu.Lock()
			defer s.ep.mu.Unlock()
			start := clock.NowMonotonic()
			var inflight []*segment
			for _, o := range tc.ops {
				clock.Advance(start.Add(o.at).Sub(clock.NowMonotonic()))
				for i := 0; i < o.send; i++ {
					seg := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.MakeWithData(make([]byte, testMSS)))
					seg.sequenceNumber = s.SndNxt
					seg.xmitTime = clock.NowMonotonic()
					s.ccsimOnTransmit(seg)
					s.SndNxt = s.SndNxt.Add(testMSS)
					s.Outstanding++
					inflight = append(inflight, seg)
				}
				if o.ack == 0 {
					continue
				}
				s.ccsim.ackPending = true
				s.ccsim.scratchAcked = 0
				s.ccsim.scratchHasSample = false
				for _, seg := range inflight[:o.ack] {
					s.ccsimAckSegment(seg)
					s.SndUna = s.SndUna.Add(seqnum.Size(seg.payloadSize()))
					s.Outstanding--
					seg.DecRef()
				}
				inflight = inflight[o.ack:]
				s.ccsimOnAck(&segment{ackNumber: s.SndUna})
			}
			for _, seg := range inflight {
				seg.DecRef()
			}
			if len(sim.samples) == 0 {
				t.Fatal("no rate sample")
			}
			got := sim.samples[len(sim.samples)-1]
			if got.Interval != tc.wantInterval || got.DeliveredBytes != tc.wantDelivered {
				t.Errorf("last sample: interval %v, delivered %d; want %v, %d", got.Interval, got.DeliveredBytes, tc.wantInterval, tc.wantDelivered)
			}
		})
	}
}

func TestPacingGate(t *testing.T) {
	// At 100 Mbps, one quantum is 12500 bytes, or 13 segments. It takes 1 ms, or 1040 us for 13 segments.
	type step struct {
		advance time.Duration // Time to wait before the sends.
		want    int           // Segments that the gate permits.
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{name: "one quantum each wake", steps: []step{{want: 13}, {want: 0}, {advance: 40 * time.Microsecond, want: 13}, {advance: 1040 * time.Microsecond, want: 13}}},
		{name: "late timer keeps the rate", steps: []step{{want: 13}, {advance: 540 * time.Microsecond, want: 13}, {advance: 540 * time.Microsecond, want: 13}}},
		{name: "sender keeps at most one quantum", steps: []step{{want: 13}, {advance: 10 * time.Millisecond, want: 13}, {want: 0}, {advance: 40 * time.Microsecond, want: 13}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, clock := newClockSender(t, 100_000_000, nil)
			s.ep.mu.Lock()
			defer s.ep.mu.Unlock()
			for i, st := range tc.steps {
				clock.Advance(st.advance)
				got := 0
				for ; got < 1000 && s.ccsimPacingAllows(); got++ {
					s.ccsimPacingCharge(testMSS)
				}
				if got != st.want {
					t.Errorf("step %d: sent %d segments, want %d", i, got, st.want)
				}
			}
		})
	}
}

func BenchmarkPacingGate(b *testing.B) {
	s, clock := newClockSender(b, 1_000_000_000, nil)
	s.ep.mu.Lock()
	defer s.ep.mu.Unlock()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// 64 KB each ms is less than the rate, so the gate does not arm the timer.
		if i%64 == 0 {
			clock.Advance(time.Millisecond)
		}
		if s.ccsimPacingAllows() {
			s.ccsimPacingCharge(testMSS)
		}
	}
}
