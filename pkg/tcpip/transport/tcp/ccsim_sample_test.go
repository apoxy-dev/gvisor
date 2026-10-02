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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// sampleSender is a sender with a rateSim and a manual clock. It sends and ACKs segments without a peer.
type sampleSender struct {
	t     *testing.T
	s     *sender
	clock *faketime.ManualClock
	sim   *rateSim
}

func newSampleSender(t *testing.T, recovery tcpip.TCPRecovery) *sampleSender {
	sim := &rateSim{}
	s, clock := newClockSender(t, 0, sim)
	s.ep.mu.Lock()
	s.writeList.set = map[*segment]struct{}{}
	s.ep.tcpRecovery = recovery
	s.SndCwnd = 100
	s.ep.mu.Unlock()
	t.Cleanup(func() {
		s.ep.mu.Lock()
		defer s.ep.mu.Unlock()
		s.ccsimPurge()
		for seg := s.writeList.Front(); seg != nil; seg = s.writeList.Front() {
			s.writeList.Remove(seg)
			seg.DecRef()
		}
	})
	return &sampleSender{t: t, s: s, clock: clock, sim: sim}
}

// send sends one segment of n bytes.
//
// +checklocks:ss.s.ep.mu
func (ss *sampleSender) send(n int) *segment {
	s := ss.s
	seg := newOutgoingSegment(stack.TransportEndpointID{}, ss.clock, buffer.MakeWithData(make([]byte, n)))
	seg.sequenceNumber = s.SndNxt
	seg.flags = header.TCPFlagAck
	s.writeList.PushBack(seg)
	seg.xmitTime = ss.clock.NowMonotonic()
	s.ccsimOnTransmit(seg)
	seg.xmitCount++
	s.SndNxt = s.SndNxt.Add(seqnum.Size(n))
	s.Outstanding += s.pCount(seg, s.MaxPayloadSize)
	return seg
}

// ack ACKs the data before ack and returns the rate sample, as handleRcvdSegment does.
//
// +checklocks:ss.s.ep.mu
func (ss *sampleSender) ack(ack seqnum.Value) SimRateSample {
	s := ss.s
	r := &segment{ackNumber: ack}
	s.ccsimPreAck(r)
	for seg := s.writeList.Front(); seg != nil && seg.sequenceNumber.LessThan(ack); seg = s.writeList.Front() {
		if end := seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize())); ack.LessThan(end) {
			left := seg.sequenceNumber.Size(ack)
			s.Outstanding -= s.pCount(seg, s.MaxPayloadSize)
			seg.TrimFront(left)
			seg.sequenceNumber.UpdateForward(left)
			s.Outstanding += s.pCount(seg, s.MaxPayloadSize)
			break
		}
		s.Outstanding -= s.pCount(seg, s.MaxPayloadSize)
		s.writeList.Remove(seg)
		seg.DecRef()
	}
	s.SndUna = ack
	n := len(ss.sim.samples)
	s.ccsimOnAck(r)
	if len(ss.sim.samples) != n+1 {
		ss.t.Fatalf("ACK of %v gave %d samples, want 1", ack, len(ss.sim.samples)-n)
	}
	return ss.sim.samples[n]
}

// The suffix of a split keeps the rate state of the segment.
func TestSplitKeepsRateState(t *testing.T) {
	ss := newSampleSender(t, 0)
	ss.s.ep.mu.Lock()
	defer ss.s.ep.mu.Unlock()
	ss.s.ccsim.delivered = 1 << 20
	ss.s.ccsim.lostCum = 50_000
	seg := ss.send(3 * testMSS)
	ss.clock.Advance(20 * time.Millisecond)
	ss.s.splitSeg(seg, testMSS)
	suffix := seg.Next()
	got := suffix.ccsim
	want := seg.ccsim
	if got == nil {
		t.Fatal("suffix has no ccsim state")
	}
	if got.delivered != want.delivered || got.deliveredTime != want.deliveredTime || got.firstSent != want.firstSent ||
		got.lostAtTx != want.lostAtTx || got.txInflight != want.txInflight || got.appLimited != want.appLimited {
		t.Errorf("suffix rate state %+v, want the state of the segment %+v", got, want)
	}
	if rs := ss.ack(ss.s.SndNxt); rs.PriorDelivered != 1<<20 || rs.LostBytes != 0 {
		t.Errorf("sample from the suffix: PriorDelivered %d, LostBytes %d; want %d, 0", rs.PriorDelivered, rs.LostBytes, 1<<20)
	}
}

// Partial ACKs of a large segment count in delivered and leave the RACK pipe.
func TestPartialAckDelivered(t *testing.T) {
	ss := newSampleSender(t, tcpip.TCPRACKLossDetection)
	ss.s.ep.mu.Lock()
	defer ss.s.ep.mu.Unlock()
	ss.send(3 * testMSS)
	for i := 1; i <= 3; i++ {
		ss.clock.Advance(time.Millisecond)
		rs := ss.ack(seqnum.Value(i * testMSS))
		if rs.AckedBytes != testMSS {
			t.Errorf("ACK %d: AckedBytes %d, want %d", i, rs.AckedBytes, testMSS)
		}
		if got, want := ss.s.ccsim.delivered, int64(i*testMSS); got != want {
			t.Errorf("ACK %d: delivered %d, want %d", i, got, want)
		}
		if got, want := ss.s.ccsim.rackPipe, 3-i; got != want {
			t.Errorf("ACK %d: rackPipe %d, want %d", i, got, want)
		}
	}
}

// Like Linux FLAG_ACK_MAYBE_DELAYED, only an ACK of one lone runt can be a delayed ACK.
func TestAckDelayed(t *testing.T) {
	cases := []struct {
		name  string
		sizes []int // Segments to send and ACK.
		// otherDelivery is data delivered between the send and the ACK.
		otherDelivery int64
		sacked        bool
		want          bool
	}{
		{name: "lone runt", sizes: []int{100}, want: true},
		{name: "one full segment", sizes: []int{testMSS}},
		{name: "two full segments", sizes: []int{testMSS, testMSS}},
		{name: "two runts", sizes: []int{100, 100}},
		{name: "runt after other delivery", sizes: []int{100}, otherDelivery: testMSS},
		{name: "runt with SACKed data", sizes: []int{100}, sacked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ss := newSampleSender(t, 0)
			ss.s.ep.mu.Lock()
			defer ss.s.ep.mu.Unlock()
			for _, n := range tc.sizes {
				ss.send(n)
			}
			if tc.sacked {
				ss.s.ep.SACKPermitted = true
				ss.s.ep.scoreboard = NewSACKScoreboard(testMSS, 0)
				ss.s.ep.scoreboard.Insert(header.SACKBlock{Start: ss.s.SndNxt.Add(testMSS), End: ss.s.SndNxt.Add(2 * testMSS)})
			}
			ss.s.ccsim.delivered += tc.otherDelivery
			ss.clock.Advance(10 * time.Millisecond)
			if rs := ss.ack(ss.s.SndNxt); rs.IsAckDelayed != tc.want {
				t.Errorf("IsAckDelayed = %t, want %t", rs.IsAckDelayed, tc.want)
			}
		})
	}
}

// The rate of a large delivery in a long interval does not overflow.
func TestDeliveryRateLarge(t *testing.T) {
	ss := newSampleSender(t, 0)
	ss.s.ep.mu.Lock()
	defer ss.s.ep.mu.Unlock()
	ss.send(testMSS)
	// The sample covers 4 GiB in 1 s, as if other segments were delivered in the interval.
	ss.s.ccsim.delivered += 4<<30 - testMSS
	ss.clock.Advance(time.Second)
	rs := ss.ack(ss.s.SndNxt)
	if want := int64(4<<30) * 8; rs.DeliveryRateBps != want {
		t.Errorf("DeliveryRateBps = %d, want %d", rs.DeliveryRateBps, want)
	}
}

// A segment counts in lostCum only with the bytes that were not delivered, as Linux tcp_mark_skb_lost
// skips SACKed data. After an RTO, a delivered segment can be sent and marked lost again.
func TestLostCount(t *testing.T) {
	cases := []struct {
		name string
		rto  bool
		// pipe is set if the SACK scoreboard marks the segment lost, without RACK.
		pipe    bool
		counted bool
		sacked  int
		want    int64
	}{
		{name: "RACK loss", want: testMSS},
		{name: "RACK loss of a partly SACKed segment", sacked: 400, want: testMSS - 400},
		{name: "RACK loss of a delivered segment", counted: true},
		{name: "RTO", rto: true, want: testMSS},
		{name: "RTO with a partly SACKed segment", rto: true, sacked: 400, want: testMSS - 400},
		{name: "RTO with a delivered segment", rto: true, counted: true},
		{name: "scoreboard loss", pipe: true, want: testMSS},
		{name: "scoreboard loss of a partly SACKed segment", pipe: true, sacked: 400, want: testMSS - 400},
		{name: "scoreboard loss of a delivered segment", pipe: true, counted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recovery := tcpip.TCPRACKLossDetection
			if tc.pipe {
				recovery = 0
			}
			ss := newSampleSender(t, recovery)
			s := ss.s
			s.ep.mu.Lock()
			defer s.ep.mu.Unlock()
			seg := ss.send(testMSS)
			seg.ccsim.counted, seg.ccsim.sacked = tc.counted, tc.sacked
			switch {
			case tc.rto:
				s.ccsimMarkAllLost()
			case tc.pipe:
				// The peer SACKs the three segments after seg.
				for range nDupAckThreshold {
					ss.send(testMSS)
				}
				s.ep.SACKPermitted = true
				s.ep.scoreboard = NewSACKScoreboard(testMSS, 0)
				s.ep.scoreboard.Insert(header.SACKBlock{Start: seg.sequenceNumber.Add(testMSS), End: s.SndNxt})
				s.FastRecovery.Active = true
				s.SetPipe()
			default:
				seg.lost = true
				s.ccsimMarkSegmentLost(seg)
			}
			if got := s.ccsim.lostCum; got != tc.want {
				t.Errorf("lostCum %d, want %d", got, tc.want)
			}
		})
	}
}

// Like Linux tcp_rate_check_app_limited, the flow is app-limited with less than one MSS to send,
// free cwnd and no lost segment that waits for a repair. An empty pipe is also app-limited.
func TestMarkAppLimited(t *testing.T) {
	cases := []struct {
		name     string
		noRACK   bool
		inFlight int
		cwnd     int
		// lost marks the first segment lost with RACK.
		lost bool
		// resendPending is set if pacing holds the first repair.
		resendPending bool
		// sacked is the number of segments at the tail that SACK recovery has in the scoreboard.
		sacked int
		// repaired is the number of segments at the head that SACK recovery sent again.
		repaired int
		want     bool
	}{
		{name: "empty pipe", cwnd: 10, want: true},
		{name: "data in flight", inFlight: 2, cwnd: 10, want: true},
		{name: "cwnd full", inFlight: 2, cwnd: 2},
		{name: "lost segment waits for a repair", inFlight: 2, lost: true, cwnd: 10},
		{name: "without RACK, pacing holds the first repair", noRACK: true, inFlight: 2, resendPending: true, cwnd: 10},
		{name: "without RACK, lost segment waits for a repair", noRACK: true, inFlight: 6, sacked: 4, repaired: 1, cwnd: 10},
		{name: "without RACK, lost segments are repaired", noRACK: true, inFlight: 6, sacked: 4, repaired: 2, cwnd: 10, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recovery := tcpip.TCPRACKLossDetection
			if tc.noRACK {
				recovery = 0
			}
			ss := newSampleSender(t, recovery)
			s := ss.s
			s.ep.mu.Lock()
			defer s.ep.mu.Unlock()
			var segs []*segment
			for i := 0; i < tc.inFlight; i++ {
				segs = append(segs, ss.send(testMSS))
			}
			if tc.lost {
				segs[0].lost = true
				s.ccsimMarkSegmentLost(segs[0])
				s.Outstanding--
			}
			if tc.sacked > 0 {
				s.ep.SACKPermitted = true
				s.ep.scoreboard = NewSACKScoreboard(testMSS, 0)
				s.ep.scoreboard.Insert(header.SACKBlock{Start: segs[tc.inFlight-tc.sacked].sequenceNumber, End: s.SndNxt})
				s.FastRecovery.Active = true
				s.FastRecovery.HighRxt = segs[tc.repaired].sequenceNumber - 1
				s.SetPipe()
			}
			s.ccsim.recoveryResendPending = tc.resendPending
			s.SndCwnd = tc.cwnd
			s.ccsimMarkAppLimited()
			if got := s.ccsim.appLimited; got != tc.want {
				t.Errorf("appLimited = %t, want %t", got, tc.want)
			}
		})
	}
}
