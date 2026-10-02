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
	"reflect"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/internal/tcp"
)

// After a spurious RTO, the data in flight is not sent again. With an undo of
// cwnd, new data goes out.
func TestSpuriousRTOResponse(t *testing.T) {
	cases := []struct {
		cc string
		// wantNew is the count of new segments after the undo. Cubic keeps
		// the cwnd of the RTO, so it sends none.
		wantNew int
		// wantCwnd is the cwnd after the undo, or 0 for no check. Cubic
		// adds the ACKed segment to the cwnd of 1 of the RTO.
		wantCwnd int
	}{
		{cc: "cubic", wantNew: 0, wantCwnd: 2},
		{cc: "bbr", wantNew: 5},
	}
	for _, tc := range cases {
		t.Run(tc.cc, func(t *testing.T) {
			p := newSimPeerTS(t, tc.cc)
			mss := p.mss()
			// RACK reads a send time of zero as the time of the last delivery.
			p.clock.Advance(time.Millisecond)
			p.write(20 * mss)
			first := p.readAll()
			if len(first) < 2 {
				t.Fatalf("first flight %d segments, want 2 or more", len(first))
			}
			flight := len(first) * mss
			stats := p.ep.stack.Stats().TCP
			for i := 0; i < 100 && stats.Timeouts.Value() == 0; i++ {
				p.clock.Advance(50 * time.Millisecond)
				p.readAll()
			}
			if got := stats.Timeouts.Value(); got != 1 {
				t.Fatalf("timeouts %d, want 1", got)
			}
			p.write(5 * mss)
			p.readAll()
			retransmits := stats.Retransmits.Value()

			// The ACK of the first segment echoes its first send.
			p.ackEcr(mss, 65535, first[0].tsVal)
			var after []peerPkt
			for i := 0; i < 5; i++ {
				after = append(after, p.readAll()...)
				p.clock.Advance(time.Millisecond)
			}
			newSegs := 0
			for _, off := range p.offsets(after) {
				if off[0] < flight {
					t.Errorf("sent %v again after the spurious RTO", off)
				} else {
					newSegs++
				}
			}
			if newSegs != tc.wantNew {
				t.Errorf("sent %d new segments, want %d", newSegs, tc.wantNew)
			}
			if got := stats.SpuriousRTORecovery.Value(); got != 1 {
				t.Errorf("spurious RTO recoveries %d, want 1", got)
			}
			if got := stats.Retransmits.Value(); got != retransmits {
				t.Errorf("retransmits %d after the undo, want %d", got, retransmits)
			}
			p.ep.LockUser()
			defer p.ep.UnlockUser()
			s := p.ep.snd
			if s.state != tcpip.Open {
				t.Errorf("state %v, want Open", s.state)
			}
			if tc.wantCwnd != 0 && s.SndCwnd != tc.wantCwnd {
				t.Errorf("cwnd %d, want %d", s.SndCwnd, tc.wantCwnd)
			}
			if want := len(first) - 1 + newSegs; s.Outstanding != want {
				t.Errorf("outstanding %d, want %d", s.Outstanding, want)
			}
			if s.ccsim != nil && s.ccsim.rackPipe != s.Outstanding {
				t.Errorf("RACK pipe %d, want outstanding %d", s.ccsim.rackPipe, s.Outstanding)
			}
		})
	}
}

// Eifel detection needs a valid TSEcr from before the repair, as in Linux
// tcp_packet_delayed.
func TestSpuriousDetectionTimestamps(t *testing.T) {
	const (
		echoNone = iota
		echoZero
		echoOriginal
		echoRepair
	)
	cases := []struct {
		name string
		ts   bool
		echo int
		want uint64
	}{
		{name: "no timestamps", want: 0},
		{name: "TSEcr 0", ts: true, echo: echoZero, want: 0},
		{name: "TSEcr of the first send", ts: true, echo: echoOriginal, want: 1},
		{name: "TSEcr of the repair", ts: true, echo: echoRepair, want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeerWith(t, "bbr", false, tc.ts)
			// With a TS offset of 0, a TSEcr of 0 is older than the repair, so
			// only the TSEcr check stops the detection.
			p.ep.LockUser()
			p.ep.TSOffset = tcp.NewTSOffset(0)
			p.ep.UnlockUser()
			mss := p.mss()
			p.clock.Advance(time.Millisecond)
			p.write(mss)
			first := p.readAll()
			p.clock.Advance(time.Millisecond)
			p.write(9 * mss)
			p.readAll()
			p.clock.Advance(10 * time.Millisecond)
			sack := [2]int{2 * mss, 10 * mss}
			p.ack(0, 65535, sack)
			var repair *peerPkt
			for _, pk := range p.readAll() {
				if pk.seq == p.at(0) {
					repair = &pk
				}
			}
			if repair == nil {
				t.Fatal("no repair of the first segment")
			}
			p.clock.Advance(10 * time.Millisecond)
			switch tc.echo {
			case echoNone:
				p.ack(mss, 65535, sack)
			case echoZero:
				p.ackEcr(mss, 65535, 0, sack)
			case echoOriginal:
				p.ackEcr(mss, 65535, first[0].tsVal, sack)
			case echoRepair:
				p.ackEcr(mss, 65535, repair.tsVal, sack)
			}
			p.readAll()
			if got := p.ep.stack.Stats().TCP.SpuriousRecovery.Value(); got != tc.want {
				t.Errorf("spurious recoveries %d, want %d", got, tc.want)
			}
		})
	}
}

// SackedOut keeps the SACKed segments when recovery starts, and is 0 when all
// data is ACKed.
func TestSackedOutAcrossRecovery(t *testing.T) {
	cases := []struct {
		name string
		cc   string
		gso  bool
		// writes are sent one at a time, 1 ms apart.
		writes []int
		sacks  [][2]int
		// wantSacked is SackedOut in recovery.
		wantSacked int
		// rto is set if an RTO comes after the SACK. mss is a smaller MSS
		// after the RTO, or 0.
		rto bool
		mss int
	}{
		{name: "cubic", cc: "cubic", writes: []int{peerMSS, 9 * peerMSS}, sacks: [][2]int{{100, 1000}}, wantSacked: 9},
		{name: "fixedsim", cc: "fixedsim", writes: []int{peerMSS, 9 * peerMSS}, sacks: [][2]int{{100, 1000}}, wantSacked: 9},
		// The RTO clears the scoreboard, but the segments stay acked.
		{name: "RTO after the SACK", cc: "fixedsim", writes: []int{peerMSS, 9 * peerMSS}, sacks: [][2]int{{100, 1000}}, wantSacked: 9, rto: true},
		{name: "smaller MSS after an RTO", cc: "fixedsim", writes: []int{peerMSS, 9 * peerMSS}, sacks: [][2]int{{100, 1000}}, wantSacked: 9,
			rto: true, mss: peerMSS / 2},
		// A SACK of the head of a GSO segment marks all of it. Recovery
		// splits off the head and sends the rest again, so only the head
		// stays in SackedOut.
		{name: "SACKed head of a GSO segment", cc: "fixedsim", gso: true, writes: []int{100, 300, 100},
			sacks: [][2]int{{100, 200}, {400, 500}}, wantSacked: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, tc.cc, tc.gso)
			end := 0
			for _, n := range tc.writes {
				p.clock.Advance(time.Millisecond)
				p.write(n)
				p.readAll()
				end += n
			}
			p.clock.Advance(10 * time.Millisecond)
			p.ack(0, 65535, tc.sacks...)
			if len(p.readAll()) == 0 {
				t.Fatal("no repair after the SACK")
			}
			sacked := func() (int, tcpip.CongestionControlState) {
				p.ep.LockUser()
				defer p.ep.UnlockUser()
				return p.ep.snd.SackedOut, p.ep.snd.state
			}
			if got, state := sacked(); got != tc.wantSacked || state != tcpip.SACKRecovery {
				t.Errorf("in recovery: SackedOut %d state %v, want %d and SACKRecovery", got, state, tc.wantSacked)
			}
			if tc.rto {
				p.clock.Advance(5 * time.Second)
				p.readAll()
			}
			if tc.mss != 0 {
				p.ep.LockUser()
				p.ep.snd.updateMaxPayloadSize(header.TCPMinimumSize+p.ep.maxOptionSize()+tc.mss, 1)
				p.ep.UnlockUser()
				p.readAll()
			}
			p.ack(end, 65535)
			p.readAll()
			if got, _ := sacked(); got != 0 {
				t.Errorf("after the ACK of all data: SackedOut %d, want 0", got)
			}
		})
	}
}

// In RTO recovery, a RACK loss of data that was not sent again after the RTO
// does not start a new recovery, as in Linux. A lost retransmission does.
func TestRACKLossInRTORecovery(t *testing.T) {
	const (
		// sackAfterRTO is a duplicate ACK with a SACK of segments 4 to 9.
		sackAfterRTO = iota
		// ackAfterRTO is the ACK of the RTO retransmission and a SACK of
		// segments 4 to 9.
		ackAfterRTO
		// reorderTimer has reordering before the RTO, so the reorder timer
		// and not the ACK can mark segment 6 lost after a SACK of segment 7.
		reorderTimer
		// spuriousSACKFirst is a SACK of segments 1 to 4 and then the ACK of
		// segments 0 to 4 that echoes the first send of segment 0.
		spuriousSACKFirst
		// lostRetransmit loses the retransmission of segment 2.
		lostRetransmit
	)
	cases := []struct {
		name     string
		cc       string
		scenario int
		// wantState is the state at the end. SACKRecovery means one new
		// recovery, with a new ssthresh.
		wantState tcpip.CongestionControlState
	}{
		{name: "cubic SACK after the RTO", cc: "cubic", scenario: sackAfterRTO, wantState: tcpip.RTORecovery},
		{name: "reno SACK after the RTO", cc: "reno", scenario: sackAfterRTO, wantState: tcpip.RTORecovery},
		{name: "bbr SACK after the RTO", cc: "bbr", scenario: sackAfterRTO, wantState: tcpip.RTORecovery},
		{name: "cubic ACK after the RTO", cc: "cubic", scenario: ackAfterRTO, wantState: tcpip.RTORecovery},
		{name: "reno ACK after the RTO", cc: "reno", scenario: ackAfterRTO, wantState: tcpip.RTORecovery},
		{name: "cubic reorder timer", cc: "cubic", scenario: reorderTimer, wantState: tcpip.RTORecovery},
		{name: "reno reorder timer", cc: "reno", scenario: reorderTimer, wantState: tcpip.RTORecovery},
		{name: "cubic spurious RTO with a SACK first", cc: "cubic", scenario: spuriousSACKFirst, wantState: tcpip.Open},
		{name: "reno spurious RTO with a SACK first", cc: "reno", scenario: spuriousSACKFirst, wantState: tcpip.Open},
		{name: "bbr spurious RTO with a SACK first", cc: "bbr", scenario: spuriousSACKFirst, wantState: tcpip.Open},
		{name: "cubic lost retransmission", cc: "cubic", scenario: lostRetransmit, wantState: tcpip.SACKRecovery},
		{name: "reno lost retransmission", cc: "reno", scenario: lostRetransmit, wantState: tcpip.SACKRecovery},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newSimPeerTS(t, tc.cc)
			mss := p.mss()
			stats := p.ep.stack.Stats().TCP
			snd := func() (tcpip.CongestionControlState, int) {
				p.ep.LockUser()
				defer p.ep.UnlockUser()
				return p.ep.snd.state, p.ep.snd.Ssthresh
			}
			// o is the offset of the first of the 10 segments.
			o := 0
			if tc.scenario == reorderTimer {
				// An RTT of 20 ms gives a reorder window of 5 ms.
				p.clock.Advance(time.Millisecond)
				p.write(mss)
				p.readAll()
				p.clock.Advance(20 * time.Millisecond)
				p.ack(mss, 65535)
				p.readAll()
				o = mss
			}
			// Send 10 segments 1 ms apart, so that RACK orders them by time.
			for i := 0; i < 10; i++ {
				p.clock.Advance(time.Millisecond)
				p.write(mss)
			}
			first := p.readAll()
			if len(first) != 10 {
				t.Fatalf("first flight %d segments, want 10", len(first))
			}
			if tc.scenario == reorderTimer {
				// Segment 4 comes before segments 0 to 3, in the reorder window.
				p.clock.Advance(20 * time.Millisecond)
				p.ack(o, 65535, [2]int{o + 4*mss, o + 5*mss})
				p.ack(o+5*mss, 65535)
				p.readAll()
			}
			for i := 0; i < 100 && stats.Timeouts.Value() == 0; i++ {
				p.clock.Advance(250 * time.Millisecond)
				p.readAll()
			}
			if got := stats.Timeouts.Value(); got != 1 {
				t.Fatalf("timeouts %d, want 1", got)
			}
			_, ssthresh := snd()
			recoveries := stats.SACKRecovery.Value()
			var sent [][2]int
			switch tc.scenario {
			case sackAfterRTO:
				p.ack(0, 65535, [2]int{4 * mss, 10 * mss})
				p.readAll()
			case ackAfterRTO:
				p.clock.Advance(10 * time.Millisecond)
				p.ack(mss, 65535, [2]int{4 * mss, 10 * mss})
				sent = p.offsets(p.readAll())
				// Go-back-N sends the next 2 segments with a cwnd of 2.
				if want := [][2]int{{mss, 2 * mss}, {2 * mss, 3 * mss}}; !reflect.DeepEqual(sent, want) {
					t.Errorf("sent %v, want %v", sent, want)
				}
			case reorderTimer:
				p.clock.Advance(time.Millisecond)
				p.ack(o+5*mss, 65535, [2]int{o + 7*mss, o + 8*mss})
				p.readAll()
				p.clock.Advance(20 * time.Millisecond)
				p.readAll()
			case spuriousSACKFirst:
				p.ack(0, 65535, [2]int{mss, 5 * mss})
				p.readAll()
				retransmits := stats.Retransmits.Value()
				p.ackEcr(5*mss, 65535, first[0].tsVal)
				p.readAll()
				if got := stats.SpuriousRTORecovery.Value(); got != 1 {
					t.Errorf("spurious RTO recoveries %d, want 1", got)
				}
				if got := stats.Retransmits.Value(); got != retransmits {
					t.Errorf("retransmits %d after the undo, want %d", got, retransmits)
				}
			case lostRetransmit:
				// Segments 1 and 2 go out, then segments 3 and 4.
				p.clock.Advance(10 * time.Millisecond)
				p.ack(mss, 65535)
				p.readAll()
				p.clock.Advance(10 * time.Millisecond)
				p.ack(2*mss, 65535)
				p.readAll()
				p.clock.Advance(10 * time.Millisecond)
				p.ack(2*mss, 65535, [2]int{3 * mss, 4 * mss})
				sent = p.offsets(p.readAll())
				if len(sent) == 0 || sent[0] != [2]int{2 * mss, 3 * mss} {
					t.Errorf("sent %v, want segment 2 first", sent)
				}
			}
			state, gotSsthresh := snd()
			if state != tc.wantState {
				t.Errorf("state %v, want %v", state, tc.wantState)
			}
			wantRecoveries := recoveries
			if tc.wantState == tcpip.SACKRecovery {
				wantRecoveries++
			} else if gotSsthresh != ssthresh {
				t.Errorf("ssthresh %d, want %d of the RTO", gotSsthresh, ssthresh)
			}
			if got := stats.SACKRecovery.Value(); got != wantRecoveries {
				t.Errorf("SACK recoveries %d, want %d", got, wantRecoveries)
			}
		})
	}
}

// fireRTO moves the clock until the RTO count is n. It returns the packets of
// the step with the last RTO.
func fireRTO(t *testing.T, p *simPeer, n uint64) []peerPkt {
	t.Helper()
	stats := p.ep.stack.Stats().TCP
	var pkts []peerPkt
	for i := 0; i < 100 && stats.Timeouts.Value() < n; i++ {
		p.clock.Advance(250 * time.Millisecond)
		pkts = p.readAll()
	}
	if got := stats.Timeouts.Value(); got != n {
		t.Fatalf("timeouts %d, want %d", got, n)
	}
	return pkts
}

// tsValAt returns the TSVal of the last packet that starts at byte off.
func tsValAt(t *testing.T, p *simPeer, pkts []peerPkt, off int) uint32 {
	t.Helper()
	for i := len(pkts) - 1; i >= 0; i-- {
		if pkts[i].seq == p.at(off) {
			return pkts[i].tsVal
		}
	}
	t.Fatalf("no packet at %d in %v", off, p.offsets(pkts))
	return 0
}

// After a 2nd RTO, or an RTO in recovery, the Eifel check uses the TSVal of the
// first retransmission of the recovery, as Linux tcp_packet_delayed.
func TestSpuriousRTOInRecovery(t *testing.T) {
	const (
		rtoFromOpen = iota
		secondRTO
		rtoInSACKRecovery
		// lostRetransmit starts a SACK recovery in RTO recovery.
		lostRetransmit
	)
	const (
		echoFirstSend = iota
		// echoFirstResend is the echo of the fast retransmit or of the 1st RTO resend.
		echoFirstResend
		echoLastResend
	)
	// tsHigh sets the top bit of the TSVals, so that they are negative as int32.
	const tsHigh = 0x80000000
	cases := []struct {
		name     string
		cc       string
		scenario int
		tsOffset uint32
		echo     int
		// want is the count of spurious recoveries.
		want      uint64
		wantState tcpip.CongestionControlState
	}{
		{name: "RTO from Open, echo of the RTO resend", cc: "cubic", scenario: rtoFromOpen, tsOffset: tsHigh, echo: echoLastResend, want: 0, wantState: tcpip.RTORecovery},
		{name: "RTO from Open, echo of the first send", cc: "cubic", scenario: rtoFromOpen, tsOffset: tsHigh, echo: echoFirstSend, want: 1, wantState: tcpip.Open},
		{name: "2nd RTO, echo of the 2nd resend", cc: "cubic", scenario: secondRTO, tsOffset: tsHigh, echo: echoLastResend, want: 0, wantState: tcpip.RTORecovery},
		{name: "2nd RTO, echo of the 1st resend", cc: "cubic", scenario: secondRTO, tsOffset: tsHigh, echo: echoFirstResend, want: 0, wantState: tcpip.RTORecovery},
		{name: "2nd RTO, echo of the first send", cc: "cubic", scenario: secondRTO, echo: echoFirstSend, want: 1, wantState: tcpip.Open},
		{name: "RTO in SACK recovery, echo of the RTO resend", cc: "cubic", scenario: rtoInSACKRecovery, tsOffset: tsHigh, echo: echoLastResend, want: 0, wantState: tcpip.RTORecovery},
		{name: "RTO in SACK recovery, echo of the fast retransmit", cc: "cubic", scenario: rtoInSACKRecovery, tsOffset: tsHigh, echo: echoFirstResend, want: 0, wantState: tcpip.RTORecovery},
		{name: "RTO in SACK recovery, echo of the first send", cc: "cubic", scenario: rtoInSACKRecovery, echo: echoFirstSend, want: 1, wantState: tcpip.Open},
		{name: "bbr RTO in SACK recovery, echo of the RTO resend", cc: "bbr", scenario: rtoInSACKRecovery, tsOffset: tsHigh, echo: echoLastResend, want: 0, wantState: tcpip.RTORecovery},
		{name: "lost retransmission in RTO recovery", cc: "cubic", scenario: lostRetransmit, tsOffset: tsHigh, echo: echoLastResend, want: 0, wantState: tcpip.SACKRecovery},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newSimPeerTS(t, tc.cc)
			p.ep.LockUser()
			p.ep.TSOffset = tcp.NewTSOffset(tc.tsOffset)
			p.ep.UnlockUser()
			mss := p.mss()
			p.clock.Advance(time.Millisecond)
			p.write(mss)
			ecr := tsValAt(t, p, p.readAll(), 0)
			p.clock.Advance(time.Millisecond)
			p.write(9 * mss)
			p.readAll()
			// The test ends with an ACK of ackTo with the SACK blocks sacks.
			ackTo := mss
			var sacks [][2]int
			switch tc.scenario {
			case rtoFromOpen:
				resend := tsValAt(t, p, fireRTO(t, p, 1), 0)
				if tc.echo != echoFirstSend {
					ecr = resend
				}
			case secondRTO:
				first := tsValAt(t, p, fireRTO(t, p, 1), 0)
				last := tsValAt(t, p, fireRTO(t, p, 2), 0)
				switch tc.echo {
				case echoFirstResend:
					ecr = first
				case echoLastResend:
					ecr = last
				}
			case rtoInSACKRecovery:
				p.clock.Advance(10 * time.Millisecond)
				sacks = [][2]int{{2 * mss, 10 * mss}}
				p.ack(0, 65535, sacks...)
				fast := tsValAt(t, p, p.readAll(), 0)
				last := tsValAt(t, p, fireRTO(t, p, 1), 0)
				switch tc.echo {
				case echoFirstResend:
					ecr = fast
				case echoLastResend:
					ecr = last
				}
			case lostRetransmit:
				// Segments 1 and 2 go out, then segments 3 and 4. The SACK of
				// segment 3 marks the resend of segment 2 lost.
				fireRTO(t, p, 1)
				p.clock.Advance(10 * time.Millisecond)
				p.ack(mss, 65535)
				p.readAll()
				p.clock.Advance(10 * time.Millisecond)
				p.ack(2*mss, 65535)
				p.readAll()
				p.clock.Advance(10 * time.Millisecond)
				p.ack(2*mss, 65535, [2]int{3 * mss, 4 * mss})
				ecr = tsValAt(t, p, p.readAll(), 2*mss)
				// A partial ACK in the new SACK recovery.
				ackTo = 4 * mss
			}
			p.clock.Advance(10 * time.Millisecond)
			p.ackEcr(ackTo, 65535, ecr, sacks...)
			p.readAll()
			stats := p.ep.stack.Stats().TCP
			if got := stats.SpuriousRecovery.Value(); got != tc.want {
				t.Errorf("spurious recoveries %d, want %d", got, tc.want)
			}
			if got := stats.SpuriousRTORecovery.Value(); got != tc.want {
				t.Errorf("spurious RTO recoveries %d, want %d", got, tc.want)
			}
			p.ep.LockUser()
			state := p.ep.snd.state
			p.ep.UnlockUser()
			if state != tc.wantState {
				t.Errorf("state %v, want %v", state, tc.wantState)
			}
		})
	}
}
