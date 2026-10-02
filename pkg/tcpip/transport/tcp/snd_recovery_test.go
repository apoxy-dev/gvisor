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

	"gvisor.dev/gvisor/pkg/tcpip"
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
