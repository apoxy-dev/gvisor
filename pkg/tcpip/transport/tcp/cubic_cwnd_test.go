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
)

// A RACK loss in RTO recovery at a cwnd of 1 sets the CUBIC WMax below 1. The
// ACKs after the recovery must not move the cwnd to 0.
func TestCubicCwndAfterLossInRTORecovery(t *testing.T) {
	p := newSimPeer(t, "cubic", false)
	mss := p.mss()
	// Send 10 segments 1 ms apart, so that RACK can order them.
	for i := 0; i < 10; i++ {
		p.clock.Advance(time.Millisecond)
		p.write(mss)
	}
	if got := len(p.readAll()); got != 10 {
		t.Fatalf("first flight %d segments, want 10", got)
	}
	stats := p.ep.stack.Stats().TCP
	for i := 0; i < 100 && stats.Timeouts.Value() == 0; i++ {
		p.clock.Advance(50 * time.Millisecond)
		p.readAll()
	}
	if got := stats.Timeouts.Value(); got != 1 {
		t.Fatalf("timeouts %d, want 1", got)
	}

	// The RTO sent segment 0 again with a cwnd of 1. A SACK of segments 4
	// to 9 makes RACK mark segments 1 to 3 lost before the cwnd grows.
	last := [2]int{4 * mss, 10 * mss}
	p.ack(0, 65535, last)
	p.clock.Advance(time.Millisecond)
	pkts := p.readAll()
	p.ep.LockUser()
	active, ssthresh := p.ep.snd.FastRecovery.Active, p.ep.snd.Ssthresh
	p.ep.UnlockUser()
	if !active || ssthresh != 2 {
		t.Fatalf("after the SACK: recovery %t, ssthresh %d, want true and 2", active, ssthresh)
	}

	// The peer gets segment 0 and each retransmission, and ACKs them.
	next := mss
	for i := 0; i < 20 && next < 10*mss; i++ {
		for _, off := range p.offsets(pkts) {
			if off[0] == next {
				next = off[1]
			}
		}
		if next == last[0] {
			next = last[1]
		}
		if next < last[0] {
			p.ack(next, 65535, last)
		} else {
			p.ack(next, 65535)
		}
		p.clock.Advance(time.Millisecond)
		pkts = p.readAll()
	}
	if next != 10*mss {
		t.Fatalf("peer has %d bytes, want %d", next, 10*mss)
	}
	p.ep.LockUser()
	active, cwnd := p.ep.snd.FastRecovery.Active, p.ep.snd.SndCwnd
	p.ep.UnlockUser()
	if active || cwnd < 1 {
		t.Fatalf("after all data is ACKed: recovery %t, cwnd %d, want false and 1 or more", active, cwnd)
	}

	// New data goes out.
	p.write(10 * mss)
	p.clock.Advance(time.Millisecond)
	if got := len(p.readAll()); got == 0 {
		t.Errorf("sent no new data, cwnd %d", cwnd)
	}
}
