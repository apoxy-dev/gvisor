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
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Reno and cubic have no ccsim state, and a checkpoint can save their sender.
func TestStockCongestionControl(t *testing.T) {
	cases := []struct {
		name tcpip.CongestionControlOption
		want string
	}{
		{name: ccReno, want: "*tcp.renoState"},
		{name: ccCubic, want: "*tcp.cubicState"},
	}
	for _, tc := range cases {
		t.Run(string(tc.name), func(t *testing.T) {
			stk := stack.New(stack.Options{})
			t.Cleanup(stk.Destroy)
			s := &sender{ep: &Endpoint{stack: stk}}
			s.ep.mu.Lock()
			s.cc = s.initCongestionControl(tc.name)
			s.ep.mu.Unlock()
			if got := fmt.Sprintf("%T", s.cc); got != tc.want {
				t.Errorf("congestion control is %s, want %s", got, tc.want)
			}
			if s.ccsim != nil {
				t.Errorf("stock sender has ccsim state %p", s.ccsim)
			}
			// Save only the sender and its congestion control.
			s.ep = nil
			var buf bytes.Buffer
			if _, err := state.Save(context.Background(), &buf, s); err != nil {
				t.Errorf("save sender: %v", err)
			}
		})
	}
}

// timeWait closes the connection from both sides. The endpoint is then in TIME-WAIT.
func (p *simPeer) timeWait() {
	p.t.Helper()
	p.ep.Shutdown(tcpip.ShutdownWrite)
	fin := p.read()
	if fin.flags != header.TCPFlagFin|header.TCPFlagAck {
		p.t.Fatalf("got flags %v, want FIN|ACK", fin.flags)
	}
	p.send(header.TCPFlagFin|header.TCPFlagAck, p.peerSeq, fin.seq+1, 65535, nil)
	p.peerSeq++
	if got := p.read(); got.flags != header.TCPFlagAck {
		p.t.Fatalf("got flags %v, want ACK", got.flags)
	}
	// The processor sent the ACK with the lock held. It starts TIME-WAIT before it releases the lock.
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	if st := p.ep.EndpointState(); st != StateTimeWait {
		p.t.Fatalf("endpoint state %v, want TIME-WAIT", st)
	}
}

// A checkpoint refuses a live endpoint with a sim congestion control, because the ccsim state is not saved.
// A closed endpoint, or one in TIME-WAIT, has no ccsim state, so a checkpoint can save it.
func TestSaveSimEndpoint(t *testing.T) {
	cases := []struct {
		name string
		cc   string
		// close closes the connection, if it is set.
		close      func(*simPeer)
		wantRefuse bool
	}{
		{name: "live fixedsim", cc: "fixedsim", wantRefuse: true},
		{name: "live reno", cc: string(ccReno)},
		{name: "aborted fixedsim", cc: "fixedsim", close: func(p *simPeer) { p.ep.Abort() }},
		{name: "aborted reno", cc: string(ccReno), close: func(p *simPeer) { p.ep.Abort() }},
		{name: "TIME-WAIT fixedsim", cc: "fixedsim", close: (*simPeer).timeWait},
		{name: "TIME-WAIT reno", cc: string(ccReno), close: (*simPeer).timeWait},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, tc.cc, false)
			if tc.close != nil {
				tc.close(p)
			}
			var perr any
			func() {
				defer func() { perr = recover() }()
				p.ep.beforeSave()
			}()
			if refused := perr != nil; refused != tc.wantRefuse {
				t.Fatalf("save refused %t (%v), want %t", refused, perr, tc.wantRefuse)
			}
			if perr != nil && !strings.Contains(fmt.Sprint(perr), "sim congestion control") {
				t.Errorf("save error %v, want the sim congestion control error", perr)
			}
		})
	}
}

// A pacing timer callback that waits for the endpoint lock while the endpoint closes must not panic.
func TestPacingTimerAfterCleanup(t *testing.T) {
	p := newSimPeer(t, "fixedsim", false)
	p.ep.LockUser()
	timer := &p.ep.snd.ccsim.pacingTimer
	timer.enable(time.Millisecond)
	cb := timer.callback
	// cleanupLocked does this while a fired callback waits for the lock.
	p.ep.snd.ccsimCleanup()
	p.ep.UnlockUser()
	defer func() {
		if r := recover(); r != nil {
			// The callback panicked with the lock held. Release it, so that the test cleanup can close the endpoint.
			p.ep.mu.Unlock()
			t.Errorf("pacing timer callback after cleanup panicked: %v", r)
		}
	}()
	cb()
}

// segsWithState returns the number of segments on writeList that have ccsim state.
//
// +checklocks:s.ep.mu
func segsWithState(s *sender) int {
	n := 0
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if seg.ccsim != nil {
			n++
		}
	}
	return n
}

// A stock flow sends, splits and frees segments without ccsim state.
func TestStockFlowHasNoSimState(t *testing.T) {
	p := newSimPeer(t, string(ccReno), false)
	// One write of 10 MSS is split into 10 segments when it is sent.
	p.write(10 * peerMSS)
	if got := len(p.readAll()); got != 10 {
		t.Fatalf("sent %d segments, want 10", got)
	}
	p.ack(5*peerMSS, 65535)
	p.readAll()
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	if s := p.ep.snd; s.ccsim != nil || segsWithState(s) != 0 {
		t.Errorf("stock sender: ccsim %p, %d segments with ccsim state; want nil and 0", s.ccsim, segsWithState(s))
	}
}

// A change to a stock congestion control drops all ccsim state. A change back tracks the segments in flight again.
// Data that was SACKed before the change back is not counted again at the next cumulative ACK.
func TestSwitchCongestionControl(t *testing.T) {
	cases := []struct {
		name string
		gso  bool
		// segs is the number of segments that 10 MSS of data uses.
		segs int
		// sacks are the SACK blocks that the peer sends while reno is selected.
		sacks         [][2]int
		wantPipe      int
		wantDelivered int64
	}{
		{name: "no SACK", segs: 10, wantPipe: 10, wantDelivered: 10 * peerMSS},
		{name: "SACKed segment in flight", segs: 10, sacks: [][2]int{{900, 1000}}, wantPipe: 9, wantDelivered: 9 * peerMSS},
		{name: "partly SACKed GSO segment in flight", gso: true, segs: 1, sacks: [][2]int{{900, 1000}}, wantPipe: 10, wantDelivered: 9 * peerMSS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, "fixedsim", tc.gso)
			// Stock RACK reads a send time of zero as the time of the last delivery.
			p.clock.Advance(time.Millisecond)
			p.write(10 * peerMSS)
			if got := len(p.readAll()); got != tc.segs {
				t.Fatalf("sent %d segments, want %d", got, tc.segs)
			}

			p.setCC(string(ccReno))
			p.ep.LockUser()
			s := p.ep.snd
			if s.ccsim != nil || segsWithState(s) != 0 || p.ep.scoreboard.ccsimBlocks {
				t.Errorf("after the change to reno: ccsim %p, %d segments with ccsim state, sim SACK limit %t; want nil, 0, false",
					s.ccsim, segsWithState(s), p.ep.scoreboard.ccsimBlocks)
			}
			p.ep.UnlockUser()
			if tc.sacks != nil {
				// All segments went out in the same tick as the SACKed one. An SRTT
				// and an RTT above 0 give RACK a reorder window, so none is lost yet.
				p.ep.LockUser()
				s.rtt.Lock()
				s.rtt.TCPRTTState.SRTT = 20 * time.Millisecond
				s.rtt.Unlock()
				p.ep.UnlockUser()
				p.clock.Advance(time.Millisecond)
				p.ack(0, 65535, tc.sacks...)
				if got := p.offsets(p.readAll()); len(got) != 0 {
					t.Fatalf("after the SACK, reno sent %v, want nothing", got)
				}
			}

			p.setCC("fixedsim")
			p.ep.LockUser()
			if s.ccsim == nil {
				t.Fatal("no ccsim state after the change to fixedsim")
			}
			if n := segsWithState(s); n != tc.segs || s.ccsim.rackPipe != tc.wantPipe {
				t.Errorf("after the change to fixedsim: %d segments with ccsim state, rackPipe %d; want %d, %d", n, s.ccsim.rackPipe, tc.segs, tc.wantPipe)
			}
			p.ep.UnlockUser()

			p.ack(10*peerMSS, 65535)
			p.readAll()
			p.ep.LockUser()
			defer p.ep.UnlockUser()
			if s.ccsim.rackPipe != 0 || s.ccsim.delivered != tc.wantDelivered {
				t.Errorf("after the ACK of all data: rackPipe %d, delivered %d; want 0, %d", s.ccsim.rackPipe, s.ccsim.delivered, tc.wantDelivered)
			}
		})
	}
}

// pacingState returns the state that the pacing switch test checks.
func (p *simPeer) pacingState() (idle, held, timer, tlp bool) {
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	s := p.ep.snd
	idle = s.SndUna == s.SndNxt
	held = s.writeNext != nil
	if s.ccsim != nil {
		timer = s.ccsim.pacingTimer.enabled()
		tlp = s.ccsim.tlpProbePending
	}
	return idle, held, timer, tlp
}

// Pacing holds new data or a tail-loss probe. After a change of congestion control,
// the sender must send the data, or arm a timer that repairs the tail.
func TestSwitchWhilePacingHolds(t *testing.T) {
	cases := []struct {
		name string
		// tlp is set if pacing holds a tail-loss probe. If not, it holds new data and nothing is in flight.
		tlp bool
		// to is the new congestion control, or "" for no change.
		to string
	}{
		{name: "data, no change"},
		{name: "data to reno", to: string(ccReno)},
		{name: "data to cubic", to: string(ccCubic)},
		{name: "data to fixedsim", to: "fixedsim"},
		{name: "data to pacedsim", to: "pacedsim"},
		{name: "probe, no change", tlp: true},
		{name: "probe to reno", tlp: true, to: string(ccReno)},
		{name: "probe to cubic", tlp: true, to: string(ccCubic)},
		{name: "probe to fixedsim", tlp: true, to: "fixedsim"},
		{name: "probe to pacedsim", tlp: true, to: "pacedsim"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, "pacedsim", false)
			p.write(2 * peerMSS)
			if got := len(p.readAll()); got != 2 {
				t.Fatalf("sent %d segments, want 2", got)
			}
			if tc.tlp {
				// The PTO fires. Pacing holds the probe.
				p.clock.Advance(1100 * time.Millisecond)
				if got := p.readAll(); len(got) != 0 {
					t.Fatalf("pacing did not hold the probe: sent %v", p.offsets(got))
				}
				if _, _, _, tlp := p.pacingState(); !tlp {
					t.Fatal("precondition: no tail-loss probe is pending")
				}
			} else {
				p.ack(2*peerMSS, 65535)
				p.readAll()
				p.write(peerMSS)
				if got := p.readAll(); len(got) != 0 {
					t.Fatalf("pacing did not hold the data: sent %v", p.offsets(got))
				}
				if idle, held, timer, _ := p.pacingState(); !idle || !held || !timer {
					t.Fatalf("precondition: idle %t, data held %t, pacing timer %t; want all true", idle, held, timer)
				}
			}
			if tc.to != "" {
				p.setCC(tc.to)
			}
			for _, d := range []time.Duration{2 * time.Second, 10 * time.Second, 120 * time.Second} {
				p.clock.Advance(d)
				if len(p.readAll()) > 0 {
					return
				}
			}
			t.Error("nothing sent in 132 s")
		})
	}
}

// A freed segment gives its ccsim state back, so that the segment pool never holds it.
func TestFreeSimSegment(t *testing.T) {
	seg := newOutgoingSegment(stack.TransportEndpointID{}, faketime.NewManualClock(), buffer.MakeWithData(make([]byte, 10)))
	ccsimSegOf(seg).delivered = 1
	seg.DecRef()
	if seg.ccsim != nil {
		t.Errorf("freed segment has ccsim state %+v", seg.ccsim)
	}
}
