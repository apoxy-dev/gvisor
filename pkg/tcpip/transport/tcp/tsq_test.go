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
	"fmt"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	// tsqCwnd is the cwnd of the senders, in packets. It is more than the
	// link queue, and the link queue is more than two limits.
	tsqCwnd      = 400
	tsqLinkQueue = 256
)

func init() {
	RegisterSimCC("tsqsim", func(h SimSender) SimCC {
		f := &fixedSim{h: h, cwnd: tsqCwnd}
		h.SetCwndPkts(f.cwnd)
		return f
	})
}

// newTSQStack returns a stack with a manual clock on a link with an MTU of
// 1500. The link tells the senders about its queue if txNotify is set.
func newTSQStack(t *testing.T, cc string, txNotify bool) (*stack.Stack, *channel.Endpoint, *faketime.ManualClock) {
	t.Helper()
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              clock,
	})
	link := channel.New(tsqLinkQueue, 1500, "")
	if txNotify {
		link.LinkEPCapabilities |= stack.CapabilityTxNotify
	}
	t.Cleanup(func() {
		stk.Destroy()
		link.Drain()
	})
	sack := tcpip.TCPSACKEnabled(true)
	rack := tcpip.TCPRACKLossDetection
	ccOpt := tcpip.CongestionControlOption(cc)
	for _, opt := range []tcpip.SettableTransportProtocolOption{&sack, &rack, &ccOpt} {
		if err := stk.SetTransportProtocolOption(ProtocolNumber, opt); err != nil {
			t.Fatalf("set %T: %v", opt, err)
		}
	}
	if err := stk.CreateNIC(1, link); err != nil {
		t.Fatalf("create NIC: %v", err)
	}
	if err := stk.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: peerLocalAddr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("add address: %v", err)
	}
	stk.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return stk, link, clock
}

// connectTSQ connects a new endpoint to the peer. The peer opens a window of
// 8 MB and sends no ACK after that.
func connectTSQ(t *testing.T, stk *stack.Stack, link *channel.Endpoint, clock *faketime.ManualClock) *simPeer {
	t.Helper()
	var wq waiter.Queue
	e, err := stk.NewEndpoint(ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		t.Fatalf("new endpoint: %v", err)
	}
	t.Cleanup(e.Close)
	e.SocketOptions().SetDelayOption(false)
	if err := e.Connect(tcpip.FullAddress{Addr: peerRemoteAddr, Port: 80}); err != nil {
		if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
			t.Fatalf("connect: %v", err)
		}
	}
	p := &simPeer{t: t, clock: clock, link: link, ep: e.(*Endpoint), peerSeq: 1000, tsVal: 1}
	syn, port := p.readPort()
	if syn.flags != header.TCPFlagSyn {
		t.Fatalf("got flags %v, want SYN", syn.flags)
	}
	p.iss, p.port = syn.seq+1, port
	opts := make([]byte, 12)
	n := header.EncodeMSSOption(1460, opts)
	n += header.EncodeSACKPermittedOption(opts[n:])
	n += header.EncodeWSOption(7, opts[n:])
	for n%4 != 0 {
		n += header.EncodeNOP(opts[n:])
	}
	p.send(header.TCPFlagSyn|header.TCPFlagAck, p.peerSeq, p.iss, 65535, opts[:n])
	p.peerSeq++
	if got := p.read(); got.flags != header.TCPFlagAck {
		t.Fatalf("got flags %v, want ACK", got.flags)
	}
	p.ack(0, 65535)
	for deadline := time.Now().Add(5 * time.Second); ; {
		p.ep.LockUser()
		wnd := p.ep.snd.SndWnd
		p.ep.UnlockUser()
		if wnd > 1<<20 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("send window %d, want the 8 MB window of the peer", wnd)
		}
		time.Sleep(time.Millisecond)
	}
	return p
}

// setStockRate sets the cwnd of a stock sender to tsqCwnd, and its SRTT to
// 10 ms. The rate then gives the smallest limit.
func (p *simPeer) setStockRate() {
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	s := p.ep.snd
	s.SndCwnd = tsqCwnd
	s.rtt.Lock()
	s.rtt.TCPRTTState.SRTT = 10 * time.Millisecond
	s.rtt.Unlock()
}

func noBufferSpace(stk *stack.Stack) uint64 {
	return stk.NICInfo()[1].Stats.TxPacketsDroppedNoBufferSpace.Value()
}

// TestTSQ writes tsqCwnd packets of data to an endpoint, and the peer sends
// no ACK. The link holds at most the limit of the endpoint. When a reader
// takes the packets, the link wakes the endpoint, which sends all of cwnd.
func TestTSQ(t *testing.T) {
	cases := []struct {
		name     string
		cc       string
		txNotify bool
		read     bool
		// wantQueued is the number of packets in the link queue with no
		// reader. 0 means the limit.
		wantQueued int
		wantDrops  uint64
	}{
		{name: "sim", cc: "tsqsim", txNotify: true},
		{name: "cubic", cc: ccCubic, txNotify: true},
		{name: "sim with a reader", cc: "tsqsim", txNotify: true, read: true},
		{name: "cubic with a reader", cc: ccCubic, txNotify: true, read: true},
		{name: "no capability", cc: "tsqsim", wantQueued: tsqLinkQueue, wantDrops: tsqCwnd - tsqLinkQueue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stk, link, clock := newTSQStack(t, tc.cc, tc.txNotify)
			p := connectTSQ(t, stk, link, clock)
			if tc.cc == ccCubic {
				p.setStockRate()
			}
			limit := tsqMinBytes / p.mss()
			p.write(tsqCwnd * p.mss())
			if !tc.read {
				want := tc.wantQueued
				if want == 0 {
					want = limit
				}
				if got := link.NumQueued(); got != want {
					t.Errorf("link queue has %d packets, want %d", got, want)
				}
			} else {
				maxQueued := 0
				for sent := 0; sent < tsqCwnd; {
					maxQueued = max(maxQueued, link.NumQueued())
					if p.read().len > 0 {
						sent++
					}
				}
				if maxQueued > limit {
					t.Errorf("link queue had %d packets, want at most %d", maxQueued, limit)
				}
			}
			if got := noBufferSpace(stk); got != tc.wantDrops {
				t.Errorf("TxPacketsDroppedNoBufferSpace = %d, want %d", got, tc.wantDrops)
			}
		})
	}
}

// TestTSQTwoEndpoints checks that two endpoints on one link each get their
// limit of the link queue.
func TestTSQTwoEndpoints(t *testing.T) {
	stk, link, clock := newTSQStack(t, "tsqsim", true)
	peers := []*simPeer{connectTSQ(t, stk, link, clock), connectTSQ(t, stk, link, clock)}
	for _, p := range peers {
		p.write(tsqCwnd * p.mss())
	}
	// A read wakes the endpoints, and they queue more packets after the
	// first n.
	queued := map[uint16]int{}
	for n := link.NumQueued(); n > 0; n-- {
		_, port := peers[0].readPort()
		queued[port]++
	}
	for i, p := range peers {
		if got, want := queued[p.port], tsqMinBytes/p.mss(); got != want {
			t.Errorf("endpoint %d has %d packets in the link queue, want %d", i, got, want)
		}
	}
	if got := noBufferSpace(stk); got != 0 {
		t.Errorf("TxPacketsDroppedNoBufferSpace = %d, want 0", got)
	}
}

// TestTSQGSO checks the limit on a link with GSO, where a packet counts as
// its segments of the MSS.
func TestTSQGSO(t *testing.T) {
	for _, read := range []bool{false, true} {
		t.Run(fmt.Sprintf("read=%t", read), func(t *testing.T) {
			stk, link, clock := newTSQStack(t, "tsqsim", true)
			link.SupportedGSOKind = stack.HostGSOSupported
			p := connectTSQ(t, stk, link, clock)
			mss := p.mss()
			limit := tsqMinBytes / mss
			// A send that starts below the limit can add one GSO packet.
			most := limit + (int(link.GSOMaxSize())+mss-1)/mss
			queued := func() int { return int(p.ep.tsq.queued.Load()) }
			p.write(tsqCwnd * mss)
			if !read {
				if got := queued(); got < limit || got >= most {
					t.Errorf("link queue has %d segments, want %d to %d", got, limit, most-1)
				}
				if got := link.NumQueued(); got >= limit {
					t.Errorf("link queue has %d packets, want fewer than %d with GSO", got, limit)
				}
			} else {
				// cwnd counts the short last segment of a GSO packet as a
				// full MSS, so read half of cwnd. That is more than two limits.
				maxQueued := 0
				for sent := 0; sent < tsqCwnd/2*mss; {
					maxQueued = max(maxQueued, queued())
					sent += p.read().len
				}
				if maxQueued >= most {
					t.Errorf("link queue had %d segments, want fewer than %d", maxQueued, most)
				}
			}
			if got := noBufferSpace(stk); got != 0 {
				t.Errorf("TxPacketsDroppedNoBufferSpace = %d, want 0", got)
			}
		})
	}
}
