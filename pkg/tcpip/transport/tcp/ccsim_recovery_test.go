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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/waiter"
)

// fixedSim is a sim congestion control with a fixed cwnd and no pacing.
type fixedSim struct {
	h    SimSender
	cwnd int
	// cwndOnAck is the cwnd that OnAck sets, if it is not 0.
	cwndOnAck int
}

func (f *fixedSim) HandleLossDetected()       { f.h.SetSsthresh(f.cwnd) }
func (f *fixedSim) HandleRTOExpired()         { f.h.SetSsthresh(f.cwnd) }
func (f *fixedSim) Update(int, time.Duration) {}
func (f *fixedSim) PostRecovery()             { f.h.SetCwndPkts(f.cwnd) }

func (f *fixedSim) OnAck(SimRateSample) {
	if f.cwndOnAck != 0 {
		f.cwnd = f.cwndOnAck
	}
	f.h.SetCwndPkts(f.cwnd)
}

// pacedSim is fixedSim with a pacing rate of 800 bits/s. Each send after the first quantum waits for 1 s.
type pacedSim struct{ fixedSim }

func (f *pacedSim) OnAck(rs SimRateSample) {
	f.fixedSim.OnAck(rs)
	f.h.SetPacingRateBps(800)
}

func init() {
	RegisterSimCC("fixedsim", func(h SimSender) SimCC {
		f := &fixedSim{h: h, cwnd: 100}
		h.SetCwndPkts(f.cwnd)
		return f
	})
	RegisterSimCC("pacedsim", func(h SimSender) SimCC {
		f := &pacedSim{fixedSim{h: h, cwnd: 100}}
		h.SetCwndPkts(f.cwnd)
		h.SetPacingRateBps(800)
		return f
	})
}

const (
	peerMSS = 100
	// peerOptSize is the room for 4 SACK blocks that the sender keeps free in each segment.
	peerOptSize = 36
)

var (
	peerLocalAddr  = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	peerRemoteAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// simPeer is the raw TCP peer of one sending endpoint. The stack uses a manual clock,
// so no timer fires before the test moves the clock.
type simPeer struct {
	t     *testing.T
	clock *faketime.ManualClock
	link  *channel.Endpoint
	ep    *Endpoint
	// iss is the sequence number of the first data byte of the endpoint.
	iss     seqnum.Value
	peerSeq seqnum.Value
	port    uint16
}

type peerPkt struct {
	seq   seqnum.Value
	flags header.TCPFlags
	len   int
}

func newSimPeer(t *testing.T, cc string, gso bool) *simPeer {
	t.Helper()
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
		Clock:              clock,
	})
	link := channel.New(1024, header.IPv4MinimumSize+header.TCPMinimumSize+peerOptSize+peerMSS, "")
	if gso {
		link.SupportedGSOKind = stack.HostGSOSupported
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
	p := &simPeer{t: t, clock: clock, link: link, ep: e.(*Endpoint), peerSeq: 1000}
	syn, port := p.readPort()
	if syn.flags != header.TCPFlagSyn {
		t.Fatalf("got flags %v, want SYN", syn.flags)
	}
	p.iss, p.port = syn.seq+1, port
	opts := make([]byte, 8)
	n := header.EncodeMSSOption(peerOptSize+peerMSS, opts)
	n += header.EncodeSACKPermittedOption(opts[n:])
	n += header.EncodeNOP(opts[n:])
	n += header.EncodeNOP(opts[n:])
	p.send(header.TCPFlagSyn|header.TCPFlagAck, p.peerSeq, p.iss, 65535, opts[:n])
	p.peerSeq++
	if got := p.read(); got.flags != header.TCPFlagAck {
		t.Fatalf("got flags %v, want ACK", got.flags)
	}
	p.ep.LockUser()
	mss := p.ep.snd.MaxPayloadSize
	p.ep.UnlockUser()
	if mss != peerMSS {
		t.Fatalf("sender MSS %d, want %d", mss, peerMSS)
	}
	return p
}

// at returns the sequence number of byte off of the endpoint data.
func (p *simPeer) at(off int) seqnum.Value { return p.iss.Add(seqnum.Size(off)) }

func (p *simPeer) write(n int) {
	p.t.Helper()
	var r bytes.Reader
	r.Reset(make([]byte, n))
	if _, err := p.ep.Write(&r, tcpip.WriteOptions{}); err != nil {
		p.t.Fatalf("write: %v", err)
	}
}

func (p *simPeer) readPort() (peerPkt, uint16) {
	p.t.Helper()
	pk, port, ok := p.readTimeout(5 * time.Second)
	if !ok {
		p.t.Fatal("no packet")
	}
	return pk, port
}

func (p *simPeer) read() peerPkt {
	p.t.Helper()
	pk, _ := p.readPort()
	return pk
}

func (p *simPeer) readTimeout(d time.Duration) (peerPkt, uint16, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	pkt := p.link.ReadContext(ctx)
	if pkt == nil {
		return peerPkt{}, 0, false
	}
	defer pkt.DecRef()
	v := pkt.ToView()
	defer v.Release()
	th := header.TCP(header.IPv4(v.AsSlice()).Payload())
	return peerPkt{seq: seqnum.Value(th.SequenceNumber()), flags: th.Flags(), len: len(th.Payload())}, th.SourcePort(), true
}

// readAll reads data packets until no packet comes for 100 ms. It skips pure ACKs.
func (p *simPeer) readAll() []peerPkt {
	var out []peerPkt
	for {
		pk, _, ok := p.readTimeout(100 * time.Millisecond)
		if !ok {
			return out
		}
		if pk.len > 0 {
			out = append(out, pk)
		}
	}
}

func (p *simPeer) send(flags header.TCPFlags, seq, ack seqnum.Value, wnd uint16, opts []byte) {
	buf := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(opts))
	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(ProtocolNumber),
		SrcAddr:     peerRemoteAddr,
		DstAddr:     peerLocalAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	th := header.TCP(buf[header.IPv4MinimumSize:])
	th.Encode(&header.TCPFields{
		SrcPort:    80,
		DstPort:    p.port,
		SeqNum:     uint32(seq),
		AckNum:     uint32(ack),
		DataOffset: uint8(header.TCPMinimumSize + len(opts)),
		Flags:      flags,
		WindowSize: wnd,
	})
	copy(th[header.TCPMinimumSize:], opts)
	xsum := header.PseudoHeaderChecksum(ProtocolNumber, peerRemoteAddr, peerLocalAddr, uint16(len(th)))
	th.SetChecksum(^th.CalculateChecksum(xsum))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
	p.link.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// ack sends an ACK of ack bytes with SACK blocks of byte offsets.
func (p *simPeer) ack(ack int, wnd uint16, sacks ...[2]int) {
	blocks := make([]header.SACKBlock, len(sacks))
	for i, sb := range sacks {
		blocks[i] = header.SACKBlock{Start: p.at(sb[0]), End: p.at(sb[1])}
	}
	opts := make([]byte, 40)
	n := 0
	if len(blocks) > 0 {
		n = header.EncodeNOP(opts)
		n += header.EncodeNOP(opts[n:])
		n += header.EncodeSACKBlocks(blocks, opts[n:])
	}
	p.send(header.TCPFlagAck, p.peerSeq, p.at(ack), wnd, opts[:n])
}

// offsets returns the data byte offsets of the packets.
func (p *simPeer) offsets(pkts []peerPkt) [][2]int {
	out := make([][2]int, len(pkts))
	for i, pk := range pkts {
		off := int(p.iss.Size(pk.seq))
		out[i] = [2]int{off, off + pk.len}
	}
	return out
}

func (p *simPeer) sim() *fixedSim {
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	return p.ep.snd.ccsim.wrap.sim.(*fixedSim)
}

func (p *simPeer) setCC(name string) {
	p.t.Helper()
	opt := tcpip.CongestionControlOption(name)
	if err := p.ep.SetSockOpt(&opt); err != nil {
		p.t.Fatalf("set congestion control %s: %v", name, err)
	}
}

// delivered returns the delivered byte count of the sim congestion control.
func (p *simPeer) delivered() int64 {
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	return p.ep.snd.ccsim.delivered
}

// Each byte counts in delivered one time, when the peer first ACKs or SACKs it, as in Linux.
func TestSimDelivered(t *testing.T) {
	cases := []struct {
		name string
		gso  bool
		// writes are sent one at a time, so that each GSO write is one segment.
		writes []int
		// sackAck is the cumulative ACK that has the SACK blocks.
		sackAck int
		sacks   [][2]int
		// rto is set if an RTO sends all data again after the SACK.
		rto bool
		// ack is the cumulative ACK after the SACK, or 0 for none. ackSacks are its SACK blocks.
		ack      int
		ackSacks [][2]int
		want     int64
	}{
		{name: "partial SACK of a GSO segment", gso: true, writes: []int{300}, sacks: [][2]int{{100, 300}}, want: 200},
		{name: "partial ACK of a partly SACKed GSO segment", gso: true, writes: []int{300}, sacks: [][2]int{{100, 200}, {210, 300}}, ack: 200, want: 290},
		{name: "partial SACK of a GSO segment, then the ACK of all data", gso: true, writes: []int{300}, sacks: [][2]int{{100, 300}}, ack: 300, want: 300},
		{name: "repairs split a partly SACKed GSO segment", gso: true, writes: []int{300, 300}, sackAck: 100, sacks: [][2]int{{110, 200}, {210, 600}}, ack: 600, want: 600},
		{name: "SACK before an RTO", writes: []int{10 * peerMSS}, sacks: [][2]int{{500, 1000}}, rto: true, ack: 10 * peerMSS, want: 10 * peerMSS},
		{name: "partial SACK of a GSO segment before an RTO", gso: true, writes: []int{300}, sacks: [][2]int{{100, 300}}, rto: true, ack: 300, want: 300},
		// The cap counts the hole 300-400 early. The SACK of 400-600 again must not add more.
		{name: "partial ACK and a repeated SACK after an RTO", gso: true, writes: []int{600}, sacks: [][2]int{{100, 300}, {400, 600}}, rto: true, ack: 300, ackSacks: [][2]int{{400, 600}}, want: 600},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, "fixedsim", tc.gso)
			// RACK reads a send time of zero as the time of the last delivery. Then the path depends on the ISS.
			p.clock.Advance(time.Millisecond)
			end := 0
			for _, n := range tc.writes {
				p.write(n)
				end += n
				if got := p.offsets(p.readAll()); len(got) == 0 || got[len(got)-1][1] != end {
					t.Fatalf("sent %v, want the data up to %d", got, end)
				}
			}
			p.clock.Advance(10 * time.Millisecond)
			p.ack(tc.sackAck, 65535, tc.sacks...)
			p.readAll()
			if tc.rto {
				// No ACK until the RTO. The RTO sends all data again.
				p.clock.Advance(5 * time.Second)
				p.readAll()
			}
			if tc.ack != 0 {
				p.ack(tc.ack, 65535, tc.ackSacks...)
				p.readAll()
			}
			if got := p.delivered(); got != tc.want {
				t.Errorf("delivered %d, want %d", got, tc.want)
			}
			p.ep.LockUser()
			defer p.ep.UnlockUser()
			for seg := p.ep.snd.writeList.Front(); seg != nil; seg = seg.Next() {
				if ss := seg.ccsim; ss != nil && ss.sacked > seg.payloadSize() {
					t.Errorf("segment at %d: sacked %d, more than its payload %d", p.iss.Size(seg.sequenceNumber), ss.sacked, seg.payloadSize())
				}
			}
		})
	}
}

// RACK marks segment 11 lost in recovery, but the receive window stops its repair.
// The ACK that ends recovery opens the window. Segment 11 must be sent then, not at the RTO.
func TestSimLostSegmentAtRecoveryExit(t *testing.T) {
	p := newSimPeer(t, "fixedsim", false)
	p.write(10 * peerMSS)
	if got := len(p.readAll()); got != 10 {
		t.Fatalf("sent %d segments, want 10", got)
	}
	p.clock.Advance(10 * time.Millisecond)
	// Segments 2-10 arrive. Segment 1 is lost.
	p.ack(0, 65535, [2]int{100, 1000})
	if got := p.offsets(p.readAll()); len(got) != 1 || got[0][0] != 0 {
		t.Fatalf("after the first SACK, sent %v, want the repair of segment 1", got)
	}
	// Segments 11-14 in recovery.
	p.write(4 * peerMSS)
	if got := len(p.readAll()); got != 4 {
		t.Fatalf("sent %d new segments, want 4", got)
	}
	p.clock.Advance(10 * time.Millisecond)
	// Segment 11 is lost. A window of 50 bytes stops its repair.
	p.ack(100, 50, [2]int{100, 1000}, [2]int{1100, 1400})
	if got := p.offsets(p.readAll()); len(got) != 0 {
		t.Fatalf("with a 50 byte window, sent %v", got)
	}
	// The ACK through segment 10 ends recovery and opens the window.
	p.ack(1000, 65535, [2]int{1100, 1400})
	if got := p.offsets(p.readAll()); len(got) == 0 || got[0][0] != 1000 {
		t.Fatalf("after recovery exit, sent %v, want the repair of segment 11 at 1000", got)
	}
}

// Two GSO segments of 300 bytes. The first has holes at 100-110 and 200-210.
// The repairs must send only the holes, not SACKed bytes.
func TestSimGSOSegmentWithTwoHoles(t *testing.T) {
	p := newSimPeer(t, "fixedsim", true)
	for i := 0; i < 2; i++ {
		p.write(300)
		if got := p.offsets(p.readAll()); len(got) != 1 || got[0][1]-got[0][0] != 300 {
			t.Fatalf("write %d: sent %v, want one GSO segment of 300 bytes", i, got)
		}
	}
	p.clock.Advance(10 * time.Millisecond)
	p.ack(100, 65535, [2]int{110, 200}, [2]int{210, 600})
	got := p.offsets(p.readAll())
	want := [][2]int{{100, 110}, {200, 210}}
	if len(got) != len(want) {
		t.Fatalf("sent %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sent %v, want %v", got, want)
		}
	}
}

// An ACK above SND.NXT is not valid. RACK must still repair a later loss before the RTO.
func TestSimAckAboveSndNxt(t *testing.T) {
	p := newSimPeer(t, "fixedsim", false)
	p.write(4 * peerMSS)
	if got := len(p.readAll()); got != 4 {
		t.Fatalf("sent %d segments, want 4", got)
	}
	p.clock.Advance(10 * time.Millisecond)
	p.ack(4*peerMSS+1000, 65535)
	p.ack(0, 65535, [2]int{100, 400})
	if got := p.offsets(p.readAll()); len(got) == 0 || got[0][0] != 0 {
		t.Fatalf("after the SACK, sent %v, want the repair of segment 1", got)
	}
}

// The congestion control gets the ACK before the sender sends, so the new cwnd applies to that send.
func TestSimOnAckBeforeSend(t *testing.T) {
	p := newSimPeer(t, "fixedsim", false)
	f := p.sim()
	p.ep.LockUser()
	f.cwnd, f.cwndOnAck = 2, 10
	f.h.SetCwndPkts(2)
	p.ep.UnlockUser()
	p.write(20 * peerMSS)
	if got := len(p.readAll()); got != 2 {
		t.Fatalf("sent %d segments with cwnd 2, want 2", got)
	}
	p.clock.Advance(10 * time.Millisecond)
	p.ack(2*peerMSS, 65535)
	if got := len(p.readAll()); got != 10 {
		t.Fatalf("after the ACK that sets cwnd 10, sent %d segments, want 10", got)
	}
}

// Abort frees the queued segments. It must empty the RACK queues first, because a freed segment
// must not stay on them. Then the cleanup drops the ccsim state.
func TestSimPurgeClearsRACKQueues(t *testing.T) {
	p := newSimPeer(t, "fixedsim", false)
	p.write(10 * peerMSS)
	if got := len(p.readAll()); got != 10 {
		t.Fatalf("sent %d segments, want 10", got)
	}
	p.clock.Advance(10 * time.Millisecond)
	p.ack(0, 65535, [2]int{500, 1000})
	p.readAll()
	p.ep.LockUser()
	queued := p.ep.snd.ccsim.rackSentHead != nil || p.ep.snd.ccsim.rackLostHead != nil
	p.ep.UnlockUser()
	if !queued {
		t.Fatal("precondition: the RACK queues are empty")
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("abort panicked: %v", r)
			}
		}()
		p.ep.Abort()
	}()
	p.ep.LockUser()
	defer p.ep.UnlockUser()
	if st := p.ep.snd.ccsim; st != nil {
		t.Errorf("after abort: ccsim state %p, want nil", st)
	}
}
