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

package tcp_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/bbr"
)

func init() { bbr.Register() }

var (
	senderAddr   = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	receiverAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

const testPort = 5201

// newTestStack returns a stack with one channel NIC at addr that uses cc.
func newTestStack(t testing.TB, addr tcpip.Address, cc string) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	ep := channel.New(4096, 1420, "")
	t.Cleanup(func() {
		s.Destroy()
		// Free the packets that nobody read, for the leak check.
		ep.Drain()
	})
	opts := []tcpip.SettableTransportProtocolOption{
		ptr(tcpip.TCPSACKEnabled(true)),
		ptr(tcpip.CongestionControlOption(cc)),
		&tcpip.TCPSendBufferSizeRangeOption{Min: 64 << 10, Default: 4 << 20, Max: 16 << 20},
		// The receiver drops out-of-order data above 75% of its buffer. Keep it larger than the send buffer.
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 64 << 10, Default: 64 << 20, Max: 64 << 20},
	}
	for _, opt := range opts {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, opt); err != nil {
			t.Fatalf("set %T: %v", opt, err)
		}
	}
	if err := s.CreateNIC(1, ep); err != nil {
		t.Fatalf("create NIC: %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("add address: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, ep
}

func ptr[T any](v T) *T { return &v }

// pipe moves packets from one endpoint to the other after delay, and drops every dropEvery-th packet.
// The test cleanup stops it, frees the queued packets and waits for its goroutines.
func pipe(t testing.TB, from, to *channel.Endpoint, delay time.Duration, dropEvery int, dropped *atomic.Int64) {
	type item struct {
		due time.Time
		buf buffer.Buffer
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	q := make(chan item, 1<<16)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for it := range q {
			if d := time.Until(it.due); d > 0 && ctx.Err() == nil {
				time.Sleep(d)
			}
			if ctx.Err() != nil {
				it.buf.Release()
				continue
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: it.buf})
			to.InjectInbound(ipv4.ProtocolNumber, pkt)
			pkt.DecRef()
		}
	}()
	go func() {
		defer wg.Done()
		defer close(q)
		// Do not drop the handshake.
		n := 0
		for {
			pkt := from.ReadContext(ctx)
			if pkt == nil {
				return
			}
			n++
			if dropEvery > 0 && n > 3 && n%dropEvery == 0 {
				dropped.Add(1)
				pkt.DecRef()
				continue
			}
			buf := pkt.ToBuffer()
			pkt.DecRef()
			q <- item{due: time.Now().Add(delay), buf: buf}
		}
	}()
}

// testConn is one TCP connection between two stacks.
type testConn struct {
	sender  *stack.Stack
	client  *gonet.TCPConn
	server  *gonet.TCPConn
	dropped atomic.Int64
}

func newTestConn(t testing.TB, cc string, delay time.Duration, dropEvery int) *testConn {
	t.Helper()
	tc := &testConn{}
	var sep, rep *channel.Endpoint
	tc.sender, sep = newTestStack(t, senderAddr, cc)
	receiver, rep := newTestStack(t, receiverAddr, "cubic")
	pipe(t, sep, rep, delay, dropEvery, &tc.dropped)
	pipe(t, rep, sep, delay, 0, &tc.dropped)

	ln, err := gonet.ListenTCP(receiver, tcpip.FullAddress{NIC: 1, Addr: receiverAddr, Port: testPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan *gonet.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c.(*gonet.TCPConn)
	}()
	dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer dcancel()
	tc.client, err = gonet.DialContextTCP(dctx, tc.sender, tcpip.FullAddress{NIC: 1, Addr: receiverAddr, Port: testPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { tc.client.Close() })
	tc.server = <-accepted
	if tc.server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { tc.server.Close() })
	return tc
}

// send writes data on the client and reads it on the server.
func (tc *testConn) send(t testing.TB, data []byte) []byte {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		_, err := tc.client.Write(data)
		errc <- err
	}()
	got := make([]byte, len(data))
	tc.server.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(tc.server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write: %v", err)
	}
	return got
}

func TestCongestionControlTransfer(t *testing.T) {
	data := make([]byte, 32<<20)
	for i := range data {
		data[i] = byte(i * 7)
	}
	cases := []struct {
		name      string
		cc        string
		delay     time.Duration
		dropEvery int
		size      int // Default 2 MiB.
	}{
		{name: "reno", cc: "reno", delay: 2 * time.Millisecond},
		{name: "cubic", cc: "cubic", delay: 2 * time.Millisecond},
		{name: "bbr", cc: "bbr", delay: 2 * time.Millisecond},
		{name: "cubic 1% loss", cc: "cubic", delay: 2 * time.Millisecond, dropEvery: 100},
		{name: "bbr 1% loss", cc: "bbr", delay: 2 * time.Millisecond, dropEvery: 100},
		{name: "bbr 5% loss", cc: "bbr", delay: 2 * time.Millisecond, dropEvery: 20},
		{name: "bbr no delay", cc: "bbr"},
		// A large window with many SACK holes.
		{name: "bbr 0.1% loss 20 ms", cc: "bbr", delay: 10 * time.Millisecond, dropEvery: 1000, size: 32 << 20},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if sync.RaceEnabled && c.size > 0 {
				t.Skip("too slow with the race detector")
			}
			tc := newTestConn(t, c.cc, c.delay, c.dropEvery)
			var cc tcpip.CongestionControlOption
			if err := tc.sender.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil || string(cc) != c.cc {
				t.Fatalf("congestion control = %q, %v; want %q", cc, err, c.cc)
			}
			size := 2 << 20
			if c.size > 0 {
				size = c.size
			}
			if sync.RaceEnabled {
				// The race run checks races and leaks, not throughput.
				// With the race detector at high load, timers fire up to 300 ms late. Pacing credit is one quantum, more than Linux keeps.
				size = 256 << 10
			}
			if got := tc.send(t, data[:size]); !bytes.Equal(got, data[:size]) {
				t.Fatal("received data differs from sent data")
			}
			st := tc.sender.Stats().TCP
			retrans, dropped := st.Retransmits.Value(), uint64(tc.dropped.Load())
			t.Logf("dropped %d, retransmits %d, timeouts %d, recoveries %d, spurious %d", dropped, retrans,
				st.Timeouts.Value(), st.SACKRecovery.Value(), st.SpuriousRecovery.Value())
			if c.dropEvery > 0 && retrans == 0 {
				t.Errorf("no retransmits with %d dropped packets", dropped)
			}
			// BBR repairs each loss about once, plus some probes. Stock gVisor can repair a loss again, so it has no limit.
			// An RTO sends the window again, so skip the check after one.
			if c.cc == "bbr" && st.Timeouts.Value() == 0 && retrans > dropped+dropped/4+8 {
				t.Errorf("%d retransmits for %d dropped packets", retrans, dropped)
			}
		})
	}
}

func TestAvailableCongestionControl(t *testing.T) {
	s, _ := newTestStack(t, senderAddr, "cubic")
	var avail tcpip.TCPAvailableCongestionControlOption
	if err := s.TransportProtocolOption(tcp.ProtocolNumber, &avail); err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(avail)); !contains(got, "bbr") || !contains(got, "cubic") {
		t.Fatalf("available congestion control = %q, want bbr and cubic", avail)
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, ptr(tcpip.CongestionControlOption("nope"))); err == nil {
		t.Fatal("unknown congestion control accepted")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func BenchmarkTransfer(b *testing.B) {
	data := make([]byte, 1<<20)
	for _, cc := range []string{"cubic", "bbr"} {
		b.Run(cc, func(b *testing.B) {
			tc := newTestConn(b, cc, 0, 0)
			got := make([]byte, len(data))
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				errc := make(chan error, 1)
				go func() {
					_, err := tc.client.Write(data)
					errc <- err
				}()
				if _, err := io.ReadFull(tc.server, got); err != nil {
					b.Fatal(err)
				}
				if err := <-errc; err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
