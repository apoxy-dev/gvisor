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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	oooSndAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	oooRcvAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// oooMTU gives 536 B segments. With the segment overhead, such a segment uses
// about 2x its payload in memory, so a full window does not fit in 75% of the
// receive buffer. Full 1460 B segments use about 1.4x and always fit.
const oooMTU = 576

// TestOutOfOrderDrop drops the first data segment of a transfer. The segments
// after it go to the out-of-order queue, and the receiver drops the segments
// that do not fit in the share of the receive buffer for that queue.
func TestOutOfOrderDrop(t *testing.T) {
	cases := []struct {
		name     string
		rcvBuf   int64
		wantDrop bool
	}{
		// The first flight fills the 32 KiB window.
		{name: "small receive buffer", rcvBuf: 64 << 10, wantDrop: true},
		{name: "large receive buffer", rcvBuf: 4 << 20, wantDrop: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			snd, sndLink := newOOOStack(t, oooSndAddr)
			rcv, rcvLink := newOOOStack(t, oooRcvAddr)
			dropped := false
			go pump(ctx, sndLink, rcvLink, func(b []byte) bool {
				if dropped || tcpPayloadLen(b) == 0 {
					return false
				}
				dropped = true
				return true
			})
			go pump(ctx, rcvLink, sndLink, func([]byte) bool { return false })

			var wq waiter.Queue
			ep, tcpipErr := rcv.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
			if tcpipErr != nil {
				t.Fatalf("NewEndpoint: %s", tcpipErr)
			}
			// Set before Listen, so that the SYN-ACK has the window scale.
			ep.SocketOptions().SetReceiveBufferSize(tc.rcvBuf, true /* notify */)
			if err := ep.Bind(tcpip.FullAddress{Port: 80}); err != nil {
				t.Fatalf("Bind: %s", err)
			}
			if err := ep.Listen(1); err != nil {
				t.Fatalf("Listen: %s", err)
			}
			ln := gonet.NewTCPListener(rcv, &wq, ep)
			defer ln.Close()

			data := make([]byte, 256<<10)
			for i := range data {
				data[i] = byte(i)
			}
			got := make(chan []byte, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					got <- nil
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
				b, _ := io.ReadAll(c)
				got <- b
			}()
			c, err := gonet.DialTCP(snd, tcpip.FullAddress{NIC: 1, Addr: oooRcvAddr, Port: 80}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatalf("DialTCP: %v", err)
			}
			_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write(data); err != nil {
				t.Fatalf("Write: %v", err)
			}
			c.Close()

			if b := <-got; !bytes.Equal(b, data) {
				t.Fatalf("receiver got %d bytes, want the %d bytes sent", len(b), len(data))
			}
			if n := rcv.Stats().TCP.OutOfOrderDrop.Value(); (n > 0) != tc.wantDrop {
				t.Errorf("OutOfOrderDrop = %d, want drops: %t", n, tc.wantDrop)
			}
		})
	}
}

// newOOOStack returns a stack with one IPv4 NIC on a channel link.
func newOOOStack(t *testing.T, addr tcpip.Address) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() {
		s.Close()
		s.Wait()
	})
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		t.Fatalf("SetTransportProtocolOption: %s", err)
	}
	link := channel.New(1024, oooMTU, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: addr.WithPrefix()}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	return s, link
}

// pump moves packets from one link to the other until ctx ends. It drops the
// packets for which drop returns true.
func pump(ctx context.Context, from, to *channel.Endpoint, drop func([]byte) bool) {
	for {
		pkt := from.ReadContext(ctx)
		if pkt == nil {
			return
		}
		v := pkt.ToView()
		pkt.DecRef()
		b := v.AsSlice()
		if drop(b) {
			v.Release()
			continue
		}
		in := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
		to.InjectInbound(ipv4.ProtocolNumber, in)
		in.DecRef()
	}
}

// tcpPayloadLen returns the TCP payload length of the IPv4 packet b.
func tcpPayloadLen(b []byte) int {
	ip := header.IPv4(b)
	if ip.TransportProtocol() != header.TCPProtocolNumber {
		return 0
	}
	hl := int(ip.HeaderLength())
	return int(ip.TotalLength()) - hl - int(header.TCP(b[hl:]).DataOffset())
}
