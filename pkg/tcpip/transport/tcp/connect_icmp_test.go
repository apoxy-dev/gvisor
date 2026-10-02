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
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	icmpLocalAddr  = tcpip.AddrFrom16([16]byte{0: 0xfd, 15: 1})
	icmpRemoteAddr = tcpip.AddrFrom16([16]byte{0: 0xfd, 15: 2})
)

// TestConnectICMPv6Unreachable answers the SYN of a connect with an ICMPv6
// destination unreachable, and checks which codes stop the connect.
func TestConnectICMPv6Unreachable(t *testing.T) {
	cases := []struct {
		name    string
		code    header.ICMPv6Code
		wantErr tcpip.Error // Nil means that the connect continues.
	}{
		{name: "no route", code: header.ICMPv6NetworkUnreachable, wantErr: &tcpip.ErrNetworkUnreachable{}},
		{name: "prohibited", code: header.ICMPv6Prohibited},
		{name: "address unreachable", code: header.ICMPv6AddressUnreachable, wantErr: &tcpip.ErrHostUnreachable{}},
		{name: "port unreachable", code: header.ICMPv6PortUnreachable, wantErr: &tcpip.ErrConnectionRefused{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, link := newICMPv6Stack(t)
			var wq waiter.Queue
			we, done := waiter.NewChannelEntry(waiter.EventHUp | waiter.EventErr | waiter.WritableEvents)
			wq.EventRegister(&we)
			defer wq.EventUnregister(&we)
			ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint: %s", err)
			}
			defer ep.Close()
			err = ep.Connect(tcpip.FullAddress{NIC: 1, Addr: icmpRemoteAddr, Port: 80})
			if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
				t.Fatalf("Connect: %v, want %s", err, &tcpip.ErrConnectStarted{})
			}

			syn := readTCP(t, link)
			pkt := dstUnreachable(tc.code, syn)
			link.InjectInbound(ipv6.ProtocolNumber, pkt)
			pkt.DecRef()

			if tc.wantErr == nil {
				select {
				case <-done:
					t.Fatalf("connect ended: %v", ep.LastError())
				case <-time.After(200 * time.Millisecond):
				}
				if got := tcp.EndpointState(ep.State()); got != tcp.StateSynSent {
					t.Errorf("state = %s, want %s", got, tcp.StateSynSent)
				}
				return
			}
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("connect did not end")
			}
			if got := ep.LastError(); got == nil || got.String() != tc.wantErr.String() {
				t.Errorf("LastError = %v, want %s", got, tc.wantErr)
			}
			if got := tcp.EndpointState(ep.State()); got != tcp.StateError {
				t.Errorf("state = %s, want %s", got, tcp.StateError)
			}
		})
	}
}

// newICMPv6Stack returns a stack with one IPv6 NIC on a channel link.
func newICMPv6Stack(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	t.Cleanup(func() {
		s.Close()
		s.Wait()
	})
	link := channel.New(16, header.IPv6MinimumMTU, "")
	if err := s.CreateNIC(1, link); err != nil {
		t.Fatalf("CreateNIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: icmpLocalAddr.WithPrefix()}
	if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv6EmptySubnet, NIC: 1}})
	return s, link
}

// readTCP returns the first TCP packet that the stack sends on link.
func readTCP(t *testing.T, link *channel.Endpoint) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		pkt := link.ReadContext(ctx)
		if pkt == nil {
			t.Fatal("no TCP packet")
		}
		v := pkt.ToView()
		pkt.DecRef()
		b := append([]byte(nil), v.AsSlice()...)
		v.Release()
		if header.IPv6(b).TransportProtocol() == header.TCPProtocolNumber {
			return b
		}
	}
}

// dstUnreachable returns an ICMPv6 destination unreachable with code for the
// packet orig that the stack sent.
func dstUnreachable(code header.ICMPv6Code, orig []byte) *stack.PacketBuffer {
	n := header.ICMPv6DstUnreachableMinimumSize + len(orig)
	b := make([]byte, header.IPv6MinimumSize+n)
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(n),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          64,
		SrcAddr:           icmpRemoteAddr,
		DstAddr:           icmpLocalAddr,
	})
	icmp := header.ICMPv6(b[header.IPv6MinimumSize:])
	icmp.SetType(header.ICMPv6DstUnreachable)
	icmp.SetCode(code)
	copy(icmp.Payload(), orig)
	icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: icmpRemoteAddr, Dst: icmpLocalAddr}))
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
}
