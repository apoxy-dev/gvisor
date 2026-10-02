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
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	icmpLocalAddr   = tcpip.AddrFrom16([16]byte{0: 0xfd, 15: 1})
	icmpRemoteAddr  = tcpip.AddrFrom16([16]byte{0: 0xfd, 15: 2})
	icmpLocalAddr4  = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	icmpRemoteAddr4 = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// TestConnectICMPUnreachable answers the SYN of a connect with an ICMP
// destination unreachable, and checks which codes stop the connect. The errors
// are the errors that Linux gives.
func TestConnectICMPUnreachable(t *testing.T) {
	const v4, v6 = ipv4.ProtocolNumber, ipv6.ProtocolNumber
	cases := []struct {
		name    string
		proto   tcpip.NetworkProtocolNumber
		code    uint8
		wantErr tcpip.Error // Nil means that the connect continues.
	}{
		{name: "v6 no route", proto: v6, code: uint8(header.ICMPv6NetworkUnreachable), wantErr: &tcpip.ErrNetworkUnreachable{}},
		{name: "v6 prohibited", proto: v6, code: uint8(header.ICMPv6Prohibited), wantErr: &tcpip.ErrPermissionDenied{}},
		{name: "v6 beyond scope", proto: v6, code: uint8(header.ICMPv6BeyondScope)},
		{name: "v6 address unreachable", proto: v6, code: uint8(header.ICMPv6AddressUnreachable), wantErr: &tcpip.ErrHostUnreachable{}},
		{name: "v6 port unreachable", proto: v6, code: uint8(header.ICMPv6PortUnreachable), wantErr: &tcpip.ErrConnectionRefused{}},
		{name: "v6 policy", proto: v6, code: uint8(header.ICMPv6Policy), wantErr: &tcpip.ErrPermissionDenied{}},
		{name: "v6 reject route", proto: v6, code: uint8(header.ICMPv6RejectRoute), wantErr: &tcpip.ErrPermissionDenied{}},
		// Linux gives no EACCES for the IPv4 prohibited codes.
		{name: "v4 net prohibited", proto: v4, code: uint8(header.ICMPv4NetProhibited), wantErr: &tcpip.ErrNetworkUnreachable{}},
		{name: "v4 host prohibited", proto: v4, code: uint8(header.ICMPv4HostProhibited), wantErr: &tcpip.ErrHostUnreachable{}},
		{name: "v4 admin prohibited", proto: v4, code: uint8(header.ICMPv4AdminProhibited), wantErr: &tcpip.ErrHostUnreachable{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, link := newICMPStack(t)
			var wq waiter.Queue
			we, done := waiter.NewChannelEntry(waiter.EventHUp | waiter.EventErr | waiter.WritableEvents)
			wq.EventRegister(&we)
			defer wq.EventUnregister(&we)
			ep, err := s.NewEndpoint(tcp.ProtocolNumber, tc.proto, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint: %s", err)
			}
			defer ep.Close()
			err = ep.Connect(tcpip.FullAddress{NIC: 1, Addr: remoteAddr(tc.proto), Port: 80})
			if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
				t.Fatalf("Connect: %v, want %s", err, &tcpip.ErrConnectStarted{})
			}

			syn := readTCP(t, link)
			pkt := dstUnreachable(tc.proto, tc.code, syn)
			link.InjectInbound(tc.proto, pkt)
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

// TestEstablishedICMPv6Prohibited answers a data segment of an established
// connection with ICMPv6 code 1. As on Linux, the connection continues, and
// IPV6_RECVERR also queues the error.
func TestEstablishedICMPv6Prohibited(t *testing.T) {
	cases := []struct {
		name    string
		recvErr bool
	}{
		{name: "soft error", recvErr: false},
		{name: "IPV6_RECVERR", recvErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, link := newICMPStack(t)
			var wq waiter.Queue
			ep, err := s.NewEndpoint(tcp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
			if err != nil {
				t.Fatalf("NewEndpoint: %s", err)
			}
			defer ep.Close()
			ep.SocketOptions().SetIPv6RecvError(tc.recvErr)
			handshake(t, ep, &wq, link)

			data := writeData(t, ep, link, "a")
			pkt := dstUnreachable(ipv6.ProtocolNumber, uint8(header.ICMPv6Prohibited), data)
			link.InjectInbound(ipv6.ProtocolNumber, pkt)
			pkt.DecRef()

			// The endpoint keeps the soft error as its last error (SO_ERROR).
			want := &tcpip.ErrPermissionDenied{}
			if got := ep.LastError(); got == nil || got.String() != want.String() {
				t.Errorf("LastError = %v, want %s", got, want)
			}
			if got := ep.LastError(); got != nil {
				t.Errorf("second LastError = %v, want nil", got)
			}
			serr := ep.SocketOptions().DequeueErr()
			switch {
			case !tc.recvErr && serr != nil:
				t.Errorf("DequeueErr = %+v, want nil", serr)
			case tc.recvErr && serr == nil:
				t.Error("DequeueErr = nil, want the ICMPv6 error")
			case tc.recvErr:
				if serr.Err.String() != want.String() {
					t.Errorf("queued Err = %s, want %s", serr.Err, want)
				}
				c := serr.Cause
				if c.Origin() != tcpip.SockExtErrorOriginICMP6 || c.Type() != uint8(header.ICMPv6DstUnreachable) || c.Code() != uint8(header.ICMPv6Prohibited) {
					t.Errorf("queued cause = (origin %d, type %d, code %d), want (%d, %d, %d)",
						c.Origin(), c.Type(), c.Code(), tcpip.SockExtErrorOriginICMP6, header.ICMPv6DstUnreachable, header.ICMPv6Prohibited)
				}
			}

			if got := tcp.EndpointState(ep.State()); got != tcp.StateEstablished {
				t.Errorf("state = %s, want %s", got, tcp.StateEstablished)
			}
			writeData(t, ep, link, "b")
		})
	}
}

// newICMPStack returns a stack with one IPv4 and IPv6 NIC on a channel link.
func newICMPStack(t *testing.T) (*stack.Stack, *channel.Endpoint) {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
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
	for _, pa := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: icmpLocalAddr4.WithPrefix()},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: icmpLocalAddr.WithPrefix()},
	} {
		if err := s.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%s): %s", pa.AddressWithPrefix, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	return s, link
}

// remoteAddr returns the remote address of the tests for proto.
func remoteAddr(proto tcpip.NetworkProtocolNumber) tcpip.Address {
	if proto == ipv4.ProtocolNumber {
		return icmpRemoteAddr4
	}
	return icmpRemoteAddr
}

// handshake connects ep to the remote address, and answers the SYN on link.
func handshake(t *testing.T, ep tcpip.Endpoint, wq *waiter.Queue, link *channel.Endpoint) {
	t.Helper()
	we, done := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	err := ep.Connect(tcpip.FullAddress{NIC: 1, Addr: icmpRemoteAddr, Port: 80})
	if _, ok := err.(*tcpip.ErrConnectStarted); !ok {
		t.Fatalf("Connect: %v, want %s", err, &tcpip.ErrConnectStarted{})
	}
	syn := header.TCP(readTCP(t, link)[header.IPv6MinimumSize:])
	b := make([]byte, header.IPv6MinimumSize+header.TCPMinimumSize)
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     header.TCPMinimumSize,
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           icmpRemoteAddr,
		DstAddr:           icmpLocalAddr,
	})
	synAck := header.TCP(b[header.IPv6MinimumSize:])
	synAck.Encode(&header.TCPFields{
		SrcPort:    syn.DestinationPort(),
		DstPort:    syn.SourcePort(),
		SeqNum:     1000,
		AckNum:     syn.SequenceNumber() + 1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn | header.TCPFlagAck,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, icmpRemoteAddr, icmpLocalAddr, header.TCPMinimumSize)
	synAck.SetChecksum(^synAck.CalculateChecksum(xsum))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	link.InjectInbound(ipv6.ProtocolNumber, pkt)
	pkt.DecRef()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connect did not end")
	}
	if got := tcp.EndpointState(ep.State()); got != tcp.StateEstablished {
		t.Fatalf("state = %s, want %s", got, tcp.StateEstablished)
	}
}

// writeData writes s on ep, and returns the first IPv6 TCP packet with data
// that the stack sends on link.
func writeData(t *testing.T, ep tcpip.Endpoint, link *channel.Endpoint, s string) []byte {
	t.Helper()
	if _, err := ep.Write(strings.NewReader(s), tcpip.WriteOptions{}); err != nil {
		t.Fatalf("Write: %s", err)
	}
	for {
		b := readTCP(t, link)
		h := header.TCP(b[header.IPv6MinimumSize:])
		if len(h) > int(h.DataOffset()) {
			return b
		}
	}
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
		switch {
		case len(b) >= header.IPv4MinimumSize && b[0]>>4 == 4:
			if header.IPv4(b).TransportProtocol() == header.TCPProtocolNumber {
				return b
			}
		case len(b) >= header.IPv6MinimumSize && b[0]>>4 == 6:
			if header.IPv6(b).TransportProtocol() == header.TCPProtocolNumber {
				return b
			}
		}
	}
}

// dstUnreachable returns an ICMP destination unreachable with code from the
// remote address for the packet orig that the stack sent.
func dstUnreachable(proto tcpip.NetworkProtocolNumber, code uint8, orig []byte) *stack.PacketBuffer {
	var b []byte
	if proto == ipv4.ProtocolNumber {
		n := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(orig)
		b = make([]byte, n)
		ip := header.IPv4(b)
		ip.Encode(&header.IPv4Fields{
			TotalLength: uint16(n),
			TTL:         64,
			Protocol:    uint8(header.ICMPv4ProtocolNumber),
			SrcAddr:     icmpRemoteAddr4,
			DstAddr:     icmpLocalAddr4,
		})
		ip.SetChecksum(^ip.CalculateChecksum())
		icmp := header.ICMPv4(b[header.IPv4MinimumSize:])
		icmp.SetType(header.ICMPv4DstUnreachable)
		icmp.SetCode(header.ICMPv4Code(code))
		copy(icmp.Payload(), orig)
		icmp.SetChecksum(header.ICMPv4Checksum(icmp[:header.ICMPv4MinimumSize], checksum.Checksum(icmp.Payload(), 0)))
	} else {
		n := header.ICMPv6DstUnreachableMinimumSize + len(orig)
		b = make([]byte, header.IPv6MinimumSize+n)
		header.IPv6(b).Encode(&header.IPv6Fields{
			PayloadLength:     uint16(n),
			TransportProtocol: header.ICMPv6ProtocolNumber,
			HopLimit:          64,
			SrcAddr:           icmpRemoteAddr,
			DstAddr:           icmpLocalAddr,
		})
		icmp := header.ICMPv6(b[header.IPv6MinimumSize:])
		icmp.SetType(header.ICMPv6DstUnreachable)
		icmp.SetCode(header.ICMPv6Code(code))
		copy(icmp.Payload(), orig)
		icmp.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: icmp, Src: icmpRemoteAddr, Dst: icmpLocalAddr}))
	}
	return stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
}
