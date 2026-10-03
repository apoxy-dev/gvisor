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

package gro

import (
	"bytes"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// recorder keeps a copy of each packet that GRO gives.
type recorder struct{ pkts [][]byte }

func (r *recorder) DeliverNetworkPacket(_ tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	v := pkt.ToView()
	r.pkts = append(r.pkts, bytes.Clone(v.AsSlice()))
	v.Release()
}

func (*recorder) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// tcp6 returns an IPv6 TCP packet with valid checksums. With hbh, a
// hop-by-hop options header comes before the TCP header.
func tcp6(hbh bool, seq uint32, payload []byte) *stack.PacketBuffer {
	src := tcpip.AddrFrom16([16]byte{0xfd, 15: 1})
	dst := tcpip.AddrFrom16([16]byte{0xfd, 15: 2})
	ext := 0
	if hbh {
		ext = 8
	}
	tcpLen := header.TCPMinimumSize + len(payload)
	b := make([]byte, header.IPv6MinimumSize+ext+tcpLen)
	next := header.TCPProtocolNumber
	if hbh {
		next = tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier)
		// The next header is TCP, and a PadN option fills the header.
		copy(b[header.IPv6MinimumSize:], []byte{uint8(header.TCPProtocolNumber), 0, 1, 4})
	}
	header.IPv6(b).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(ext + tcpLen),
		TransportProtocol: next,
		HopLimit:          64,
		SrcAddr:           src,
		DstAddr:           dst,
	})
	tcp := header.TCP(b[header.IPv6MinimumSize+ext:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    1000,
		DstPort:    443,
		SeqNum:     seq,
		AckNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 512,
	})
	copy(tcp.Payload(), payload)
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, src, dst, uint16(tcpLen))
	tcp.SetChecksum(^tcp.CalculateChecksum(checksum.Combine(xsum, checksum.Checksum(payload, 0))))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
	pkt.NetworkProtocolNumber = header.IPv6ProtocolNumber
	return pkt
}

// TestGRO6 joins IPv6 TCP segments with and without an extension header.
func TestGRO6(t *testing.T) {
	const segs, size = 4, 100
	for _, tc := range []struct {
		name string
		hbh  bool
	}{
		{name: "no extension header"},
		{name: "hop-by-hop", hbh: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &recorder{}
			g := &GRO{Dispatcher: r}
			g.Init(true)
			data := make([]byte, segs*size)
			for i := range data {
				data[i] = byte(i)
			}
			for i := range segs {
				pkt := tcp6(tc.hbh, uint32(i*size), data[i*size:(i+1)*size])
				g.Enqueue(pkt)
				pkt.DecRef()
			}
			g.Flush()
			if len(r.pkts) != 1 {
				t.Fatalf("got %d packets, want 1", len(r.pkts))
			}
			p := r.pkts[0]
			ipLen := len(p) - header.TCPMinimumSize - len(data)
			if got, want := int(header.IPv6(p).PayloadLength()), len(p)-header.IPv6MinimumSize; got != want {
				t.Errorf("payload length = %d, want %d", got, want)
			}
			if got := header.TCP(p[ipLen:]).Payload(); !bytes.Equal(got, data) {
				t.Errorf("joined payload has %d bytes, want the %d bytes of the segments", len(got), len(data))
			}
		})
	}
}

// discard drops the packets that GRO gives.
type discard struct{}

func (discard) DeliverNetworkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

func (discard) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// BenchmarkGRO6 makes 64 IPv6 TCP segments of one flow and joins them.
func BenchmarkGRO6(b *testing.B) {
	for _, hbh := range []bool{false, true} {
		name := "no extension header"
		if hbh {
			name = "hop-by-hop"
		}
		b.Run(name, func(b *testing.B) {
			const segs, size = 64, 1200
			data := make([]byte, segs*size)
			g := &GRO{Dispatcher: discard{}}
			g.Init(true)
			b.ReportAllocs()
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				for i := range segs {
					pkt := tcp6(hbh, uint32(i*size), data[i*size:(i+1)*size])
					g.Enqueue(pkt)
					pkt.DecRef()
				}
				g.Flush()
			}
		})
	}
}
