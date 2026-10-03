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
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

// linkDispatcher gives the packets of GRO to a channel endpoint.
type linkDispatcher struct{ link *channel.Endpoint }

func (d linkDispatcher) DeliverNetworkPacket(proto tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.link.InjectInbound(proto, pkt)
}

func (linkDispatcher) DeliverLinkPacket(tcpip.NetworkProtocolNumber, *stack.PacketBuffer) {}

// dataPacket returns a data segment of the peer at seq with a valid checksum.
func (p *simPeer) dataPacket(seq seqnum.Value, data []byte) *stack.PacketBuffer {
	buf := make([]byte, header.IPv4MinimumSize+header.TCPMinimumSize+len(data))
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
		AckNum:     uint32(p.iss),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagAck,
		WindowSize: 65535,
	})
	copy(th.Payload(), data)
	xsum := header.PseudoHeaderChecksum(ProtocolNumber, peerRemoteAddr, peerLocalAddr, uint16(len(th)))
	th.SetChecksum(^th.CalculateChecksum(checksum.Combine(xsum, checksum.Checksum(data, 0))))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(buf)})
	pkt.NetworkProtocolNumber = ipv4.ProtocolNumber
	return pkt
}

// TestGRO gives in-order data segments of the peer to GRO on a link with no
// RX checksum offload. The NIC keeps the checksum check of GRO, so the
// endpoint gets the joined segments. A segment with a bad checksum drops.
func TestGRO(t *testing.T) {
	const segs, size = 4, 100
	cases := []struct {
		name      string
		bad       int // Index of a segment with a bad checksum, or -1.
		wantData  int // Bytes that the endpoint can read.
		wantValid uint64
		wantBad   uint64
	}{
		// The four segments become one.
		{name: "valid", bad: -1, wantData: segs * size, wantValid: 1},
		// GRO gives the bad segment to the NIC at once. The first segment
		// follows. The last two become one segment that is out of order.
		{name: "bad checksum", bad: 1, wantData: size, wantValid: 2, wantBad: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, ccCubic, false)
			st := p.ep.stack.Stats().TCP
			valid, bad := st.ValidSegmentsReceived.Value(), st.ChecksumErrors.Value()
			g := &gro.GRO{Dispatcher: linkDispatcher{p.link}}
			g.Init(true)
			data := make([]byte, segs*size)
			for i := range data {
				data[i] = byte(i)
			}
			for i := range segs {
				pkt := p.dataPacket(p.peerSeq.Add(seqnum.Size(i*size)), data[i*size:(i+1)*size])
				if i == tc.bad {
					b, _ := pkt.Data().PullUp(pkt.Data().Size())
					b[len(b)-1] ^= 1
				}
				g.Enqueue(pkt)
				pkt.DecRef()
			}
			g.Flush()

			var got bytes.Buffer
			for deadline := time.Now().Add(5 * time.Second); got.Len() < tc.wantData && time.Now().Before(deadline); {
				if _, err := p.ep.Read(&got, tcpip.ReadOptions{}); err != nil {
					if _, ok := err.(*tcpip.ErrWouldBlock); !ok {
						t.Fatalf("read: %v", err)
					}
					time.Sleep(time.Millisecond)
				}
			}
			if !bytes.Equal(got.Bytes(), data[:tc.wantData]) {
				t.Errorf("endpoint read %d bytes, want the first %d bytes of the data", got.Len(), tc.wantData)
			}
			for deadline := time.Now().Add(5 * time.Second); st.ValidSegmentsReceived.Value()-valid < tc.wantValid && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
			if got := st.ValidSegmentsReceived.Value() - valid; got != tc.wantValid {
				t.Errorf("ValidSegmentsReceived = %d, want %d", got, tc.wantValid)
			}
			if got := st.ChecksumErrors.Value() - bad; got != tc.wantBad {
				t.Errorf("ChecksumErrors = %d, want %d", got, tc.wantBad)
			}
		})
	}
}
