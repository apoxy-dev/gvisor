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

package channel

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestWritePacketsFullQueue writes packets to an endpoint with a queue of 2.
func TestWritePacketsFullQueue(t *testing.T) {
	cases := []struct {
		name   string
		queued int // Packets in the queue before the write.
		write  int // Packets in the write.
		wantN  int
		full   bool // The write returns ErrNoBufferSpace.
	}{
		{name: "room for all", write: 2, wantN: 2},
		{name: "room for some", queued: 1, write: 2, wantN: 1},
		{name: "queue full", queued: 2, write: 1, full: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := New(2, 1280, "")
			defer ep.Close()
			defer ep.Drain()
			write := func(n int) (int, tcpip.Error) {
				var pkts stack.PacketBufferList
				for range n {
					pkts.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{}))
				}
				defer pkts.DecRef()
				return ep.WritePackets(pkts)
			}
			if n, err := write(tc.queued); n != tc.queued || err != nil {
				t.Fatalf("write(%d) = %d, %v", tc.queued, n, err)
			}
			n, err := write(tc.write)
			if _, full := err.(*tcpip.ErrNoBufferSpace); n != tc.wantN || full != tc.full || err != nil && !full {
				t.Errorf("WritePackets = %d, %v, want %d and ErrNoBufferSpace %t", n, err, tc.wantN, tc.full)
			}
			if got, want := ep.NumQueued(), min(tc.queued+tc.write, 2); got != want {
				t.Errorf("NumQueued = %d, want %d", got, want)
			}
		})
	}
}

// TestNICCountsFullQueue checks that the NIC counts a packet that does not
// fit in the queue as a drop, and not as sent.
func TestNICCountsFullQueue(t *testing.T) {
	const nicID = 1
	ep := New(1, 1280, "")
	defer ep.Drain()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	defer s.Destroy()
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	if err := s.WritePacketToRemote(nicID, "", header.IPv4ProtocolNumber, buffer.MakeWithData([]byte{1})); err != nil {
		t.Fatalf("first write: %v", err)
	}
	err := s.WritePacketToRemote(nicID, "", header.IPv4ProtocolNumber, buffer.MakeWithData([]byte{2}))
	if _, ok := err.(*tcpip.ErrNoBufferSpace); !ok {
		t.Errorf("second write: got %v, want ErrNoBufferSpace", err)
	}
	stats := s.NICInfo()[nicID].Stats
	if got := stats.Tx.Packets.Value(); got != 1 {
		t.Errorf("Tx.Packets = %d, want 1", got)
	}
	if got := stats.TxPacketsDroppedNoBufferSpace.Value(); got != 1 {
		t.Errorf("TxPacketsDroppedNoBufferSpace = %d, want 1", got)
	}
}

// txCounter counts the TxNotify calls for the packets of one sender.
type txCounter struct{ queued, dequeued int }

func (c *txCounter) TxQueued()   { c.queued++ }
func (c *txCounter) TxDequeued() { c.dequeued++ }

// TestTxNotify writes packets with a TxNotify to an endpoint with a queue of
// 2, and then takes the packets out of the queue.
func TestTxNotify(t *testing.T) {
	// take returns a packet that a reader took. Its second call of
	// NotifyTxDequeued must do nothing.
	take := func(t *testing.T, p *stack.PacketBuffer) {
		if p.TxNotify != nil {
			t.Errorf("packet from the queue has TxNotify %v", p.TxNotify)
		}
		p.NotifyTxDequeued()
		p.DecRef()
	}
	read := func(t *testing.T, ep *Endpoint) {
		for p := ep.Read(); p != nil; p = ep.Read() {
			take(t, p)
		}
	}
	readContext := func(t *testing.T, ep *Endpoint) {
		for ep.NumQueued() > 0 {
			take(t, ep.ReadContext(context.Background()))
		}
	}
	cases := []struct {
		name    string
		write   int  // Packets with a TxNotify.
		senders int  // Packet i has the TxNotify of sender i%senders.
		clone   bool // Also write a clone of each packet, which has no TxNotify.
		take    func(*testing.T, *Endpoint)
		// The calls for each sender after the writes, and after take.
		wantQueued, wantDequeuedAtWrite, wantDequeued int
	}{
		{name: "read", write: 2, senders: 1, take: read, wantQueued: 2, wantDequeued: 2},
		{name: "read context", write: 2, senders: 1, take: readContext, wantQueued: 2, wantDequeued: 2},
		{name: "drain", write: 2, senders: 1, take: func(_ *testing.T, ep *Endpoint) { ep.Drain() }, wantQueued: 2, wantDequeued: 2},
		{name: "close", write: 2, senders: 1, take: func(_ *testing.T, ep *Endpoint) { ep.Close() }, wantQueued: 2, wantDequeued: 2},
		{name: "queue full", write: 3, senders: 1, take: read, wantQueued: 3, wantDequeuedAtWrite: 1, wantDequeued: 3},
		{name: "cloned packet", write: 1, senders: 1, clone: true, take: read, wantQueued: 1, wantDequeued: 1},
		{name: "two senders", write: 2, senders: 2, take: read, wantQueued: 1, wantDequeued: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := New(2, 1280, "")
			defer ep.Close()
			c := make([]txCounter, tc.senders)
			write := func(p *stack.PacketBuffer) {
				var pkts stack.PacketBufferList
				pkts.PushBack(p)
				ep.WritePackets(pkts)
				pkts.DecRef()
			}
			for i := range tc.write {
				p := stack.NewPacketBuffer(stack.PacketBufferOptions{})
				p.TxNotify = &c[i%tc.senders]
				if tc.clone {
					clone := p.Clone()
					if clone.TxNotify != nil {
						t.Errorf("clone has TxNotify %v", clone.TxNotify)
					}
					write(clone)
				}
				write(p)
			}
			for i, c := range c {
				if c.queued != tc.wantQueued || c.dequeued != tc.wantDequeuedAtWrite {
					t.Errorf("sender %d after the writes: TxQueued %d, TxDequeued %d calls, want %d, %d", i, c.queued, c.dequeued, tc.wantQueued, tc.wantDequeuedAtWrite)
				}
			}
			tc.take(t, ep)
			for i, c := range c {
				if c.queued != tc.wantQueued || c.dequeued != tc.wantDequeued {
					t.Errorf("sender %d after take: TxQueued %d, TxDequeued %d calls, want %d, %d", i, c.queued, c.dequeued, tc.wantQueued, tc.wantDequeued)
				}
			}
		})
	}
}
