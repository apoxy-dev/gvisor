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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

func sb(start, end seqnum.Value) header.SACKBlock {
	return header.SACKBlock{Start: start, End: end}
}

// newPartSender returns a sender with the scoreboard ranges, SndUna 0 and SndNxt 10000.
func newPartSender(board []header.SACKBlock) *sender {
	s := &sender{ep: &Endpoint{scoreboard: NewSACKScoreboard(100, 0)}}
	s.ep.SACKPermitted = true
	s.ccsim = &ccsimSenderState{}
	s.SndNxt = 10000
	for _, r := range board {
		s.ep.scoreboard.Insert(r)
	}
	s.ccsimInitSACKWalk()
	return s
}

func TestNoteNewSACK(t *testing.T) {
	var many []header.SACKBlock
	for i := seqnum.Value(0); i < 20; i++ {
		many = append(many, sb(1000+20*i, 1010+20*i))
	}
	cases := []struct {
		name   string
		board  []header.SACKBlock
		ack    seqnum.Value
		blocks []header.SACKBlock
		want   []ccsimSACKPart
	}{
		{name: "empty board", blocks: []header.SACKBlock{sb(100, 200)},
			want: []ccsimSACKPart{{sb(100, 200), sb(100, 200)}}},
		{name: "right edge grows", board: []header.SACKBlock{sb(100, 150)}, blocks: []header.SACKBlock{sb(100, 200)},
			want: []ccsimSACKPart{{sb(150, 200), sb(100, 200)}}},
		{name: "hole filled", board: []header.SACKBlock{sb(100, 150), sb(170, 200)}, blocks: []header.SACKBlock{sb(100, 200)},
			want: []ccsimSACKPart{{sb(150, 170), sb(100, 200)}}},
		{name: "both edges grow", board: []header.SACKBlock{sb(120, 150)}, blocks: []header.SACKBlock{sb(100, 200)},
			want: []ccsimSACKPart{{sb(100, 120), sb(100, 200)}, {sb(150, 200), sb(100, 200)}}},
		{name: "range before the block", board: []header.SACKBlock{sb(50, 120)}, blocks: []header.SACKBlock{sb(100, 200)},
			want: []ccsimSACKPart{{sb(120, 200), sb(100, 200)}}},
		{name: "known block", board: []header.SACKBlock{sb(100, 200)}, blocks: []header.SACKBlock{sb(120, 180)}},
		{name: "sorted", blocks: []header.SACKBlock{sb(300, 400), sb(100, 200)},
			want: []ccsimSACKPart{{sb(100, 200), sb(100, 200)}, {sb(300, 400), sb(300, 400)}}},
		{name: "below the ACK", ack: 150, blocks: []header.SACKBlock{sb(100, 150), sb(300, 400)},
			want: []ccsimSACKPart{{sb(300, 400), sb(300, 400)}}},
		{name: "after SndNxt", blocks: []header.SACKBlock{sb(9000, 11000)}},
		{name: "too many parts", board: many, blocks: []header.SACKBlock{sb(2000, 2100), sb(1000, 1500)},
			want: []ccsimSACKPart{{sb(1000, 1500), sb(1000, 1500)}, {sb(2000, 2100), sb(2000, 2100)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newPartSender(tc.board)
			s.ep.mu.Lock()
			defer s.ep.mu.Unlock()
			rcvd := &segment{ackNumber: tc.ack}
			rcvd.parsedOptions.SACKBlocks = tc.blocks
			s.ccsimNoteNewSACK(rcvd)
			got := append([]ccsimSACKPart(nil), s.ccsim.newSACK[:s.ccsim.nNewSACK]...)
			if len(got) == 0 {
				got = nil
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func BenchmarkNoteNewSACK(b *testing.B) {
	var board []header.SACKBlock
	for i := seqnum.Value(0); i < 64; i++ {
		board = append(board, sb(100*i, 100*i+50))
	}
	s := newPartSender(board)
	s.ep.mu.Lock()
	defer s.ep.mu.Unlock()
	rcvd := &segment{}
	rcvd.parsedOptions.SACKBlocks = []header.SACKBlock{sb(6300, 6400), sb(3200, 3300), sb(1000, 1050)}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.ccsimNoteNewSACK(rcvd)
	}
}
