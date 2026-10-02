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
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// RACK puts segments with the same send time in sequence order. Only the
// segments that end before RACK.end_seq are older, so only they can be lost.
func TestRACKSameSendTimeOrder(t *testing.T) {
	cases := []struct {
		name string
		// rackEnd is RACK.end_seq. Segment i holds byte i.
		rackEnd  seqnum.Value
		wantLost []bool
	}{
		{name: "RACK at the first segment", rackEnd: 1, wantLost: []bool{false, false, false}},
		{name: "RACK at the second segment", rackEnd: 2, wantLost: []bool{true, false, false}},
		{name: "RACK at the last segment", rackEnd: 3, wantLost: []bool{true, true, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clock := faketime.NewManualClock()
			st := stack.New(stack.Options{Clock: clock})
			defer st.Destroy()
			var s sender
			s.ep = &Endpoint{stack: st, scoreboard: NewSACKScoreboard(1, 0)}
			s.writeList.set = map[*segment]struct{}{}
			s.reorderTimer.init(clock, func() {})
			defer s.reorderTimer.cleanup()
			s.rc.init(&s, 0)
			now := clock.NowMonotonic()
			s.rc.XmitTime = now
			s.rc.EndSequence = tc.rackEnd
			for i := range tc.wantLost {
				seg := newOutgoingSegment(stack.TransportEndpointID{}, clock, buffer.MakeWithView(buffer.NewViewSize(1)))
				defer seg.DecRef()
				seg.sequenceNumber = seqnum.Value(i)
				seg.xmitCount = 1
				seg.xmitTime = now
				s.writeList.PushBack(seg)
			}
			s.rc.detectLoss(now)
			i := 0
			for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
				if seg.lost != tc.wantLost[i] {
					t.Errorf("segment %d: lost %t, want %t", i, seg.lost, tc.wantLost[i])
				}
				i++
			}
		})
	}
}
