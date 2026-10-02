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
	"math"
	"testing"
	"time"
)

// A loss at a cwnd of 1, as in RTO recovery, leaves the CUBIC WMax below 1
// and the CUBIC target below cwnd. The ACKs must not lower cwnd.
func TestCubicCwndAfterLossInRTORecovery(t *testing.T) {
	const srtt = 20 * time.Millisecond
	cases := []struct {
		name  string
		acked int
	}{
		{name: "1 segment per ACK", acked: 1},
		{name: "3 segments per ACK", acked: 3},
		{name: "10 segments per ACK", acked: 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, "cubic", false)
			p.ep.LockUser()
			defer p.ep.UnlockUser()
			s := p.ep.snd
			c := s.cc.(*cubicState)
			s.rtt.Lock()
			s.rtt.TCPRTTState.SRTT = srtt
			s.rtt.Unlock()
			// HandleLossDetected with fast convergence at a cwnd of 1.
			c.T = s.ep.stack.Clock().NowMonotonic()
			c.WLastMax = 1
			c.WMax = 0.85
			c.K = math.Cbrt(c.WMax * (1 - c.Beta) / c.C)
			s.Ssthresh = 2
			s.SndCwnd = 2
			for i := 0; i < 5; i++ {
				c.Update(tc.acked, srtt)
				if s.SndCwnd < 2 {
					t.Fatalf("cwnd %d after ACK %d, want 2 or more", s.SndCwnd, i)
				}
			}
		})
	}
}
