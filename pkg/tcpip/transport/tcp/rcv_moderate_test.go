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
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// The moderated receive buffer gives a window of 2 times the data that the
// application read in one RTT, as Linux tcp_rcv_space_adjust does.
func TestModerateRecvBufWindow(t *testing.T) {
	const maxBuf = 32 << 20
	cases := []struct {
		name   string
		copied int
		// wantMax is set when the buffer stops at the maximum.
		wantMax bool
	}{
		{name: "below the max", copied: 1 << 20},
		{name: "at the max", copied: 64 << 20, wantMax: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSimPeer(t, "cubic", false)
			opt := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: maxBuf}
			if err := p.ep.stack.SetTransportProtocolOption(ProtocolNumber, &opt); err != nil {
				t.Fatalf("set the receive buffer range: %v", err)
			}
			const rtt = 10 * time.Millisecond
			p.ep.rcvQueueMu.Lock()
			p.ep.RcvAutoParams.Disabled = false
			p.ep.RcvAutoParams.RTT = rtt
			p.ep.RcvAutoParams.MeasureTime = p.clock.NowMonotonic()
			p.ep.RcvAutoParams.CopiedBytes = 0
			// One byte less than this RTT, so that the buffer grows with no slow-start part.
			p.ep.RcvAutoParams.PrevCopiedBytes = tc.copied - 1
			p.ep.rcvQueueMu.Unlock()
			p.clock.Advance(rtt)
			p.ep.ModerateRecvBuf(tc.copied)

			p.ep.LockUser()
			buf := int(p.ep.ops.GetReceiveBufferSize())
			wnd := int(p.ep.selectWindow())
			p.ep.UnlockUser()
			if buf > maxBuf {
				t.Errorf("buffer %d, more than the max %d", buf, maxBuf)
			}
			if tc.wantMax {
				if buf != maxBuf {
					t.Errorf("buffer %d, want the max %d", buf, maxBuf)
				}
				return
			}
			if wnd < 2*tc.copied {
				t.Errorf("window %d with buffer %d, want 2 times the %d bytes read or more", wnd, buf, tc.copied)
			}
		})
	}
}
