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
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// The data of an endpoint in the link queue is the data of 1 ms at the send
// rate, from tsqMinBytes to tsqMaxBytes.
const (
	tsqMinBytes = 128 << 10
	tsqMaxBytes = 1 << 20
)

// tsq limits the packets of an endpoint in the queue of a link with
// stack.CapabilityTxNotify, as TCP small queues in Linux.
type tsq struct {
	ep *Endpoint
	// queued is the number of packets in the link queue.
	queued atomicbitops.Int32
	// wake is the queued count at which TxDequeued continues the sends.
	wake atomicbitops.Int32
	// throttled is set when the limit stops a send.
	throttled atomicbitops.Bool
	// resume is set when the processor must continue the sends.
	resume atomicbitops.Bool
}

// TxQueued implements stack.TxNotifier.
func (q *tsq) TxQueued() { q.queued.Add(1) }

// TxDequeued implements stack.TxNotifier. It runs on the reader of the link
// queue and takes no endpoint lock.
func (q *tsq) TxDequeued() {
	if q.queued.Add(-1) > q.wake.Load() || !q.throttled.CompareAndSwap(true, false) {
		return
	}
	e := q.ep
	// UnlockUser reads resume under the same lock, so a user that holds the
	// endpoint wakes the processor when it unlocks.
	e.segmentQueue.mu.Lock()
	q.resume.Store(true)
	owned := e.isOwnedByUser()
	e.segmentQueue.mu.Unlock()
	if !owned {
		e.protocol.dispatcher.selectProcessor(e.ID).queueEndpoint(e)
	}
}

// tsqResumePending reports whether the processor must continue the sends of
// e. It drops the wake of an endpoint that cannot send.
func (e *Endpoint) tsqResumePending() bool {
	if !e.tsq.resume.Load() {
		return false
	}
	if st := e.EndpointState(); st.connected() && st != StateTimeWait {
		return true
	}
	e.tsq.resume.Store(false)
	return false
}

// tsqAllows reports whether the link queue has room for a send. If not, the
// link wakes the endpoint when the queue holds half of the limit.
//
// +checklocks:s.ep.mu
func (s *sender) tsqAllows() bool {
	q := &s.ep.tsq
	n := q.queued.Load()
	if int(n) < tsqMinBytes/s.MaxPayloadSize {
		return true
	}
	limit := s.tsqLimit()
	if n < limit {
		return true
	}
	q.wake.Store(limit / 2)
	q.throttled.Store(true)
	// The reader can take packets before it sees throttled. Then this read
	// sees them, so that no wake is lost.
	return q.queued.Load() < limit && q.throttled.CompareAndSwap(true, false)
}

// tsqLimit returns the most packets of the endpoint in the link queue. The
// rate is the pacing rate, or cwnd/SRTT.
//
// +checklocks:s.ep.mu
func (s *sender) tsqLimit() int32 {
	var perMs float64 // Bytes in 1 ms.
	if st := s.ccsim; st != nil && st.wrap.pacingBps > 0 {
		perMs = float64(st.wrap.pacingBps) / 8000
	} else {
		s.rtt.Lock()
		srtt := s.rtt.TCPRTTState.SRTT
		s.rtt.Unlock()
		if srtt > 0 {
			perMs = float64(s.SndCwnd) * float64(s.MaxPayloadSize) * float64(time.Millisecond) / float64(srtt)
		}
	}
	b := min(max(perMs, tsqMinBytes), tsqMaxBytes)
	return int32(max(int(b)/s.MaxPayloadSize, 1))
}

// xmitAllows reports whether the link queue limit and pacing permit a send
// now. If not, a wake from the link or the pacing timer continues the sends.
//
// +checklocks:s.ep.mu
func (s *sender) xmitAllows() bool {
	return s.tsqAllows() && s.ccsimPacingAllows()
}

// resumeXmit continues the sends that the link queue limit or pacing stopped.
//
// +checklocks:s.ep.mu
func (s *sender) resumeXmit() {
	st := s.ccsim
	if st != nil && st.tlpProbePending {
		s.ccsimSendTLPProbe()
		return
	}
	if s.FastRecovery.Active {
		if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
			// Send the RACK repairs first. sendData then sends new data.
			s.rc.DoRecovery(nil, false /* fastRetransmit */)
		} else {
			if st != nil && st.recoveryResendPending {
				s.resendSegment()
				if st.recoveryResendPending {
					return
				}
			}
			if sr, ok := s.lr.(*sackRecovery); ok && s.ep.SACKPermitted {
				// sr.s is s, so s.ep.mu is held.
				dataSent := sr.handleSACKRecovery(s.MaxPayloadSize, s.SndUna.Add(s.SndWnd)) // +checklocksignore
				s.postXmit(dataSent, true /* shouldScheduleProbe */)
				return
			}
		}
	}
	s.sendData()
}
