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

// Sim congestion control: delivery-rate samples, pacing and RACK queues for a registered SimCC.
// Reno and cubic do not use it. The ccsim names match apoxy-dev/ccsim, where this code is simulated.

package tcp

import (
	"math"
	"math/bits"
	"sort"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

// SimRateSample is one delivery-rate sample per ACK.
type SimRateSample struct {
	// Now is the monotonic receive time of the ACK.
	Now time.Duration
	// AckedBytes is the payload newly delivered by this ACK, cumulative and SACKed.
	AckedBytes int64
	// Delivered is the cumulative delivered byte count.
	Delivered int64
	// DeliveredBytes is the volume delivered in this sample interval.
	DeliveredBytes int64
	// DeliveredCEBytes is the CE-marked part of DeliveredBytes.
	DeliveredCEBytes int64
	// PriorDelivered is Delivered when the sampled segment was sent, or -1 for no sample.
	PriorDelivered int64
	// DeliveryRateBps is the sampled delivery rate, or 0 if not valid.
	DeliveryRateBps int64
	// RTT is the RTT of the sampled segment, or 0 for a retransmission.
	RTT time.Duration
	// IsAckDelayed is true when the ACK can be a delayed ACK: it ACKs one lone runt and nothing is SACKed.
	IsAckDelayed bool
	// IsAckingTLPRetransmit is true when the ACK covers a tail-loss probe repair.
	IsAckingTLPRetransmit bool
	// Interval is the sample interval of the rate.
	Interval time.Duration
	// IsAppLimited is true when the sampled segment was sent app-limited.
	IsAppLimited bool
	// InflightBytes is the bytes in flight after the ACK.
	InflightBytes int64
	// ECE is true if the ACK has the ECN echo flag.
	ECE bool
	// TxInflight is the bytes in flight when the sampled segment was sent.
	TxInflight int64
	// LostBytes is the volume marked lost since the sampled segment was sent.
	LostBytes int64
	// LostBytesCum is the cumulative marked-lost byte count.
	LostBytesCum int64
	// IsCwndLimited is true when the last send used all of cwnd.
	IsCwndLimited bool
}

// SimSender is the sender handle given to registered congestion controls.
// The sender calls the congestion control with s.ep.mu held. The callers in other packages
// cannot name that lock, so the methods that use the sender state have +checklocksignore.
type SimSender struct{ s *sender }

// MSS returns the sender's maximum payload size.
//
// +checklocksignore
func (h SimSender) MSS() int { return h.s.MaxPayloadSize }

// CwndPkts returns the congestion window in packets.
//
// +checklocksignore
func (h SimSender) CwndPkts() int { return h.s.SndCwnd }

// SetCwndPkts sets the congestion window in packets, with a floor of 1.
//
// +checklocksignore
func (h SimSender) SetCwndPkts(c int) {
	if c < 1 {
		c = 1
	}
	h.s.SndCwnd = c
}

// SetPacingRateBps sets the pacing rate in bits/s. 0 disables pacing.
func (h SimSender) SetPacingRateBps(bps int64) {
	if h.s.ccsim != nil {
		h.s.ccsim.wrap.pacingBps = bps
	}
}

// SRTT returns the smoothed RTT.
func (h SimSender) SRTT() time.Duration {
	h.s.rtt.Lock()
	defer h.s.rtt.Unlock()
	return h.s.rtt.TCPRTTState.SRTT
}

// Now returns the stack's monotonic time.
func (h SimSender) Now() time.Duration {
	return h.s.ep.stack.Clock().NowMonotonic().Sub(tcpip.MonotonicTime{})
}

// InRecovery reports whether the sender is in loss recovery.
func (h SimSender) InRecovery() bool { return h.s.inRecovery() }

// LocalPort returns the local port of the connection.
func (h SimSender) LocalPort() uint16 { return h.s.ep.ID.LocalPort }

// SetSsthresh sets the slow-start threshold in packets, with a floor of 2.
//
// +checklocksignore
func (h SimSender) SetSsthresh(v int) {
	if v < 2 {
		v = 2
	}
	h.s.Ssthresh = v
}

// Seed returns a random seed for the per-flow random stream.
func (h SimSender) Seed() uint64 { return h.s.ep.stack.InsecureRNG().Uint64() }

// ECNLowLatency returns false. Netstack does not negotiate ECN.
func (h SimSender) ECNLowLatency() bool { return false }

// MarkAppLimited marks data sent from now on as app-limited until it is ACKed.
//
// +checklocksignore
func (h SimSender) MarkAppLimited() {
	st := h.s.ccsim
	st.appLimited = true
	st.appLimitedSeq = h.s.SndNxt
}

// SimCC is the interface of a registered congestion control.
type SimCC interface {
	HandleLossDetected()
	HandleRTOExpired()
	Update(packetsAcked int, rtt time.Duration)
	PostRecovery()
	// OnAck gets one rate sample per ACK, before more data is sent.
	OnAck(SimRateSample)
}

// SimCCWithUndo restores the model when recovery was spurious.
type SimCCWithUndo interface {
	UndoRecovery()
}

// SimCCWithIdleRestart handles a new flight after an app-limited idle period.
type SimCCWithIdleRestart interface {
	HandleRestartFromIdle()
}

// SimLossProbeRecovery describes a loss that a tail-loss probe repaired.
type SimLossProbeRecovery struct {
	LostBytes    int64
	LostBytesCum int64
	// IsAppLimited is the app-limited state of the original transmission.
	IsAppLimited bool
}

// SimCCWithLossProbeRecovery handles a loss repaired by a tail-loss probe.
type SimCCWithLossProbeRecovery interface {
	HandleLossProbeRecovery(SimLossProbeRecovery)
}

var simCCRegistry = map[string]func(SimSender) SimCC{}

// RegisterSimCC registers a congestion control under name.
// Call it only from init. The registry has no lock.
func RegisterSimCC(name string, f func(SimSender) SimCC) {
	simCCRegistry[name] = f
}

func simRegisteredCCNames() []string {
	names := make([]string, 0, len(simCCRegistry))
	for n := range simCCRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ccsimSenderState is the state of a sender with a sim congestion control.
// The sender has it only while a sim congestion control is selected. All ccsim hooks do nothing without it.
type ccsimSenderState struct {
	wrap *ccsimWrapper

	pacingTimer timer
	nextSend    tcpip.MonotonicTime
	// pacingBurst is the number of bytes that the current burst can still send.
	pacingBurst int

	// Delivery rate estimation.
	delivered     int64
	deliveredCE   int64
	deliveredTime tcpip.MonotonicTime
	firstSent     tcpip.MonotonicTime
	appLimitedSeq seqnum.Value // App-limited until this sequence is ACKed.
	appLimited    bool
	// idleRestartEligible is set when the application ran out of data.
	idleRestartEligible bool
	// idleRestartNotified stops repeated idle-restart events for one flight.
	idleRestartNotified bool

	// lostCum is the cumulative marked-lost byte count.
	lostCum int64
	// cwndLimited is true when the last sendData used all of cwnd.
	cwndLimited bool

	// Scratch for ccsimSetPipe: scoreboard ranges and suffix byte sums.
	pipeRanges   []header.SACKBlock
	pipeSufBytes []seqnum.Size
	// pipeLostSeq is the start of the last lost segment that ccsimSetPipe found, if pipeLost is set.
	pipeLostSeq seqnum.Value
	pipeLost    bool
	// rackPipe is the number of transmissions that RACK counts in flight.
	rackPipe int
	// rackSent is in transmit-time order. rackLost holds repairs in sequence order.
	rackSentHead *segment
	rackSentTail *segment
	rackLostHead *segment
	rackLostTail *segment
	// rackLost is the number of segments in the rackLost queue.
	rackLost int
	// newSACK holds the parts of the SACK blocks of this ACK that are new to the scoreboard.
	newSACK  [16]ccsimSACKPart
	nNewSACK int
	// newSACKFull is set when newSACK has no space for all parts.
	newSACKFull bool
	// partBlock and partPos are the state of the scoreboard walk in ccsimAddSACKParts.
	partBlock      header.SACKBlock
	partPos        seqnum.Value
	partVisit      func(header.SACKBlock) bool
	partVisitFirst func(header.SACKBlock) bool
	// found is the result of findVisit in ccsimFindRange.
	found     header.SACKBlock
	foundOK   bool
	findVisit func(header.SACKBlock) bool

	// Scratch from ccsimPreAck for ccsimOnAck.
	ackPending bool
	// scratchSegs is the number of segments that the ACK fully ACKed or SACKed.
	scratchSegs        int
	scratchPartial     bool
	scratchPriorSACKed bool
	scratchAcked       int64
	scratchHasSample   bool
	scratchAckingTLP   bool
	scratchSeg         struct {
		delivered     int64
		deliveredTime tcpip.MonotonicTime
		firstSent     tcpip.MonotonicTime
		xmitTime      tcpip.MonotonicTime
		appLimited    bool
		isRetrans     bool
		txInflight    int64
		lostAtTx      int64
		deliveredCE   int64
	}

	// recoveryResendPending is set when pacing stopped the first fast retransmit.
	recoveryResendPending bool
	// tlpProbePending is set when pacing stopped a tail-loss probe.
	tlpProbePending bool
	// tlpOrigAppLimited is the app-limited state of the original tail segment.
	tlpOrigAppLimited bool
}

// ccsimSACKPart is a part of a received SACK block that is new to the scoreboard.
type ccsimSACKPart struct {
	part, block header.SACKBlock
}

// ccsimSegState is the rate and RACK state of a segment.
// A segment has it only after a transmit with a sim congestion control.
type ccsimSegState struct {
	delivered     int64
	deliveredCE   int64
	deliveredTime tcpip.MonotonicTime
	firstSent     tcpip.MonotonicTime
	appLimited    bool
	// counted is set when all of the segment is in delivered. A retransmission keeps it, as Linux keeps SACKED_ACKED.
	counted bool
	// sacked is the number of bytes that partial SACKs added to delivered.
	sacked int
	// txInflight is the bytes in flight at the last transmit, with this segment.
	txInflight int64
	// lostAtTx is lostCum at the last transmit.
	lostAtTx int64
	// lostCounted is set when the segment is in lostCum. A transmit clears it.
	lostCounted bool
	// rackPipeCopies is the number of live transmissions, 2 during a TLP.
	rackPipeCopies int
	rackSentPrev   *segment
	rackSentNext   *segment
	rackSentQueued bool
	rackLostPrev   *segment
	rackLostNext   *segment
	rackLostQueued bool
}

// ccsimSegPool keeps the ccsim state of freed segments.
var ccsimSegPool = sync.Pool{New: func() any { return new(ccsimSegState) }}

// ccsimSegOf returns the ccsim state of seg. It gets a new state on the first call.
func ccsimSegOf(seg *segment) *ccsimSegState {
	if seg.ccsim == nil {
		ss := ccsimSegPool.Get().(*ccsimSegState)
		*ss = ccsimSegState{}
		seg.ccsim = ss
	}
	return seg.ccsim
}

// ccsimFree puts the ccsim state of s back in the pool. DecRef calls it before it frees s.
func (s *segment) ccsimFree() {
	if ss := s.ccsim; ss != nil {
		if ss.rackSentQueued || ss.rackLostQueued {
			panic("tcp: freed segment is still on a RACK queue")
		}
		s.ccsim = nil
		ccsimSegPool.Put(ss)
	}
}

// ccsimWrapper is the congestionControl of a sender with a sim congestion control.
type ccsimWrapper struct {
	s         *sender
	sim       SimCC
	pacingBps int64
}

var _ congestionControl = (*ccsimWrapper)(nil)

func (w *ccsimWrapper) HandleLossDetected() { w.sim.HandleLossDetected() }

// +checklocks:w.s.ep.mu
func (w *ccsimWrapper) HandleRTOExpired() {
	// An RTO marks all un-SACKed data lost and stops the sends that pacing holds.
	w.s.ccsimMarkAllLost()
	w.s.ccsim.recoveryResendPending = false
	w.s.ccsim.tlpProbePending = false
	w.sim.HandleRTOExpired()
}

func (w *ccsimWrapper) Update(packetsAcked int, rtt time.Duration) {
	w.sim.Update(packetsAcked, rtt)
}

func (w *ccsimWrapper) PostRecovery() { w.sim.PostRecovery() }

// ccsimInitCC returns the sim congestion control for name, or nil for a stock one.
// It drops the old ccsim state. Only a sim congestion control gets a new one.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimInitCC(name tcpip.CongestionControlOption) congestionControl {
	f, ok := simCCRegistry[string(name)]
	if s.ccsim != nil {
		s.ccsimReset()
		s.ccsimSetSACKLimit()
	}
	if !ok {
		return nil
	}
	w := &ccsimWrapper{s: s}
	// Set the state first, so that the constructor can set the pacing rate.
	st := &ccsimSenderState{wrap: w}
	s.ccsim = st
	st.pacingTimer.init(s.ep.stack.Clock(), timerHandler(s.ep, st.pacingTimerExpired))
	s.ccsimInitSACKWalk()
	s.ccsimTrackInFlight()
	s.ccsimSetSACKLimit()
	w.sim = f(SimSender{s})
	return w
}

// ccsimSwitchCC sets the congestion control of an established flow.
// After a sim congestion control, it sends the work that the old pacing timer held, and arms the RTO or PTO.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimSwitchCC(name tcpip.CongestionControlOption) {
	sim := s.ccsim != nil
	s.cc = s.initCongestionControl(name)
	if sim {
		s.sendData()
	}
}

// ccsimReset drops the ccsim state of the sender and its segments.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimReset() {
	s.ccsimPurge()
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		seg.ccsimFree()
	}
	s.writeList.sackHint = nil
	s.ccsim.pacingTimer.cleanup()
	s.ccsim = nil
}

// ccsimTrackInFlight adds the segments in flight to the RACK queues after a change to a sim congestion control.
// Their rate state is not known, so they are app-limited.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimTrackInFlight() {
	st := s.ccsim
	if s.SndUna == s.SndNxt {
		return
	}
	st.appLimited = true
	st.appLimitedSeq = s.SndNxt
	rack := s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0
	for seg := s.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		ss := ccsimSegOf(seg)
		ss.appLimited = true
		if s.ep.SACKPermitted {
			// The SACKed data was delivered before the change. Do not count it again.
			if s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
				ss.counted = true
				continue
			}
			ss.sacked = s.ccsimSACKedIn(seg.sequenceNumber, rackSegmentEnd(seg))
		}
		if !rack {
			continue
		}
		if seg.lost {
			s.ccsimRACKInsertLost(seg)
			continue
		}
		s.ccsimRACKInsertSent(seg)
		n := s.pCount(seg, s.MaxPayloadSize)
		ss.rackPipeCopies = n
		st.rackPipe += n
	}
}

// ccsimSetSACKLimit sets the scoreboard block limit for the congestion control.
func (s *sender) ccsimSetSACKLimit() {
	if s.ep.scoreboard != nil {
		s.ep.scoreboard.ccsimBlocks = s.ccsim != nil
	}
}

// ccsimPurge empties the RACK queues. Call it before the segments are freed.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPurge() {
	st := s.ccsim
	if st == nil {
		return
	}
	for seg := s.writeList.Front(); seg != nil; seg = seg.Next() {
		if ss := seg.ccsim; ss != nil {
			ss.rackPipeCopies = 0
			ss.rackSentPrev, ss.rackSentNext, ss.rackSentQueued = nil, nil, false
			ss.rackLostPrev, ss.rackLostNext, ss.rackLostQueued = nil, nil, false
		}
	}
	st.rackSentHead, st.rackSentTail = nil, nil
	st.rackLostHead, st.rackLostTail = nil, nil
	st.rackLost, st.rackPipe = 0, 0
}

// rackSentAfter reports whether transmission 1 is after transmission 2.
// On a time tie, the higher end sequence is after (RFC 8985).
func rackSentAfter(t1 tcpip.MonotonicTime, end1 seqnum.Value, t2 tcpip.MonotonicTime, end2 seqnum.Value) bool {
	return t2.Before(t1) || (t1 == t2 && end2.LessThan(end1))
}

func rackSegmentEnd(seg *segment) seqnum.Value {
	return seg.sequenceNumber.Add(seqnum.Size(seg.payloadSize()))
}

func (s *sender) ccsimRACKUnlinkSent(seg *segment) {
	if !seg.ccsim.rackSentQueued {
		return
	}
	prev, next := seg.ccsim.rackSentPrev, seg.ccsim.rackSentNext
	if prev != nil {
		prev.ccsim.rackSentNext = next
	} else {
		s.ccsim.rackSentHead = next
	}
	if next != nil {
		next.ccsim.rackSentPrev = prev
	} else {
		s.ccsim.rackSentTail = prev
	}
	seg.ccsim.rackSentPrev = nil
	seg.ccsim.rackSentNext = nil
	seg.ccsim.rackSentQueued = false
}

// ccsimRACKInsertSent inserts seg in (transmit time, end sequence) order.
func (s *sender) ccsimRACKInsertSent(seg *segment) {
	if seg.ccsim.rackSentQueued {
		return
	}
	end := rackSegmentEnd(seg)
	prev := s.ccsim.rackSentTail
	for prev != nil && rackSentAfter(prev.xmitTime, rackSegmentEnd(prev), seg.xmitTime, end) {
		prev = prev.ccsim.rackSentPrev
	}
	if prev == nil {
		next := s.ccsim.rackSentHead
		seg.ccsim.rackSentNext = next
		if next != nil {
			next.ccsim.rackSentPrev = seg
		} else {
			s.ccsim.rackSentTail = seg
		}
		s.ccsim.rackSentHead = seg
	} else {
		next := prev.ccsim.rackSentNext
		seg.ccsim.rackSentPrev = prev
		seg.ccsim.rackSentNext = next
		prev.ccsim.rackSentNext = seg
		if next != nil {
			next.ccsim.rackSentPrev = seg
		} else {
			s.ccsim.rackSentTail = seg
		}
	}
	seg.ccsim.rackSentQueued = true
}

func (s *sender) ccsimRACKUnlinkLost(seg *segment) {
	if !seg.ccsim.rackLostQueued {
		return
	}
	prev, next := seg.ccsim.rackLostPrev, seg.ccsim.rackLostNext
	if prev != nil {
		prev.ccsim.rackLostNext = next
	} else {
		s.ccsim.rackLostHead = next
	}
	if next != nil {
		next.ccsim.rackLostPrev = prev
	} else {
		s.ccsim.rackLostTail = prev
	}
	seg.ccsim.rackLostPrev = nil
	seg.ccsim.rackLostNext = nil
	seg.ccsim.rackLostQueued = false
	s.ccsim.rackLost--
}

// ccsimRACKInsertLost inserts seg in sequence order.
func (s *sender) ccsimRACKInsertLost(seg *segment) {
	if seg.ccsim.rackLostQueued {
		return
	}
	prev := s.ccsim.rackLostTail
	for prev != nil && seg.sequenceNumber.LessThan(prev.sequenceNumber) {
		prev = prev.ccsim.rackLostPrev
	}
	if prev == nil {
		next := s.ccsim.rackLostHead
		seg.ccsim.rackLostNext = next
		if next != nil {
			next.ccsim.rackLostPrev = seg
		} else {
			s.ccsim.rackLostTail = seg
		}
		s.ccsim.rackLostHead = seg
	} else {
		next := prev.ccsim.rackLostNext
		seg.ccsim.rackLostPrev = prev
		seg.ccsim.rackLostNext = next
		prev.ccsim.rackLostNext = seg
		if next != nil {
			next.ccsim.rackLostPrev = seg
		} else {
			s.ccsim.rackLostTail = seg
		}
	}
	seg.ccsim.rackLostQueued = true
	s.ccsim.rackLost++
}

func (s *sender) ccsimRACKTrackTransmit(seg *segment) {
	// A retransmission removes a pending repair and moves seg to the queue tail.
	s.ccsimRACKUnlinkLost(seg)
	s.ccsimRACKUnlinkSent(seg)
	s.ccsimRACKInsertSent(seg)
}

// ccsimSplitSegment gives the suffix of a split the ccsim state of seg, and puts both parts in the RACK queues.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimSplitSegment(seg, suffix *segment) {
	if s.ccsim == nil || seg.ccsim == nil {
		return
	}
	// clone does not copy the ccsim state. The suffix was sent with seg, so its rate state is the same.
	ss := ccsimSegOf(suffix)
	*ss = *seg.ccsim
	ss.rackSentPrev, ss.rackSentNext, ss.rackSentQueued = nil, nil, false
	ss.rackLostPrev, ss.rackLostNext, ss.rackLostQueued = nil, nil, false
	ss.rackPipeCopies = 0
	if ss.sacked > 0 {
		// Each part keeps the counted SACKed bytes that it holds.
		ss.sacked = s.ccsimSACKedPart(seg.ccsim, suffix.sequenceNumber, rackSegmentEnd(suffix), seg.payloadSize())
		seg.ccsim.sacked -= ss.sacked
	}
	suffix.lost = seg.lost
	if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 {
		return
	}
	wasSent, wasLost := seg.ccsim.rackSentQueued, seg.ccsim.rackLostQueued
	s.ccsimRACKUnlinkSent(seg)
	s.ccsimRACKUnlinkLost(seg)
	if copies := seg.ccsim.rackPipeCopies; copies > 0 {
		oldPackets := (seg.payloadSize()+suffix.payloadSize()-1)/s.MaxPayloadSize + 1
		first := copies * s.pCount(seg, s.MaxPayloadSize) / oldPackets
		seg.ccsim.rackPipeCopies = first
		ss.rackPipeCopies = copies - first
	}
	if wasSent {
		s.ccsimRACKInsertSent(seg)
		s.ccsimRACKInsertSent(suffix)
	}
	if wasLost {
		s.ccsimRACKInsertLost(seg)
		s.ccsimRACKInsertLost(suffix)
	}
}

// ccsimOnTransmit records the rate state of seg. sendSegment calls it after it sets xmitTime.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimOnTransmit(seg *segment) {
	st := s.ccsim
	if st == nil {
		return
	}
	if s.SndUna == s.SndNxt || st.firstSent == (tcpip.MonotonicTime{}) {
		// The pipe was empty. Start new send and ACK intervals, as Linux tcp_rate_skb_sent does.
		st.firstSent = seg.xmitTime
		st.deliveredTime = seg.xmitTime
	}
	ss := ccsimSegOf(seg)
	ss.delivered = st.delivered
	ss.deliveredCE = st.deliveredCE
	ss.deliveredTime = st.deliveredTime
	ss.firstSent = st.firstSent
	ss.appLimited = st.appLimited
	rack := s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0
	// The pipe does not include this transmission yet.
	pipe := s.Outstanding
	if rack {
		pipe = st.rackPipe
	}
	ss.txInflight = int64(pipe)*int64(s.MaxPayloadSize) + int64(seg.payloadSize())
	ss.lostAtTx = st.lostCum
	ss.lostCounted = false
	if rack {
		s.ccsimRACKTrackTransmit(seg)
		packets := s.pCount(seg, s.MaxPayloadSize)
		ss.rackPipeCopies += packets
		st.rackPipe += packets
	}
}

// ccsimRACKAcknowledge removes seg from the RACK queues and all its live copies from the RACK pipe.
func (s *sender) ccsimRACKAcknowledge(seg *segment) {
	if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 || seg.ccsim == nil {
		return
	}
	s.ccsimRACKUnlinkSent(seg)
	s.ccsimRACKUnlinkLost(seg)
	seg.lost = false
	if seg.ccsim.rackPipeCopies == 0 {
		return
	}
	s.ccsimRACKPipeSub(seg.ccsim.rackPipeCopies)
	seg.ccsim.rackPipeCopies = 0
}

// ccsimRACKMarkLost removes the last live copy of seg from the RACK pipe.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimRACKMarkLost(seg *segment) {
	if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 || seg.ccsim == nil {
		return
	}
	s.ccsimRACKUnlinkSent(seg)
	if seg.lost && !seg.ccsim.counted {
		s.ccsimRACKInsertLost(seg)
	}
	if seg.ccsim.rackPipeCopies == 0 {
		return
	}
	packets := s.pCount(seg, s.MaxPayloadSize)
	if packets > seg.ccsim.rackPipeCopies {
		packets = seg.ccsim.rackPipeCopies
	}
	seg.ccsim.rackPipeCopies -= packets
	s.ccsimRACKPipeSub(packets)
}

// ccsimRACKPipeSub decreases the RACK pipe, with a floor of 0.
func (s *sender) ccsimRACKPipeSub(n int) {
	s.ccsim.rackPipe -= n
	if s.ccsim.rackPipe < 0 {
		s.ccsim.rackPipe = 0
	}
}

// ccsimMarkAppLimited marks the flow app-limited, as Linux tcp_rate_check_app_limited does:
// less than one MSS to send, free cwnd, and no lost segment that waits for a repair.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimMarkAppLimited() {
	st := s.ccsim
	if st == nil {
		return
	}
	st.cwndLimited = s.Outstanding >= s.SndCwnd
	// Without RACK, a lost segment waits while pacing holds the first repair, or while it is above HighRxt.
	lostWaits := st.rackLost > 0 || st.recoveryResendPending ||
		(s.FastRecovery.Active && st.pipeLost && s.FastRecovery.HighRxt.LessThan(st.pipeLostSeq))
	if st.cwndLimited || lostWaits {
		return
	}
	if n := s.writeNext; n != nil && (n.Next() != nil || n.payloadSize() >= s.MaxPayloadSize) {
		return
	}
	st.appLimited = true
	st.appLimitedSeq = s.SndNxt
	st.idleRestartEligible = true
}

// ccsimMaybeHandleRestartFromIdle sends the idle-restart event to the congestion control.
// It returns true while the restart flight is pending, so that cwnd is not reset to IW.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimMaybeHandleRestartFromIdle() bool {
	st := s.ccsim
	if st == nil || s.writeNext == nil || s.Outstanding != 0 || !st.idleRestartEligible {
		return false
	}
	h, ok := st.wrap.sim.(SimCCWithIdleRestart)
	if !ok {
		return false
	}
	if !st.idleRestartNotified {
		st.idleRestartNotified = true
		st.appLimited = true
		st.appLimitedSeq = s.SndNxt
		h.HandleRestartFromIdle()
	}
	return true
}

// handleRcvdSegment adds the rate sample of the sim congestion control to the ACK processing.
//
// +checklocks:s.ep.mu
func (s *sender) handleRcvdSegment(rcvdSeg *segment) {
	s.ccsimPreAck(rcvdSeg)
	s.handleRcvdSegmentInner(rcvdSeg)
	// handleRcvdSegmentInner calls ccsimOnAck before it sends. This call is for its early returns.
	s.ccsimOnAck(rcvdSeg)
}

// ccsimPreAck records the rate state of the segments that the ACK covers, before they are removed.
// It visits only the newly ACKed and the newly SACKed segments.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPreAck(rcvdSeg *segment) {
	st := s.ccsim
	if st == nil {
		return
	}
	st.nNewSACK = 0
	ack := rcvdSeg.ackNumber
	if s.SndNxt.LessThan(ack) {
		// handleRcvdSegmentInner ignores an ACK above SND.NXT. It gives no sample.
		return
	}
	st.ackPending = true
	st.scratchAcked = 0
	st.scratchSegs = 0
	st.scratchPartial = false
	st.scratchHasSample = false
	st.scratchPriorSACKed = s.ep.SACKPermitted && s.ep.scoreboard.Sacked() != 0
	st.scratchAckingTLP = s.rc.tlpRxtOut && s.rc.tlpHighRxt.LessThanEq(ack)
	s.ccsimNoteNewSACK(rcvdSeg)
	seg := s.writeList.Front()
	for ; seg != nil && s.isAssignedSequenceNumber(seg) && ccsimSegEnd(seg).LessThanEq(ack); seg = seg.Next() {
		s.ccsimAckSegment(seg)
	}
	if seg != nil && s.isAssignedSequenceNumber(seg) && seg.sequenceNumber.LessThan(ack) {
		s.ccsimPartialAck(seg, ack)
	}
	for _, p := range st.newSACK[:st.nNewSACK] {
		for seg := s.ccsimSACKSeek(p.part.Start); seg != nil && s.isAssignedSequenceNumber(seg) && seg.sequenceNumber.LessThan(p.part.End); seg = seg.Next() {
			if p.block.Start.LessThanEq(seg.sequenceNumber) && ccsimSegEnd(seg).LessThanEq(p.block.End) {
				s.ccsimAckSegment(seg)
			} else {
				s.ccsimPartialSACK(seg, p.part, ack)
			}
			s.writeList.sackHint = seg
		}
	}
}

// ccsimAckSegment adds one ACKed or SACKed segment to the rate sample.
func (s *sender) ccsimAckSegment(seg *segment) {
	ss := seg.ccsim
	if ss == nil {
		return
	}
	// After an RTO, a counted segment can be on the RACK queues again.
	s.ccsimRACKAcknowledge(seg)
	if ss.counted {
		return
	}
	ss.counted = true
	n := seg.payloadSize() - ss.sacked
	if n <= 0 {
		return
	}
	s.ccsim.scratchAcked += int64(n)
	s.ccsim.scratchSegs++
	s.ccsimSampleSegment(seg)
}

// ccsimPartialSACK adds the bytes of seg in a new SACK part to the rate sample,
// as Linux counts the SACKed part of a split TSO packet. ack is the cumulative ACK of the same segment.
func (s *sender) ccsimPartialSACK(seg *segment, part header.SACKBlock, ack seqnum.Value) {
	ss := seg.ccsim
	if ss == nil || ss.counted {
		return
	}
	start, end := seg.sequenceNumber, rackSegmentEnd(seg)
	if start.LessThan(part.Start) {
		start = part.Start
	}
	if part.End.LessThan(end) {
		end = part.End
	}
	if !start.LessThan(end) {
		return
	}
	// After an RTO the scoreboard is empty, and a SACK can repeat bytes that are already counted.
	// ccsimPartialAck moved the counted bytes of the ACKed head out of sacked, so use only the part above ack.
	avail := seg.payloadSize()
	if seg.sequenceNumber.LessThan(ack) {
		avail -= int(seg.sequenceNumber.Size(ack))
	}
	n := min(int(start.Size(end)), avail-ss.sacked)
	if n <= 0 {
		return
	}
	ss.sacked += n
	s.ccsim.scratchAcked += int64(n)
	s.ccsimSampleSegment(seg)
}

// ccsimPartialAck adds the ACKed head of seg to the rate sample. handleRcvdSegmentInner trims it after this.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPartialAck(seg *segment, ack seqnum.Value) {
	ss := seg.ccsim
	if ss == nil {
		return
	}
	acked := int(seg.sequenceNumber.Size(ack))
	// The ACKed packets leave the RACK pipe.
	if copies := ss.rackPipeCopies; copies > 0 {
		before := s.pCount(seg, s.MaxPayloadSize)
		after := (seg.payloadSize()-acked-1)/s.MaxPayloadSize + 1
		keep := copies * after / before
		ss.rackPipeCopies = keep
		s.ccsimRACKPipeSub(copies - keep)
	}
	if ss.counted {
		return
	}
	n := acked
	if ss.sacked > 0 {
		// Do not count the SACKed bytes of the head again.
		in := s.ccsimSACKedPart(ss, seg.sequenceNumber, ack, seg.payloadSize()-acked)
		ss.sacked -= in
		n -= in
	}
	if n <= 0 {
		return
	}
	s.ccsim.scratchAcked += int64(n)
	s.ccsim.scratchPartial = true
	s.ccsimSampleSegment(seg)
}

// ccsimSACKedPart returns the counted SACKed bytes of a segment that are in [start, end).
// other is the payload of the segment outside the range. The result is kept in the possible
// range, because after an RTO the scoreboard does not have all of the SACKed bytes.
func (s *sender) ccsimSACKedPart(ss *ccsimSegState, start, end seqnum.Value, other int) int {
	return min(max(s.ccsimSACKedIn(start, end), ss.sacked-other), ss.sacked)
}

// ccsimSACKedIn returns the number of bytes in [start, end) that the scoreboard has.
func (s *sender) ccsimSACKedIn(start, end seqnum.Value) int {
	n := 0
	if r, ok := s.ccsimFindRange(start, true); ok && start.LessThan(r.End) {
		if end.LessThan(r.End) {
			return int(start.Size(end))
		}
		n = int(start.Size(r.End))
		start = r.End
	}
	for start.LessThan(end) {
		r, ok := s.ccsimFindRange(start, false)
		if !ok || !r.Start.LessThan(end) {
			break
		}
		if end.LessThan(r.End) {
			return n + int(r.Start.Size(end))
		}
		n += int(r.Start.Size(r.End))
		start = r.End
	}
	return n
}

// ccsimSampleSegment uses seg for the rate sample if it is the last transmission so far.
// On a time tie, the later segment in the walk, with the higher sequence, wins.
func (s *sender) ccsimSampleSegment(seg *segment) {
	st := s.ccsim
	if st.scratchHasSample && seg.xmitTime.Before(st.scratchSeg.xmitTime) {
		return
	}
	st.scratchHasSample = true
	st.scratchSeg.delivered = seg.ccsim.delivered
	st.scratchSeg.deliveredTime = seg.ccsim.deliveredTime
	st.scratchSeg.firstSent = seg.ccsim.firstSent
	st.scratchSeg.xmitTime = seg.xmitTime
	st.scratchSeg.appLimited = seg.ccsim.appLimited
	st.scratchSeg.isRetrans = seg.xmitCount > 1
	st.scratchSeg.txInflight = seg.ccsim.txInflight
	st.scratchSeg.lostAtTx = seg.ccsim.lostAtTx
	st.scratchSeg.deliveredCE = seg.ccsim.deliveredCE
}

// ccsimNoteNewSACK keeps the parts of the SACK blocks of rcvdSeg that the scoreboard does not have yet,
// in sequence order.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimNoteNewSACK(rcvdSeg *segment) {
	st := s.ccsim
	st.nNewSACK = 0
	st.newSACKFull = false
	if !s.ep.SACKPermitted {
		return
	}
	for _, sb := range rcvdSeg.parsedOptions.SACKBlocks {
		if s.ccsimNewSACKBlock(rcvdSeg, sb) {
			s.ccsimAddSACKParts(sb)
		}
	}
	if st.newSACKFull {
		// Walk the full blocks. The walks skip segments that are already ACKed.
		st.nNewSACK = 0
		for _, sb := range rcvdSeg.parsedOptions.SACKBlocks {
			if s.ccsimNewSACKBlock(rcvdSeg, sb) && st.nNewSACK < len(st.newSACK) {
				st.newSACK[st.nNewSACK] = ccsimSACKPart{part: sb, block: sb}
				st.nNewSACK++
			}
		}
	}
	for i := 1; i < st.nNewSACK; i++ {
		for j := i; j > 0 && st.newSACK[j].part.Start.LessThan(st.newSACK[j-1].part.Start); j-- {
			st.newSACK[j], st.newSACK[j-1] = st.newSACK[j-1], st.newSACK[j]
		}
	}
}

// ccsimNewSACKBlock reports if the scoreboard insert in handleRcvdSegmentInner accepts sb.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimNewSACKBlock(rcvdSeg *segment, sb header.SACKBlock) bool {
	return rcvdSeg.ackNumber.LessThan(sb.Start) && s.SndUna.LessThan(sb.Start) &&
		sb.End.LessThanEq(s.SndNxt) && !s.ep.scoreboard.IsSACKED(sb)
}

// ccsimInitSACKWalk makes the scoreboard visit functions one time, so that an ACK does not allocate them.
func (s *sender) ccsimInitSACKWalk() {
	st := s.ccsim
	st.partVisit = s.ccsimPartVisit
	st.partVisitFirst = func(r header.SACKBlock) bool {
		s.ccsimPartVisit(r)
		return false
	}
	st.findVisit = func(r header.SACKBlock) bool {
		st.found, st.foundOK = r, true
		return false
	}
}

// ccsimAddSACKParts adds the parts of sb that are not in the scoreboard.
func (s *sender) ccsimAddSACKParts(sb header.SACKBlock) {
	st := s.ccsim
	st.partBlock = sb
	st.partPos = sb.Start
	pivot := header.SACKBlock{Start: sb.Start}
	s.ep.scoreboard.ranges.DescendLessOrEqual(pivot, st.partVisitFirst)
	s.ep.scoreboard.ranges.AscendGreaterOrEqual(pivot, st.partVisit)
	if st.partPos.LessThan(sb.End) {
		s.ccsimAddSACKPart(header.SACKBlock{Start: st.partPos, End: sb.End})
	}
}

// ccsimPartVisit adds the part of the current block before r, and moves the walk past r.
func (s *sender) ccsimPartVisit(r header.SACKBlock) bool {
	st := s.ccsim
	if !r.Start.LessThan(st.partBlock.End) {
		return false
	}
	if st.partPos.LessThan(r.Start) {
		s.ccsimAddSACKPart(header.SACKBlock{Start: st.partPos, End: r.Start})
	}
	if st.partPos.LessThan(r.End) {
		st.partPos = r.End
	}
	return true
}

// ccsimAddSACKPart adds one new part of the current block, or sets newSACKFull.
func (s *sender) ccsimAddSACKPart(part header.SACKBlock) {
	st := s.ccsim
	if st.nNewSACK == len(st.newSACK) {
		st.newSACKFull = true
		return
	}
	st.newSACK[st.nNewSACK] = ccsimSACKPart{part: part, block: st.partBlock}
	st.nNewSACK++
}

// ccsimSACKSeek returns the first segment that ends after seq.
// It starts at the list front or at the last SACK walk segment, whichever is nearer.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimSACKSeek(seq seqnum.Value) *segment {
	seg := s.writeList.Front()
	if seg == nil {
		return nil
	}
	if h := s.writeList.sackHint; h != nil && ccsimSeqDist(h.sequenceNumber, seq) < ccsimSeqDist(seg.sequenceNumber, seq) {
		seg = h
		for p := seg.Prev(); p != nil && seq.LessThan(seg.sequenceNumber); p = seg.Prev() {
			seg = p
		}
	}
	for seg != nil && s.isAssignedSequenceNumber(seg) && ccsimSegEnd(seg).LessThanEq(seq) {
		seg = seg.Next()
	}
	return seg
}

func ccsimSegEnd(seg *segment) seqnum.Value {
	return seg.sequenceNumber.Add(seqnum.Size(seg.logicalLen()))
}

func ccsimSeqDist(a, b seqnum.Value) seqnum.Size {
	if a.LessThan(b) {
		return a.Size(b)
	}
	return b.Size(a)
}

// ccsimWalkSACK updates RACK for the new parts of the SACK blocks, in sequence order.
// As in Linux, a SACK gives an RTT sample when the ACK does not acknowledge new data.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimWalkSACK(rcvdSeg *segment) {
	var firstSACKed tcpip.MonotonicTime
	for _, p := range s.ccsim.newSACK[:s.ccsim.nNewSACK] {
		for seg := s.ccsimSACKSeek(p.part.Start); seg != nil && seg.sequenceNumber.LessThan(p.part.End) && seg.xmitCount != 0; seg = seg.Next() {
			if p.block.Start.LessThanEq(seg.sequenceNumber) && !seg.acked {
				s.rc.update(seg, rcvdSeg)
				s.rc.detectReorder(seg)
				seg.acked = true
				s.SackedOut += s.pCount(seg, s.MaxPayloadSize)
				if seg.xmitCount == 1 && firstSACKed == (tcpip.MonotonicTime{}) {
					firstSACKed = seg.xmitTime
				}
			}
			s.writeList.sackHint = seg
		}
	}
	if firstSACKed != (tcpip.MonotonicTime{}) && !(rcvdSeg.ackNumber-1).InRange(s.SndUna, s.SndNxt) {
		s.updateRTO(s.ep.stack.Clock().NowMonotonic().Sub(firstSACKed))
	}
}

// ccsimOnAck makes the rate sample of the ACK and gives it to the congestion control.
// handleRcvdSegmentInner calls it before it sends, as Linux calls cong_control before it sends.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimOnAck(rcvdSeg *segment) {
	st := s.ccsim
	if st == nil || !st.ackPending {
		return
	}
	st.ackPending = false
	nowMT := s.ep.stack.Clock().NowMonotonic()
	ece := rcvdSeg.flags.Contains(header.TCPFlagEce)

	if st.scratchAcked > 0 {
		st.delivered += st.scratchAcked
		if st.idleRestartNotified {
			st.idleRestartEligible = false
		}
		st.idleRestartNotified = false
		if ece {
			st.deliveredCE += st.scratchAcked
		}
		st.deliveredTime = nowMT
		if st.appLimited && st.appLimitedSeq.LessThanEq(rcvdSeg.ackNumber) {
			st.appLimited = false
		}
	}
	// Later sends start their send interval at the send time of the newest ACKed segment, as in Linux.
	if st.scratchHasSample && st.firstSent.Before(st.scratchSeg.xmitTime) {
		st.firstSent = st.scratchSeg.xmitTime
	}

	sample := SimRateSample{
		Now:            nowMT.Sub(tcpip.MonotonicTime{}),
		AckedBytes:     st.scratchAcked,
		Delivered:      st.delivered,
		PriorDelivered: -1,
		// Use the pipe, not SND.NXT-SND.UNA. SACK holes make the span too large.
		InflightBytes:         int64(s.Outstanding) * int64(s.MaxPayloadSize),
		ECE:                   ece,
		LostBytesCum:          st.lostCum,
		IsCwndLimited:         st.cwndLimited,
		IsAckingTLPRetransmit: st.scratchAckingTLP,
	}
	if st.scratchHasSample {
		sc := &st.scratchSeg
		sample.DeliveredBytes = st.delivered - sc.delivered
		sample.DeliveredCEBytes = st.deliveredCE - sc.deliveredCE
		sample.TxInflight = sc.txInflight
		sample.LostBytes = st.lostCum - sc.lostAtTx
		sample.PriorDelivered = sc.delivered
		interval := nowMT.Sub(sc.deliveredTime)
		if sendElapsed := sc.xmitTime.Sub(sc.firstSent); sendElapsed > interval {
			interval = sendElapsed
		}
		sample.IsAppLimited = sc.appLimited
		if !sc.isRetrans {
			sample.RTT = nowMT.Sub(sc.xmitTime)
		}
		// Like Linux, discard intervals shorter than min RTT.
		if interval > 0 && (s.rc.minRTT <= 0 || interval >= s.rc.minRTT) {
			sample.Interval = interval
			sample.DeliveryRateBps = ccsimRate(sample.DeliveredBytes, interval)
		}
		// Linux FLAG_ACK_MAYBE_DELAYED: one lone runt is ACKed, nothing is SACKed, and nothing else was delivered.
		sample.IsAckDelayed = st.scratchSegs == 1 && !st.scratchPartial && st.scratchAcked < int64(s.MaxPayloadSize) &&
			!st.scratchPriorSACKed && st.nNewSACK == 0 && !ece && sample.DeliveredBytes == st.scratchAcked
	}
	if st.scratchAcked > 0 || ece || st.scratchHasSample {
		st.wrap.sim.OnAck(sample)
	}
}

// ccsimRate returns bytes per interval in bits/s. It does not overflow.
func ccsimRate(bytes int64, interval time.Duration) int64 {
	if bytes <= 0 || interval <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(uint64(bytes), 8*uint64(time.Second))
	if hi >= uint64(interval) {
		return math.MaxInt64
	}
	q, _ := bits.Div64(hi, lo, uint64(interval))
	if q > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(q)
}

// ccsimUndoRecovery tells the congestion control that the recovery was spurious.
func (s *sender) ccsimUndoRecovery() {
	if s.ccsim != nil {
		if u, ok := s.ccsim.wrap.sim.(SimCCWithUndo); ok {
			u.UndoRecovery()
		}
	}
}

// ccsimHandleLossProbeRecovery counts the loss that a tail-loss probe repaired.
// The repaired segment is still on writeList.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimHandleLossProbeRecovery() {
	if s.ccsim == nil {
		return
	}
	lost := s.ccsimMarkTLPLost()
	if lost == 0 {
		// A FIN-only probe has no payload. Count one packet.
		lost = int64(s.MaxPayloadSize)
	}
	if h, ok := s.ccsim.wrap.sim.(SimCCWithLossProbeRecovery); ok {
		h.HandleLossProbeRecovery(SimLossProbeRecovery{
			LostBytes:    lost,
			LostBytesCum: s.ccsim.lostCum,
			IsAppLimited: s.ccsim.tlpOrigAppLimited,
		})
	}
}

// ccsimEnterRecovery drops a tail-loss probe that pacing holds, and does not inflate cwnd.
// The sim congestion control sets cwnd on each ACK.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimEnterRecovery() {
	if s.ccsim == nil {
		return
	}
	s.ccsim.tlpProbePending = false
	s.SndCwnd = s.Ssthresh
}

// ccsimLeaveRecovery drops a fast retransmit that pacing holds.
func (s *sender) ccsimLeaveRecovery() {
	if s.ccsim != nil {
		s.ccsim.recoveryResendPending = false
	}
}

// ccsimDropTLPProbe drops a tail-loss probe that pacing holds.
func (s *sender) ccsimDropTLPProbe() {
	if s.ccsim != nil {
		s.ccsim.tlpProbePending = false
	}
}

// ccsimCleanup drops the ccsim state and gives the sender a stock congestion control.
// A closed endpoint, or one in TIME-WAIT, sends no more data, and a checkpoint can then save it.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimCleanup() {
	if s.ccsim == nil {
		return
	}
	s.ccsimReset()
	s.ccsimSetSACKLimit()
	s.cc = newRenoCC(s)
}

// ccsimExitRTO tells the sim congestion control that RTO recovery ended.
func (s *sender) ccsimExitRTO() {
	if s.ccsim != nil {
		s.cc.PostRecovery()
	}
}

// ccsimUndoRTO puts the sent data back in the RACK queue and pipe after a spurious RTO.
// ccsimMarkAllLost took it out. lostCum does not change, as Linux tp->lost does not.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimUndoRTO() {
	if s.ccsim == nil || s.ep.tcpRecovery&tcpip.TCPRACKLossDetection == 0 {
		return
	}
	for seg := s.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		ss := seg.ccsim
		if ss == nil || ss.counted || ss.rackPipeCopies != 0 || s.ep.SACKPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			continue
		}
		s.ccsimRACKUnlinkLost(seg)
		s.ccsimRACKInsertSent(seg)
		n := s.pCount(seg, s.MaxPayloadSize)
		ss.rackPipeCopies = n
		s.ccsim.rackPipe += n
	}
}

// ccsimResendAllowed reports whether pacing permits the first retransmission.
// If not, the pacing timer sends it.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimResendAllowed() bool {
	if s.ccsim == nil {
		return true
	}
	s.ccsim.recoveryResendPending = !s.ccsimPacingAllows()
	return !s.ccsim.recoveryResendPending
}

// ccsimOnResend charges pacing for the retransmission of the first segment and restarts the RTO.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimOnResend(seg *segment) {
	if s.ccsim == nil {
		return
	}
	s.ccsimPacingCharge(seg.payloadSize())
	s.ccsimRestartRTO()
}

// ccsimRestartRTO restarts the RTO after a retransmission of the first segment, as Linux does.
// The retransmission then has a full RTO to be acknowledged.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimRestartRTO() {
	s.probeTimer.disable()
	s.resendTimer.enable(s.RTO)
}

// ccsimDetectLoss is RACK detectLoss over the transmit-ordered queue.
// It returns the number of lost segments that wait for a repair, as Linux uses lost_out.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimDetectLoss(rcvTime tcpip.MonotonicTime) int {
	rc := &s.rc
	var timeout time.Duration
	for seg := s.ccsim.rackSentHead; seg != nil; {
		next := seg.ccsim.rackSentNext
		if s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			s.ccsimRACKAcknowledge(seg)
			seg = next
			continue
		}
		// The queue is in transmit order. Stop at the first segment that is not older.
		if !rackSentAfter(rc.XmitTime, rc.EndSequence, seg.xmitTime, rackSegmentEnd(seg)) {
			break
		}
		timeRemaining := seg.xmitTime.Sub(rcvTime) + rc.RTT + rc.ReoWnd
		if timeRemaining <= 0 {
			seg.lost = true
			s.ccsimMarkSegmentLost(seg)
		} else if timeRemaining > timeout {
			// Like Linux, wait for the longest remaining time.
			timeout = timeRemaining
		}
		seg = next
	}
	if timeout != 0 && !s.reorderTimer.enabled() {
		s.reorderTimer.enable(timeout)
	}
	return s.ccsim.rackLost
}

// ccsimDoRecovery is RACK DoRecovery over the sequence-ordered lost queue.
// It sends only the parts of the lost segments that are not SACKed.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimDoRecovery(fastRetransmit bool) {
	if fastRetransmit {
		// Do not measure the RTT with data that was sent before the recovery.
		s.RTTMeasureSeqNum = s.SndNxt
		if front := s.writeList.Front(); s.ccsim.rackLost == 0 && front != nil && front.xmitCount != 0 {
			// Duplicate ACKs started the recovery. As Linux does, mark the first segment lost.
			front.lost = true
			s.ccsimMarkSegmentLost(front)
		}
	}
	var dataSent bool
	smss := int(s.ep.scoreboard.SMSS())
	// Each pass sends or removes the queue head, or stops.
	for seg := s.ccsim.rackLostHead; seg != nil && seg != s.writeNext; seg = s.ccsim.rackLostHead {
		limit := smss
		if seg.payloadSize() > 0 {
			off, n := s.ccsimHole(seg)
			if n == 0 {
				s.ccsimRACKAcknowledge(seg)
				continue
			}
			if off > 0 {
				// Split off the SACKed head. The suffix is the next queue head.
				s.splitSeg(seg, off)
				s.ccsimRACKAcknowledge(seg)
				continue
			}
			limit = min(limit, n)
		}
		// A later ACK or the pacing timer continues the walk.
		if s.Outstanding >= s.SndCwnd || !s.ccsimPacingAllows() {
			break
		}
		if !s.maybeSendSegment(seg, limit, s.SndUna.Add(s.SndWnd)) {
			break
		}
		dataSent = true
		if fastRetransmit {
			fastRetransmit = false
			s.ep.stack.Stats().TCP.FastRetransmit.Increment()
			s.ep.stats.SendErrors.FastRetransmit.Increment()
		}
		if seg == s.writeList.Front() {
			s.ccsimRestartRTO()
		}
		s.ccsimPacingCharge(seg.payloadSize())
		s.Outstanding += s.pCount(seg, s.MaxPayloadSize)
	}
	s.postXmit(dataSent, true /* shouldScheduleProbe */)
}

// ccsimHole returns the offset and the size of the first part of seg that is not SACKed.
// The size is 0 if all of seg is SACKed.
func (s *sender) ccsimHole(seg *segment) (off, n int) {
	start := seg.sequenceNumber
	end := rackSegmentEnd(seg)
	if !s.ep.SACKPermitted {
		return 0, seg.payloadSize()
	}
	for {
		r, ok := s.ccsimFindRange(start, true)
		if !ok || !start.LessThan(r.End) {
			break
		}
		start = r.End
		if !start.LessThan(end) {
			return seg.payloadSize(), 0
		}
	}
	if r, ok := s.ccsimFindRange(start, false); ok && r.Start.LessThan(end) {
		end = r.Start
	}
	return int(seg.sequenceNumber.Size(start)), int(start.Size(end))
}

// ccsimFindRange returns the last scoreboard range that starts at or before seq if before is set.
// If not, it returns the first range that starts at or after seq.
func (s *sender) ccsimFindRange(seq seqnum.Value, before bool) (header.SACKBlock, bool) {
	st := s.ccsim
	st.found, st.foundOK = header.SACKBlock{}, false
	pivot := header.SACKBlock{Start: seq}
	if before {
		s.ep.scoreboard.ranges.DescendLessOrEqual(pivot, st.findVisit)
	} else {
		s.ep.scoreboard.ranges.AscendGreaterOrEqual(pivot, st.findVisit)
	}
	return st.found, st.foundOK
}

// ccsimSendTLPProbe is probeTimerExpired for a sim congestion control. Pacing can hold the probe.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimSendTLPProbe() {
	var dataSent bool
	if s.writeNext != nil && s.writeNext.xmitCount == 0 && s.Outstanding < s.SndCwnd {
		if !s.ccsimPacingAllows() {
			return
		}
		dataSent = s.maybeSendSegment(s.writeNext, int(s.ep.scoreboard.SMSS()), s.SndUna.Add(s.SndWnd))
		if dataSent {
			s.ccsimPacingCharge(s.writeNext.payloadSize())
			s.Outstanding += s.pCount(s.writeNext, s.MaxPayloadSize)
			s.updateWriteNext(s.writeNext.Next())
		}
	}

	if !dataSent && !s.rc.tlpRxtOut {
		var highestSeqXmit *segment
		for highestSeqXmit = s.writeList.Front(); highestSeqXmit != nil; highestSeqXmit = highestSeqXmit.Next() {
			if highestSeqXmit.xmitCount == 0 {
				highestSeqXmit = nil
				break
			}
			if highestSeqXmit.Next() == nil || highestSeqXmit.Next().xmitCount == 0 {
				break
			}
		}

		if highestSeqXmit != nil {
			if !s.ccsimPacingAllows() {
				return
			}
			origAppLimited := highestSeqXmit.ccsim != nil && highestSeqXmit.ccsim.appLimited
			dataSent = s.maybeSendSegment(highestSeqXmit, int(s.ep.scoreboard.SMSS()), s.SndUna.Add(s.SndWnd))
			if dataSent {
				s.ccsimPacingCharge(highestSeqXmit.payloadSize())
				s.rc.tlpRxtOut = true
				s.rc.tlpHighRxt = s.SndNxt
				s.ccsim.tlpOrigAppLimited = origAppLimited
			}
		}
	}

	s.ccsim.tlpProbePending = false
	// Arm the resend timer, not the probe timer, so that the probes are not sent back to back.
	s.postXmit(dataSent, false /* shouldScheduleProbe */)
}

// pacingTimerExpired is the pacing timer handler of st.
//
// +checklocks:st.wrap.s.ep.mu
func (st *ccsimSenderState) pacingTimerExpired() tcpip.Error {
	return st.wrap.s.ccsimPacingTimerExpired(st)
}

// ccsimPacingTimerExpired continues the sends that pacing stopped.
// The callback can run after a cleanup or a change of congestion control. Then it does nothing.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPacingTimerExpired(st *ccsimSenderState) tcpip.Error {
	if s.ccsim != st || st.pacingTimer.isUninitialized() || !st.pacingTimer.checkExpiration() {
		return nil
	}
	if st.tlpProbePending {
		s.ccsimSendTLPProbe()
		return nil
	}
	if s.FastRecovery.Active {
		if s.ep.SACKPermitted && s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
			// Send the RACK repairs first. sendData then sends new data.
			s.rc.DoRecovery(nil, false /* fastRetransmit */)
		} else {
			if st.recoveryResendPending {
				s.resendSegment()
				if st.recoveryResendPending {
					return nil
				}
			}
			if sr, ok := s.lr.(*sackRecovery); ok && s.ep.SACKPermitted {
				// sr.s is s, so s.ep.mu is held.
				dataSent := sr.handleSACKRecovery(s.MaxPayloadSize, s.SndUna.Add(s.SndWnd)) // +checklocksignore
				s.postXmit(dataSent, true /* shouldScheduleProbe */)
				return nil
			}
		}
	}
	s.sendData()
	return nil
}

// ccsimPacingAllows reports whether pacing permits a send now.
// If not, it arms the pacing timer and the caller must stop.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPacingAllows() bool {
	st := s.ccsim
	if st == nil || st.wrap.pacingBps <= 0 || st.pacingBurst > 0 {
		return true
	}
	now := s.ep.stack.Clock().NowMonotonic()
	if !now.Before(st.nextSend) {
		// Send one quantum before the next wait, as Linux sends one TSO packet.
		st.pacingBurst, _ = s.ccsimPacingQuantum(st.wrap)
		return true
	}
	st.pacingTimer.enable(st.nextSend.Sub(now))
	return false
}

// ccsimPacingQuantum returns the burst size, min(rate*1ms, 64KB) and at least 2 MSS, and its send time.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPacingQuantum(w *ccsimWrapper) (int, time.Duration) {
	quantum := w.pacingBps / 8 / 1000
	if quantum > 64<<10 {
		quantum = 64 << 10
	}
	if min := int64(2 * s.MaxPayloadSize); quantum < min {
		quantum = min
	}
	return int(quantum), time.Duration(quantum * 8 * int64(time.Second) / w.pacingBps)
}

// ccsimPacingCharge moves the next send time by size bytes at the pacing rate.
// The sender keeps up to one quantum of unused send time.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimPacingCharge(size int) {
	st := s.ccsim
	if st == nil || st.wrap.pacingBps <= 0 || size <= 0 {
		return
	}
	st.pacingBurst = max(st.pacingBurst-size, 0)
	now := s.ep.stack.Clock().NowMonotonic()
	_, qt := s.ccsimPacingQuantum(st.wrap)
	if floor := now.Add(-qt); st.nextSend.Before(floor) {
		st.nextSend = floor
	}
	txTime := time.Duration(int64(size) * 8 * int64(time.Second) / st.wrap.pacingBps)
	st.nextSend = st.nextSend.Add(txTime)
}

// ccsimSetPipe returns the RFC 6675 pipe in packets, in one pass over writeList.
// With RACK it returns the RACK pipe counter.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimSetPipe() int {
	if s.ep.tcpRecovery&tcpip.TCPRACKLossDetection != 0 {
		return s.ccsim.rackPipe
	}

	board := s.ep.scoreboard
	s.ccsim.pipeLost = false
	ranges := s.ccsim.pipeRanges[:0]
	board.ranges.Ascend(func(r header.SACKBlock) bool {
		ranges = append(ranges, r)
		return true
	})
	s.ccsim.pipeRanges = ranges
	n := len(ranges)
	suf := s.ccsim.pipeSufBytes
	if cap(suf) < n+1 {
		suf = make([]seqnum.Size, n+1)
	}
	suf = suf[:n+1]
	suf[n] = 0
	for j := n - 1; j >= 0; j-- {
		suf[j] = suf[j+1] + ranges[j].Start.Size(ranges[j].End)
	}
	s.ccsim.pipeSufBytes = suf

	smss := seqnum.Size(board.SMSS())
	lostBytes := seqnum.Size((nDupAckThreshold - 1) * board.SMSS())
	pipe := 0
	i := 0 // First range with End > chunk start.
	for s1 := s.writeList.Front(); s1 != nil && s1.payloadSize() != 0 && s.isAssignedSequenceNumber(s1); s1 = s1.Next() {
		// With GSO a segment can be larger than SMSS. Walk it in SMSS chunks.
		segEnd := s1.sequenceNumber.Add(seqnum.Size(s1.payloadSize()))
		for startSeq := s1.sequenceNumber; startSeq.LessThan(segEnd); startSeq = startSeq.Add(smss) {
			endSeq := startSeq.Add(smss)
			if segEnd.LessThan(endSeq) {
				endSeq = segEnd
			}
			if !s1.sequenceNumber.LessThan(s.SndNxt) {
				break
			}
			for i < n && !startSeq.LessThan(ranges[i].End) {
				i++
			}
			r := header.SACKBlock{Start: startSeq, End: endSeq}
			// Only ranges[i] can contain startSeq.
			if i < n && ranges[i].Contains(r) {
				continue
			}
			// A transmission that RACK marked lost is not in flight.
			if s1.lost {
				continue
			}
			// (a) If IsLost(S1) is false, increment pipe.
			if !ccsimRangeLost(ranges, suf, i, r, lostBytes) {
				pipe++
			} else {
				s.ccsim.pipeLost, s.ccsim.pipeLostSeq = true, s1.sequenceNumber
				if s1.xmitCount == 1 && s1.ccsim != nil && !s1.ccsim.lostCounted && !s1.ccsim.counted {
					// Count an original transmission in lostCum the first time it is lost. Delivered data is not lost.
					s1.ccsim.lostCounted = true
					s.ccsim.lostCum += int64(s1.payloadSize() - s1.ccsim.sacked)
				}
			}
			// (b) If S1 <= HighRxt, increment pipe.
			if s1.sequenceNumber.LessThanEq(s.FastRecovery.HighRxt) {
				pipe++
			}
		}
	}
	return pipe
}

// ccsimMarkAllLost counts all sent, un-SACKed segments in lostCum on RTO.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimMarkAllLost() {
	for seg := s.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		// Delivered data is not lost.
		if seg.payloadSize() == 0 || seg.ccsim == nil || seg.ccsim.lostCounted || seg.ccsim.counted {
			continue
		}
		if s.ep.SACKPermitted && s.ep.scoreboard.IsSACKED(seg.sackBlock()) {
			continue
		}
		seg.ccsim.lostCounted = true
		s.ccsim.lostCum += int64(seg.payloadSize() - seg.ccsim.sacked)
	}
	// No transmission is in flight after an RTO. Each retransmit adds itself again.
	s.ccsimPurge()
}

// ccsimMarkSegmentLost counts one RACK loss. RACK can also mark a retransmission lost.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimMarkSegmentLost(seg *segment) {
	if seg == nil || seg.ccsim == nil {
		return
	}
	s.ccsimRACKMarkLost(seg)
	// Delivered data is not lost, as Linux tcp_mark_skb_lost skips SACKed data.
	if seg.payloadSize() == 0 || seg.ccsim.lostCounted || seg.ccsim.counted {
		return
	}
	seg.ccsim.lostCounted = true
	s.ccsim.lostCum += int64(seg.payloadSize() - seg.ccsim.sacked)
}

// ccsimMarkTLPLost counts the tail segment that the tail-loss probe repaired.
//
// +checklocks:s.ep.mu
func (s *sender) ccsimMarkTLPLost() int64 {
	for seg := s.writeList.Front(); seg != nil && seg.xmitCount != 0; seg = seg.Next() {
		end := seg.sequenceNumber.Add(seqnum.Size(seg.logicalLen()))
		if end != s.rc.tlpHighRxt || seg.payloadSize() == 0 {
			continue
		}
		lost := int64(seg.payloadSize())
		if seg.ccsim != nil && !seg.ccsim.lostCounted {
			s.ccsimMarkSegmentLost(seg)
		}
		return lost
	}
	return 0
}

// ccsimRangeLost is SACKScoreboard.IsRangeLost for a chunk r that is not fully SACKed.
// i is the first range with End > r.Start.
func ccsimRangeLost(ranges []header.SACKBlock, suf []seqnum.Size, i int, r header.SACKBlock, lostBytes seqnum.Size) bool {
	n := len(ranges)
	if n == 0 {
		return false
	}
	k := i
	if i < n && !r.Start.LessThan(ranges[i].Start) {
		// ranges[i] overlaps the start of r. Count from the next range.
		k = i + 1
	}
	if k >= n {
		return false
	}
	return n-k >= nDupAckThreshold || suf[k] >= lostBytes
}
