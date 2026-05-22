package spurt

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	asig "github.com/scottocs/Tyche/spurt/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

const Protocol = "spurt"

var errEpochTimeout = errors.New("epoch timeout")

const sendTimeout = 20 * time.Second

type Node struct {
	ID        p2p.NodeID
	Keys      asig.KeyPair
	Public    map[string]ed25519.PublicKey
	BLS       asig.BLSKeyPair
	BLSPublic map[string]kyber.Point
	Transport p2p.Transport
	Perf      *PerfMetrics
	State     *State
	PVSS      asig.PVSSScheme

	seqMu       sync.Mutex
	seq         uint64
	prodMu      sync.Mutex
	prodPending int

	mu      sync.Mutex
	epochs  map[uint64]*epochState
	beacons chan *Beacon
}

type NodeConfig struct {
	ID        p2p.NodeID
	Members   []p2p.NodeID
	F         int
	QueueLen  int
	Seed      []byte
	Keys      asig.KeyPair
	Public    map[string]ed25519.PublicKey
	BLS       asig.BLSKeyPair
	BLSPublic map[string]kyber.Point
	Transport p2p.Transport
	PVSS      asig.PVSSScheme
}

type AgreementMessage struct {
	Epoch    uint64          `json:"epoch"`
	Leader   p2p.NodeID      `json:"leader"`
	Digest   string          `json:"digest"`
	Selected []CommitmentRef `json:"selected"`
	// Aggregate is public data and is bound into Digest. Keeping it in the
	// proposal lets every node verify the same selected-input aggregate once,
	// while private PVSS_DATA messages only carry the recipient-specific column.
	Aggregate asig.PVSSCommitment `json:"aggregate"`
}

type VoteMessage struct {
	Epoch  uint64     `json:"epoch"`
	Leader p2p.NodeID `json:"leader"`
	Digest string     `json:"digest"`
}

type ReconMessage struct {
	Epoch  uint64                  `json:"epoch"`
	Digest string                  `json:"digest"`
	Share  asig.PVSSDecryptedShare `json:"share"`
}

type PrivateDataMessage struct {
	Epoch    uint64          `json:"epoch"`
	Leader   p2p.NodeID      `json:"leader"`
	Digest   string          `json:"digest"`
	Selected []CommitmentRef `json:"selected"`
	// Columns contains this recipient's vbar/cbar/pi_bar data for the selected
	// inputs. It intentionally does not repeat Aggregate; Aggregate is public in
	// PROPOSAL and is checked against Digest before these private columns are
	// accepted.
	Columns []asig.PVSSColumnEntry `json:"columns"`
}

type pendingPrivateData struct {
	msg  PrivateDataMessage
	from p2p.NodeID
}

type BeaconMessage struct {
	Epoch      uint64                 `json:"epoch"`
	Leader     p2p.NodeID             `json:"leader"`
	Digest     string                 `json:"digest"`
	Random     []byte                 `json:"random"`
	RandomHash string                 `json:"random_hash"`
	Signature  asig.BLSSignatureShare `json:"signature"`
}

type epochState struct {
	epoch uint64

	leaderProposal    *AgreementMessage
	proposalBroadcast bool
	decided           bool

	prepareSent   bool
	precommitSent bool
	commitSent    bool
	finalizeSent  bool
	prepare       map[p2p.NodeID]struct{}
	precommit     map[p2p.NodeID]struct{}
	commit        map[p2p.NodeID]struct{}
	finalize      map[p2p.NodeID]struct{}

	pendingProposal *AgreementMessage
	// Private data can arrive before the public proposal on an asynchronous
	// transport. Buffer it until Aggregate is known, then validate it against the
	// digest-bound public proposal.
	pendingPrivate []pendingPrivateData
	selected       []CommitmentRef
	digest         string
	aggregate      *asig.PVSSCommitment
	// privateVerified gates PREPARE. A node does not vote for the proposal until
	// both public aggregate consistency and its private column proof pass.
	privateVerified bool

	reconShares  map[p2p.NodeID]asig.PVSSDecryptedShare
	reconSent    bool
	pendingRecon []ReconMessage
	secret       []byte

	random         []byte
	randomHash     string
	beaconSent     bool
	beaconVotes    map[string]map[p2p.NodeID]asig.BLSSignatureShare
	certificate    asig.BLSAggregateSignature
	certificateSet bool

	selectedSet bool
}

func NewNode(cfg NodeConfig) (*Node, error) {
	if cfg.ID == "" {
		return nil, errors.New("node id is required")
	}
	if cfg.Transport == nil {
		return nil, errors.New("transport is required")
	}
	if cfg.PVSS == nil {
		return nil, errors.New("real pvss scheme is required")
	}
	if cfg.BLS.Private == nil || len(cfg.BLSPublic) == 0 {
		return nil, errors.New("bls keys are required")
	}
	if len(cfg.Members) < 3*cfg.F+1 {
		return nil, errors.New("must satisfy n >= 3f+1")
	}
	state := NewState(cfg.Members, cfg.F, cfg.QueueLen, cfg.Seed)
	return &Node{
		ID: cfg.ID, Keys: cfg.Keys, Public: cfg.Public, BLS: cfg.BLS, BLSPublic: cfg.BLSPublic,
		Transport: cfg.Transport, Perf: &PerfMetrics{}, State: state, PVSS: cfg.PVSS,
		epochs:  make(map[uint64]*epochState),
		beacons: make(chan *Beacon, state.N*4),
	}, nil
}

func (n *Node) Start(ctx context.Context) error {
	if err := n.Transport.Start(ctx); err != nil {
		return err
	}
	n.StartProtocol(ctx)
	return nil
}

func (n *Node) StartProtocol(ctx context.Context) {
	go n.dispatch(ctx)
}

func (n *Node) Produce(ctx context.Context) (asig.PVSSCommitment, error) {
	n.seqMu.Lock()
	n.seq++
	seq := n.seq
	n.seqMu.Unlock()

	start := time.Now()
	commit, _, err := n.PVSS.Share(n.ID, seq, n.State.MembersSnapshot())
	if n.Perf != nil {
		n.Perf.addShare(time.Since(start))
	}
	if err != nil {
		return asig.PVSSCommitment{}, err
	}

	leader := n.State.Leader(n.State.CurrentEpoch())
	msg, err := p2p.NewMessage(Protocol, "PVSS", epochInstance(n.State.CurrentEpoch()), n.ID, leader, commit)
	if err != nil {
		return asig.PVSSCommitment{}, err
	}
	if err := n.Transport.Send(ctx, leader, msg); err != nil {
		return asig.PVSSCommitment{}, err
	}
	return commit, nil
}

func (n *Node) StartProducer(ctx context.Context, interval time.Duration) {
	// SPURT sends one PVSS tuple to the epoch leader during each epoch's
	// commitment phase. The shared runner still calls StartProducer.
}

func (n *Node) producerPendingCount() int {
	n.prodMu.Lock()
	defer n.prodMu.Unlock()
	return n.prodPending
}

func (n *Node) markProducerDelivered() {
	n.prodMu.Lock()
	defer n.prodMu.Unlock()
	if n.prodPending > 0 {
		n.prodPending--
	}
}

func (n *Node) markProducedDelivered() {
	n.markProducerDelivered()
}

func (n *Node) RunEpoch(ctx context.Context, timeout time.Duration) (*Beacon, error) {
	epoch := n.State.CurrentEpoch()
	if err := n.propose(ctx, epoch); err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}

	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	for {
		select {
		case <-ticker.C:
			n.tick(epoch)
		case b := <-n.beacons:
			if b != nil && b.Epoch == epoch {
				n.markProducerDelivered()
				n.State.Advance(b.Random)
				return b, nil
			}
		case <-deadline.C:
			return nil, errEpochTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (n *Node) propose(ctx context.Context, epoch uint64) error {
	if epoch != n.State.CurrentEpoch() {
		return nil
	}
	_, err := n.Produce(ctx)
	return err
}

func (n *Node) dispatch(ctx context.Context) {
	for {
		select {
		case msg, ok := <-n.Transport.Inbox():
			if !ok {
				return
			}
			switch msg.Protocol {
			case Protocol:
				n.dispatchSpurt(msg)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) dispatchSpurt(msg p2p.Message) {
	switch msg.Type {
	case "PVSS":
		body, err := p2p.DecodePayload[asig.PVSSCommitment](msg)
		if err != nil {
			return
		}
		n.handleCommit(body)
	case "PROPOSAL":
		body, err := p2p.DecodePayload[AgreementMessage](msg)
		if err != nil {
			return
		}
		n.handleProposal(body)
	case "PVSS_DATA":
		body, err := p2p.DecodePayload[PrivateDataMessage](msg)
		if err != nil {
			return
		}
		n.handlePrivateData(body, msg.From)
	case "PREPARE", "PRECOMMIT", "COMMIT", "FINALIZE":
		body, err := p2p.DecodePayload[VoteMessage](msg)
		if err != nil {
			return
		}
		n.handleVote(msg.Type, body, msg.From)
	case "RECON":
		body, err := p2p.DecodePayload[ReconMessage](msg)
		if err != nil {
			return
		}
		n.handleRecon(body, msg.From)
	case "BEACON":
		body, err := p2p.DecodePayload[BeaconMessage](msg)
		if err != nil {
			return
		}
		n.handleBeacon(body, msg.From)
	}
}

func (n *Node) handleCommit(commit asig.PVSSCommitment) {
	if n.State.Leader(n.State.CurrentEpoch()) != n.ID {
		return
	}
	if commit.Dealer == "" || commit.Seq == 0 {
		return
	}
	if !n.PVSS.Verify(commit) {
		return
	}
	if !n.State.Enqueue(commit) {
		return
	}
	// A newly arrived head commitment may satisfy a pending proposal.
	n.tick(n.State.CurrentEpoch())
}

func (n *Node) tick(epoch uint64) {
	es := n.stateAt(epoch)
	if es == nil {
		return
	}
	n.tryPendingProposal(es)
	n.tryLeaderProposal(es)
	n.maybeSendPrepare(es)
	n.progressVotes(es)
	n.tryReconstruct(es)
	n.tryBroadcastBeacon(es)
}

func (n *Node) tryLeaderProposal(es *epochState) {
	if es.proposalBroadcast {
		return
	}
	if n.State.Leader(es.epoch) != n.ID {
		return
	}
	heads := n.State.AllHeads()
	t := n.State.Threshold()
	if len(heads) < t {
		return
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].Dealer < heads[j].Dealer })
	selected := make([]CommitmentRef, t)
	copy(selected, heads[:t])
	headsMap := n.State.Heads()
	cmps, err := selectedCommitments(selected, headsMap)
	if err != nil {
		return
	}
	// Each commitment in State.ComQ was verified locally before enqueueing in
	// handleCommit. The leader can therefore aggregate from its own trusted
	// local queue without repeating the full PVSS pairing/R-S verification in
	// this epoch's critical path. Followers still verify the public aggregate
	// carried by PROPOSAL independently.
	aggregate, err := n.PVSS.AggregateTrusted(n.ID, es.epoch+1, cmps, n.State.MembersSnapshot())
	if err != nil {
		return
	}
	digest := computeAgreementDigest(n.State.RPrevBytes(), es.epoch, n.ID, selected, aggregate)
	if digest == "" {
		return
	}
	msg := AgreementMessage{
		Epoch:     es.epoch,
		Leader:    n.ID,
		Digest:    digest,
		Selected:  selected,
		Aggregate: aggregate,
	}
	n.mu.Lock()
	es.leaderProposal = &msg
	es.selected = selected
	es.digest = digest
	es.aggregate = &aggregate
	es.proposalBroadcast = true
	es.selectedSet = true
	es.pendingProposal = nil
	es.prepareSent = false
	es.precommitSent = false
	es.commitSent = false
	es.finalizeSent = false
	es.privateVerified = false
	n.mu.Unlock()
	n.sendPrivateData(es.epoch, n.ID, digest, selected, cmps)
	// Broadcast the public proposal after private sends are queued. Correctness
	// does not depend on ordering: receivers buffer private columns if they
	// arrive before this proposal.
	n.broadcastAsync(Protocol, "PROPOSAL", es.epoch, msg)
}

func (n *Node) maybeSendPrepare(es *epochState) {
	n.mu.Lock()
	// PREPARE is delayed until privateVerified is true so the optimization of
	// moving Aggregate to PROPOSAL does not weaken the paper-level requirement:
	// each node still validates its private vbar/cbar/pi_bar data first.
	if es.leaderProposal == nil || es.aggregate == nil || !es.privateVerified || es.prepareSent {
		n.mu.Unlock()
		return
	}
	es.prepareSent = true
	n.mu.Unlock()
	_ = n.sendVote("PREPARE", es)
}

func (n *Node) progressVotes(es *epochState) {
	n.mu.Lock()
	if es.leaderProposal == nil {
		n.mu.Unlock()
		return
	}
	twoF1 := 2*n.State.F + 1
	var precommit, commit, finalize bool
	if !es.precommitSent && len(es.prepare) >= twoF1 {
		es.precommitSent = true
		precommit = true
	}
	if !es.commitSent && len(es.precommit) >= twoF1 {
		es.commitSent = true
		commit = true
	}
	if !es.finalizeSent && len(es.commit) >= twoF1 {
		es.finalizeSent = true
		finalize = true
	}
	if len(es.finalize) >= twoF1 {
		es.decided = true
	}
	n.mu.Unlock()

	if precommit {
		_ = n.sendVote("PRECOMMIT", es)
	}
	if commit {
		_ = n.sendVote("COMMIT", es)
	}
	if finalize {
		_ = n.sendVote("FINALIZE", es)
	}
}

func (n *Node) handleProposal(msg AgreementMessage) {
	if !n.epochAllowed(msg.Epoch) || msg.Leader == "" || msg.Digest == "" {
		return
	}
	if msg.Leader != n.State.Leader(msg.Epoch) {
		return
	}
	if !n.PVSS.Verify(msg.Aggregate) {
		return
	}
	selected, ok, pending := n.validateProposal(msg.Epoch, msg.Selected, msg.Digest)
	if !ok {
		if !pending {
			return
		}
	}
	if ok {
		// The proposal carries all public data needed to recompute Digest. This
		// replaces the older implementation where every private message repeated
		// the same aggregate, reducing per-recipient bandwidth without changing
		// the public consistency check.
		if !aggregateMatchesSelection(msg.Aggregate, selected) {
			return
		}
		expected := computeAgreementDigest(n.State.RPrevBytes(), msg.Epoch, msg.Leader, selected, msg.Aggregate)
		if expected == "" || expected != msg.Digest {
			return
		}
	}
	n.mu.Lock()
	es := n.stateAtLocked(msg.Epoch)
	if es == nil {
		n.mu.Unlock()
		return
	}
	if es.leaderProposal != nil {
		if es.leaderProposal.Digest == msg.Digest {
			n.mu.Unlock()
			n.maybeSendPrepare(es)
			return
		}
		n.mu.Unlock()
		return
	}
	if !ok {
		if pending {
			es.pendingProposal = &msg
		}
		n.mu.Unlock()
		return
	}
	aggregate := msg.Aggregate
	es.leaderProposal = &msg
	es.selected = selected
	es.digest = msg.Digest
	es.aggregate = &aggregate
	es.selectedSet = true
	es.pendingProposal = nil
	pendingPrivate := append([]pendingPrivateData(nil), es.pendingPrivate...)
	es.pendingPrivate = nil
	n.mu.Unlock()
	// Re-play buffered private messages after Aggregate becomes available.
	// handlePrivateData will still verify digest, selected inputs, aggregate
	// membership, and column DLEQ proofs before setting privateVerified.
	for _, pending := range pendingPrivate {
		n.handlePrivateData(pending.msg, pending.from)
	}
	n.maybeSendPrepare(es)
}

func (n *Node) tryPendingProposal(es *epochState) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if es.leaderProposal != nil || es.pendingProposal == nil {
		return
	}
	msg := *es.pendingProposal
	if !n.PVSS.Verify(msg.Aggregate) {
		es.pendingProposal = nil
		return
	}
	selected, ok, pending := n.validateProposal(msg.Epoch, msg.Selected, msg.Digest)
	if !ok {
		if !pending {
			es.pendingProposal = nil
		}
		return
	}
	if !aggregateMatchesSelection(msg.Aggregate, selected) {
		es.pendingProposal = nil
		return
	}
	expected := computeAgreementDigest(n.State.RPrevBytes(), msg.Epoch, msg.Leader, selected, msg.Aggregate)
	if expected == "" || expected != msg.Digest {
		es.pendingProposal = nil
		return
	}
	aggregate := msg.Aggregate
	es.leaderProposal = &msg
	es.selected = selected
	es.digest = msg.Digest
	es.aggregate = &aggregate
	es.selectedSet = true
	es.pendingProposal = nil
}

func (n *Node) handlePrivateData(msg PrivateDataMessage, from p2p.NodeID) {
	if !n.epochAllowed(msg.Epoch) || msg.Leader == "" || msg.Digest == "" {
		return
	}
	if msg.Leader != n.State.Leader(msg.Epoch) || from != msg.Leader {
		return
	}
	selected := normalizeRefs(msg.Selected)
	if len(selected) != len(msg.Selected) || len(selected) < n.State.Threshold() {
		return
	}
	n.mu.Lock()
	es := n.stateAtLocked(msg.Epoch)
	if es == nil {
		n.mu.Unlock()
		return
	}
	if es.aggregate == nil {
		// Private PVSS_DATA is recipient-specific and may race ahead of the
		// public proposal. Store it rather than rejecting it; it will be checked
		// once the digest-bound Aggregate is available.
		es.pendingPrivate = append(es.pendingPrivate, pendingPrivateData{msg: msg, from: from})
		n.mu.Unlock()
		return
	}
	if es.digest != "" && es.digest != msg.Digest {
		n.mu.Unlock()
		return
	}
	aggregate := *es.aggregate
	n.mu.Unlock()

	if !aggregateMatchesSelection(aggregate, selected) {
		return
	}
	// This is the optimized private-data validation point: Aggregate came from
	// the public proposal, while msg.Columns contains only this node's private
	// column. The check proves they match exactly.
	if !n.PVSS.VerifyAggregationColumn(n.ID, aggregate, msg.Columns) {
		return
	}
	expected := computeAgreementDigest(n.State.RPrevBytes(), msg.Epoch, msg.Leader, selected, aggregate)
	if expected == "" || expected != msg.Digest {
		return
	}
	n.mu.Lock()
	es = n.stateAtLocked(msg.Epoch)
	if es == nil || es.aggregate == nil {
		n.mu.Unlock()
		return
	}
	if es.digest != "" && es.digest != msg.Digest {
		n.mu.Unlock()
		return
	}
	es.selected = selected
	es.digest = msg.Digest
	es.selectedSet = true
	es.privateVerified = true
	n.mu.Unlock()
	n.tryPendingProposal(es)
	n.maybeSendPrepare(es)
}

func (n *Node) validateProposal(epoch uint64, selected []CommitmentRef, digest string) (selectedOut []CommitmentRef, ok bool, pending bool) {
	if len(selected) < n.State.Threshold() {
		return nil, false, true
	}
	normalized := normalizeRefs(selected)
	if len(normalized) != len(selected) || len(normalized) < n.State.Threshold() {
		return nil, false, false
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i].Dealer < normalized[j].Dealer })
	return normalized, true, false
}

func isMissingError(err error) bool {
	if err == nil {
		return false
	}
	e := err.Error()
	return contains(e, "missing commitment")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func (n *Node) handleVote(stage string, msg VoteMessage, from p2p.NodeID) {
	if !n.epochAllowed(msg.Epoch) || msg.Leader == "" || msg.Digest == "" {
		return
	}
	start := time.Now()
	n.mu.Lock()
	es := n.stateAtLocked(msg.Epoch)
	if es == nil || es.leaderProposal == nil || es.leaderProposal.Digest != msg.Digest || es.leaderProposal.Leader != msg.Leader {
		n.mu.Unlock()
		return
	}
	switch stage {
	case "PREPARE":
		es.prepare[from] = struct{}{}
	case "PRECOMMIT":
		es.precommit[from] = struct{}{}
	case "COMMIT":
		es.commit[from] = struct{}{}
	case "FINALIZE":
		es.finalize[from] = struct{}{}
	}
	n.mu.Unlock()
	if n.Perf != nil {
		n.Perf.addAgreement(time.Since(start))
	}
	n.progressVotes(es)
}

func (n *Node) handleRecon(msg ReconMessage, from p2p.NodeID) {
	if !n.epochAllowed(msg.Epoch) || msg.Digest == "" || from == "" {
		return
	}
	n.mu.Lock()
	es := n.stateAtLocked(msg.Epoch)
	if es == nil || es.aggregate == nil || es.digest != msg.Digest {
		if es != nil {
			es.pendingRecon = append(es.pendingRecon, msg)
		}
		n.mu.Unlock()
		return
	}
	aggregate := *es.aggregate
	n.mu.Unlock()

	start := time.Now()
	okShare := n.PVSS.VerifyShare(aggregate, msg.Share)
	if n.Perf != nil {
		n.Perf.addVerify(time.Since(start))
	}
	if !okShare {
		return
	}
	n.mu.Lock()
	es.reconShares[from] = msg.Share
	pending := es.pendingRecon
	if len(pending) > 0 {
		es.pendingRecon = nil
	}
	n.mu.Unlock()
	for _, extra := range pending {
		if extra.Digest != msg.Digest || extra.Epoch != msg.Epoch {
			continue
		}
		if !n.PVSS.VerifyShare(aggregate, extra.Share) {
			continue
		}
		n.mu.Lock()
		if es.aggregate != nil && es.digest == msg.Digest {
			es.reconShares[extra.Share.Holder] = extra.Share
		}
		n.mu.Unlock()
	}
}

func (n *Node) tryReconstruct(es *epochState) {
	n.mu.Lock()
	if !es.decided {
		n.mu.Unlock()
		return
	}
	if len(es.selected) == 0 || es.aggregate == nil {
		n.mu.Unlock()
		return
	}
	t := n.State.Threshold()

	if !es.reconSent {
		es.reconSent = true
		aggregate := *es.aggregate
		go n.broadcastRecon(es, aggregate)
	}

	if es.random != nil {
		n.mu.Unlock()
		return
	}

	if es.secret == nil {
		if len(es.reconShares) < t {
			n.mu.Unlock()
			return
		}
		decrypted := make([]asig.PVSSDecryptedShare, 0, len(es.reconShares))
		for _, share := range es.reconShares {
			decrypted = append(decrypted, share)
		}
		aggregate := *es.aggregate
		n.mu.Unlock()
		start := time.Now()
		recovered, err := n.PVSS.ReconTrusted(aggregate, decrypted, t)
		if n.Perf != nil {
			n.Perf.addRecon(time.Since(start))
		}
		if err != nil {
			return
		}
		n.mu.Lock()
		if es.secret == nil {
			es.secret = recovered
		}
		if es.random != nil {
			n.mu.Unlock()
			return
		}
	}
	secret := append([]byte(nil), es.secret...)
	digest := es.digest
	epoch := es.epoch
	n.mu.Unlock()

	parts := [][]byte{n.State.RPrevBytes(), encodeEpoch(epoch)}
	parts = append(parts, []byte(digest), secret)
	random := asig.HashBytes(parts...)
	hash := randomHash(random)

	n.mu.Lock()
	if es.random == nil {
		es.random = random
		es.randomHash = hash
	}
	n.mu.Unlock()
}

func (n *Node) broadcastRecon(es *epochState, c asig.PVSSCommitment) {
	start := time.Now()
	share, err := n.PVSS.PreReconTrusted(c, n.ID)
	if n.Perf != nil {
		n.Perf.addPreRecon(time.Since(start))
	}
	if err != nil {
		return
	}
	n.send(Protocol, "RECON", es.epoch, ReconMessage{
		Epoch:  es.epoch,
		Digest: es.digest,
		Share:  share,
	})
}

func (n *Node) tryBroadcastBeacon(es *epochState) {
	if es.random == nil || es.randomHash == "" || es.beaconSent {
		return
	}
	es.beaconSent = true
	randomHashValue := randomHash(es.random)
	msg := &Beacon{
		Epoch:    es.epoch,
		Random:   append([]byte(nil), es.random...),
		Digest:   es.digest,
		Selected: es.selected,
	}
	sig, err := asig.SignBLS(string(n.ID), n.BLS.Private, beaconVoteBytes(es.epoch, es.digest, randomHashValue))
	if err != nil {
		return
	}
	_ = n.broadcast(Protocol, "BEACON", es.epoch, BeaconMessage{
		Epoch:      msg.Epoch,
		Leader:     n.State.Leader(es.epoch),
		Digest:     msg.Digest,
		Random:     msg.Random,
		RandomHash: randomHashValue,
		Signature:  sig,
	})
	n.addBeaconVote(*msg, sig, n.ID)
}

func (n *Node) handleBeacon(msg BeaconMessage, from p2p.NodeID) {
	if !n.epochAllowed(msg.Epoch) || msg.Leader == "" || msg.Digest == "" || msg.RandomHash == "" || from == "" {
		return
	}
	if msg.Leader != n.State.Leader(msg.Epoch) {
		return
	}
	n.mu.Lock()
	es := n.stateAtLocked(msg.Epoch)
	if es == nil || es.leaderProposal == nil || es.leaderProposal.Digest != msg.Digest {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()

	d := randomHash(msg.Random)
	if d != msg.RandomHash {
		return
	}
	if len(msg.Random) == 0 {
		return
	}
	n.mu.Lock()
	es = n.stateAtLocked(msg.Epoch)
	if es == nil {
		n.mu.Unlock()
		return
	}
	if existing := es.beaconVotes[msg.RandomHash]; existing != nil {
		if _, dup := existing[from]; dup {
			n.mu.Unlock()
			return
		}
	}
	n.mu.Unlock()
	start := time.Now()
	ok := asig.VerifyBLSShare(msg.Signature, n.BLSPublic, beaconVoteBytes(msg.Epoch, msg.Digest, msg.RandomHash))
	if n.Perf != nil {
		n.Perf.addBLSVerify(time.Since(start))
	}
	if !ok {
		return
	}
	n.mu.Lock()
	es = n.stateAtLocked(msg.Epoch)
	if es == nil {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()
	msgObj := Beacon{Epoch: msg.Epoch, Random: msg.Random, Digest: msg.Digest, Selected: []CommitmentRef{}}
	n.addBeaconVote(msgObj, msg.Signature, from)
}

func (n *Node) addBeaconVote(beacon Beacon, sig asig.BLSSignatureShare, from p2p.NodeID) {
	n.mu.Lock()
	es := n.stateAtLocked(beacon.Epoch)
	if es == nil || es.leaderProposal == nil || es.leaderProposal.Digest != beacon.Digest {
		n.mu.Unlock()
		return
	}
	if es.beaconVotes == nil {
		es.beaconVotes = make(map[string]map[p2p.NodeID]asig.BLSSignatureShare)
	}
	rh := randomHash(beacon.Random)
	if rh == "" {
		n.mu.Unlock()
		return
	}
	votes := es.beaconVotes[rh]
	if votes == nil {
		votes = make(map[p2p.NodeID]asig.BLSSignatureShare)
		es.beaconVotes[rh] = votes
	}
	votes[from] = sig
	if es.random == nil {
		es.random = append([]byte(nil), beacon.Random...)
	}
	es.beaconVotes[rh] = votes
	es.randomHash = rh
	n.mu.Unlock()
	n.tryAssembleBeacon(es)
}

func (n *Node) tryAssembleBeacon(es *epochState) {
	if es.certificateSet {
		return
	}
	n.mu.Lock()
	msgHash := es.randomHash
	randomHashVotes := es.beaconVotes[msgHash]
	if len(randomHashVotes) < n.State.Threshold() || len(es.selected) == 0 {
		n.mu.Unlock()
		return
	}
	votes := make([]asig.BLSSignatureShare, 0, len(randomHashVotes))
	for _, v := range randomHashVotes {
		votes = append(votes, v)
	}
	n.mu.Unlock()

	start := time.Now()
	agg, err := asig.AggregateBLSTrusted(votes, n.BLSPublic, beaconVoteBytes(es.epoch, es.digest, msgHash), n.State.Threshold())
	if n.Perf != nil {
		n.Perf.addBLSAggregate(time.Since(start))
	}
	if err != nil {
		return
	}
	n.mu.Lock()
	if es.certificateSet {
		n.mu.Unlock()
		return
	}
	es.certificate = agg
	es.certificateSet = true
	// Selected commitments are consumed once one beacon certificate is formed.
	if n.State.Leader(es.epoch) == n.ID {
		n.State.PopAll(es.selected)
	}
	n.mu.Unlock()
	selected := append([]CommitmentRef(nil), es.selected...)
	n.beacons <- &Beacon{
		Epoch:      es.epoch,
		Random:     append([]byte(nil), es.random...),
		Digest:     es.digest,
		Selected:   selected,
		Signature:  agg,
		Committeds: len(selected),
	}
}

func (n *Node) sendVote(stage string, es *epochState) error {
	return n.broadcast(Protocol, stage, es.epoch, VoteMessage{
		Epoch: es.epoch, Leader: n.State.Leader(es.epoch), Digest: es.digest,
	})
}

func (n *Node) broadcast(protocol, typ string, epoch uint64, payload any) error {
	msg, err := p2p.NewMessage(protocol, typ, epochInstance(epoch), n.ID, "", payload)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(context.Background(), msg)
}

func (n *Node) send(protocol, typ string, epoch uint64, payload any) error {
	msg, err := p2p.NewMessage(protocol, typ, epochInstance(epoch), n.ID, "", payload)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(context.Background(), msg)
}

func (n *Node) sendPrivateData(epoch uint64, leader p2p.NodeID, digest string, selected []CommitmentRef, commitments []asig.PVSSCommitment) {
	for _, member := range n.State.MembersSnapshot() {
		payload, ok := privateDataForMember(epoch, leader, digest, selected, commitments, member)
		if !ok {
			continue
		}
		msg, err := p2p.NewMessage(Protocol, "PVSS_DATA", epochInstance(epoch), n.ID, member, payload)
		if err != nil {
			continue
		}
		n.sendAsync(member, msg)
	}
}

func (n *Node) broadcastAsync(protocol, typ string, epoch uint64, payload any) {
	for _, member := range n.State.MembersSnapshot() {
		msg, err := p2p.NewMessage(protocol, typ, epochInstance(epoch), n.ID, member, payload)
		if err != nil {
			continue
		}
		n.sendAsync(member, msg)
	}
}

func (n *Node) sendAsync(to p2p.NodeID, msg p2p.Message) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
		defer cancel()
		_ = n.Transport.Send(ctx, to, msg)
	}()
}

func privateDataForMember(epoch uint64, leader p2p.NodeID, digest string, selected []CommitmentRef, commitments []asig.PVSSCommitment, member p2p.NodeID) (PrivateDataMessage, bool) {
	// Build only the recipient's selected-input column. The aggregate is not
	// included here because it is common public data already carried by
	// AgreementMessage and bound by Digest.
	columns := make([]asig.PVSSColumnEntry, 0, len(commitments))
	for _, c := range commitments {
		proof, ok := c.DLEQ[member]
		if !ok {
			return PrivateDataMessage{}, false
		}
		commit, ok := c.Commit[member]
		if !ok {
			return PrivateDataMessage{}, false
		}
		cipher, ok := c.Cipher[member]
		if !ok {
			return PrivateDataMessage{}, false
		}
		columns = append(columns, asig.PVSSColumnEntry{
			Source: asig.PVSSSource{Dealer: c.Dealer, Seq: c.Seq, SecretID: c.SecretID},
			Commit: commit,
			Cipher: cipher,
			Proof:  proof,
		})
	}
	return PrivateDataMessage{
		Epoch: epoch, Leader: leader, Digest: digest, Selected: selected,
		Columns: columns,
	}, true
}

func (n *Node) stateAt(epoch uint64) *epochState {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.stateAtLocked(epoch)
}

func (n *Node) stateAtLocked(epoch uint64) *epochState {
	if epochState, ok := n.epochs[epoch]; ok {
		return epochState
	}
	es := &epochState{
		epoch:        epoch,
		prepare:      make(map[p2p.NodeID]struct{}),
		precommit:    make(map[p2p.NodeID]struct{}),
		commit:       make(map[p2p.NodeID]struct{}),
		finalize:     make(map[p2p.NodeID]struct{}),
		reconShares:  make(map[p2p.NodeID]asig.PVSSDecryptedShare),
		beaconVotes:  make(map[string]map[p2p.NodeID]asig.BLSSignatureShare),
		pendingRecon: make([]ReconMessage, 0),
	}
	n.epochs[epoch] = es
	return es
}

func (n *Node) epochAllowed(epoch uint64) bool {
	current := n.State.CurrentEpoch()
	return epoch >= current
}

func (n *Node) PerfSnapshot() PerfSnapshot {
	if n.Perf == nil {
		return PerfSnapshot{}
	}
	return n.Perf.Snapshot()
}

func (n *Node) ProposalCount(epoch uint64) int {
	es := n.stateAt(epoch)
	if es == nil {
		return 0
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(es.selected)
}

func computeAgreementDigest(rprev []byte, epoch uint64, leader p2p.NodeID, refs []CommitmentRef, aggregate asig.PVSSCommitment) string {
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Dealer == refs[j].Dealer {
			return refs[i].Seq < refs[j].Seq
		}
		return refs[i].Dealer < refs[j].Dealer
	})
	parts := [][]byte{
		[]byte("Spurt-v1/AGREEMENT"),
		encodeEpoch(epoch),
		[]byte(leader),
		rprev,
		[]byte(aggregate.SecretID),
	}
	for _, ref := range refs {
		parts = append(parts, []byte(ref.Dealer), encodeEpoch(ref.Seq))
	}
	return hex.EncodeToString(asig.HashBytes(parts...))
}

func selectedCommitments(refs []CommitmentRef, heads map[p2p.NodeID]asig.PVSSCommitment) ([]asig.PVSSCommitment, error) {
	out := make([]asig.PVSSCommitment, 0, len(refs))
	for _, ref := range refs {
		c, ok := heads[ref.Dealer]
		if !ok || c.Seq != ref.Seq {
			return nil, errors.New("invalid selection")
		}
		out = append(out, c)
	}
	return out, nil
}

func normalizeRefs(in []CommitmentRef) []CommitmentRef {
	out := make([]CommitmentRef, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dealer == out[j].Dealer {
			return out[i].Seq < out[j].Seq
		}
		return out[i].Dealer < out[j].Dealer
	})
	return uniqueRefs(out)
}

func aggregateMatchesSelection(aggregate asig.PVSSCommitment, selected []CommitmentRef) bool {
	if len(aggregate.Sources) != len(selected) {
		return false
	}
	refs := normalizeRefs(selected)
	sources := append([]asig.PVSSSource(nil), aggregate.Sources...)
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Dealer == sources[j].Dealer {
			return sources[i].Seq < sources[j].Seq
		}
		return sources[i].Dealer < sources[j].Dealer
	})
	for i, ref := range refs {
		if sources[i].Dealer != ref.Dealer || sources[i].Seq != ref.Seq || sources[i].SecretID == "" {
			return false
		}
	}
	return true
}

func uniqueRefs(in []CommitmentRef) []CommitmentRef {
	seen := make(map[p2p.NodeID]struct{}, len(in))
	out := make([]CommitmentRef, 0, len(in))
	for _, ref := range in {
		if _, ok := seen[ref.Dealer]; ok {
			continue
		}
		seen[ref.Dealer] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func epochInstance(epoch uint64) string {
	return fmt.Sprintf("epoch-%d", epoch)
}

func randomHash(random []byte) string {
	return hex.EncodeToString(asig.HashBytes(random))
}

func beaconVoteBytes(epoch uint64, digest string, randomHash string) []byte {
	return asig.HashBytes([]byte("Spurt-v1/BEACON"), encodeEpoch(epoch), []byte(digest), []byte(randomHash))
}
