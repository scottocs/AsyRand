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

	asig "tyche.local/Tyche/spurt/crypto"
	"tyche.local/Tyche/utils/cryptoexec"
	"tyche.local/Tyche/utils/p2p"
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
	Crypto    *cryptoexec.Executor

	seqMu     sync.Mutex
	seq       uint64
	prodMu    sync.Mutex
	produced  map[uint64]struct{}
	lookahead uint64

	mu      sync.Mutex
	epochs  map[uint64]*epochState
	beacons chan *Beacon
	pending map[uint64]*Beacon
}

type NodeConfig struct {
	ID            p2p.NodeID
	Members       []p2p.NodeID
	F             int
	Seed          []byte
	Keys          asig.KeyPair
	Public        map[string]ed25519.PublicKey
	BLS           asig.BLSKeyPair
	BLSPublic     map[string]kyber.Point
	Transport     p2p.Transport
	PVSS          asig.PVSSScheme
	CryptoWorkers int
	Lookahead     int
}

type AgreementMessage struct {
	Epoch    uint64          `json:"epoch"`
	Leader   p2p.NodeID      `json:"leader"`
	Digest   string          `json:"digest"`
	Selected []CommitmentRef `json:"selected"`
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
	// Aggregate is the public vhat/chat data bound by Digest. It is carried on
	// the leader's per-recipient private-data channel so the agreement path only
	// gossips the compact digest, matching SPURT's paper design.
	Aggregate asig.PVSSCommitment    `json:"aggregate"`
	Columns   []asig.PVSSColumnEntry `json:"columns"`
}

type pendingPrivateData struct {
	msg  PrivateDataMessage
	from p2p.NodeID
}

type pendingVote struct {
	stage string
	msg   VoteMessage
	from  p2p.NodeID
}

type pendingBeaconMessage struct {
	msg  BeaconMessage
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
	proposalGossiped  bool
	proposing         bool
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
	// commits caches the current epoch-local PVSS inputs seen by this epoch's
	// leader. SPURT has no producer-consumer queue: one dealer contributes at
	// most one PVSS commitment per leader/epoch, and the leader aggregates one
	// deterministic set after collecting t inputs.
	commits         map[p2p.NodeID]asig.PVSSCommitment
	preAggregating  bool
	selectedColumns map[p2p.NodeID][]asig.PVSSColumnEntry
	// Private data can arrive before the public proposal on an asynchronous
	// transport. Buffer it until Aggregate is known, then validate it against the
	// digest-bound public proposal.
	pendingPrivate []pendingPrivateData
	pendingVotes   []pendingVote
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
	pendingBeacon  []pendingBeaconMessage
	beaconVotes    map[string]map[p2p.NodeID]asig.BLSSignatureShare
	certificate    asig.BLSAggregateSignature
	certificateSet bool
	assemblingCert bool
	reconstructing bool

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
	lookahead := cfg.Lookahead
	if lookahead <= 0 {
		lookahead = len(cfg.Members)
	}
	state := NewState(cfg.Members, cfg.F, cfg.Seed)
	return &Node{
		ID: cfg.ID, Keys: cfg.Keys, Public: cfg.Public, BLS: cfg.BLS, BLSPublic: cfg.BLSPublic,
		Transport: cfg.Transport, Perf: &PerfMetrics{}, State: state, PVSS: cfg.PVSS,
		Crypto:    cryptoexec.New(cfg.CryptoWorkers),
		produced:  make(map[uint64]struct{}),
		lookahead: uint64(lookahead),
		epochs:    make(map[uint64]*epochState),
		beacons:   make(chan *Beacon, state.N*4),
		pending:   make(map[uint64]*Beacon),
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
	return n.ProduceForEpoch(ctx, n.State.CurrentEpoch())
}

func (n *Node) ProduceForEpoch(ctx context.Context, epoch uint64) (asig.PVSSCommitment, error) {
	n.seqMu.Lock()
	n.seq++
	seq := n.seq
	n.seqMu.Unlock()

	commit, err := n.sharePVSS(ctx, seq)
	if err != nil {
		return asig.PVSSCommitment{}, err
	}
	if err := n.sendPVSS(ctx, epoch, commit); err != nil {
		return asig.PVSSCommitment{}, err
	}
	return commit, nil
}

func (n *Node) sharePVSS(ctx context.Context, seq uint64) (asig.PVSSCommitment, error) {
	type result struct {
		commit asig.PVSSCommitment
		err    error
	}
	resultCh := make(chan result, 1)
	members := n.State.MembersSnapshot()
	start := time.Now()
	n.Crypto.Go(ctx, func() {
		commit, _, err := n.PVSS.Share(n.ID, seq, members)
		if n.Perf != nil {
			n.Perf.addShare(time.Since(start))
		}
		select {
		case resultCh <- result{commit: commit, err: err}:
		case <-ctx.Done():
		}
	})
	select {
	case result := <-resultCh:
		return result.commit, result.err
	case <-ctx.Done():
		return asig.PVSSCommitment{}, ctx.Err()
	}
}

func (n *Node) sendPVSS(ctx context.Context, epoch uint64, commit asig.PVSSCommitment) error {
	leader := n.State.Leader(epoch)
	msg, err := p2p.NewMessage(Protocol, "PVSS", epochInstance(epoch), n.ID, leader, commit)
	if err != nil {
		return err
	}
	if err := n.Transport.Send(ctx, leader, msg); err != nil {
		return err
	}
	return nil
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
		if b := n.pendingBeacon(epoch); b != nil {
			n.State.Advance(b.Random)
			return b, nil
		}
		select {
		case <-ticker.C:
			n.tick(epoch)
		case b := <-n.beacons:
			if b != nil && b.Epoch == epoch {
				n.State.Advance(b.Random)
				return b, nil
			}
			if b != nil && b.Epoch > epoch {
				n.pending[b.Epoch] = b
			}
		case <-deadline.C:
			return n.SkipCurrentEpochAt("beacon_wait", "timeout"), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (n *Node) SkipCurrentEpoch(reason string) *Beacon {
	return n.SkipCurrentEpochAt(reason, reason)
}

func (n *Node) SkipCurrentEpochAt(stage string, reason string) *Beacon {
	epoch, random := n.State.Skip(reason)
	diag := n.skipDiagnostics(epoch)
	n.mu.Lock()
	delete(n.epochs, epoch)
	n.mu.Unlock()
	return &Beacon{Epoch: epoch, Random: random, Digest: reason, Skipped: true, SkipStage: stage, SkipReason: reason, SkipDiag: diag}
}

func (n *Node) skipDiagnostics(epoch uint64) string {
	n.mu.Lock()
	totalEpochs := len(n.epochs)
	pendingBeacons := len(n.pending)
	commits := 0
	selected := 0
	prepare := 0
	precommit := 0
	commit := 0
	finalize := 0
	reconShares := 0
	proposal := false
	privateVerified := false
	decided := false
	reconSent := false
	if es := n.epochs[epoch]; es != nil {
		commits = len(es.commits)
		selected = len(es.selected)
		prepare = len(es.prepare)
		precommit = len(es.precommit)
		commit = len(es.commit)
		finalize = len(es.finalize)
		reconShares = len(es.reconShares)
		proposal = es.leaderProposal != nil
		privateVerified = es.privateVerified
		decided = es.decided
		reconSent = es.reconSent
	}
	n.mu.Unlock()
	metrics := n.Transport.Metrics()
	leader := n.State.Leader(epoch)
	return fmt.Sprintf(
		"local_epoch=%d leader=%s epochs=%d pending_beacons=%d proposal=%t commits=%d selected=%d private_verified=%t decided=%t prepare=%d precommit=%d commit=%d finalize=%d recon_sent=%t recon_shares=%d sent_msgs=%d recv_msgs=%d",
		n.State.CurrentEpoch(), leader, totalEpochs, pendingBeacons, proposal, commits, selected, privateVerified, decided, prepare, precommit, commit, finalize, reconSent, reconShares, metrics.SentMessages, metrics.RecvMessages,
	)
}

func (n *Node) pendingBeacon(epoch uint64) *Beacon {
	b := n.pending[epoch]
	if b != nil {
		delete(n.pending, epoch)
	}
	return b
}

func (n *Node) propose(ctx context.Context, epoch uint64) error {
	if epoch != n.State.CurrentEpoch() {
		return nil
	}
	if err := n.produceWindow(ctx, epoch); err != nil {
		return err
	}
	n.tick(epoch)
	return nil
}

func (n *Node) produceWindow(ctx context.Context, current uint64) error {
	for epoch := current; epoch <= current+n.lookahead; epoch++ {
		n.prodMu.Lock()
		if _, ok := n.produced[epoch]; ok {
			n.prodMu.Unlock()
			continue
		}
		n.prodMu.Unlock()

		n.prodMu.Lock()
		n.produced[epoch] = struct{}{}
		n.prodMu.Unlock()
		n.produceForEpochAsync(ctx, epoch)
	}
	return nil
}

func (n *Node) produceForEpochAsync(ctx context.Context, epoch uint64) {
	n.seqMu.Lock()
	n.seq++
	seq := n.seq
	n.seqMu.Unlock()

	members := n.State.MembersSnapshot()
	start := time.Now()
	n.Crypto.Go(ctx, func() {
		commit, _, err := n.PVSS.Share(n.ID, seq, members)
		if n.Perf != nil {
			n.Perf.addShare(time.Since(start))
		}
		if err == nil {
			sendCtx, cancel := context.WithTimeout(context.Background(), sendTimeout)
			err = n.sendPVSS(sendCtx, epoch, commit)
			cancel()
		}
		if err != nil {
			n.prodMu.Lock()
			delete(n.produced, epoch)
			n.prodMu.Unlock()
		}
	})
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
		epoch, ok := parseEpochInstance(msg.Instance)
		if !ok {
			return
		}
		n.Crypto.Go(context.Background(), func() { n.handleCommit(epoch, body) })
	case "PROPOSAL":
		body, err := p2p.DecodePayload[AgreementMessage](msg)
		if err != nil {
			return
		}
		n.Crypto.Go(context.Background(), func() { n.handleProposal(body) })
	case "PVSS_DATA":
		body, err := p2p.DecodePayload[PrivateDataMessage](msg)
		if err != nil {
			return
		}
		from := msg.From
		n.Crypto.Go(context.Background(), func() { n.handlePrivateData(body, from) })
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
		from := msg.From
		n.Crypto.Go(context.Background(), func() { n.handleRecon(body, from) })
	case "BEACON":
		body, err := p2p.DecodePayload[BeaconMessage](msg)
		if err != nil {
			return
		}
		from := msg.From
		n.Crypto.Go(context.Background(), func() { n.handleBeacon(body, from) })
	}
}

func (n *Node) handleCommit(epoch uint64, commit asig.PVSSCommitment) {
	if !n.epochAllowed(epoch) || n.State.Leader(epoch) != n.ID {
		return
	}
	if commit.Dealer == "" || commit.Seq == 0 {
		return
	}
	if !n.PVSS.Verify(commit) {
		return
	}
	n.mu.Lock()
	es := n.stateAtLocked(epoch)
	if es == nil || es.proposalBroadcast || es.proposing || es.commits == nil {
		n.mu.Unlock()
		return
	}
	if _, exists := es.commits[commit.Dealer]; exists {
		n.mu.Unlock()
		return
	}
	es.commits[commit.Dealer] = commit
	n.mu.Unlock()
	n.tick(epoch)
}

func (n *Node) tick(epoch uint64) {
	es := n.stateAt(epoch)
	if es == nil {
		return
	}
	n.tryPendingProposal(es)
	n.maybePreAggregate(es)
	n.tryLeaderProposal(es)
	n.maybeSendPrepare(es)
	n.progressVotes(es)
	n.tryReconstruct(es)
	n.tryBroadcastBeacon(es)
}

func (n *Node) maybePreAggregate(es *epochState) {
	if n.State.Leader(es.epoch) != n.ID {
		return
	}
	t := n.State.Threshold()
	n.mu.Lock()
	if es.aggregate != nil || es.preAggregating || len(es.commits) < t {
		n.mu.Unlock()
		return
	}
	es.preAggregating = true
	commitments := make([]asig.PVSSCommitment, 0, len(es.commits))
	for _, commit := range es.commits {
		commitments = append(commitments, commit)
	}
	epoch := es.epoch
	n.mu.Unlock()

	members := n.State.MembersSnapshot()
	n.Crypto.Go(context.Background(), func() {
		n.finishPreAggregate(es, epoch, t, commitments, members)
	})
}

func (n *Node) finishPreAggregate(es *epochState, epoch uint64, t int, commitments []asig.PVSSCommitment, members []p2p.NodeID) {
	clearPreAggregating := func() {
		n.mu.Lock()
		es.preAggregating = false
		n.mu.Unlock()
	}
	sort.Slice(commitments, func(i, j int) bool {
		if commitments[i].Dealer == commitments[j].Dealer {
			return commitments[i].Seq < commitments[j].Seq
		}
		return commitments[i].Dealer < commitments[j].Dealer
	})
	selected := make([]CommitmentRef, t)
	cmps := make([]asig.PVSSCommitment, t)
	for i := 0; i < t; i++ {
		c := commitments[i]
		selected[i] = CommitmentRef{Dealer: c.Dealer, Seq: c.Seq}
		cmps[i] = c
	}
	// Each epoch-local commitment was verified before caching in handleCommit.
	// Followers still verify the public aggregate carried by PROPOSAL.
	aggregate, err := n.PVSS.AggregateTrusted(n.ID, epoch+1, cmps, members)
	if err != nil {
		clearPreAggregating()
		return
	}
	columns, ok := privateColumnsByMember(cmps, members)
	if !ok {
		clearPreAggregating()
		return
	}
	n.mu.Lock()
	if es.aggregate == nil {
		es.selected = selected
		es.aggregate = &aggregate
		es.selectedColumns = columns
		es.selectedSet = true
		es.commits = nil
	}
	es.preAggregating = false
	n.mu.Unlock()
	n.tick(epoch)
}

func (n *Node) tryLeaderProposal(es *epochState) {
	if n.State.Leader(es.epoch) != n.ID || es.epoch != n.State.CurrentEpoch() {
		return
	}
	n.mu.Lock()
	if es.proposalBroadcast || es.proposing || es.aggregate == nil || len(es.selected) < n.State.Threshold() || es.selectedColumns == nil {
		n.mu.Unlock()
		return
	}
	es.proposing = true
	selected := append([]CommitmentRef(nil), es.selected...)
	aggregate := *es.aggregate
	columns := cloneColumnsByMember(es.selectedColumns)
	n.mu.Unlock()

	clearProposing := func() {
		n.mu.Lock()
		es.proposing = false
		n.mu.Unlock()
	}
	digest := computeAgreementDigest(n.State.RPrevBytes(), es.epoch, n.ID, selected, aggregate)
	if digest == "" {
		clearProposing()
		return
	}
	msg := AgreementMessage{
		Epoch:    es.epoch,
		Leader:   n.ID,
		Digest:   digest,
		Selected: selected,
	}
	n.mu.Lock()
	if es.proposalBroadcast {
		es.proposing = false
		n.mu.Unlock()
		return
	}
	es.leaderProposal = &msg
	es.selected = selected
	es.digest = digest
	es.proposalBroadcast = true
	es.selectedSet = true
	es.pendingProposal = nil
	es.prepareSent = false
	es.precommitSent = false
	es.commitSent = false
	es.finalizeSent = false
	es.privateVerified = false
	es.proposing = false
	n.mu.Unlock()
	n.sendPrivateColumns(es.epoch, n.ID, digest, selected, aggregate, columns)
	// Broadcast the public proposal after private sends are queued. Correctness
	// does not depend on ordering: receivers buffer private columns if they
	// arrive before this proposal.
	n.broadcastAsync(Protocol, "PROPOSAL", es.epoch, msg)
}

func (n *Node) maybeSendPrepare(es *epochState) {
	n.mu.Lock()
	// PREPARE is delayed until privateVerified is true: each node must validate
	// the digest-bound aggregate and its private vbar/cbar/pi_bar data first.
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
	if msg.Epoch > n.State.CurrentEpoch() {
		n.mu.Lock()
		es := n.stateAtLocked(msg.Epoch)
		if es != nil && es.leaderProposal == nil {
			es.pendingProposal = &msg
		}
		n.mu.Unlock()
		return
	}
	selected, ok, pending := n.validateProposal(msg.Epoch, msg.Selected, msg.Digest)
	if !ok {
		if !pending {
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
			shouldGossip := !es.proposalGossiped
			es.proposalGossiped = true
			pendingPrivate := append([]pendingPrivateData(nil), es.pendingPrivate...)
			es.pendingPrivate = nil
			pendingVotes := append([]pendingVote(nil), es.pendingVotes...)
			es.pendingVotes = nil
			pendingRecon := append([]ReconMessage(nil), es.pendingRecon...)
			es.pendingRecon = nil
			pendingBeacon := append([]pendingBeaconMessage(nil), es.pendingBeacon...)
			es.pendingBeacon = nil
			n.mu.Unlock()
			if shouldGossip {
				n.broadcastAsync(Protocol, "PROPOSAL", msg.Epoch, msg)
			}
			for _, pending := range pendingPrivate {
				n.handlePrivateData(pending.msg, pending.from)
			}
			n.replayPendingVotes(pendingVotes, msg.Digest)
			n.replayPendingRecon(pendingRecon, msg.Digest)
			n.replayPendingBeacon(pendingBeacon, msg.Digest)
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
	es.leaderProposal = &msg
	es.selected = selected
	es.digest = msg.Digest
	es.selectedSet = true
	es.pendingProposal = nil
	shouldGossip := !es.proposalGossiped
	es.proposalGossiped = true
	pendingPrivate := append([]pendingPrivateData(nil), es.pendingPrivate...)
	es.pendingPrivate = nil
	pendingVotes := append([]pendingVote(nil), es.pendingVotes...)
	es.pendingVotes = nil
	pendingRecon := append([]ReconMessage(nil), es.pendingRecon...)
	es.pendingRecon = nil
	pendingBeacon := append([]pendingBeaconMessage(nil), es.pendingBeacon...)
	es.pendingBeacon = nil
	n.mu.Unlock()
	if shouldGossip {
		n.broadcastAsync(Protocol, "PROPOSAL", msg.Epoch, msg)
	}
	// Re-play buffered private messages after the digest proposal is installed.
	// handlePrivateData will still verify digest, selected inputs, aggregate
	// membership, and column DLEQ proofs before setting privateVerified.
	for _, pending := range pendingPrivate {
		n.handlePrivateData(pending.msg, pending.from)
	}
	n.replayPendingVotes(pendingVotes, msg.Digest)
	n.replayPendingRecon(pendingRecon, msg.Digest)
	n.replayPendingBeacon(pendingBeacon, msg.Digest)
	n.maybeSendPrepare(es)
}

func (n *Node) tryPendingProposal(es *epochState) {
	n.mu.Lock()
	if es.leaderProposal != nil || es.pendingProposal == nil {
		n.mu.Unlock()
		return
	}
	msg := *es.pendingProposal
	selected, ok, pending := n.validateProposal(msg.Epoch, msg.Selected, msg.Digest)
	if !ok {
		if !pending {
			es.pendingProposal = nil
		}
		n.mu.Unlock()
		return
	}
	es.leaderProposal = &msg
	es.selected = selected
	es.digest = msg.Digest
	es.selectedSet = true
	es.pendingProposal = nil
	shouldGossip := !es.proposalGossiped
	es.proposalGossiped = true
	pendingPrivate := append([]pendingPrivateData(nil), es.pendingPrivate...)
	es.pendingPrivate = nil
	pendingVotes := append([]pendingVote(nil), es.pendingVotes...)
	es.pendingVotes = nil
	pendingRecon := append([]ReconMessage(nil), es.pendingRecon...)
	es.pendingRecon = nil
	pendingBeacon := append([]pendingBeaconMessage(nil), es.pendingBeacon...)
	es.pendingBeacon = nil
	n.mu.Unlock()
	if shouldGossip {
		n.broadcastAsync(Protocol, "PROPOSAL", msg.Epoch, msg)
	}
	for _, pending := range pendingPrivate {
		n.handlePrivateData(pending.msg, pending.from)
	}
	n.replayPendingVotes(pendingVotes, msg.Digest)
	n.replayPendingRecon(pendingRecon, msg.Digest)
	n.replayPendingBeacon(pendingBeacon, msg.Digest)
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
	if es.leaderProposal == nil {
		// Private PVSS_DATA is recipient-specific and may race ahead of the
		// public proposal. Store it rather than rejecting it; it will be checked
		// once the digest-bound proposal is available.
		es.pendingPrivate = append(es.pendingPrivate, pendingPrivateData{msg: msg, from: from})
		n.mu.Unlock()
		return
	}
	if es.digest != "" && es.digest != msg.Digest {
		n.mu.Unlock()
		return
	}
	proposalSelected := append([]CommitmentRef(nil), es.selected...)
	n.mu.Unlock()

	if !n.PVSS.Verify(msg.Aggregate) {
		return
	}
	if !sameRefs(selected, proposalSelected) {
		return
	}
	aggregate := msg.Aggregate
	if !aggregateMatchesSelection(aggregate, selected) {
		return
	}
	// The private-data validation point: Aggregate and this recipient's
	// vbar/cbar/pi_bar column must match the digest-only agreement proposal.
	if !n.PVSS.VerifyAggregationColumn(n.ID, aggregate, msg.Columns) {
		return
	}
	expected := computeAgreementDigest(n.State.RPrevBytes(), msg.Epoch, msg.Leader, selected, aggregate)
	if expected == "" || expected != msg.Digest {
		return
	}
	n.mu.Lock()
	es = n.stateAtLocked(msg.Epoch)
	if es == nil || es.leaderProposal == nil {
		n.mu.Unlock()
		return
	}
	if es.digest != "" && es.digest != msg.Digest {
		n.mu.Unlock()
		return
	}
	es.selected = selected
	es.digest = msg.Digest
	es.aggregate = &aggregate
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
	if es == nil {
		n.mu.Unlock()
		return
	}
	if es.leaderProposal == nil {
		es.pendingVotes = append(es.pendingVotes, pendingVote{stage: stage, msg: msg, from: from})
		n.mu.Unlock()
		return
	}
	if es.leaderProposal.Digest != msg.Digest || es.leaderProposal.Leader != msg.Leader {
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

func (n *Node) replayPendingVotes(votes []pendingVote, digest string) {
	for _, vote := range votes {
		if vote.msg.Digest != digest {
			continue
		}
		n.handleVote(vote.stage, vote.msg, vote.from)
	}
}

func (n *Node) replayPendingRecon(messages []ReconMessage, digest string) {
	for _, msg := range messages {
		if msg.Digest != digest {
			continue
		}
		n.handleRecon(msg, msg.Share.Holder)
	}
}

func (n *Node) replayPendingBeacon(messages []pendingBeaconMessage, digest string) {
	for _, pending := range messages {
		if pending.msg.Digest != digest {
			continue
		}
		n.handleBeacon(pending.msg, pending.from)
	}
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
	t := n.State.Threshold()
	if es.secret != nil || es.random != nil || es.reconstructing || len(es.reconShares) >= t || es.reconShares[from].CommitmentID != "" {
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
	if es.secret != nil || es.random != nil || es.reconstructing || len(es.reconShares) >= t || es.reconShares[from].CommitmentID != "" {
		n.mu.Unlock()
		return
	}
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
		n.mu.Lock()
		if es.secret != nil || es.random != nil || es.reconstructing || len(es.reconShares) >= t || es.reconShares[extra.Share.Holder].CommitmentID != "" {
			n.mu.Unlock()
			continue
		}
		n.mu.Unlock()
		if !n.PVSS.VerifyShare(aggregate, extra.Share) {
			continue
		}
		n.mu.Lock()
		if es.aggregate != nil && es.digest == msg.Digest && es.secret == nil && es.random == nil && !es.reconstructing && len(es.reconShares) < t {
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
		epoch := es.epoch
		digest := es.digest
		n.Crypto.Go(context.Background(), func() { n.broadcastRecon(epoch, digest, aggregate) })
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
		if es.reconstructing {
			n.mu.Unlock()
			return
		}
		es.reconstructing = true
		decrypted := make([]asig.PVSSDecryptedShare, 0, len(es.reconShares))
		for _, share := range es.reconShares {
			decrypted = append(decrypted, share)
		}
		aggregate := *es.aggregate
		epoch := es.epoch
		n.mu.Unlock()
		n.Crypto.Go(context.Background(), func() {
			start := time.Now()
			recovered, err := n.PVSS.ReconTrusted(aggregate, decrypted, t)
			if n.Perf != nil {
				n.Perf.addRecon(time.Since(start))
			}
			n.mu.Lock()
			if err == nil && es.secret == nil {
				es.secret = recovered
			}
			es.reconstructing = false
			n.mu.Unlock()
			if err == nil {
				n.tick(epoch)
			}
		})
		return
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

func (n *Node) broadcastRecon(epoch uint64, digest string, c asig.PVSSCommitment) {
	start := time.Now()
	share, err := n.PVSS.PreReconTrusted(c, n.ID)
	if n.Perf != nil {
		n.Perf.addPreRecon(time.Since(start))
	}
	if err != nil {
		return
	}
	n.send(Protocol, "RECON", epoch, ReconMessage{
		Epoch:  epoch,
		Digest: digest,
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
	start := time.Now()
	sig, err := asig.SignBLS(string(n.ID), n.BLS.Private, beaconVoteBytes(es.epoch, es.digest, randomHashValue))
	if n.Perf != nil {
		n.Perf.addBLSSign(time.Since(start))
	}
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
		if es != nil && es.leaderProposal == nil {
			es.pendingBeacon = append(es.pendingBeacon, pendingBeaconMessage{msg: msg, from: from})
		}
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
	n.mu.Lock()
	if es.certificateSet || es.assemblingCert {
		n.mu.Unlock()
		return
	}
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
	epoch := es.epoch
	digest := es.digest
	threshold := n.State.Threshold()
	es.assemblingCert = true
	n.mu.Unlock()

	n.Crypto.Go(context.Background(), func() {
		start := time.Now()
		agg, err := asig.AggregateBLSTrusted(votes, n.BLSPublic, beaconVoteBytes(epoch, digest, msgHash), threshold)
		if n.Perf != nil {
			n.Perf.addBLSAggregate(time.Since(start))
		}
		if err != nil {
			n.mu.Lock()
			es.assemblingCert = false
			n.mu.Unlock()
			return
		}
		n.finishAssembleBeacon(es, agg)
	})
}

func (n *Node) finishAssembleBeacon(es *epochState, agg asig.BLSAggregateSignature) {
	n.mu.Lock()
	if es.certificateSet {
		es.assemblingCert = false
		n.mu.Unlock()
		return
	}
	es.certificate = agg
	es.certificateSet = true
	es.assemblingCert = false
	epoch := es.epoch
	random := append([]byte(nil), es.random...)
	digest := es.digest
	selected := append([]CommitmentRef(nil), es.selected...)
	n.mu.Unlock()
	n.beacons <- &Beacon{
		Epoch:      epoch,
		Random:     random,
		Digest:     digest,
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

func (n *Node) sendPrivateColumns(epoch uint64, leader p2p.NodeID, digest string, selected []CommitmentRef, aggregate asig.PVSSCommitment, columns map[p2p.NodeID][]asig.PVSSColumnEntry) {
	for _, member := range n.State.MembersSnapshot() {
		memberColumns, ok := columns[member]
		if !ok {
			continue
		}
		payload := PrivateDataMessage{
			Epoch: epoch, Leader: leader, Digest: digest, Selected: selected,
			Aggregate: aggregate,
			Columns:   cloneColumns(memberColumns),
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

func privateColumnsByMember(commitments []asig.PVSSCommitment, members []p2p.NodeID) (map[p2p.NodeID][]asig.PVSSColumnEntry, bool) {
	out := make(map[p2p.NodeID][]asig.PVSSColumnEntry, len(members))
	for _, member := range members {
		columns := make([]asig.PVSSColumnEntry, 0, len(commitments))
		for _, c := range commitments {
			proof, ok := c.DLEQ[member]
			if !ok {
				return nil, false
			}
			commit, ok := c.Commit[member]
			if !ok {
				return nil, false
			}
			cipher, ok := c.Cipher[member]
			if !ok {
				return nil, false
			}
			columns = append(columns, asig.PVSSColumnEntry{
				Source: asig.PVSSSource{Dealer: c.Dealer, Seq: c.Seq, SecretID: c.SecretID},
				Commit: commit,
				Cipher: cipher,
				Proof:  proof,
			})
		}
		out[member] = columns
	}
	return out, true
}

func cloneColumnsByMember(in map[p2p.NodeID][]asig.PVSSColumnEntry) map[p2p.NodeID][]asig.PVSSColumnEntry {
	out := make(map[p2p.NodeID][]asig.PVSSColumnEntry, len(in))
	for member, columns := range in {
		out[member] = cloneColumns(columns)
	}
	return out
}

func cloneColumns(in []asig.PVSSColumnEntry) []asig.PVSSColumnEntry {
	out := make([]asig.PVSSColumnEntry, len(in))
	copy(out, in)
	return out
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
		commits:      make(map[p2p.NodeID]asig.PVSSCommitment),
		reconShares:  make(map[p2p.NodeID]asig.PVSSDecryptedShare),
		beaconVotes:  make(map[string]map[p2p.NodeID]asig.BLSSignatureShare),
		pendingRecon: make([]ReconMessage, 0),
		pendingVotes: make([]pendingVote, 0),
	}
	n.epochs[epoch] = es
	return es
}

func (n *Node) epochAllowed(epoch uint64) bool {
	current := n.State.CurrentEpoch()
	if epoch >= current {
		return true
	}
	n.mu.Lock()
	_, ok := n.epochs[epoch]
	n.mu.Unlock()
	return ok
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

func (n *Node) CachedCommitments() (total int, max int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, es := range n.epochs {
		count := len(es.commits)
		total += count
		if count > max {
			max = count
		}
	}
	return total, max
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

func sameRefs(a, b []CommitmentRef) bool {
	a = normalizeRefs(a)
	b = normalizeRefs(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

func parseEpochInstance(instance string) (uint64, bool) {
	var epoch uint64
	if _, err := fmt.Sscanf(instance, "epoch-%d", &epoch); err != nil {
		return 0, false
	}
	return epoch, true
}

func randomHash(random []byte) string {
	return hex.EncodeToString(asig.HashBytes(random))
}

func beaconVoteBytes(epoch uint64, digest string, randomHash string) []byte {
	return asig.HashBytes([]byte("Spurt-v1/BEACON"), encodeEpoch(epoch), []byte(digest), []byte(randomHash))
}
