package protocol

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	asig "github.com/scottocs/Tyche/asyrand/crypto"
	"github.com/scottocs/Tyche/asyrand/protocol/rbc"
	"github.com/scottocs/Tyche/utils/cryptoexec"
	"github.com/scottocs/Tyche/utils/p2p"
	"sync"
	"time"
)

const Protocol = "asyrand"
const maxSourceAttemptTimeout = 20 * time.Second

var errCommitmentNotReady = errors.New("source commitment not ready")

type Node struct {
	ID        p2p.NodeID
	Keys      asig.KeyPair
	Public    map[string]ed25519.PublicKey
	Transport p2p.Transport
	Perf      *PerfMetrics

	State  *State
	PVSS   asig.Scheme
	RBC    *rbc.Broadcaster
	Crypto *cryptoexec.Executor

	seqMu sync.Mutex
	seq   uint64

	producerMu       sync.Mutex
	producerInFlight []uint64

	reconMu      sync.Mutex
	recon        map[string]*reconState
	pendingRecon map[string][]ReconMessage
	pendingEcho  map[string][]BeaconVoteMessage
	pendingReady map[string][]BeaconVoteMessage
	beacons      chan *Beacon
}

type NodeConfig struct {
	ID            p2p.NodeID
	Members       []p2p.NodeID
	F             int
	QueueLen      int
	Seed          []byte
	Keys          asig.KeyPair
	Public        map[string]ed25519.PublicKey
	Transport     p2p.Transport
	PVSS          asig.Scheme
	CryptoWorkers int
}

type ReconMessage struct {
	Epoch    uint64              `json:"epoch"`
	Source   p2p.NodeID          `json:"source"`
	CommitID string              `json:"commit_id"`
	Share    asig.DecryptedShare `json:"share"`
}

type BeaconVoteMessage struct {
	Epoch      uint64         `json:"epoch"`
	Source     p2p.NodeID     `json:"source"`
	CommitID   string         `json:"commit_id"`
	Random     []byte         `json:"random"`
	RandomHash string         `json:"random_hash"`
	Vote       asig.VoteShare `json:"vote"`
}

type reconState struct {
	epoch    uint64
	source   p2p.NodeID
	commit   asig.Commitment
	instance string

	shares       map[p2p.NodeID]asig.DecryptedShare
	randomByHash map[string][]byte
	echo         map[string]map[p2p.NodeID]asig.VoteShare
	ready        map[string]map[p2p.NodeID]asig.VoteShare
	echoSent     map[string]bool
	readySent    map[string]bool
	delivered    bool
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
	state := NewState(cfg.Members, cfg.F, cfg.QueueLen, cfg.Seed)
	return &Node{
		ID: cfg.ID, Keys: cfg.Keys, Public: cfg.Public,
		Transport: cfg.Transport, Perf: &PerfMetrics{}, State: state, PVSS: cfg.PVSS,
		Crypto: cryptoexec.New(cfg.CryptoWorkers),
		RBC:    rbc.New(cfg.ID, state.N, state.F, cfg.Transport),
		recon:  make(map[string]*reconState), pendingRecon: make(map[string][]ReconMessage),
		pendingEcho: make(map[string][]BeaconVoteMessage), pendingReady: make(map[string][]BeaconVoteMessage),
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

func (n *Node) Produce(ctx context.Context) (asig.Commitment, error) {
	n.seqMu.Lock()
	n.seq++
	seq := n.seq
	n.seqMu.Unlock()

	start := time.Now()
	commit, _, err := n.PVSS.Share(n.ID, seq, n.State.Members)
	if n.Perf != nil {
		n.Perf.addShare(time.Since(start))
	}
	if err != nil {
		return asig.Commitment{}, err
	}
	raw, err := json.Marshal(commit)
	if err != nil {
		return asig.Commitment{}, err
	}
	if err := n.RBC.Broadcast(ctx, seq, raw); err != nil {
		return asig.Commitment{}, err
	}
	return commit, nil
}

func (n *Node) StartProducer(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	queueLen := n.State.QueueLen
	if queueLen <= 0 {
		queueLen = 8
	}
	high := 4
	if high > queueLen {
		high = queueLen
	}
	low := 2
	if low > high {
		low = high
	}
	if low <= 0 {
		low = 1
	}
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()
		producing := true
		for {
			select {
			case <-timer.C:
				n.refreshProducerInFlight()
				depth := n.State.QueueLength(n.ID)
				inFlight := n.producerInFlightCount()
				level := depth + inFlight
				if level >= high {
					producing = false
				} else if level <= low {
					producing = true
				}
				if producing && level < high && depth < queueLen && inFlight < high {
					commit, err := n.Produce(ctx)
					if err == nil {
						n.trackProducerInFlight(commit.Seq)
					}
				}
				timer.Reset(interval)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (n *Node) RunEpoch(ctx context.Context, timeout time.Duration) (*Beacon, bool, error) {
	source, err := n.State.Source()
	if err != nil {
		return nil, false, err
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	epochDeadline := time.Now().Add(timeout)
	sourceWait := timeout
	if sourceWait > maxSourceAttemptTimeout {
		sourceWait = maxSourceAttemptTimeout
	}
	sourceDeadline := time.Now().Add(sourceWait)
	epoch := n.State.CurrentEpoch()
	instance := fmt.Sprintf("epoch/%d/source/%s", epoch, source)
	var commitID string
	for {
		if n.State.HasCommitment(source) {
			commitID, err = n.startConsumer(ctx, epoch, source, instance)
			if err == nil {
				break
			}
			if !errors.Is(err, errCommitmentNotReady) {
				return nil, false, err
			}
		}
		remaining := time.Until(sourceDeadline)
		if remaining <= 0 {
			if !n.State.AdvanceHeadToNextCommitment(source) {
				n.State.RemoveSource(source)
			}
			return nil, false, nil
		}
		wait := 10 * time.Millisecond
		if remaining < wait {
			wait = remaining
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}

	remaining := time.Until(epochDeadline)
	if remaining <= 0 {
		return n.SkipCurrentEpochAt(source, "consumer_start", "timeout"), false, nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	for {
		select {
		case beacon := <-n.beacons:
			if beacon.Epoch != epoch || beacon.Source != source || beacon.CommitID != commitID {
				continue
			}
			n.State.AdvanceForSource(beacon.Random, source)
			return beacon, true, nil
		case <-timer.C:
			return n.SkipCurrentEpochAt(source, "beacon_wait", "timeout"), false, nil
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (n *Node) SkipCurrentEpoch(source p2p.NodeID, reason string) *Beacon {
	return n.SkipCurrentEpochAt(source, reason, reason)
}

func (n *Node) SkipCurrentEpochAt(source p2p.NodeID, stage string, reason string) *Beacon {
	epoch := n.State.CurrentEpoch()
	diag := n.skipDiagnostics(source)
	random := n.State.Skip(source, reason)
	return &Beacon{Epoch: epoch, Source: source, Random: random, CommitID: reason, Skipped: true, SkipStage: stage, SkipReason: reason, SkipDiag: diag}
}

func (n *Node) skipDiagnostics(source p2p.NodeID) string {
	queueTotal, queueMax := n.State.QueueBacklog()
	current := n.State.CurrentEpoch()
	hasCommitment := false
	queueLen := 0
	consumedSeq := uint64(0)
	if source != "" {
		hasCommitment = n.State.HasCommitment(source)
		queueLen = n.State.QueueLength(source)
		consumedSeq = n.State.ConsumedSeq(source)
	}
	metrics := n.Transport.Metrics()
	return fmt.Sprintf(
		"local_epoch=%d source=%s source_has_commitment=%t source_queue=%d source_consumed_seq=%d queue_total=%d queue_max=%d sent_msgs=%d recv_msgs=%d",
		current, source, hasCommitment, queueLen, consumedSeq, queueTotal, queueMax, metrics.SentMessages, metrics.RecvMessages,
	)
}

func (n *Node) AcceptCommitment(commit asig.Commitment) bool {
	if !n.PVSS.Verify(commit) {
		return false
	}
	queued := n.State.Enqueue(commit)
	if commit.Dealer == n.ID {
		n.markProducedDelivered(commit.Seq)
	}
	return queued
}

func (n *Node) dispatch(ctx context.Context) {
	for {
		select {
		case msg, ok := <-n.Transport.Inbox():
			if !ok {
				return
			}
			switch msg.Protocol {
			case rbc.Protocol:
				start := time.Now()
				_ = n.RBC.Handle(ctx, msg)
				if n.Perf != nil {
					n.Perf.addRBCHandle(time.Since(start))
				}
				n.drainDeliveries()
			case Protocol:
				_ = n.handleAsyRand(ctx, msg)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) drainDeliveries() {
	for {
		select {
		case delivery := <-n.RBC.Deliveries:
			var commit asig.Commitment
			if err := json.Unmarshal(delivery.Value, &commit); err == nil {
				n.AcceptCommitment(commit)
			}
		default:
			return
		}
	}
}

func (n *Node) startConsumer(ctx context.Context, epoch uint64, source p2p.NodeID, instance string) (string, error) {
	commit, ok := n.State.PopCommitment(source)
	if !ok {
		return "", errCommitmentNotReady
	}
	st := n.ensureReconState(epoch, source, commit, instance)
	start := time.Now()
	share, err := n.PVSS.PreReconTrusted(commit, n.ID)
	if n.Perf != nil {
		n.Perf.addPreRecon(time.Since(start))
	}
	if err != nil {
		return "", err
	}
	msg, err := p2p.NewMessage(Protocol, "RECON", st.instance, n.ID, "", ReconMessage{Epoch: epoch, Source: source, CommitID: commit.SecretID, Share: share})
	if err != nil {
		return "", err
	}
	if err := n.Transport.Broadcast(ctx, msg); err != nil {
		return "", err
	}
	n.drainPendingConsumerMessages(ctx, st)
	return commit.SecretID, nil
}

func (n *Node) handleAsyRand(ctx context.Context, msg p2p.Message) error {
	switch msg.Type {
	case "RECON":
		body, err := p2p.DecodePayload[ReconMessage](msg)
		if err != nil {
			return err
		}
		if n.reconStateForMessage(body.Epoch, body.Source, body.CommitID) == nil {
			n.bufferRecon(body)
			return nil
		}
		n.Crypto.Go(ctx, func() { n.handleRecon(ctx, body) })
	case "ECHO":
		body, err := p2p.DecodePayload[BeaconVoteMessage](msg)
		if err != nil {
			return err
		}
		if n.reconStateForMessage(body.Epoch, body.Source, body.CommitID) == nil {
			n.bufferEcho(body)
			return nil
		}
		n.Crypto.Go(ctx, func() { n.handleEcho(ctx, body) })
	case "READY":
		body, err := p2p.DecodePayload[BeaconVoteMessage](msg)
		if err != nil {
			return err
		}
		if n.reconStateForMessage(body.Epoch, body.Source, body.CommitID) == nil {
			n.bufferReady(body)
			return nil
		}
		n.Crypto.Go(ctx, func() { n.handleReady(ctx, body) })
	}
	return nil
}

func (n *Node) handleRecon(ctx context.Context, msg ReconMessage) {
	st := n.reconStateForMessage(msg.Epoch, msg.Source, msg.CommitID)
	if st == nil {
		return
	}
	start := time.Now()
	ok := n.PVSS.VerifyShare(st.commit, msg.Share)
	if n.Perf != nil {
		n.Perf.addVerify(time.Since(start))
	}
	if !ok {
		return
	}
	n.reconMu.Lock()
	if st.delivered || st.shares[msg.Share.Holder].CommitmentID != "" {
		n.reconMu.Unlock()
		return
	}
	st.shares[msg.Share.Holder] = msg.Share
	shares := make([]asig.DecryptedShare, 0, len(st.shares))
	for _, share := range st.shares {
		shares = append(shares, share)
	}
	alreadyEchoed := len(st.echoSent) > 0
	n.reconMu.Unlock()
	if len(shares) < n.State.F+1 || alreadyEchoed {
		return
	}
	start = time.Now()
	secret, err := n.PVSS.ReconTrusted(st.commit, shares, n.State.F+1)
	if n.Perf != nil {
		n.Perf.addRecon(time.Since(start))
	}
	if err != nil {
		return
	}
	random := asig.HashBytes(n.State.RPrevBytes(), secret, []byte(st.commit.SecretID))
	_ = n.broadcastVote(ctx, "ECHO", st, random)
}

func (n *Node) handleEcho(ctx context.Context, msg BeaconVoteMessage) {
	st := n.reconStateForMessage(msg.Epoch, msg.Source, msg.CommitID)
	if st == nil || !n.verifyVote("ECHO", msg) {
		return
	}
	n.reconMu.Lock()
	n.recordVote(st.echo, msg)
	count := len(st.echo[msg.RandomHash])
	shouldReady := count >= 2*n.State.F+1 && !st.readySent[msg.RandomHash]
	if shouldReady {
		st.randomByHash[msg.RandomHash] = append([]byte(nil), msg.Random...)
	}
	n.reconMu.Unlock()
	if shouldReady {
		_ = n.broadcastVote(ctx, "READY", st, msg.Random)
	}
}

func (n *Node) handleReady(ctx context.Context, msg BeaconVoteMessage) {
	st := n.reconStateForMessage(msg.Epoch, msg.Source, msg.CommitID)
	if st == nil || !n.verifyVote("READY", msg) {
		return
	}
	var shouldReady bool
	var beacon *Beacon
	n.reconMu.Lock()
	n.recordVote(st.ready, msg)
	st.randomByHash[msg.RandomHash] = append([]byte(nil), msg.Random...)
	readyCount := len(st.ready[msg.RandomHash])
	shouldReady = readyCount >= n.State.F+1 && !st.readySent[msg.RandomHash]
	if readyCount >= 2*n.State.F+1 && !st.delivered {
		votes := make([]asig.VoteShare, 0, len(st.ready[msg.RandomHash]))
		for _, vote := range st.ready[msg.RandomHash] {
			votes = append(votes, vote)
		}
		start := time.Now()
		agg, err := asig.BuildQuorumCertificate(votes, n.memberSet(), 2*n.State.F+1)
		if n.Perf != nil {
			n.Perf.addCertAggregate(time.Since(start))
		}
		if err == nil {
			shares := make([]asig.DecryptedShare, 0, len(st.shares))
			for _, share := range st.shares {
				shares = append(shares, share)
			}
			st.delivered = true
			beacon = &Beacon{Epoch: msg.Epoch, Source: msg.Source, Random: append([]byte(nil), msg.Random...), CommitID: msg.CommitID, Certificate: agg, Shares: shares}
		}
	}
	n.reconMu.Unlock()
	if shouldReady {
		_ = n.broadcastVote(ctx, "READY", st, msg.Random)
	}
	if beacon != nil {
		n.beacons <- beacon
	}
}

func (n *Node) broadcastVote(ctx context.Context, typ string, st *reconState, random []byte) error {
	hash := randomHash(random)
	start := time.Now()
	vote, err := asig.NewVoteShare(string(n.ID))
	if n.Perf != nil {
		n.Perf.addCertSign(time.Since(start))
	}
	if err != nil {
		return err
	}
	n.reconMu.Lock()
	if typ == "ECHO" {
		if st.echoSent[hash] {
			n.reconMu.Unlock()
			return nil
		}
		st.echoSent[hash] = true
	} else {
		if st.readySent[hash] {
			n.reconMu.Unlock()
			return nil
		}
		st.readySent[hash] = true
	}
	st.randomByHash[hash] = append([]byte(nil), random...)
	n.reconMu.Unlock()
	msg, err := p2p.NewMessage(Protocol, typ, st.instance, n.ID, "", BeaconVoteMessage{
		Epoch: st.epoch, Source: st.source, CommitID: st.commit.SecretID, Random: random, RandomHash: hash, Vote: vote,
	})
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) verifyVote(typ string, msg BeaconVoteMessage) bool {
	if msg.RandomHash != randomHash(msg.Random) {
		return false
	}
	start := time.Now()
	ok := asig.VerifyVoteShare(msg.Vote, n.memberSet())
	if n.Perf != nil {
		n.Perf.addCertVerify(time.Since(start))
	}
	return ok
}

func (n *Node) recordVote(bucket map[string]map[p2p.NodeID]asig.VoteShare, msg BeaconVoteMessage) {
	if bucket[msg.RandomHash] == nil {
		bucket[msg.RandomHash] = make(map[p2p.NodeID]asig.VoteShare)
	}
	bucket[msg.RandomHash][p2p.NodeID(msg.Vote.Signer)] = msg.Vote
}

func (n *Node) epochTimeoutError(epoch uint64, source p2p.NodeID) error {
	total, max := n.State.QueueBacklog()
	return fmt.Errorf("epoch timed out node=%s epoch=%d source=%s has_source_commit=%t source_queue=%d queue_total=%d queue_max=%d",
		n.ID, epoch, source, n.State.HasCommitment(source), n.State.QueueLength(source), total, max)
}

func (n *Node) reconStateForMessage(epoch uint64, source p2p.NodeID, commitID string) *reconState {
	key := reconKey(epoch, source, commitID)
	n.reconMu.Lock()
	st := n.recon[key]
	n.reconMu.Unlock()
	return st
}

func (n *Node) ensureReconState(epoch uint64, source p2p.NodeID, commit asig.Commitment, instance string) *reconState {
	key := reconKey(epoch, source, commit.SecretID)
	n.reconMu.Lock()
	defer n.reconMu.Unlock()
	if st := n.recon[key]; st != nil {
		return st
	}
	st := &reconState{
		epoch: epoch, source: source, commit: commit, instance: instance,
		shares: make(map[p2p.NodeID]asig.DecryptedShare), randomByHash: make(map[string][]byte),
		echo:     make(map[string]map[p2p.NodeID]asig.VoteShare),
		ready:    make(map[string]map[p2p.NodeID]asig.VoteShare),
		echoSent: make(map[string]bool), readySent: make(map[string]bool),
	}
	n.recon[key] = st
	return st
}

func reconKey(epoch uint64, source p2p.NodeID, commitID string) string {
	return fmt.Sprintf("%d/%s/%s", epoch, source, commitID)
}

func randomHash(random []byte) string {
	return hex.EncodeToString(asig.HashBytes(random))
}

func (n *Node) memberSet() map[string]struct{} {
	n.State.mu.RLock()
	defer n.State.mu.RUnlock()
	out := make(map[string]struct{}, len(n.State.Members))
	for _, id := range n.State.Members {
		out[string(id)] = struct{}{}
	}
	return out
}

func (n *Node) producerInFlightCount() int {
	n.producerMu.Lock()
	defer n.producerMu.Unlock()
	return len(n.producerInFlight)
}

func (n *Node) trackProducerInFlight(seq uint64) {
	n.producerMu.Lock()
	defer n.producerMu.Unlock()
	n.producerInFlight = append(n.producerInFlight, seq)
}

func (n *Node) markProducedDelivered(seq uint64) {
	n.producerMu.Lock()
	defer n.producerMu.Unlock()
	out := n.producerInFlight[:0]
	for _, pending := range n.producerInFlight {
		if pending != seq {
			out = append(out, pending)
		}
	}
	n.producerInFlight = out
}

func (n *Node) refreshProducerInFlight() {
	n.producerMu.Lock()
	inFlight := append([]uint64(nil), n.producerInFlight...)
	n.producerMu.Unlock()
	kept := inFlight[:0]
	for _, seq := range inFlight {
		if n.State.HasCommitmentSeq(n.ID, seq) || n.State.ConsumedSeq(n.ID) >= seq {
			continue
		}
		kept = append(kept, seq)
	}
	n.producerMu.Lock()
	n.producerInFlight = kept
	n.producerMu.Unlock()
}

func (n *Node) bufferRecon(msg ReconMessage) {
	key := reconKey(msg.Epoch, msg.Source, msg.CommitID)
	n.reconMu.Lock()
	defer n.reconMu.Unlock()
	n.pendingRecon[key] = append(n.pendingRecon[key], msg)
}

func (n *Node) bufferEcho(msg BeaconVoteMessage) {
	key := reconKey(msg.Epoch, msg.Source, msg.CommitID)
	n.reconMu.Lock()
	defer n.reconMu.Unlock()
	n.pendingEcho[key] = append(n.pendingEcho[key], msg)
}

func (n *Node) bufferReady(msg BeaconVoteMessage) {
	key := reconKey(msg.Epoch, msg.Source, msg.CommitID)
	n.reconMu.Lock()
	defer n.reconMu.Unlock()
	n.pendingReady[key] = append(n.pendingReady[key], msg)
}

func (n *Node) drainPendingConsumerMessages(ctx context.Context, st *reconState) {
	key := reconKey(st.epoch, st.source, st.commit.SecretID)
	n.reconMu.Lock()
	reconMsgs := append([]ReconMessage(nil), n.pendingRecon[key]...)
	echoMsgs := append([]BeaconVoteMessage(nil), n.pendingEcho[key]...)
	readyMsgs := append([]BeaconVoteMessage(nil), n.pendingReady[key]...)
	delete(n.pendingRecon, key)
	delete(n.pendingEcho, key)
	delete(n.pendingReady, key)
	n.reconMu.Unlock()
	for _, msg := range reconMsgs {
		n.handleRecon(ctx, msg)
	}
	for _, msg := range echoMsgs {
		n.handleEcho(ctx, msg)
	}
	for _, msg := range readyMsgs {
		n.handleReady(ctx, msg)
	}
}

func (n *Node) PerfSnapshot() PerfSnapshot {
	if n.Perf == nil {
		return PerfSnapshot{}
	}
	return n.Perf.Snapshot()
}
