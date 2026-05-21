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
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"sync"
	"time"
)

const Protocol = "asyrand"

var errCommitmentNotReady = errors.New("source commitment not ready")

type Node struct {
	ID        p2p.NodeID
	Keys      asig.KeyPair
	Public    map[string]ed25519.PublicKey
	BLS       asig.BLSKeyPair
	BLSPublic map[string]kyber.Point
	Transport p2p.Transport
	Perf      *PerfMetrics

	State *State
	PVSS  asig.Scheme
	RBC   *rbc.Broadcaster

	seqMu sync.Mutex
	seq   uint64

	producerMu      sync.Mutex
	producerPending int

	reconMu      sync.Mutex
	recon        map[string]*reconState
	pendingRecon map[string][]ReconMessage
	pendingEcho  map[string][]BeaconVoteMessage
	pendingReady map[string][]BeaconVoteMessage
	beacons      chan *Beacon
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
	PVSS      asig.Scheme
}

type ReconMessage struct {
	Epoch    uint64              `json:"epoch"`
	Source   p2p.NodeID          `json:"source"`
	CommitID string              `json:"commit_id"`
	Share    asig.DecryptedShare `json:"share"`
}

type BeaconVoteMessage struct {
	Epoch      uint64                 `json:"epoch"`
	Source     p2p.NodeID             `json:"source"`
	CommitID   string                 `json:"commit_id"`
	Random     []byte                 `json:"random"`
	RandomHash string                 `json:"random_hash"`
	Signature  asig.BLSSignatureShare `json:"signature"`
}

type reconState struct {
	epoch    uint64
	source   p2p.NodeID
	commit   asig.Commitment
	instance string

	shares       map[p2p.NodeID]asig.DecryptedShare
	randomByHash map[string][]byte
	echo         map[string]map[p2p.NodeID]asig.BLSSignatureShare
	ready        map[string]map[p2p.NodeID]asig.BLSSignatureShare
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
	if cfg.BLS.Private == nil || len(cfg.BLSPublic) == 0 {
		return nil, errors.New("bls signing keys are required")
	}
	state := NewState(cfg.Members, cfg.F, cfg.QueueLen, cfg.Seed)
	return &Node{
		ID: cfg.ID, Keys: cfg.Keys, Public: cfg.Public, BLS: cfg.BLS, BLSPublic: cfg.BLSPublic,
		Transport: cfg.Transport, Perf: &PerfMetrics{}, State: state, PVSS: cfg.PVSS,
		RBC:   rbc.New(cfg.ID, state.N, state.F, cfg.Transport),
		recon: make(map[string]*reconState), pendingRecon: make(map[string][]ReconMessage),
		pendingEcho: make(map[string][]BeaconVoteMessage), pendingReady: make(map[string][]BeaconVoteMessage),
		beacons: make(chan *Beacon, state.N*4),
	}, nil
}

func (n *Node) Start(ctx context.Context) error {
	if err := n.Transport.Start(ctx); err != nil {
		return err
	}
	go n.dispatch(ctx)
	return nil
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
	go func() {
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			select {
			case <-timer.C:
				pending := n.producerPendingCount()
				if n.State.QueueHasSpace(n.ID, pending) {
					n.producerMu.Lock()
					n.producerPending++
					n.producerMu.Unlock()
					if _, err := n.Produce(ctx); err != nil {
						n.markProducedDelivered()
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
	epoch := n.State.CurrentEpoch()
	instance := fmt.Sprintf("epoch/%d/source/%s", epoch, source)
	if !n.State.HasCommitment(source) {
		n.State.RemoveSource(source)
		return nil, false, nil
	}
	commitID, err := n.startConsumer(ctx, epoch, source, instance)
	if errors.Is(err, errCommitmentNotReady) {
		n.State.RemoveSource(source)
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	timer := time.NewTimer(timeout)
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
			return nil, false, errors.New("epoch timed out")
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func (n *Node) AcceptCommitment(commit asig.Commitment) bool {
	if !n.PVSS.Verify(commit) {
		return false
	}
	queued := n.State.Enqueue(commit)
	if commit.Dealer == n.ID {
		n.markProducedDelivered()
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
		n.handleRecon(ctx, body)
	case "ECHO":
		body, err := p2p.DecodePayload[BeaconVoteMessage](msg)
		if err != nil {
			return err
		}
		if n.reconStateForMessage(body.Epoch, body.Source, body.CommitID) == nil {
			n.bufferEcho(body)
			return nil
		}
		n.handleEcho(ctx, body)
	case "READY":
		body, err := p2p.DecodePayload[BeaconVoteMessage](msg)
		if err != nil {
			return err
		}
		if n.reconStateForMessage(body.Epoch, body.Source, body.CommitID) == nil {
			n.bufferReady(body)
			return nil
		}
		n.handleReady(ctx, body)
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
	if len(st.ready[msg.RandomHash]) >= 2*n.State.F+1 && !st.delivered {
		votes := make([]asig.BLSSignatureShare, 0, len(st.ready[msg.RandomHash]))
		for _, vote := range st.ready[msg.RandomHash] {
			votes = append(votes, vote)
		}
		msgBytes := voteBytes("READY", msg.Epoch, msg.Source, msg.CommitID, msg.RandomHash)
		start := time.Now()
		agg, err := asig.AggregateBLSTrusted(votes, n.BLSPublic, msgBytes, 2*n.State.F+1)
		if n.Perf != nil {
			n.Perf.addBLSAggregate(time.Since(start))
		}
		if err == nil {
			shares := make([]asig.DecryptedShare, 0, len(st.shares))
			for _, share := range st.shares {
				shares = append(shares, share)
			}
			st.delivered = true
			beacon = &Beacon{Epoch: msg.Epoch, Source: msg.Source, Random: append([]byte(nil), msg.Random...), CommitID: msg.CommitID, Signature: agg, Shares: shares}
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
	msgBytes := voteBytes(typ, st.epoch, st.source, st.commit.SecretID, hash)
	sig, err := asig.SignBLS(string(n.ID), n.BLS.Private, msgBytes)
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
		Epoch: st.epoch, Source: st.source, CommitID: st.commit.SecretID, Random: random, RandomHash: hash, Signature: sig,
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
	ok := asig.VerifyBLSShare(msg.Signature, n.BLSPublic, voteBytes(typ, msg.Epoch, msg.Source, msg.CommitID, msg.RandomHash))
	if n.Perf != nil {
		n.Perf.addBLSVerify(time.Since(start))
	}
	return ok
}

func (n *Node) recordVote(bucket map[string]map[p2p.NodeID]asig.BLSSignatureShare, msg BeaconVoteMessage) {
	if bucket[msg.RandomHash] == nil {
		bucket[msg.RandomHash] = make(map[p2p.NodeID]asig.BLSSignatureShare)
	}
	bucket[msg.RandomHash][p2p.NodeID(msg.Signature.Signer)] = msg.Signature
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
		echo:     make(map[string]map[p2p.NodeID]asig.BLSSignatureShare),
		ready:    make(map[string]map[p2p.NodeID]asig.BLSSignatureShare),
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

func voteBytes(typ string, epoch uint64, source p2p.NodeID, commitID, randomHash string) []byte {
	return []byte(fmt.Sprintf("AsyRand-v1/%s/%d/%s/%s/%s", typ, epoch, source, commitID, randomHash))
}

func (n *Node) producerPendingCount() int {
	n.producerMu.Lock()
	defer n.producerMu.Unlock()
	return n.producerPending
}

func (n *Node) markProducedDelivered() {
	n.producerMu.Lock()
	defer n.producerMu.Unlock()
	if n.producerPending > 0 {
		n.producerPending--
	}
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
