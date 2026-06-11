package grandline

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	asig "tyche.local/Tyche/grandline/crypto"
	"tyche.local/Tyche/utils/cryptoexec"
	"tyche.local/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

const Protocol = "grandline"

const (
	defaultEpochTimeout = 20 * time.Second
)

var errEpochTimeout = errors.New("epoch timeout")

type Node struct {
	ID        p2p.NodeID
	Keys      asig.KeyPair
	Public    map[string]ed25519.PublicKey
	Transport p2p.Transport
	Perf      *PerfMetrics
	State     *State
	PVSS      asig.PVSSScheme
	Crypto    *cryptoexec.Executor

	GRand asig.GRandShare

	roundMu       sync.Mutex
	rounds        map[string]*roundState
	pendingShares map[string][]shareMessage
	commitments   map[p2p.NodeID]*asig.VerifiedBeaconCommitment
	commitAlpha   kyber.Scalar
	commitSent    bool

	beacons chan *Beacon
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
	PVSS          asig.PVSSScheme
	GRand         asig.GRandShare
	CryptoWorkers int
}

type shareMessage struct {
	Epoch uint64           `json:"epoch"`
	Share asig.BeaconShare `json:"share"`
}

type roundState struct {
	epoch      uint64
	msg        []byte
	shares     map[p2p.NodeID]asig.BeaconShare
	delivered  bool
	recovering bool
}

func NewNode(cfg NodeConfig) (*Node, error) {
	if cfg.ID == "" {
		return nil, errors.New("node id is required")
	}
	if cfg.Transport == nil {
		return nil, errors.New("transport is required")
	}
	if cfg.PVSS == nil {
		return nil, errors.New("pvss scheme is required")
	}
	if cfg.GRand.SecretShare == "" || len(cfg.GRand.PublicShares) == 0 {
		return nil, errors.New("GRand keys are required")
	}
	if len(cfg.Members) < 2*cfg.F+1 {
		return nil, errors.New("must satisfy n >= 2f + 1")
	}
	state := NewState(cfg.Members, cfg.F, cfg.QueueLen, cfg.Seed)
	return &Node{
		ID: cfg.ID, Keys: cfg.Keys, Public: cfg.Public, Transport: cfg.Transport, Perf: &PerfMetrics{},
		State: state, PVSS: cfg.PVSS, Crypto: cryptoexec.New(cfg.CryptoWorkers), GRand: cfg.GRand,
		rounds: make(map[string]*roundState), pendingShares: make(map[string][]shareMessage),
		commitments: make(map[p2p.NodeID]*asig.VerifiedBeaconCommitment),
		beacons:     make(chan *Beacon, state.N*4),
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

func (n *Node) StartProducer(ctx context.Context, interval time.Duration) {
	// GRandLine has no per-epoch producer/source queue. The runner still calls
	// StartProducer because it shares scaffolding with other protocols.
}

func (n *Node) RunEpoch(ctx context.Context, timeout time.Duration) (*Beacon, error) {
	if timeout <= 0 {
		timeout = defaultEpochTimeout
	}
	overall := time.NewTimer(timeout)
	defer overall.Stop()

	epoch := n.State.CurrentEpoch()
	key := roundKey(epoch)
	msg := n.beaconMsg(epoch)
	if err := n.ensureCommitment(ctx); err != nil {
		return nil, err
	}
	st := n.ensureRoundState(key, epoch, msg)

	signStart := time.Now()
	commitment, ok := n.commitmentFor(n.ID)
	if !ok {
		return nil, errors.New("local beacon commitment is not available")
	}
	share, err := asig.NewBeaconShareWithCommitment(epoch, msg, n.ID, n.GRand.SecretShare, n.commitAlpha, commitment.CM1)
	if err != nil {
		return nil, err
	}
	if n.Perf != nil {
		n.Perf.addSign(time.Since(signStart))
	}
	n.recordLocalShare(st, share)
	out, err := p2p.NewMessage(Protocol, "SHARE", key, n.ID, "", shareMessage{Epoch: epoch, Share: share})
	if err != nil {
		return nil, err
	}
	if err := n.Transport.Broadcast(ctx, out); err != nil {
		return nil, err
	}
	for {
		select {
		case beacon := <-n.beacons:
			if beacon == nil || beacon.Epoch != epoch {
				continue
			}
			n.State.Advance(beacon.Random, "")
			return beacon, nil
		case <-overall.C:
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
	key := roundKey(epoch)
	diag := n.skipDiagnostics(key)
	n.roundMu.Lock()
	delete(n.rounds, key)
	delete(n.pendingShares, key)
	n.roundMu.Unlock()
	return &Beacon{Epoch: epoch, Random: random, Commit: reason, Skipped: true, SkipStage: stage, SkipReason: reason, SkipDiag: diag}
}

func (n *Node) skipDiagnostics(key string) string {
	queueTotal, queueMax := n.State.QueueBacklog()
	n.roundMu.Lock()
	rounds := len(n.rounds)
	pendingShares := len(n.pendingShares[key])
	commitments := len(n.commitments)
	commitSent := n.commitSent
	shareCount := 0
	delivered := false
	recovering := false
	if st := n.rounds[key]; st != nil {
		shareCount = len(st.shares)
		delivered = st.delivered
		recovering = st.recovering
	}
	n.roundMu.Unlock()
	metrics := n.Transport.Metrics()
	return fmt.Sprintf(
		"local_epoch=%d rounds=%d commitments=%d commit_sent=%t shares=%d pending_shares=%d delivered=%t recovering=%t queue_total=%d queue_max=%d sent_msgs=%d recv_msgs=%d",
		n.State.CurrentEpoch(), rounds, commitments, commitSent, shareCount, pendingShares, delivered, recovering, queueTotal, queueMax, metrics.SentMessages, metrics.RecvMessages,
	)
}

func (n *Node) dispatch(ctx context.Context) {
	for {
		select {
		case msg, ok := <-n.Transport.Inbox():
			if !ok {
				return
			}
			if msg.Protocol != Protocol {
				continue
			}
			switch msg.Type {
			case "COMMIT":
				_ = n.handleCommitment(msg)
			case "SHARE":
				_ = n.handleShare(msg)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) handleShare(msg p2p.Message) error {
	var payload shareMessage
	var err error
	payload, err = p2p.DecodePayload[shareMessage](msg)
	if err != nil {
		return err
	}
	key := roundKey(payload.Epoch)
	if payload.Share.Signer == "" {
		payload.Share.Signer = msg.From
	}
	st := n.getRound(key)
	if st == nil {
		n.roundMu.Lock()
		n.pendingShares[key] = append(n.pendingShares[key], payload)
		n.roundMu.Unlock()
		return nil
	}
	n.recordShare(st, payload)
	return nil
}

func (n *Node) ensureCommitment(ctx context.Context) error {
	n.roundMu.Lock()
	if n.commitSent {
		n.roundMu.Unlock()
		return nil
	}
	commitment, alpha, err := asig.NewBeaconCommitment(n.ID, n.GRand.SecretShare)
	if err != nil {
		n.roundMu.Unlock()
		return err
	}
	publicShare := n.GRand.PublicShares[n.ID]
	verified, ok := asig.DecodeAndVerifyBeaconCommitment(publicShare, commitment)
	if !ok {
		n.roundMu.Unlock()
		return errors.New("generated invalid beacon commitment")
	}
	n.commitments[n.ID] = verified
	n.commitAlpha = alpha
	n.commitSent = true
	n.roundMu.Unlock()
	msg, err := p2p.NewMessage(Protocol, "COMMIT", "commitment", n.ID, "", commitment)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) handleCommitment(msg p2p.Message) error {
	commitment, err := p2p.DecodePayload[asig.BeaconCommitment](msg)
	if err != nil {
		return err
	}
	if commitment.Signer == "" {
		commitment.Signer = msg.From
	}
	publicShare := n.GRand.PublicShares[commitment.Signer]
	verified, ok := asig.DecodeAndVerifyBeaconCommitment(publicShare, commitment)
	if publicShare == "" || !ok {
		return nil
	}
	n.roundMu.Lock()
	if _, exists := n.commitments[commitment.Signer]; !exists {
		n.commitments[commitment.Signer] = verified
	}
	keys := make([]string, 0, len(n.rounds))
	for key := range n.rounds {
		keys = append(keys, key)
	}
	n.roundMu.Unlock()
	for _, key := range keys {
		n.flushPendingShares(key)
	}
	return nil
}

func (n *Node) recordLocalShare(st *roundState, share asig.BeaconShare) {
	n.recordShare(st, shareMessage{Epoch: st.epoch, Share: share})
}

func (n *Node) recordShare(st *roundState, payload shareMessage) {
	if payload.Share.Signer == "" || payload.Share.Sigma1 == "" || payload.Share.Sigma2 == "" {
		return
	}
	n.roundMu.Lock()
	if st.delivered || st.recovering {
		n.roundMu.Unlock()
		return
	}
	n.roundMu.Unlock()
	commitment, ok := n.commitmentFor(payload.Share.Signer)
	if !ok {
		n.roundMu.Lock()
		if !st.delivered && !st.recovering {
			n.pendingShares[roundKey(st.epoch)] = append(n.pendingShares[roundKey(st.epoch)], payload)
		}
		n.roundMu.Unlock()
		return
	}
	msg := append([]byte(nil), st.msg...)
	n.Crypto.Go(context.Background(), func() {
		n.verifyAndRecordShare(st, payload, commitment, msg)
	})
}

func (n *Node) verifyAndRecordShare(st *roundState, payload shareMessage, commitment *asig.VerifiedBeaconCommitment, msg []byte) {
	n.roundMu.Lock()
	if st.delivered || st.recovering {
		n.roundMu.Unlock()
		return
	}
	n.roundMu.Unlock()
	acceptStart := time.Now()
	if !asig.VerifyBeaconShareWithCommitment(msg, commitment, payload.Share) {
		return
	}
	if n.Perf != nil {
		n.Perf.addVerify(time.Since(acceptStart))
	}
	n.roundMu.Lock()
	if st.delivered {
		n.roundMu.Unlock()
		return
	}
	if st.shares == nil {
		st.shares = make(map[p2p.NodeID]asig.BeaconShare)
	}
	if _, exists := st.shares[payload.Share.Signer]; exists {
		n.roundMu.Unlock()
		return
	}
	parts := make([]asig.BeaconShare, 0, len(st.shares)+1)
	st.shares[payload.Share.Signer] = payload.Share
	for _, share := range st.shares {
		parts = append(parts, share)
	}
	threshold := n.State.Threshold()
	if len(parts) >= threshold {
		if st.recovering {
			n.roundMu.Unlock()
			return
		}
		st.recovering = true
	}
	n.roundMu.Unlock()

	if len(parts) < threshold {
		return
	}
	recoverStart := time.Now()
	random, signature, err := asig.RecoverBeacon(msg, parts, threshold, n.State.MembersSnapshot())
	if n.Perf != nil {
		n.Perf.addRecover(time.Since(recoverStart))
	}
	if err != nil {
		n.roundMu.Lock()
		st.recovering = false
		n.roundMu.Unlock()
		return
	}
	n.roundMu.Lock()
	if st.delivered {
		n.roundMu.Unlock()
		return
	}
	epoch := st.epoch
	sharesCount := len(st.shares)
	st.delivered = true
	delete(n.rounds, roundKey(epoch))
	n.roundMu.Unlock()
	beacon := &Beacon{
		Epoch:  epoch,
		Random: random,
		Commit: hex.EncodeToString(msg),
		SigHex: signature,
		Shares: sharesCount,
	}
	select {
	case n.beacons <- beacon:
	default:
	}
}

func (n *Node) commitmentFor(id p2p.NodeID) (*asig.VerifiedBeaconCommitment, bool) {
	n.roundMu.Lock()
	defer n.roundMu.Unlock()
	commitment, ok := n.commitments[id]
	return commitment, ok
}

func (n *Node) commitmentSnapshot() map[p2p.NodeID]asig.BeaconCommitment {
	n.roundMu.Lock()
	defer n.roundMu.Unlock()
	out := make(map[p2p.NodeID]asig.BeaconCommitment, len(n.commitments))
	for id, commitment := range n.commitments {
		out[id] = commitment.Commitment
	}
	return out
}

func (n *Node) flushPendingShares(key string) {
	n.roundMu.Lock()
	pending := append([]shareMessage(nil), n.pendingShares[key]...)
	delete(n.pendingShares, key)
	st := n.rounds[key]
	n.roundMu.Unlock()
	if st == nil {
		return
	}
	for _, payload := range pending {
		n.recordShare(st, payload)
	}
}

func (n *Node) ensureRoundState(key string, epoch uint64, msg []byte) *roundState {
	n.roundMu.Lock()
	st, exists := n.rounds[key]
	var pending []shareMessage
	if !exists {
		st = &roundState{
			epoch:  epoch,
			msg:    msg,
			shares: make(map[p2p.NodeID]asig.BeaconShare),
		}
		n.rounds[key] = st
		pending = append(pending, n.pendingShares[key]...)
		delete(n.pendingShares, key)
	}
	n.roundMu.Unlock()
	for _, payload := range pending {
		n.recordShare(st, payload)
	}
	return st
}

func (n *Node) getRound(key string) *roundState {
	n.roundMu.Lock()
	defer n.roundMu.Unlock()
	return n.rounds[key]
}

func (n *Node) beaconMsg(epoch uint64) []byte {
	payload := struct {
		Protocol string `json:"protocol"`
		Epoch    uint64 `json:"epoch"`
		RPrev    string `json:"rprev"`
	}{
		Protocol: Protocol,
		Epoch:    epoch,
		RPrev:    hex.EncodeToString(n.State.RPrevBytes()),
	}
	raw, _ := json.Marshal(payload)
	return asig.HashBytes(raw)
}
