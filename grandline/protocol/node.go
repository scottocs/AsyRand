package grandline

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	asig "github.com/scottocs/Tyche/grandline/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
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

	GRand asig.GRandShare

	roundMu       sync.Mutex
	rounds        map[string]*roundState
	pendingShares map[string][]shareMessage
	commitments   map[p2p.NodeID]asig.BeaconCommitment
	commitAlpha   kyber.Scalar
	commitSent    bool

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
	Transport p2p.Transport
	PVSS      asig.PVSSScheme
	GRand     asig.GRandShare
}

type shareMessage struct {
	Epoch uint64           `json:"epoch"`
	Share asig.BeaconShare `json:"share"`
}

type roundState struct {
	epoch     uint64
	msg       []byte
	shares    map[p2p.NodeID]asig.BeaconShare
	delivered bool
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
		State: state, PVSS: cfg.PVSS, GRand: cfg.GRand,
		rounds: make(map[string]*roundState), pendingShares: make(map[string][]shareMessage),
		commitments: make(map[p2p.NodeID]asig.BeaconCommitment),
		beacons:     make(chan *Beacon, state.N*4),
	}, nil
}

func (n *Node) Start(ctx context.Context) error {
	if err := n.Transport.Start(ctx); err != nil {
		return err
	}
	go n.dispatch(ctx)
	return nil
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
	share, err := asig.NewBeaconShare(epoch, msg, n.ID, n.GRand.SecretShare, n.commitAlpha)
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
			return nil, errEpochTimeout
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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
	n.commitments[n.ID] = commitment
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
	if publicShare == "" || !asig.VerifyBeaconCommitment(publicShare, commitment) {
		return nil
	}
	n.roundMu.Lock()
	if _, exists := n.commitments[commitment.Signer]; !exists {
		n.commitments[commitment.Signer] = commitment
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
	commitment, ok := n.commitmentFor(payload.Share.Signer)
	if !ok {
		n.roundMu.Lock()
		n.pendingShares[roundKey(st.epoch)] = append(n.pendingShares[roundKey(st.epoch)], payload)
		n.roundMu.Unlock()
		return
	}
	publicShare := n.GRand.PublicShares[payload.Share.Signer]
	if publicShare == "" {
		return
	}
	acceptStart := time.Now()
	if !asig.VerifyBeaconShare(st.msg, publicShare, commitment, payload.Share) {
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
	n.roundMu.Unlock()

	threshold := n.State.Threshold()
	if len(parts) < threshold {
		return
	}
	recoverStart := time.Now()
	random, signature, err := asig.RecoverBeacon(st.msg, parts, threshold, n.State.MembersSnapshot())
	if n.Perf != nil {
		n.Perf.addRecover(time.Since(recoverStart))
	}
	if err != nil {
		return
	}
	beacon := &Beacon{
		Epoch:  st.epoch,
		Random: random,
		Commit: hex.EncodeToString(st.msg),
		SigHex: signature,
		Shares: len(st.shares),
	}
	n.roundMu.Lock()
	if st.delivered {
		n.roundMu.Unlock()
		return
	}
	st.delivered = true
	delete(n.rounds, roundKey(st.epoch))
	n.roundMu.Unlock()
	select {
	case n.beacons <- beacon:
	default:
	}
}

func (n *Node) commitmentFor(id p2p.NodeID) (asig.BeaconCommitment, bool) {
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
		out[id] = commitment
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
