package grandline

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	asig "Tyche/grandline/crypto"
	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
)

const Protocol = "grandline/authenticated-v1"
const ReferenceProtocol = "grandline/reference-v1"

// Keep the mathematical epoch input stable across the transport-format change.
const beaconEpochDomain = "grandline/paper-v3/epoch"

const (
	defaultEpochTimeout = 20 * time.Second
)

var errEpochTimeout = errors.New("epoch timeout")

type Node struct {
	reference bool
	signer    *asig.BeaconSigner
	ctx       context.Context
	checks    *verification.Cache
	ID        p2p.NodeID
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
	commitSent    bool

	beacons chan *Beacon
}

type NodeConfig struct {
	BeaconMode           string
	ReferenceCommitments map[p2p.NodeID]asig.BeaconCommitment
	ReferenceAlpha       string
	ID                   p2p.NodeID
	Members              []p2p.NodeID
	F                    int
	Transport            p2p.Transport
	PVSS                 asig.PVSSScheme
	GRand                asig.GRandShare
	CryptoWorkers        int
}

type shareMessage struct {
	Epoch uint64           `json:"epoch"`
	Share asig.BeaconShare `json:"share"`
}

type roundState struct {
	crypto     *asig.BeaconEpoch
	epoch      uint64
	msg        []byte
	shares     map[p2p.NodeID]*asig.VerifiedBeaconShare
	verifying  map[p2p.NodeID]verification.Key
	candidates map[p2p.NodeID][]shareCandidate
	delivered  bool
	recovering bool
}

type shareCandidate struct {
	payload shareMessage
	key     verification.Key
}

func NewNode(cfg NodeConfig) (*Node, error) {
	// "signed" is a legacy configuration alias; it no longer enables signing.
	if cfg.BeaconMode == "signed" {
		cfg.BeaconMode = "standard"
	}
	if cfg.BeaconMode != "" && cfg.BeaconMode != "standard" && cfg.BeaconMode != "reference" {
		return nil, errors.New("unknown beacon mode")
	}
	if cfg.ID == "" {
		return nil, errors.New("node id is required")
	}
	if cfg.Transport == nil {
		return nil, errors.New("transport is required")
	}
	if !p2p.AuthenticatedDelivery(cfg.Transport) {
		return nil, errors.New("GRandLine requires authenticated delivery without outer message signatures")
	}
	if cfg.Transport.ID() != cfg.ID {
		return nil, errors.New("transport identity does not match node id")
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
	checks := verification.New()
	if owner, ok := cfg.PVSS.(interface{ VerificationCache() *verification.Cache }); ok {
		checks = verification.Select(owner.VerificationCache())
	}
	state := NewState(cfg.Members, cfg.F)
	n := &Node{checks: checks, reference: cfg.BeaconMode == "reference",
		ID: cfg.ID, Transport: cfg.Transport, Perf: &PerfMetrics{},
		State: state, PVSS: cfg.PVSS, GRand: cfg.GRand,
		rounds: make(map[string]*roundState), pendingShares: make(map[string][]shareMessage),
		commitments: make(map[p2p.NodeID]*asig.VerifiedBeaconCommitment),
		beacons:     make(chan *Beacon, state.N*4),
	}
	if n.reference {
		if len(cfg.ReferenceCommitments) != len(cfg.Members) {
			return nil, errors.New("missing fixed reference commitments")
		}
		for _, id := range cfg.Members {
			c, ok := cfg.ReferenceCommitments[id]
			if !ok || c.Signer != id || cfg.GRand.PublicShares[id] == "" {
				return nil, errors.New("reference commitment identity mismatch")
			}
			checked, ok := asig.DecodeAndVerifyBeaconCommitment(cfg.GRand.PublicShares[id], c, checks)
			if !ok {
				return nil, errors.New("invalid fixed reference commitment")
			}
			n.commitments[id] = checked
		}
		a, err := asig.DecodeReferenceAlpha(cfg.ReferenceAlpha)
		if err != nil {
			return nil, err
		}
		var errSigner error
		n.signer, errSigner = asig.NewBeaconSigner(n.ID, n.GRand.SecretShare, a, n.commitments[n.ID])
		if errSigner != nil {
			return nil, errSigner
		}
		n.commitSent = true
	}
	n.Crypto = cryptoexec.New(cfg.CryptoWorkers)
	return n, nil
}

func (n *Node) Start(ctx context.Context) error {
	if err := n.Transport.Start(ctx); err != nil {
		return err
	}
	n.StartProtocol(ctx)
	return nil
}

func (n *Node) StartProtocol(ctx context.Context) {
	n.ctx = ctx
	go n.dispatch(ctx)
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
	share, verified, err := n.signer.Share(st.crypto)
	if err != nil {
		return nil, err
	}
	if n.Perf != nil {
		n.Perf.addSign(time.Since(signStart))
	}
	n.storeVerifiedShare(st, shareMessage{Epoch: epoch, Share: share}, verified)
	out, err := n.newMessage("SHARE", key, shareMessage{Epoch: epoch, Share: share})
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
			n.State.Advance()
			return beacon, nil
		case <-overall.C:
			return nil, fmt.Errorf("%w: %s", errEpochTimeout, n.epochDiagnostics(key))
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (n *Node) epochDiagnostics(key string) string {
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
		"local_epoch=%d rounds=%d commitments=%d commit_sent=%t shares=%d pending_shares=%d delivered=%t recovering=%t sent_msgs=%d recv_msgs=%d",
		n.State.CurrentEpoch(), rounds, commitments, commitSent, shareCount, pendingShares, delivered, recovering, metrics.SentMessages, metrics.RecvMessages,
	)
}

func (n *Node) dispatch(ctx context.Context) {
	for {
		select {
		case msg, ok := <-n.Transport.Inbox():
			if !ok {
				return
			}
			n.dispatchMessage(msg)
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) dispatchMessage(msg p2p.Message) {
	if msg.Protocol != n.wireProtocol() || !msg.Authenticated() || n.GRand.PublicShares[msg.From] == "" {
		return
	}
	if n.reference && msg.Type != "SHARE" {
		return
	}
	switch msg.Type {
	case "COMMIT":
		_ = n.handleCommitment(msg)
	case "SHARE":
		_ = n.handleShare(msg)
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
	if payload.Share.Signer != msg.From || n.GRand.PublicShares[msg.From] == "" || payload.Share.Epoch != payload.Epoch || msg.Instance != key {
		return nil
	}
	st := n.getRound(key)
	if st == nil {
		if n.State != nil && payload.Epoch < n.State.CurrentEpoch() {
			return nil
		}
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
	verified, ok := asig.DecodeAndVerifyBeaconCommitment(publicShare, commitment, n.checks)
	if !ok {
		n.roundMu.Unlock()
		return errors.New("generated invalid beacon commitment")
	}
	n.commitments[n.ID] = verified
	n.signer, err = asig.NewBeaconSigner(n.ID, n.GRand.SecretShare, alpha, verified)
	if err != nil {
		n.roundMu.Unlock()
		return err
	}
	n.commitSent = true
	n.roundMu.Unlock()
	msg, err := n.newMessage("COMMIT", "commitment", commitment)
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
	if commitment.Signer != msg.From || n.GRand.PublicShares[msg.From] == "" || msg.Instance != "commitment" {
		return nil
	}
	publicShare := n.GRand.PublicShares[commitment.Signer]
	verified, ok := asig.DecodeAndVerifyBeaconCommitment(publicShare, commitment, n.checks)
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

func (n *Node) recordShare(st *roundState, payload shareMessage) {
	if payload.Share.Signer == "" || payload.Share.Sigma1 == "" || payload.Share.Sigma2 == "" {
		return
	}
	n.roundMu.Lock()
	if st.delivered || st.recovering || st.shares[payload.Share.Signer] != nil {
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
	n.roundMu.Lock()
	if st.verifying == nil {
		st.verifying = make(map[p2p.NodeID]verification.Key)
	}
	if st.delivered || st.recovering || st.shares[payload.Share.Signer] != nil {
		n.roundMu.Unlock()
		return
	}
	key := verification.JSONKey("grandline/candidate", payload)
	if active, ok := st.verifying[payload.Share.Signer]; ok {
		if active != key {
			if st.candidates == nil {
				st.candidates = make(map[p2p.NodeID][]shareCandidate)
			}
			pending := st.candidates[payload.Share.Signer]
			duplicate := false
			for _, old := range pending {
				if old.key == key {
					duplicate = true
					break
				}
			}
			// Authenticated peers cannot occupy another identity's slots. Bound
			// equivocation by faulty senders without dropping the next candidate.
			if !duplicate && len(pending) < 32 {
				st.candidates[payload.Share.Signer] = append(pending, shareCandidate{payload, key})
			}
		}
		n.roundMu.Unlock()
		return
	}
	st.verifying[payload.Share.Signer] = key
	n.roundMu.Unlock()
	n.Crypto.GoPriority(n.workContext(), func() {
		n.verifyAndRecordShare(st, payload, commitment, key)
	})
}

func (n *Node) verifyAndRecordShare(st *roundState, payload shareMessage, commitment *asig.VerifiedBeaconCommitment, key verification.Key) {
	defer n.finishCandidate(st, payload.Share.Signer, key)
	n.roundMu.Lock()
	if st.delivered || st.recovering || st.shares[payload.Share.Signer] != nil {
		n.roundMu.Unlock()
		return
	}
	n.roundMu.Unlock()
	acceptStart := time.Now()
	verified, ok := st.crypto.VerifyShare(commitment, payload.Share, n.checks)
	if !ok {
		return
	}
	if n.Perf != nil {
		n.Perf.addVerify(time.Since(acceptStart))
	}
	n.storeVerifiedShare(st, payload, verified)
}
func (n *Node) storeVerifiedShare(st *roundState, payload shareMessage, verified *asig.VerifiedBeaconShare) {
	if payload.Epoch != st.epoch || !st.crypto.Accepts(verified, payload.Share.Signer) {
		return
	}
	n.roundMu.Lock()
	delete(st.candidates, payload.Share.Signer)
	if st.delivered {
		n.roundMu.Unlock()
		return
	}
	if st.shares == nil {
		st.shares = make(map[p2p.NodeID]*asig.VerifiedBeaconShare)
	}
	if _, exists := st.shares[payload.Share.Signer]; exists {
		n.roundMu.Unlock()
		return
	}
	parts := make([]*asig.VerifiedBeaconShare, 0, len(st.shares)+1)
	st.shares[payload.Share.Signer] = verified
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
	random, signature, err := st.crypto.Recover(parts, threshold, n.State.MembersSnapshot())
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
		Commit: hex.EncodeToString(st.msg),
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
			shares: make(map[p2p.NodeID]*asig.VerifiedBeaconShare),
			crypto: asig.NewBeaconEpoch(epoch, msg),
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
	return encodeBeaconEpoch(n.GRand.PublicKey, epoch)
}
func encodeBeaconEpoch(publicKey string, epoch uint64) []byte {
	raw, _ := json.Marshal(struct {
		Domain, PublicKey string
		Epoch             uint64
	}{beaconEpochDomain, publicKey, epoch})
	return raw
}

func (n *Node) newMessage(typ, instance string, payload any) (p2p.Message, error) {
	if !p2p.AuthenticatedDelivery(n.Transport) || (n.reference && typ != "SHARE") {
		return p2p.Message{}, errors.New("message requires authenticated delivery and an allowed type")
	}
	return p2p.NewMessage(n.wireProtocol(), typ, instance, n.ID, "", payload)
}

func (n *Node) wireProtocol() string {
	if n.reference {
		return ReferenceProtocol
	}
	return Protocol
}
func (n *Node) workContext() context.Context {
	if n.ctx != nil {
		return n.ctx
	}
	return context.Background()
}

func (n *Node) finishCandidate(st *roundState, id p2p.NodeID, key verification.Key) {
	n.roundMu.Lock()
	if active, ok := st.verifying[id]; !ok || active != key {
		n.roundMu.Unlock()
		return
	}
	delete(st.verifying, id)
	pending := st.candidates[id]
	if st.delivered || st.recovering || st.shares[id] != nil {
		delete(st.candidates, id)
		n.roundMu.Unlock()
		return
	}
	var next *shareCandidate
	if len(pending) > 0 {
		copy := pending[0]
		next = &copy
		st.candidates[id] = pending[1:]
	}
	n.roundMu.Unlock()
	if next != nil {
		n.recordShare(st, next.payload)
	}
}
