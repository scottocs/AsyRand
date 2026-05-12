package grandline

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	asig "github.com/scottocs/asyrand/grandline/internal/crypto"
	"github.com/scottocs/asyrand/grandline/internal/p2p"
	"github.com/scottocs/asyrand/grandline/internal/pvss"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
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
	PVSS      pvss.Scheme

	CoinShare  *share.PriShare
	CoinPublic *share.PubPoly

	roundMu       sync.Mutex
	rounds        map[string]*roundState
	pendingShares map[string][]shareMessage

	beacons chan *Beacon
}

type NodeConfig struct {
	ID         p2p.NodeID
	Members    []p2p.NodeID
	F          int
	QueueLen   int
	Seed       []byte
	Keys       asig.KeyPair
	Public     map[string]ed25519.PublicKey
	Transport  p2p.Transport
	PVSS       pvss.Scheme
	CoinShare  *share.PriShare
	CoinPublic *share.PubPoly
}

type shareMessage struct {
	Epoch  uint64     `json:"epoch"`
	Signer p2p.NodeID `json:"signer"`
	Sig    []byte     `json:"sig"`
}

type roundState struct {
	epoch     uint64
	msg       []byte
	shares    map[p2p.NodeID][]byte
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
	if cfg.CoinShare == nil || cfg.CoinPublic == nil {
		return nil, errors.New("dkg keys are required")
	}
	if len(cfg.Members) < 3*cfg.F+1 {
		return nil, errors.New("must satisfy n >= 3f + 1")
	}
	state := NewState(cfg.Members, cfg.F, cfg.QueueLen, cfg.Seed)
	return &Node{
		ID: cfg.ID, Keys: cfg.Keys, Public: cfg.Public, Transport: cfg.Transport, Perf: &PerfMetrics{},
		State: state, PVSS: cfg.PVSS, CoinShare: cfg.CoinShare, CoinPublic: cfg.CoinPublic,
		rounds: make(map[string]*roundState), pendingShares: make(map[string][]shareMessage),
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
	st := n.ensureRoundState(key, epoch, msg)

	signStart := time.Now()
	sig, err := tbls.Sign(pairingSuite(), n.CoinShare, msg)
	if err != nil {
		return nil, err
	}
	if n.Perf != nil {
		n.Perf.addSign(time.Since(signStart))
	}
	n.recordLocalShare(st, sig)
	out, err := p2p.NewMessage(Protocol, "SHARE", key, n.ID, "", shareMessage{Epoch: epoch, Signer: n.ID, Sig: sig})
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
	if payload.Signer == "" {
		payload.Signer = msg.From
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

func (n *Node) recordLocalShare(st *roundState, sig []byte) {
	msg := shareMessage{
		Epoch:  st.epoch,
		Signer: n.ID,
		Sig:    sig,
	}
	n.recordShare(st, msg)
}

func (n *Node) recordShare(st *roundState, payload shareMessage) {
	if payload.Signer == "" || len(payload.Sig) == 0 {
		return
	}
	acceptStart := time.Now()
	if err := tbls.Verify(pairingSuite(), n.CoinPublic, st.msg, payload.Sig); err != nil {
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
		st.shares = make(map[p2p.NodeID][]byte)
	}
	if _, exists := st.shares[payload.Signer]; exists {
		n.roundMu.Unlock()
		return
	}
	parts := make([][]byte, 0, len(st.shares)+1)
	st.shares[payload.Signer] = payload.Sig
	for _, sig := range st.shares {
		parts = append(parts, sig)
	}
	n.roundMu.Unlock()

	threshold := n.State.Threshold()
	if len(parts) < threshold {
		return
	}
	recoverStart := time.Now()
	recovered, err := tbls.Recover(pairingSuite(), n.CoinPublic, st.msg, parts, threshold, n.State.N)
	if n.Perf != nil {
		n.Perf.addRecover(time.Since(recoverStart))
	}
	if err != nil {
		return
	}
	beacon := &Beacon{
		Epoch:  st.epoch,
		Random: asig.HashBytes(recovered),
		Commit: hex.EncodeToString(st.msg),
		SigHex: hex.EncodeToString(recovered),
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

func (n *Node) ensureRoundState(key string, epoch uint64, msg []byte) *roundState {
	n.roundMu.Lock()
	st, exists := n.rounds[key]
	var pending []shareMessage
	if !exists {
		st = &roundState{
			epoch:  epoch,
			msg:    msg,
			shares: make(map[p2p.NodeID][]byte),
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
