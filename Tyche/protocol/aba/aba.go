package aba

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

const Protocol = "aba"

const bvalBroadcastDelay = 50 * time.Millisecond

type InputMessage struct {
	Value     bool              `json:"value"`
	Signature crypto.SignedVote `json:"signature"`
}

type FinishMessage struct {
	Value     bool              `json:"value"`
	Signature crypto.SignedVote `json:"signature"`
}

type BValMessage struct {
	Round     uint64            `json:"round"`
	Value     bool              `json:"value"`
	Signature crypto.SignedVote `json:"signature"`
}

type AuxMessage struct {
	Round     uint64            `json:"round"`
	Value     bool              `json:"value"`
	Signature crypto.SignedVote `json:"signature"`
}

type ConfMessage struct {
	Round     uint64            `json:"round"`
	Values    []bool            `json:"values"`
	Signature crypto.SignedVote `json:"signature"`
}

type CoinRequest struct {
	ConfigVersion uint64 `json:"config_version"`
	Instance      string `json:"instance"`
	Round         uint64 `json:"round"`
}

type Decision struct {
	ConfigVersion uint64      `json:"config_version"`
	Instance      string      `json:"instance"`
	Value         bool        `json:"value"`
	FastPath      bool        `json:"fast_path"`
	Certificate   Certificate `json:"certificate"`
}

// Certificate is transferable evidence for one ABA decision. Fast-path
// certificates aggregate q matching FINISH(true) messages. Regular
// certificates aggregate q matching singleton CONF messages from the deciding
// round; the verifier additionally checks the externally supplied common coin.
type Certificate struct {
	ConfigVersion uint64                         `json:"config_version"`
	Purpose       string                         `json:"purpose"`
	Instance      string                         `json:"instance"`
	Round         uint64                         `json:"round"`
	Value         bool                           `json:"value"`
	FastPath      bool                           `json:"fast_path"`
	Quorum        crypto.SignedQuorumCertificate `json:"quorum"`
}

type Status struct {
	Instance    string
	Round       uint64
	Decided     bool
	Value       bool
	CoinWait    bool
	Inputs      int
	InputTrue   int
	InputFalse  int
	Finish      int
	BValTrue    int
	BValFalse   int
	BinTrue     bool
	BinFalse    bool
	Aux         int
	Conf        int
	Certificate Certificate
}

type Agreement struct {
	ID            p2p.NodeID
	N             int
	F             int
	Transport     p2p.Transport
	Version       uint64
	Purpose       string
	Members       map[p2p.NodeID]struct{}
	PrivateKey    ed25519.PrivateKey
	PublicKeys    map[string]ed25519.PublicKey
	Authenticated bool

	mu           sync.Mutex
	state        map[string]*instanceState
	pruned       map[string]bool
	Decisions    chan Decision
	CoinRequests chan CoinRequest
}

type instanceState struct {
	proposed    bool
	est         bool
	round       uint64
	decided     bool
	decision    bool
	certificate Certificate

	inputs     map[p2p.NodeID]bool
	inputCount map[bool]int
	finish     map[p2p.NodeID]crypto.SignedVote
	finishSent bool

	bval        map[uint64]map[bool]map[p2p.NodeID]bool
	bvalSent    map[uint64]map[bool]bool
	bin         map[uint64]map[bool]bool
	auxPending  map[uint64]map[p2p.NodeID]bool
	aux         map[uint64]map[p2p.NodeID]bool
	auxVal      map[uint64]map[bool]bool
	auxSent     map[uint64]bool
	confPending map[uint64]map[p2p.NodeID][]bool
	conf        map[uint64]map[p2p.NodeID]bool
	confVotes   map[uint64]map[bool]map[p2p.NodeID]crypto.SignedVote
	confVal     map[uint64]map[bool]bool
	confSent    map[uint64]bool
	coinReq     map[uint64]bool
	coinWait    map[uint64]bool
	coins       map[uint64]bool
	coinSeen    map[uint64]bool
}

func New(id p2p.NodeID, n, f int, transport p2p.Transport) *Agreement {
	return newAgreement(id, 0, "legacy", nil, n, f, transport)
}

func NewConfigured(id p2p.NodeID, version uint64, purpose string, members []p2p.NodeID, f int, transport p2p.Transport) (*Agreement, error) {
	return newConfigured(id, version, purpose, members, f, transport, nil, nil)
}

func NewAuthenticated(id p2p.NodeID, version uint64, purpose string, members []p2p.NodeID, f int, transport p2p.Transport, private ed25519.PrivateKey, publicKeys map[string]ed25519.PublicKey) (*Agreement, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid ABA identity private key")
	}
	for _, member := range members {
		if len(publicKeys[string(member)]) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("missing ABA identity public key for %s", member)
		}
	}
	return newConfigured(id, version, purpose, members, f, transport, private, publicKeys)
}

func newConfigured(id p2p.NodeID, version uint64, purpose string, members []p2p.NodeID, f int, transport p2p.Transport, private ed25519.PrivateKey, publicKeys map[string]ed25519.PublicKey) (*Agreement, error) {
	if purpose == "" {
		return nil, fmt.Errorf("ABA purpose is required")
	}
	memberSet := make(map[p2p.NodeID]struct{}, len(members))
	for _, member := range members {
		if member == "" {
			return nil, fmt.Errorf("empty ABA member")
		}
		if _, duplicate := memberSet[member]; duplicate {
			return nil, fmt.Errorf("duplicate ABA member %s", member)
		}
		memberSet[member] = struct{}{}
	}
	if _, ok := memberSet[id]; !ok {
		return nil, fmt.Errorf("ABA node %s is not in configuration %d", id, version)
	}
	if f < 0 || len(members) < 3*f+1 {
		return nil, fmt.Errorf("invalid ABA fault bound n=%d f=%d", len(members), f)
	}
	a := newAgreement(id, version, purpose, memberSet, len(members), f, transport)
	if len(private) == ed25519.PrivateKeySize {
		a.PrivateKey = append(ed25519.PrivateKey(nil), private...)
		a.PublicKeys = make(map[string]ed25519.PublicKey, len(publicKeys))
		for signer, public := range publicKeys {
			a.PublicKeys[signer] = append(ed25519.PublicKey(nil), public...)
		}
		a.Authenticated = true
	}
	return a, nil
}

func newAgreement(id p2p.NodeID, version uint64, purpose string, members map[p2p.NodeID]struct{}, n, f int, transport p2p.Transport) *Agreement {
	return &Agreement{
		ID: id, N: n, F: f, Transport: transport, Version: version, Purpose: purpose, Members: members,
		state:        make(map[string]*instanceState),
		pruned:       make(map[string]bool),
		Decisions:    make(chan Decision, n*4),
		CoinRequests: make(chan CoinRequest, n*8),
	}
}

func (a *Agreement) Propose(ctx context.Context, instance string, value bool) error {
	if !a.validInstance(instance) {
		return fmt.Errorf("ABA instance %q is outside configuration %d/%s", instance, a.Version, a.Purpose)
	}
	a.mu.Lock()
	if _, ok := a.pruned[instance]; ok {
		a.mu.Unlock()
		return nil
	}
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return nil
	}
	first := !st.proposed
	if !st.proposed {
		st.proposed = true
		st.est = value
	}
	a.mu.Unlock()
	if first {
		go a.rebroadcastUntilReady(ctx, instance)
	}
	a.handleInput(ctx, instance, a.ID, value)
	a.handleBVal(ctx, instance, a.ID, 0, value)
	if err := a.broadcastBVal(ctx, instance, 0, value); err != nil {
		return err
	}
	return a.broadcast(ctx, "INPUT", instance, InputMessage{Value: value})
}

func (a *Agreement) Handle(ctx context.Context, msg p2p.Message) error {
	if !a.acceptsSender(msg.From) || !a.validInstance(msg.Instance) {
		return nil
	}
	switch msg.Type {
	case "INPUT":
		body, err := p2p.DecodePayload[InputMessage](msg)
		if err != nil {
			return err
		}
		if !a.verifyPayload(msg.Type, msg.Instance, msg.From, body, body.Signature) {
			return nil
		}
		a.handleInput(ctx, msg.Instance, msg.From, body.Value)
	case "FINISH":
		body, err := p2p.DecodePayload[FinishMessage](msg)
		if err != nil {
			return err
		}
		if !a.verifyPayload(msg.Type, msg.Instance, msg.From, body, body.Signature) {
			return nil
		}
		a.handleFinish(ctx, msg.Instance, msg.From, body)
	case "BVAL":
		body, err := p2p.DecodePayload[BValMessage](msg)
		if err != nil {
			return err
		}
		if !a.verifyPayload(msg.Type, msg.Instance, msg.From, body, body.Signature) {
			return nil
		}
		a.handleBVal(ctx, msg.Instance, msg.From, body.Round, body.Value)
	case "AUX":
		body, err := p2p.DecodePayload[AuxMessage](msg)
		if err != nil {
			return err
		}
		if !a.verifyPayload(msg.Type, msg.Instance, msg.From, body, body.Signature) {
			return nil
		}
		a.handleAux(ctx, msg.Instance, msg.From, body.Round, body.Value)
	case "CONF":
		body, err := p2p.DecodePayload[ConfMessage](msg)
		if err != nil {
			return err
		}
		if !a.verifyPayload(msg.Type, msg.Instance, msg.From, body, body.Signature) {
			return nil
		}
		a.handleConf(ctx, msg.Instance, msg.From, body)
	}
	return nil
}

func (a *Agreement) FeedCoin(ctx context.Context, instance string, round uint64, bit bool) {
	a.mu.Lock()
	if _, ok := a.pruned[instance]; ok {
		a.mu.Unlock()
		return
	}
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	st.coins[round] = bit
	st.coinSeen[round] = true
	a.mu.Unlock()
	a.tryAdvanceWithCoin(ctx, instance, round)
}

func (a *Agreement) FeedSeed(ctx context.Context, instance string, round uint64, seed []byte) {
	a.FeedCoin(ctx, instance, round, CoinFromSeed(instance, round, seed))
}

func (a *Agreement) Status(instance string) Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	if decision, ok := a.pruned[instance]; ok {
		return Status{Instance: instance, Decided: true, Value: decision}
	}
	st := a.get(instance)
	round := st.round
	a.ensureRound(st, round)
	return Status{
		Instance:    instance,
		Round:       round,
		Decided:     st.decided,
		Value:       st.decision,
		CoinWait:    st.coinWait[round],
		Inputs:      len(st.inputs),
		InputTrue:   st.inputCount[true],
		InputFalse:  st.inputCount[false],
		Finish:      len(st.finish),
		BValTrue:    len(st.bval[round][true]),
		BValFalse:   len(st.bval[round][false]),
		BinTrue:     st.bin[round][true],
		BinFalse:    st.bin[round][false],
		Aux:         len(st.aux[round]),
		Conf:        len(st.conf[round]),
		Certificate: st.certificate,
	}
}

func (a *Agreement) Prune(instance string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.state[instance]
	if st == nil || !st.decided {
		return
	}
	delete(a.state, instance)
	a.pruned[instance] = st.decision
}

// AdoptVerifiedDecision installs a transferable certificate that the caller
// has already verified against the configuration quorum and assigned beacon
// seed.  It is the event-driven catch-up path: certificate dissemination
// delivers the same ABA decision to a copy that did not locally assemble the
// quorum.  No second agreement round is involved.
func (a *Agreement) AdoptVerifiedDecision(cert Certificate) bool {
	if cert.ConfigVersion != a.Version || cert.Purpose != a.Purpose ||
		!a.validInstance(cert.Instance) {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if decision, ok := a.pruned[cert.Instance]; ok {
		return decision == cert.Value
	}
	st := a.get(cert.Instance)
	if st.decided {
		return st.decision == cert.Value
	}
	st.decided = true
	st.decision = cert.Value
	st.certificate = cert
	st.coinWait[st.round] = false
	return true
}

func (a *Agreement) get(instance string) *instanceState {
	st := a.state[instance]
	if st != nil {
		return st
	}
	if decision, ok := a.pruned[instance]; ok {
		return &instanceState{decided: true, decision: decision}
	}
	st = &instanceState{
		inputs: make(map[p2p.NodeID]bool), inputCount: make(map[bool]int), finish: make(map[p2p.NodeID]crypto.SignedVote),
		bval: make(map[uint64]map[bool]map[p2p.NodeID]bool), bvalSent: make(map[uint64]map[bool]bool),
		bin: make(map[uint64]map[bool]bool), auxPending: make(map[uint64]map[p2p.NodeID]bool),
		aux:    make(map[uint64]map[p2p.NodeID]bool),
		auxVal: make(map[uint64]map[bool]bool), auxSent: make(map[uint64]bool),
		confPending: make(map[uint64]map[p2p.NodeID][]bool),
		conf:        make(map[uint64]map[p2p.NodeID]bool), confVal: make(map[uint64]map[bool]bool),
		confVotes: make(map[uint64]map[bool]map[p2p.NodeID]crypto.SignedVote),
		confSent:  make(map[uint64]bool), coinReq: make(map[uint64]bool), coinWait: make(map[uint64]bool),
		coins: make(map[uint64]bool), coinSeen: make(map[uint64]bool),
	}
	a.state[instance] = st
	return st
}

func (a *Agreement) ensureRound(st *instanceState, r uint64) {
	if st.bval[r] == nil {
		st.bval[r] = map[bool]map[p2p.NodeID]bool{false: {}, true: {}}
	}
	if st.bvalSent[r] == nil {
		st.bvalSent[r] = make(map[bool]bool)
	}
	if st.bin[r] == nil {
		st.bin[r] = make(map[bool]bool)
	}
	if st.auxPending[r] == nil {
		st.auxPending[r] = make(map[p2p.NodeID]bool)
	}
	if st.aux[r] == nil {
		st.aux[r] = make(map[p2p.NodeID]bool)
	}
	if st.auxVal[r] == nil {
		st.auxVal[r] = make(map[bool]bool)
	}
	if st.conf[r] == nil {
		st.conf[r] = make(map[p2p.NodeID]bool)
	}
	if st.confPending[r] == nil {
		st.confPending[r] = make(map[p2p.NodeID][]bool)
	}
	if st.confVal[r] == nil {
		st.confVal[r] = make(map[bool]bool)
	}
	if st.confVotes[r] == nil {
		st.confVotes[r] = map[bool]map[p2p.NodeID]crypto.SignedVote{
			false: {},
			true:  {},
		}
	}
}

func (a *Agreement) quorum() int { return a.N - a.F }

func (a *Agreement) handleInput(ctx context.Context, instance string, from p2p.NodeID, value bool) {
	a.mu.Lock()
	st := a.get(instance)
	if _, ok := st.inputs[from]; ok || st.decided {
		a.mu.Unlock()
		return
	}
	st.inputs[from] = value
	st.inputCount[value]++
	shouldFinish := st.inputCount[true] >= a.quorum() && !st.finishSent
	if shouldFinish {
		st.finishSent = true
	}
	a.mu.Unlock()
	if shouldFinish {
		a.broadcastAsync("FINISH", instance, FinishMessage{Value: true})
	}
}

func (a *Agreement) handleFinish(ctx context.Context, instance string, from p2p.NodeID, body FinishMessage) {
	if !body.Value {
		return
	}
	a.mu.Lock()
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	st.finish[from] = body.Signature
	if len(st.finish) >= a.quorum() {
		votes := signedVotes(st.finish, a.quorum())
		cert, err := a.buildDecisionQuorum(votes)
		if err != nil {
			a.mu.Unlock()
			return
		}
		certificate := Certificate{
			ConfigVersion: a.Version,
			Purpose:       a.Purpose,
			Instance:      instance,
			Value:         true,
			FastPath:      true,
			Quorum:        cert,
		}
		st.decided = true
		st.decision = true
		st.certificate = certificate
		a.mu.Unlock()
		a.Decisions <- Decision{ConfigVersion: a.Version, Instance: instance, Value: true, FastPath: true, Certificate: certificate}
		return
	}
	a.mu.Unlock()
}

func (a *Agreement) handleBVal(ctx context.Context, instance string, from p2p.NodeID, round uint64, value bool) {
	a.mu.Lock()
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	st.bval[round][value][from] = true
	count := len(st.bval[round][value])
	amplify := count >= a.F+1 && !st.bvalSent[round][value]
	if amplify {
		st.bvalSent[round][value] = true
	}
	if count >= a.quorum() {
		st.bin[round][value] = true
	}
	sendAux := len(st.bin[round]) > 0 && !st.auxSent[round]
	auxValue := value
	if sendAux {
		if st.bin[round][st.est] {
			auxValue = st.est
		} else {
			for v := range st.bin[round] {
				auxValue = v
				break
			}
		}
		st.auxSent[round] = true
	}
	sendConf, confValues := a.processPendingAuxLocked(st, round)
	needCoin, hasCoin := a.processPendingConfLocked(st, round)
	a.mu.Unlock()
	if amplify {
		a.broadcastBValAsync(instance, round, value)
	}
	if sendAux {
		a.broadcastAsync("AUX", instance, AuxMessage{Round: round, Value: auxValue})
	}
	if sendConf {
		a.broadcastAsync("CONF", instance, ConfMessage{Round: round, Values: confValues})
	}
	if needCoin {
		a.CoinRequests <- CoinRequest{ConfigVersion: a.Version, Instance: instance, Round: round}
	}
	if hasCoin {
		a.tryAdvanceWithCoin(ctx, instance, round)
	}
}

func (a *Agreement) handleAux(ctx context.Context, instance string, from p2p.NodeID, round uint64, value bool) {
	a.mu.Lock()
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	if st.aux[round][from] {
		a.mu.Unlock()
		return
	}
	st.auxPending[round][from] = value
	sendConf, values := a.processPendingAuxLocked(st, round)
	needCoin, hasCoin := a.processPendingConfLocked(st, round)
	a.mu.Unlock()
	if sendConf {
		a.broadcastAsync("CONF", instance, ConfMessage{Round: round, Values: values})
	}
	if needCoin {
		a.CoinRequests <- CoinRequest{ConfigVersion: a.Version, Instance: instance, Round: round}
	}
	if hasCoin {
		a.tryAdvanceWithCoin(ctx, instance, round)
	}
}

func (a *Agreement) handleConf(ctx context.Context, instance string, from p2p.NodeID, body ConfMessage) {
	round := body.Round
	values := body.Values
	a.mu.Lock()
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	if st.conf[round][from] {
		a.mu.Unlock()
		return
	}
	st.confPending[round][from] = append([]bool(nil), values...)
	if len(values) == 1 {
		st.confVotes[round][values[0]][from] = body.Signature
	}
	needCoin, hasCoin := a.processPendingConfLocked(st, round)
	a.mu.Unlock()
	if needCoin {
		a.CoinRequests <- CoinRequest{ConfigVersion: a.Version, Instance: instance, Round: round}
	}
	if hasCoin {
		a.tryAdvanceWithCoin(ctx, instance, round)
	}
}

func (a *Agreement) processPendingAuxLocked(st *instanceState, round uint64) (bool, []bool) {
	for from, value := range st.auxPending[round] {
		if st.aux[round][from] {
			delete(st.auxPending[round], from)
			continue
		}
		if !st.bin[round][value] {
			continue
		}
		st.aux[round][from] = true
		st.auxVal[round][value] = true
		delete(st.auxPending[round], from)
	}
	if len(st.aux[round]) < a.quorum() {
		return false, nil
	}
	if st.confSent[round] {
		return false, nil
	}
	values := make([]bool, 0, len(st.auxVal[round]))
	for v := range st.auxVal[round] {
		values = append(values, v)
	}
	st.confSent[round] = true
	return true, values
}

func (a *Agreement) processPendingConfLocked(st *instanceState, round uint64) (bool, bool) {
	for from, values := range st.confPending[round] {
		if st.conf[round][from] {
			delete(st.confPending[round], from)
			continue
		}
		ready := true
		for _, v := range values {
			if !st.bin[round][v] {
				ready = false
				break
			}
		}
		if !ready {
			continue
		}
		st.conf[round][from] = true
		for _, v := range values {
			st.confVal[round][v] = true
		}
		delete(st.confPending[round], from)
	}
	needCoin := len(st.conf[round]) >= a.quorum() && !st.coinReq[round]
	if needCoin {
		st.coinReq[round] = true
		st.coinWait[round] = true
		st.round = round
	}
	return needCoin, st.coinSeen[round]
}

func (a *Agreement) tryAdvanceWithCoin(ctx context.Context, instance string, round uint64) {
	a.mu.Lock()
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	if len(st.conf[round]) < a.quorum() || !st.coinSeen[round] {
		a.mu.Unlock()
		return
	}
	values := make([]bool, 0, len(st.confVal[round]))
	for v := range st.confVal[round] {
		values = append(values, v)
	}
	coin := st.coins[round]
	st.coinWait[round] = false
	if len(values) == 1 {
		b := values[0]
		st.est = b
		if b == coin {
			votes := signedVotes(st.confVotes[round][b], a.quorum())
			cert, err := a.buildDecisionQuorum(votes)
			if err != nil {
				a.mu.Unlock()
				return
			}
			certificate := Certificate{
				ConfigVersion: a.Version,
				Purpose:       a.Purpose,
				Instance:      instance,
				Round:         round,
				Value:         b,
				Quorum:        cert,
			}
			st.decided = true
			st.decision = b
			st.certificate = certificate
			a.mu.Unlock()
			a.Decisions <- Decision{ConfigVersion: a.Version, Instance: instance, Value: b, FastPath: false, Certificate: certificate}
			return
		}
	} else {
		st.est = coin
	}
	nextRound := round + 1
	st.round = nextRound
	nextEst := st.est
	a.mu.Unlock()
	a.broadcastBValAsync(instance, nextRound, nextEst)
}

func (a *Agreement) broadcastBVal(ctx context.Context, instance string, round uint64, value bool) error {
	a.mu.Lock()
	if _, ok := a.pruned[instance]; ok {
		a.mu.Unlock()
		return nil
	}
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return nil
	}
	a.ensureRound(st, round)
	if st.bvalSent[round][value] {
		a.mu.Unlock()
		return nil
	}
	st.bvalSent[round][value] = true
	a.mu.Unlock()
	a.broadcastDelayed("BVAL", instance, BValMessage{Round: round, Value: value}, bvalBroadcastDelay)
	return nil
}

func (a *Agreement) broadcastBValAsync(instance string, round uint64, value bool) {
	a.mu.Lock()
	if _, ok := a.pruned[instance]; ok {
		a.mu.Unlock()
		return
	}
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	st.bvalSent[round][value] = true
	a.mu.Unlock()
	a.broadcastDelayed("BVAL", instance, BValMessage{Round: round, Value: value}, bvalBroadcastDelay)
}

func (a *Agreement) rebroadcastUntilReady(ctx context.Context, instance string) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		a.mu.Lock()
		st := a.get(instance)
		if st.decided || st.coinWait[st.round] {
			a.mu.Unlock()
			return
		}
		round := st.round
		est := st.est
		a.mu.Unlock()
		_ = a.broadcastBVal(ctx, instance, round, est)
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (a *Agreement) broadcast(ctx context.Context, typ, instance string, payload any) error {
	var err error
	payload, err = a.signPayload(typ, instance, payload)
	if err != nil {
		return err
	}
	msg, err := p2p.NewMessage(Protocol, typ, instance, a.ID, "", payload)
	if err != nil {
		return err
	}
	return a.Transport.Broadcast(ctx, msg)
}

func (a *Agreement) broadcastAsync(typ, instance string, payload any) {
	a.broadcastDelayed(typ, instance, payload, 0)
}

func (a *Agreement) broadcastDelayed(typ, instance string, payload any, delay time.Duration) {
	var err error
	payload, err = a.signPayload(typ, instance, payload)
	if err != nil {
		return
	}
	msg, err := p2p.NewMessage(Protocol, typ, instance, a.ID, "", payload)
	if err != nil {
		return
	}
	go func() {
		if delay > 0 {
			timer := time.NewTimer(delay)
			defer timer.Stop()
			<-timer.C
		}
		if a.decidedOrPruned(instance) {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Transport.Broadcast(ctx, msg)
	}()
}

func (a *Agreement) decidedOrPruned(instance string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.pruned[instance]; ok {
		return true
	}
	st := a.state[instance]
	return st != nil && st.decided
}

func CoinFromSeed(instance string, round uint64, seed []byte) bool {
	h := crypto.DomainHash("Tyche/ABA/Coin/v1", seed, []byte(instance), []byte(fmt.Sprintf("%d", round)))
	return h[len(h)-1]&1 == 1
}

// VerifyCertificate checks a transferable decision certificate. seed is
// ignored for the all-1 fast path; a regular certificate must be accompanied
// by the certified beacon value assigned to its deciding round.
func VerifyCertificate(cert Certificate, publicKeys map[string]ed25519.PublicKey, quorum int, seed []byte) error {
	if cert.Instance == "" || cert.Purpose == "" || quorum <= 0 {
		return fmt.Errorf("invalid ABA certificate context")
	}
	var kind string
	var payload any
	if cert.FastPath {
		if !cert.Value {
			return fmt.Errorf("ABA fast-path certificate cannot decide 0")
		}
		kind = "FINISH"
		payload = FinishMessage{Value: true}
	} else {
		if len(seed) == 0 {
			return fmt.Errorf("regular ABA certificate requires its certified seed")
		}
		if CoinFromSeed(cert.Instance, cert.Round, seed) != cert.Value {
			return fmt.Errorf("ABA certificate value does not match its deciding coin")
		}
		kind = "CONF"
		payload = ConfMessage{Round: cert.Round, Values: []bool{cert.Value}}
	}
	raw, _ := json.Marshal(unsignedPayload(payload))
	transcript := crypto.DomainHash(
		"Tyche/ABAMessage/v1",
		[]byte(fmt.Sprintf("%d", cert.ConfigVersion)),
		[]byte(cert.Purpose),
		[]byte(kind),
		[]byte(cert.Instance),
		raw,
	)
	return crypto.VerifySignedQuorumCertificate(cert.Quorum, publicKeys, quorum, transcript)
}

func EpochInstance(epoch uint64) string {
	return fmt.Sprintf("epoch/%d", epoch)
}

func EpochInstanceFor(configVersion, epoch uint64) string {
	return fmt.Sprintf("aba/%d/control/epoch/%d", configVersion, epoch)
}

func JoinInstanceFor(configVersion uint64, joiner string) string {
	return fmt.Sprintf("aba/%d/control/join/%s", configVersion, joiner)
}

func ConfigVersionFromInstance(instance string) (uint64, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) < 3 || parts[0] != "aba" {
		return 0, false
	}
	version, err := strconv.ParseUint(parts[1], 10, 64)
	return version, err == nil
}

func EpochFromInstance(instance string) (uint64, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) != 5 || parts[0] != "aba" || parts[2] != "control" || parts[3] != "epoch" {
		return 0, false
	}
	epoch, err := strconv.ParseUint(parts[4], 10, 64)
	return epoch, err == nil
}

func JoinerFromInstance(instance string) (string, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) == 2 && parts[0] == "join" && parts[1] != "" {
		return parts[1], true
	}
	if len(parts) == 5 && parts[0] == "aba" && parts[2] == "control" &&
		parts[3] == "join" && parts[4] != "" {
		return parts[4], true
	}
	return "", false
}

func (a *Agreement) acceptsSender(sender p2p.NodeID) bool {
	if a.Members == nil {
		return sender != ""
	}
	_, ok := a.Members[sender]
	return ok
}

func (a *Agreement) validInstance(instance string) bool {
	if instance == "" {
		return false
	}
	if a.Purpose == "legacy" {
		return true
	}
	return strings.HasPrefix(instance, fmt.Sprintf("aba/%d/%s/", a.Version, a.Purpose))
}

func signedVotes(votes map[p2p.NodeID]crypto.SignedVote, limit int) []crypto.SignedVote {
	senders := make([]p2p.NodeID, 0, len(votes))
	for sender := range votes {
		senders = append(senders, sender)
	}
	sort.Slice(senders, func(i, j int) bool { return senders[i] < senders[j] })
	if len(senders) > limit {
		senders = senders[:limit]
	}
	out := make([]crypto.SignedVote, 0, len(senders))
	for _, sender := range senders {
		out = append(out, votes[sender])
	}
	return out
}

func (a *Agreement) buildDecisionQuorum(votes []crypto.SignedVote) (crypto.SignedQuorumCertificate, error) {
	if !a.Authenticated {
		return crypto.SignedQuorumCertificate{}, nil
	}
	return crypto.EncodeVerifiedSignedQuorumCertificate(votes, a.PublicKeys, a.quorum())
}

func (a *Agreement) payloadTranscript(kind, instance string, payload any) []byte {
	raw, _ := json.Marshal(unsignedPayload(payload))
	return crypto.DomainHash(
		"Tyche/ABAMessage/v1",
		[]byte(fmt.Sprintf("%d", a.Version)),
		[]byte(a.Purpose),
		[]byte(kind),
		[]byte(instance),
		raw,
	)
}

func unsignedPayload(payload any) any {
	switch body := payload.(type) {
	case InputMessage:
		return struct {
			Value bool `json:"value"`
		}{body.Value}
	case FinishMessage:
		return struct {
			Value bool `json:"value"`
		}{body.Value}
	case BValMessage:
		return struct {
			Round uint64 `json:"round"`
			Value bool   `json:"value"`
		}{body.Round, body.Value}
	case AuxMessage:
		return struct {
			Round uint64 `json:"round"`
			Value bool   `json:"value"`
		}{body.Round, body.Value}
	case ConfMessage:
		return struct {
			Round  uint64 `json:"round"`
			Values []bool `json:"values"`
		}{body.Round, append([]bool(nil), body.Values...)}
	default:
		return payload
	}
}

func (a *Agreement) signPayload(kind, instance string, payload any) (any, error) {
	if !a.Authenticated {
		return payload, nil
	}
	signature, err := crypto.SignTranscript(string(a.ID), a.PrivateKey, a.payloadTranscript(kind, instance, payload))
	if err != nil {
		return nil, err
	}
	switch body := payload.(type) {
	case InputMessage:
		body.Signature = signature
		return body, nil
	case FinishMessage:
		body.Signature = signature
		return body, nil
	case BValMessage:
		body.Signature = signature
		return body, nil
	case AuxMessage:
		body.Signature = signature
		return body, nil
	case ConfMessage:
		body.Signature = signature
		return body, nil
	default:
		return nil, fmt.Errorf("unsupported authenticated ABA payload %T", payload)
	}
}

func (a *Agreement) verifyPayload(kind, instance string, sender p2p.NodeID, payload any, signature crypto.SignedVote) bool {
	if !a.Authenticated {
		return true
	}
	if signature.Signer != string(sender) {
		return false
	}
	return crypto.VerifySignedVote(signature, a.PublicKeys, a.payloadTranscript(kind, instance, payload)) == nil
}
