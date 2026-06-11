package aba

import (
	"context"
	"fmt"
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
	Value bool `json:"value"`
}

type FinishMessage struct {
	Value bool `json:"value"`
}

type BValMessage struct {
	Round uint64 `json:"round"`
	Value bool   `json:"value"`
}

type AuxMessage struct {
	Round uint64 `json:"round"`
	Value bool   `json:"value"`
}

type ConfMessage struct {
	Round  uint64 `json:"round"`
	Values []bool `json:"values"`
}

type CoinRequest struct {
	Instance string
	Round    uint64
}

type Decision struct {
	Instance string
	Value    bool
	FastPath bool
}

type Status struct {
	Instance   string
	Round      uint64
	Decided    bool
	Value      bool
	CoinWait   bool
	Inputs     int
	InputTrue  int
	InputFalse int
	Finish     int
	BValTrue   int
	BValFalse  int
	BinTrue    bool
	BinFalse   bool
	Aux        int
	Conf       int
}

type Agreement struct {
	ID        p2p.NodeID
	N         int
	F         int
	Transport p2p.Transport

	mu           sync.Mutex
	state        map[string]*instanceState
	pruned       map[string]bool
	Decisions    chan Decision
	CoinRequests chan CoinRequest
}

type instanceState struct {
	proposed bool
	est      bool
	round    uint64
	decided  bool
	decision bool

	inputs     map[p2p.NodeID]bool
	inputCount map[bool]int
	finish     map[p2p.NodeID]bool
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
	confVal     map[uint64]map[bool]bool
	confSent    map[uint64]bool
	coinReq     map[uint64]bool
	coinWait    map[uint64]bool
	coins       map[uint64]bool
	coinSeen    map[uint64]bool
}

func New(id p2p.NodeID, n, f int, transport p2p.Transport) *Agreement {
	return &Agreement{
		ID: id, N: n, F: f, Transport: transport,
		state:        make(map[string]*instanceState),
		pruned:       make(map[string]bool),
		Decisions:    make(chan Decision, n*4),
		CoinRequests: make(chan CoinRequest, n*8),
	}
}

func (a *Agreement) Propose(ctx context.Context, instance string, value bool) error {
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
	switch msg.Type {
	case "INPUT":
		body, err := p2p.DecodePayload[InputMessage](msg)
		if err != nil {
			return err
		}
		a.handleInput(ctx, msg.Instance, msg.From, body.Value)
	case "FINISH":
		body, err := p2p.DecodePayload[FinishMessage](msg)
		if err != nil {
			return err
		}
		a.handleFinish(ctx, msg.Instance, msg.From, body.Value)
	case "BVAL":
		body, err := p2p.DecodePayload[BValMessage](msg)
		if err != nil {
			return err
		}
		a.handleBVal(ctx, msg.Instance, msg.From, body.Round, body.Value)
	case "AUX":
		body, err := p2p.DecodePayload[AuxMessage](msg)
		if err != nil {
			return err
		}
		a.handleAux(ctx, msg.Instance, msg.From, body.Round, body.Value)
	case "CONF":
		body, err := p2p.DecodePayload[ConfMessage](msg)
		if err != nil {
			return err
		}
		a.handleConf(ctx, msg.Instance, msg.From, body.Round, body.Values)
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
		Instance:   instance,
		Round:      round,
		Decided:    st.decided,
		Value:      st.decision,
		CoinWait:   st.coinWait[round],
		Inputs:     len(st.inputs),
		InputTrue:  st.inputCount[true],
		InputFalse: st.inputCount[false],
		Finish:     len(st.finish),
		BValTrue:   len(st.bval[round][true]),
		BValFalse:  len(st.bval[round][false]),
		BinTrue:    st.bin[round][true],
		BinFalse:   st.bin[round][false],
		Aux:        len(st.aux[round]),
		Conf:       len(st.conf[round]),
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

func (a *Agreement) get(instance string) *instanceState {
	st := a.state[instance]
	if st != nil {
		return st
	}
	if decision, ok := a.pruned[instance]; ok {
		return &instanceState{decided: true, decision: decision}
	}
	st = &instanceState{
		inputs: make(map[p2p.NodeID]bool), inputCount: make(map[bool]int), finish: make(map[p2p.NodeID]bool),
		bval: make(map[uint64]map[bool]map[p2p.NodeID]bool), bvalSent: make(map[uint64]map[bool]bool),
		bin: make(map[uint64]map[bool]bool), auxPending: make(map[uint64]map[p2p.NodeID]bool),
		aux:    make(map[uint64]map[p2p.NodeID]bool),
		auxVal: make(map[uint64]map[bool]bool), auxSent: make(map[uint64]bool),
		confPending: make(map[uint64]map[p2p.NodeID][]bool),
		conf:        make(map[uint64]map[p2p.NodeID]bool), confVal: make(map[uint64]map[bool]bool),
		confSent: make(map[uint64]bool), coinReq: make(map[uint64]bool), coinWait: make(map[uint64]bool),
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
	shouldFinish := st.inputCount[true] >= 2*a.F+1 && !st.finishSent
	if shouldFinish {
		st.finishSent = true
	}
	a.mu.Unlock()
	if shouldFinish {
		a.broadcastAsync("FINISH", instance, FinishMessage{Value: true})
	}
}

func (a *Agreement) handleFinish(ctx context.Context, instance string, from p2p.NodeID, value bool) {
	if !value {
		return
	}
	a.mu.Lock()
	st := a.get(instance)
	if st.decided {
		a.mu.Unlock()
		return
	}
	st.finish[from] = true
	if len(st.finish) >= 2*a.F+1 {
		st.decided = true
		st.decision = true
		a.mu.Unlock()
		a.Decisions <- Decision{Instance: instance, Value: true, FastPath: true}
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
		a.CoinRequests <- CoinRequest{Instance: instance, Round: round}
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
		a.CoinRequests <- CoinRequest{Instance: instance, Round: round}
	}
	if hasCoin {
		a.tryAdvanceWithCoin(ctx, instance, round)
	}
}

func (a *Agreement) handleConf(ctx context.Context, instance string, from p2p.NodeID, round uint64, values []bool) {
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
	needCoin, hasCoin := a.processPendingConfLocked(st, round)
	a.mu.Unlock()
	if needCoin {
		a.CoinRequests <- CoinRequest{Instance: instance, Round: round}
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
			st.decided = true
			st.decision = b
			a.mu.Unlock()
			a.Decisions <- Decision{Instance: instance, Value: b, FastPath: false}
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
	h := crypto.HashBytes([]byte("Tyche-v1/ABA/coin/"), seed, []byte(instance), []byte(fmt.Sprintf("/%d", round)))
	return h[len(h)-1]&1 == 1
}

func EpochInstance(epoch uint64, source p2p.NodeID) string {
	return fmt.Sprintf("epoch/%d/source/%s", epoch, source)
}

func JoinInstance(transition, requestDigest string, firstCoinEpoch uint64) string {
	return fmt.Sprintf("join/%s/%s/%d", transition, requestDigest, firstCoinEpoch)
}

func ParseJoinInstance(instance string) (uint64, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) < 5 || parts[0] != "join" {
		return 0, false
	}
	first, err := strconv.ParseUint(parts[len(parts)-1], 10, 64)
	if err != nil {
		return 0, false
	}
	return first, true
}
