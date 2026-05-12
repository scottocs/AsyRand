package aba

import (
	"context"
	"fmt"
	"sync"

	asig "github.com/scottocs/asyrand/asyrand/internal/crypto"
	"github.com/scottocs/asyrand/asyrand/internal/p2p"
)

const Protocol = "aba"

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

type CoinMessage struct {
	Round uint64         `json:"round"`
	Share asig.CoinShare `json:"share"`
}

type Decision struct {
	Instance string
	Value    bool
	FastPath bool
}

type InstanceID string

type Agreement struct {
	ID        p2p.NodeID
	N         int
	F         int
	Transport p2p.Transport
	Coin      asig.ThresholdCoin

	mu        sync.Mutex
	state     map[InstanceID]*instanceState
	Decisions chan Decision
}

type instanceState struct {
	proposed bool
	est      bool
	round    uint64
	decided  bool

	inputs     map[p2p.NodeID]bool
	inputCount map[bool]int
	finish     map[p2p.NodeID]bool
	finishSent bool

	bval     map[uint64]map[bool]map[p2p.NodeID]bool
	bvalSent map[uint64]map[bool]bool
	bin      map[uint64]map[bool]bool
	aux      map[uint64]map[p2p.NodeID]bool
	auxVal   map[uint64]map[bool]bool
	auxSent  map[uint64]bool
	conf     map[uint64]map[p2p.NodeID]bool
	confVal  map[uint64]map[bool]bool
	confSent map[uint64]bool
	coins    map[uint64][]asig.CoinShare
	coinSent map[uint64]bool
}

func New(id p2p.NodeID, n, f int, transport p2p.Transport, coin asig.ThresholdCoin) *Agreement {
	return &Agreement{
		ID: id, N: n, F: f, Transport: transport, Coin: coin,
		state:     make(map[InstanceID]*instanceState),
		Decisions: make(chan Decision, n*4),
	}
}

func (a *Agreement) Propose(ctx context.Context, instance string, value bool) error {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	if !st.proposed {
		st.proposed = true
		st.est = value
	}
	a.mu.Unlock()
	if err := a.broadcast(ctx, "INPUT", instance, InputMessage{Value: value}); err != nil {
		return err
	}
	return a.broadcastBVal(ctx, instance, 0, value)
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
	case "COIN":
		body, err := p2p.DecodePayload[CoinMessage](msg)
		if err != nil {
			return err
		}
		a.handleCoin(ctx, msg.Instance, body.Round, body.Share)
	}
	return nil
}

func (a *Agreement) get(id InstanceID) *instanceState {
	st := a.state[id]
	if st != nil {
		return st
	}
	st = &instanceState{
		inputs: make(map[p2p.NodeID]bool), inputCount: make(map[bool]int), finish: make(map[p2p.NodeID]bool),
		bval: make(map[uint64]map[bool]map[p2p.NodeID]bool), bvalSent: make(map[uint64]map[bool]bool),
		bin: make(map[uint64]map[bool]bool), aux: make(map[uint64]map[p2p.NodeID]bool),
		auxVal: make(map[uint64]map[bool]bool), auxSent: make(map[uint64]bool),
		conf: make(map[uint64]map[p2p.NodeID]bool), confVal: make(map[uint64]map[bool]bool),
		confSent: make(map[uint64]bool), coins: make(map[uint64][]asig.CoinShare), coinSent: make(map[uint64]bool),
	}
	a.state[id] = st
	return st
}

func (a *Agreement) ensureRound(st *instanceState, r uint64) {
	if st.bval[r] == nil {
		st.bval[r] = map[bool]map[p2p.NodeID]bool{false: {}, true: {}}
	}
	if st.bvalSent[r] == nil {
		st.bvalSent[r] = map[bool]bool{}
	}
	if st.bin[r] == nil {
		st.bin[r] = make(map[bool]bool)
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
	if st.confVal[r] == nil {
		st.confVal[r] = make(map[bool]bool)
	}
}

func (a *Agreement) quorum() int { return a.N - a.F }

func (a *Agreement) handleInput(ctx context.Context, instance string, from p2p.NodeID, value bool) {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
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
		_ = a.broadcast(ctx, "FINISH", instance, FinishMessage{Value: true})
	}
}

func (a *Agreement) handleFinish(ctx context.Context, instance string, from p2p.NodeID, value bool) {
	if !value {
		return
	}
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	if st.decided {
		a.mu.Unlock()
		return
	}
	st.finish[from] = true
	if len(st.finish) >= 2*a.F+1 {
		st.decided = true
		a.mu.Unlock()
		a.Decisions <- Decision{Instance: instance, Value: true, FastPath: true}
		return
	}
	a.mu.Unlock()
}

func (a *Agreement) handleBVal(ctx context.Context, instance string, from p2p.NodeID, round uint64, value bool) {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
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
	a.mu.Unlock()
	if amplify {
		_ = a.broadcastBVal(ctx, instance, round, value)
	}
	if sendAux {
		_ = a.broadcast(ctx, "AUX", instance, AuxMessage{Round: round, Value: auxValue})
	}
}

func (a *Agreement) handleAux(ctx context.Context, instance string, from p2p.NodeID, round uint64, value bool) {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	if !st.bin[round][value] || st.aux[round][from] {
		a.mu.Unlock()
		return
	}
	st.aux[round][from] = true
	st.auxVal[round][value] = true
	sendConf := len(st.aux[round]) >= a.quorum() && !st.confSent[round]
	values := make([]bool, 0, len(st.auxVal[round]))
	if sendConf {
		for v := range st.auxVal[round] {
			values = append(values, v)
		}
		st.confSent[round] = true
	}
	a.mu.Unlock()
	if sendConf {
		_ = a.broadcast(ctx, "CONF", instance, ConfMessage{Round: round, Values: values})
		_ = a.broadcastCoin(ctx, instance, round)
	}
}

func (a *Agreement) handleConf(ctx context.Context, instance string, from p2p.NodeID, round uint64, values []bool) {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	if st.conf[round][from] {
		a.mu.Unlock()
		return
	}
	for _, v := range values {
		if !st.bin[round][v] {
			a.mu.Unlock()
			return
		}
	}
	st.conf[round][from] = true
	for _, v := range values {
		st.confVal[round][v] = true
	}
	needCoin := len(st.conf[round]) >= a.quorum() && !st.coinSent[round]
	if needCoin {
		st.coinSent[round] = true
	}
	a.mu.Unlock()
	if needCoin {
		_ = a.broadcast(ctx, "COIN", instance, CoinMessage{Round: round, Share: a.Coin.Share(instance, round)})
	}
}

func (a *Agreement) handleCoin(ctx context.Context, instance string, round uint64, share asig.CoinShare) {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	if st.decided {
		a.mu.Unlock()
		return
	}
	a.ensureRound(st, round)
	st.coins[round] = append(st.coins[round], share)
	values := make([]bool, 0, len(st.confVal[round]))
	for v := range st.confVal[round] {
		values = append(values, v)
	}
	hasConfQuorum := len(st.conf[round]) >= a.quorum()
	shares := append([]asig.CoinShare(nil), st.coins[round]...)
	a.mu.Unlock()
	if !hasConfQuorum {
		return
	}
	coin, err := a.Coin.Combine(instance, round, shares)
	if err != nil {
		return
	}
	a.mu.Lock()
	st = a.get(InstanceID(instance))
	if st.decided {
		a.mu.Unlock()
		return
	}
	if len(values) == 1 {
		b := values[0]
		st.est = b
		if b == coin {
			st.decided = true
			a.mu.Unlock()
			a.Decisions <- Decision{Instance: instance, Value: b, FastPath: false}
			return
		}
	} else {
		st.est = coin
	}
	nextRound := round + 1
	nextEst := st.est
	a.mu.Unlock()
	_ = a.broadcastBVal(ctx, instance, nextRound, nextEst)
}

func (a *Agreement) broadcastCoin(ctx context.Context, instance string, round uint64) error {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	a.ensureRound(st, round)
	if st.coinSent[round] {
		a.mu.Unlock()
		return nil
	}
	st.coinSent[round] = true
	a.mu.Unlock()
	return a.broadcast(ctx, "COIN", instance, CoinMessage{Round: round, Share: a.Coin.Share(instance, round)})
}

func (a *Agreement) broadcastBVal(ctx context.Context, instance string, round uint64, value bool) error {
	a.mu.Lock()
	st := a.get(InstanceID(instance))
	a.ensureRound(st, round)
	if st.bvalSent[round][value] {
		a.mu.Unlock()
		return nil
	}
	st.bvalSent[round][value] = true
	a.mu.Unlock()
	return a.broadcast(ctx, "BVAL", instance, BValMessage{Round: round, Value: value})
}

func (a *Agreement) broadcast(ctx context.Context, typ, instance string, payload any) error {
	msg, err := p2p.NewMessage(Protocol, typ, instance, a.ID, "", payload)
	if err != nil {
		return err
	}
	return a.Transport.Broadcast(ctx, msg)
}

func EpochInstance(epoch uint64, source p2p.NodeID) string {
	return fmt.Sprintf("epoch/%d/source/%s", epoch, source)
}
