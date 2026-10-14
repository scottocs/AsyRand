package aba

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"sort"
	"sync"

	asig "Tyche/asyrand/crypto"
	"Tyche/utils/p2p"
)

const (
	PRE      = "PRE"
	VOTE     = "VOTE"
	MAIN     = "MAIN"
	FINAL    = "FINAL"
	DECISION = "DECISION"
	REQUEST  = "CERT_REQUEST"
	RESPONSE = "CERT_RESPONSE"
)

var (
	ErrInvalidMessage      = errors.New("invalid Quadratic-ABA message")
	ErrAlreadyProposed     = errors.New("ABA input already submitted")
	ErrAlreadyCertified    = errors.New("ABA certificate adopted before proposal")
	ErrConflictingDecision = errors.New("conflicting ABA decision")
)

type Config struct {
	PublicConfig
	ID       p2p.NodeID
	Instance string
	Private  ed25519.PrivateKey
	// Nil uses crypto/rand.Reader. A custom reader is for testing or an
	// independent secure local entropy source, never beacon/common coins.
	Coin io.Reader
}

type CoreMessage struct {
	CommitteeID string `json:"committee_id"`
	Round       uint64 `json:"round"`
	Value       Value  `json:"value"`
	SigHex      string `json:"sig_hex"`
}

type DecisionVote struct {
	CommitteeID string `json:"committee_id"`
	Bit         Value  `json:"bit"`
	SigHex      string `json:"sig_hex"`
}

type CertificateRequest struct {
	CommitteeID string `json:"committee_id"`
	SigHex      string `json:"sig_hex"`
}

type candidate struct {
	from  p2p.NodeID
	value Value
}

type phaseState struct {
	pending  []candidate
	seen     map[p2p.NodeID]uint8
	accepted map[p2p.NodeID]Value
	order    []candidate
	counts   [3]int
	support  uint8
}

func newPhase() phaseState {
	return phaseState{seen: make(map[p2p.NodeID]uint8), accepted: make(map[p2p.NodeID]Value)}
}

type roundState struct {
	entered                       bool
	pre                           [2]map[p2p.NodeID]bool
	preSent                       [2]bool
	binary                        [2]bool
	vote, main, final             phaseState
	voteSent, mainSent, finalSent bool
}

func newRound() *roundState {
	return &roundState{pre: [2]map[p2p.NodeID]bool{make(map[p2p.NodeID]bool), make(map[p2p.NodeID]bool)}, vote: newPhase(), main: newPhase(), final: newPhase()}
}

type Status struct {
	Proposed         bool
	Input            Value
	Round            uint64
	Estimate         Value
	InternalDecided  bool
	InternalDecision Value
	Stopped          bool
	Certified        bool
}

// Instance is a serializable event-driven state machine for one unique ABA
// identifier. Propose/Handle/Adopt/Progress return outbound messages. The
// caller MUST route every returned message, even if the accompanying error is
// a local coin read failure. To=="" means broadcast to the fixed membership.
// Local messages are counted immediately; network loopback is optional.
// Keep routing messages after Wait succeeds: certificate adoption does not
// stop the core or its required next-round FINAL transmission. Entered-round
// relay/validation handlers remain available even after the core stops.
type Instance struct {
	mu              sync.Mutex
	verifier        *Verifier
	id              p2p.NodeID
	instance        string
	private         ed25519.PrivateKey
	coin            io.Reader
	proposed        bool
	input, estimate Value
	round           uint64
	rounds          map[uint64]*roundState
	dirty           map[uint64]bool
	internal        *Value
	stopRound       uint64
	stopped         bool
	decisionSent    bool
	votes           [2]map[p2p.NodeID]string
	certificate     *Certificate
	waiters         map[p2p.NodeID]bool
	done            chan struct{}
}

func New(cfg Config) (*Instance, error) {
	verifier, err := NewVerifier(cfg.PublicConfig)
	if err != nil {
		return nil, err
	}
	if !validInstance(cfg.Instance) || verifier.public[cfg.ID] == nil || !validPrivate(cfg.Private, verifier.public[cfg.ID]) {
		return nil, errors.New("ABA requires a unique valid instance and matching local signing key")
	}
	coin := cfg.Coin
	if coin == nil {
		coin = rand.Reader
	}
	return &Instance{
		verifier: verifier, id: cfg.ID, instance: cfg.Instance, private: append(ed25519.PrivateKey(nil), cfg.Private...), coin: coin,
		rounds: make(map[uint64]*roundState), dirty: make(map[uint64]bool), votes: [2]map[p2p.NodeID]string{make(map[p2p.NodeID]string), make(map[p2p.NodeID]string)},
		waiters: make(map[p2p.NodeID]bool), done: make(chan struct{}),
	}, nil
}

func (a *Instance) Verifier() *Verifier { return a.verifier }

// VerifyCoreMessage authenticates a core packet without allocating round state.
// A runtime can defer far-future packets and recover them from sender archives.
func (a *Instance) VerifyCoreMessage(msg p2p.Message) bool {
	if msg.Protocol != Protocol || msg.Instance != a.instance || a.verifier.public[msg.From] == nil || (msg.To != "" && msg.To != a.id) {
		return false
	}
	if msg.Type != PRE && msg.Type != VOTE && msg.Type != MAIN && msg.Type != FINAL {
		return false
	}
	body, err := p2p.DecodePayload[CoreMessage](msg)
	return err == nil && body.CommitteeID == a.verifier.committeeID && validValue(msg.Type, body.Value) &&
		a.verifier.verifySignature(msg.From, a.coreStatement(msg.From, msg.Type, body.Round, body.Value), body.SigHex)
}

func (a *Instance) Propose(bit Value) ([]p2p.Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !bit.binary() {
		return nil, errors.New("ABA input must be binary")
	}
	if a.proposed {
		return nil, ErrAlreadyProposed
	}
	if a.certificate != nil {
		return nil, ErrAlreadyCertified
	}
	a.proposed = true
	a.input = bit
	a.estimate = bit
	var out []p2p.Message
	a.enterRound(0, &out)
	err := a.drive(&out)
	return out, err
}

// Progress retries enabled work after a local entropy read failure. Core
// rounds never advance by a timeout, and failures never substitute a fixed coin.
func (a *Instance) Progress() ([]p2p.Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []p2p.Message
	err := a.drive(&out)
	return out, err
}

// Handle buffers future-round and currently unsupported signed messages. A
// malformed or unauthenticated message is rejected before changing any state.
func (a *Instance) Handle(msg p2p.Message) ([]p2p.Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if msg.Protocol != Protocol || msg.Instance != a.instance || a.verifier.public[msg.From] == nil || (msg.To != "" && msg.To != a.id) {
		return nil, ErrInvalidMessage
	}
	var out []p2p.Message
	switch msg.Type {
	case PRE, VOTE, MAIN, FINAL:
		body, err := p2p.DecodePayload[CoreMessage](msg)
		if err != nil || body.CommitteeID != a.verifier.committeeID || !validValue(msg.Type, body.Value) ||
			!a.verifier.verifySignature(msg.From, a.coreStatement(msg.From, msg.Type, body.Round, body.Value), body.SigHex) {
			return nil, ErrInvalidMessage
		}
		a.observeCore(msg.From, msg.Type, body.Round, body.Value)
	case DECISION:
		body, err := p2p.DecodePayload[DecisionVote](msg)
		if err != nil || body.CommitteeID != a.verifier.committeeID || !body.Bit.binary() ||
			!a.verifier.verifySignature(msg.From, a.verifier.decisionStatement(a.instance, body.Bit), body.SigHex) {
			return nil, ErrInvalidMessage
		}
		if err := a.observeDecision(msg.From, body.Bit, body.SigHex, &out); err != nil {
			return out, err
		}
	case REQUEST:
		body, err := p2p.DecodePayload[CertificateRequest](msg)
		if err != nil || body.CommitteeID != a.verifier.committeeID || !a.verifier.verifySignature(msg.From, a.requestStatement(msg.From), body.SigHex) {
			return nil, ErrInvalidMessage
		}
		if a.certificate != nil {
			a.respond(msg.From, &out)
		} else {
			a.waiters[msg.From] = true
		}
	case RESPONSE:
		cert, err := p2p.DecodePayload[Certificate](msg)
		if err != nil {
			return nil, ErrInvalidMessage
		}
		if err := a.adopt(cert, &out); err != nil {
			return out, err
		}
	default:
		return nil, ErrInvalidMessage
	}
	err := a.drive(&out)
	return out, err
}

// RequestCertificate works before Propose. Receivers remember the request
// and serve a retained certificate when available; no polling timer is needed.
// Recovery traffic is separate from the core's quadratic-per-round traffic.
func (a *Instance) RequestCertificate() []p2p.Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.certificate != nil {
		return nil
	}
	payload := CertificateRequest{CommitteeID: a.verifier.committeeID, SigHex: hex.EncodeToString(asig.Sign(a.private, a.requestStatement(a.id)))}
	return []p2p.Message{a.message(REQUEST, "", payload)}
}

// Adopt serializes certificate installation with proposal submission. It
// does not create an internal decision, sign a decision or cancel active help.
func (a *Instance) Adopt(cert Certificate) ([]p2p.Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []p2p.Message
	if err := a.adopt(cert, &out); err != nil {
		return out, err
	}
	err := a.drive(&out)
	return out, err
}

func (a *Instance) Result() (Decision, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.result()
}
func (a *Instance) result() (Decision, bool) {
	if a.certificate == nil {
		return Decision{}, false
	}
	return Decision{Bit: a.certificate.Bit, Certificate: cloneCertificate(*a.certificate)}, true
}

// Wait observes certificate delivery, not a native internal decision. The
// application must continue its message dispatcher independently of this wait.
func (a *Instance) Wait(ctx context.Context) (Decision, error) {
	select {
	case <-a.done:
		result, _ := a.Result()
		return result, nil
	case <-ctx.Done():
		return Decision{}, ctx.Err()
	}
}

func (a *Instance) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	status := Status{Proposed: a.proposed, Input: a.input, Round: a.round, Estimate: a.estimate, InternalDecided: a.internal != nil, Stopped: a.stopped, Certified: a.certificate != nil}
	if a.internal != nil {
		status.InternalDecision = *a.internal
	}
	return status
}

func validValue(phase string, value Value) bool {
	if phase == PRE || phase == VOTE {
		return value.binary()
	}
	return (phase == MAIN || phase == FINAL) && value <= Wildcard
}

func (a *Instance) coreStatement(from p2p.NodeID, phase string, round uint64, value Value) []byte {
	return encode(struct {
		Domain, CommitteeID, Instance string
		Sender                        p2p.NodeID
		Round                         uint64
		Phase                         string
		Value                         Value
	}{Protocol + "/core", a.verifier.committeeID, a.instance, from, round, phase, value})
}
func (a *Instance) requestStatement(from p2p.NodeID) []byte {
	return encode(struct {
		Domain, CommitteeID, Instance string
		Sender                        p2p.NodeID
	}{Protocol + "/request", a.verifier.committeeID, a.instance, from})
}
func (a *Instance) message(phase string, to p2p.NodeID, payload any) p2p.Message {
	msg, err := p2p.NewMessage(Protocol, phase, a.instance, a.id, to, payload)
	if err != nil {
		panic(err)
	}
	return msg
}
func (a *Instance) sendCore(phase string, round uint64, value Value, out *[]p2p.Message) {
	body := CoreMessage{CommitteeID: a.verifier.committeeID, Round: round, Value: value, SigHex: hex.EncodeToString(asig.Sign(a.private, a.coreStatement(a.id, phase, round, value)))}
	*out = append(*out, a.message(phase, "", body))
	a.observeCore(a.id, phase, round, value)
}
func (a *Instance) state(round uint64) *roundState {
	s := a.rounds[round]
	if s == nil {
		s = newRound()
		a.rounds[round] = s
	}
	return s
}
func (a *Instance) enterRound(round uint64, out *[]p2p.Message) {
	a.round = round
	s := a.state(round)
	s.entered = true
	a.dirty[round] = true
	s.preSent[a.estimate] = true
	a.sendCore(PRE, round, a.estimate, out)
}
func (a *Instance) observeCore(from p2p.NodeID, phase string, round uint64, value Value) {
	s := a.state(round)
	if phase == PRE {
		if s.pre[value][from] {
			return
		}
		s.pre[value][from] = true
		if s.entered {
			a.dirty[round] = true
		}
		return
	}
	var p *phaseState
	switch phase {
	case VOTE:
		p = &s.vote
	case MAIN:
		p = &s.main
	case FINAL:
		p = &s.final
	}
	bit := uint8(1) << uint(value)
	if p.seen[from]&bit != 0 {
		return
	}
	p.seen[from] |= bit
	// A sender can have at most three candidates, but only one accepted vote.
	// An unsupported first candidate must not suppress a later valid value.
	if _, ok := p.accepted[from]; !ok {
		c := candidate{from, value}
		if s.entered && p.support&bit != 0 {
			p.accept(c)
		} else {
			p.pending = append(p.pending, c)
		}
		if s.entered {
			a.dirty[round] = true
		}
	}
}

func (a *Instance) promote(s *roundState, p *phaseState, phase string) {
	var support uint8
	for value := Zero; value <= One; value++ {
		valid := false
		switch phase {
		case VOTE:
			valid = s.binary[value]
		case MAIN:
			valid = s.vote.counts[value] >= a.verifier.f+1
		case FINAL:
			valid = s.main.counts[value] >= a.verifier.f+1
		}
		if valid {
			support |= 1 << uint(value)
		}
	}
	if phase != VOTE && s.binary[0] && s.binary[1] {
		support |= 1 << uint(Wildcard)
	}
	if support == p.support {
		return
	}
	p.support = support
	// Each predicate becomes true at most once. Scan unsupported candidates
	// only when support grows, giving linear work in messages per round.
	retained := p.pending[:0]
	for _, candidate := range p.pending {
		if _, ok := p.accepted[candidate.from]; ok {
			continue
		}
		if support&(1<<uint(candidate.value)) != 0 {
			p.accept(candidate)
		} else {
			retained = append(retained, candidate)
		}
	}
	p.pending = retained
}
func (p *phaseState) accept(c candidate) {
	p.accepted[c.from] = c.value
	p.order = append(p.order, c)
	p.counts[c.value]++
}
func same(batch []candidate) Value {
	value := batch[0].value
	for _, v := range batch[1:] {
		if v.value != value {
			return Wildcard
		}
	}
	return value
}

// drive runs enabled actions to a fixed point. All entered rounds retain
// their PRE relay and validation handlers, including rounds preceding round.
func (a *Instance) drive(out *[]p2p.Message) error {
	for {
		entered := make([]uint64, 0, len(a.dirty))
		for round := range a.dirty {
			entered = append(entered, round)
		}
		sort.Slice(entered, func(i, j int) bool { return entered[i] < entered[j] })
		for _, round := range entered {
			s := a.rounds[round]
			for bit := Zero; bit <= One; bit++ {
				if len(s.pre[bit]) >= a.verifier.f+1 && !s.preSent[bit] {
					s.preSent[bit] = true
					a.sendCore(PRE, round, bit, out)
				}
				if len(s.pre[bit]) >= 2*a.verifier.f+1 {
					s.binary[bit] = true
				}
			}
			a.promote(s, &s.vote, VOTE)
			a.promote(s, &s.main, MAIN)
			a.promote(s, &s.final, FINAL)
			// Self PRE relays above are already processed in this pass.
			delete(a.dirty, round)
		}
		if !a.proposed || a.stopped {
			return nil
		}
		s := a.state(a.round)
		if !s.voteSent {
			if !s.binary[0] && !s.binary[1] {
				return nil
			}
			bit := Zero
			if !s.binary[0] {
				bit = One
			}
			s.voteSent = true
			a.sendCore(VOTE, a.round, bit, out)
			continue
		}
		if !s.mainSent {
			if len(s.vote.order) < a.verifier.coreQuorum {
				return nil
			}
			s.mainSent = true
			a.sendCore(MAIN, a.round, same(s.vote.order[:a.verifier.coreQuorum]), out)
			continue
		}
		if !s.finalSent {
			if len(s.main.order) < a.verifier.coreQuorum {
				return nil
			}
			s.finalSent = true
			a.sendCore(FINAL, a.round, same(s.main.order[:a.verifier.coreQuorum]), out)
			continue
		}
		// Help stops AFTER FINAL transmission in the one additional round.
		if a.internal != nil && a.round == a.stopRound {
			a.stopped = true
			return nil
		}
		if len(s.final.order) < a.verifier.coreQuorum {
			return nil
		}
		values := [3]bool{}
		for _, candidate := range s.final.order[:a.verifier.coreQuorum] {
			values[candidate.value] = true
		}
		next := Zero
		switch {
		case values[0] && !values[1] && !values[2]:
			next = Zero
			if err := a.decide(Zero, out); err != nil {
				return err
			}
		case values[1] && !values[0] && !values[2]:
			next = One
			if err := a.decide(One, out); err != nil {
				return err
			}
		case values[0] && !values[1]:
			next = Zero // {0,*}
		case values[1] && !values[0]:
			next = One // {1,*}
		default:
			var coin [1]byte
			if _, err := io.ReadFull(a.coin, coin[:]); err != nil {
				return err
			}
			next = Value(coin[0] & 1)
		}
		if a.round == math.MaxUint64 {
			return errors.New("ABA round counter exhausted")
		}
		a.estimate = next
		a.enterRound(a.round+1, out)
	}
}

func (a *Instance) decide(bit Value, out *[]p2p.Message) error {
	if a.internal != nil {
		if *a.internal != bit {
			return ErrConflictingDecision
		}
		return nil
	}
	if a.certificate != nil && a.certificate.Bit != bit {
		return ErrConflictingDecision
	}
	if a.round == math.MaxUint64 {
		return errors.New("ABA round counter exhausted")
	}
	internal := bit
	a.internal = &internal
	a.stopRound = a.round + 1
	if !a.decisionSent {
		a.decisionSent = true
		sig := hex.EncodeToString(asig.Sign(a.private, a.verifier.decisionStatement(a.instance, bit)))
		*out = append(*out, a.message(DECISION, "", DecisionVote{CommitteeID: a.verifier.committeeID, Bit: bit, SigHex: sig}))
		return a.observeDecision(a.id, bit, sig, out)
	}
	return nil
}

func (a *Instance) observeDecision(from p2p.NodeID, bit Value, sig string, out *[]p2p.Message) error {
	if a.certificate != nil {
		return nil
	}
	a.votes[bit][from] = sig
	if len(a.votes[bit]) < a.verifier.certificateQuorum {
		return nil
	}
	cert := Certificate{CommitteeID: a.verifier.committeeID, Instance: a.instance, Bit: bit}
	for _, member := range a.verifier.members {
		if sig, ok := a.votes[bit][member]; ok {
			cert.Signatures = append(cert.Signatures, Signature{Signer: member, SigHex: sig})
		}
		if len(cert.Signatures) == a.verifier.certificateQuorum {
			break
		}
	}
	return a.adopt(cert, out)
}
func (a *Instance) adopt(cert Certificate, out *[]p2p.Message) error {
	if err := a.verifier.VerifyCertificate(cert, a.instance); err != nil {
		return err
	}
	if (a.certificate != nil && a.certificate.Bit != cert.Bit) || (a.internal != nil && *a.internal != cert.Bit) {
		return ErrConflictingDecision
	}
	if a.certificate != nil {
		return nil
	}
	retained := cloneCertificate(cert)
	a.certificate = &retained
	close(a.done)
	for _, member := range a.verifier.members {
		if a.waiters[member] {
			a.respond(member, out)
		}
	}
	clear(a.waiters)
	return nil
}
func (a *Instance) respond(to p2p.NodeID, out *[]p2p.Message) {
	*out = append(*out, a.message(RESPONSE, to, cloneCertificate(*a.certificate)))
}
