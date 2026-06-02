package rbc

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
)

const Protocol = "rbc"

type ValueMessage struct {
	Dealer p2p.NodeID `json:"dealer"`
	Seq    uint64     `json:"seq"`
	Value  []byte     `json:"value"`
	Hash   string     `json:"hash"`
}

type RequestMessage struct {
	Dealer p2p.NodeID `json:"dealer"`
	Seq    uint64     `json:"seq"`
	Hash   string     `json:"hash"`
}

type VoteMessage struct {
	Dealer p2p.NodeID `json:"dealer"`
	Seq    uint64     `json:"seq"`
	Hash   string     `json:"hash"`
}

type Delivery struct {
	Dealer p2p.NodeID
	Seq    uint64
	Value  []byte
	Hash   string
}

type Broadcaster struct {
	ID        p2p.NodeID
	N         int
	F         int
	Transport p2p.Transport

	mu         sync.Mutex
	values     map[string]ValueMessage
	echoes     map[string]map[p2p.NodeID]bool
	readies    map[string]map[p2p.NodeID]bool
	echoSent   map[string]bool
	readySent  map[string]bool
	delivered  map[string]bool
	requested  map[string]map[p2p.NodeID]bool
	Deliveries chan Delivery
}

func New(id p2p.NodeID, n, f int, transport p2p.Transport) *Broadcaster {
	return &Broadcaster{
		ID: id, N: n, F: f, Transport: transport,
		values: make(map[string]ValueMessage), echoes: make(map[string]map[p2p.NodeID]bool),
		readies: make(map[string]map[p2p.NodeID]bool), echoSent: make(map[string]bool),
		readySent: make(map[string]bool), delivered: make(map[string]bool), requested: make(map[string]map[p2p.NodeID]bool),
		Deliveries: make(chan Delivery, n*4),
	}
}

func Instance(dealer p2p.NodeID, seq uint64, hash string) string {
	return fmt.Sprintf("%s/%d/%s", dealer, seq, hash)
}

func Digest(value []byte) string {
	return hex.EncodeToString(crypto.HashBytes(value))
}

func (b *Broadcaster) Broadcast(ctx context.Context, seq uint64, value []byte) error {
	hash := Digest(value)
	k := Instance(b.ID, seq, hash)
	val := ValueMessage{Dealer: b.ID, Seq: seq, Value: append([]byte(nil), value...), Hash: hash}
	b.mu.Lock()
	if _, ok := b.values[k]; !ok {
		b.values[k] = val
	}
	b.mu.Unlock()
	msg, err := p2p.NewMessage(Protocol, "VAL", k, b.ID, "", VoteMessage{Dealer: b.ID, Seq: seq, Hash: hash})
	if err != nil {
		return err
	}
	return b.Transport.Broadcast(ctx, msg)
}

func (b *Broadcaster) Handle(ctx context.Context, msg p2p.Message) error {
	switch msg.Type {
	case "VAL":
		vote, err := p2p.DecodePayload[VoteMessage](msg)
		if err != nil {
			return err
		}
		return b.handleVal(ctx, vote, msg.From)
	case "REQ":
		req, err := p2p.DecodePayload[RequestMessage](msg)
		if err != nil {
			return err
		}
		return b.sendValue(ctx, msg.From, req.Dealer, req.Seq, req.Hash)
	case "DATA":
		val, err := p2p.DecodePayload[ValueMessage](msg)
		if err != nil {
			return err
		}
		return b.acceptValue(ctx, val)
	case "ECHO":
		vote, err := p2p.DecodePayload[VoteMessage](msg)
		if err != nil {
			return err
		}
		b.observe(ctx, "echo", vote, msg.From)
	case "READY":
		vote, err := p2p.DecodePayload[VoteMessage](msg)
		if err != nil {
			return err
		}
		b.observe(ctx, "ready", vote, msg.From)
	}
	return nil
}

func (b *Broadcaster) requestValue(ctx context.Context, dealer p2p.NodeID, seq uint64, hash string, to p2p.NodeID) error {
	if hash == "" || to == "" {
		return nil
	}
	k := Instance(dealer, seq, hash)
	b.mu.Lock()
	if _, ok := b.values[k]; ok {
		b.mu.Unlock()
		return nil
	}
	if b.requested[k] == nil {
		b.requested[k] = make(map[p2p.NodeID]bool)
	}
	if b.requested[k][to] {
		b.mu.Unlock()
		return nil
	}
	b.requested[k][to] = true
	b.mu.Unlock()
	msg, err := p2p.NewMessage(Protocol, "REQ", k, b.ID, to, RequestMessage{Dealer: dealer, Seq: seq, Hash: hash})
	if err != nil {
		return err
	}
	return b.Transport.Send(ctx, to, msg)
}

func (b *Broadcaster) handleVal(ctx context.Context, vote VoteMessage, from p2p.NodeID) error {
	if vote.Hash == "" || vote.Dealer == "" || from != vote.Dealer {
		return nil
	}
	k := Instance(vote.Dealer, vote.Seq, vote.Hash)
	var deliver Delivery
	var shouldDeliver bool
	b.mu.Lock()
	alreadyEcho := b.echoSent[k]
	b.echoSent[k] = true
	_, hasValue := b.values[k]
	deliver, shouldDeliver = b.deliveryIfReadyLocked(k)
	b.mu.Unlock()

	if !hasValue {
		_ = b.requestValue(ctx, vote.Dealer, vote.Seq, vote.Hash, vote.Dealer)
	}
	if !alreadyEcho {
		if err := b.broadcastVote(ctx, "ECHO", vote.Dealer, vote.Seq, vote.Hash); err != nil {
			return err
		}
	}
	if shouldDeliver {
		b.Deliveries <- deliver
	}
	return nil
}

func (b *Broadcaster) sendValue(ctx context.Context, to p2p.NodeID, dealer p2p.NodeID, seq uint64, hash string) error {
	k := Instance(dealer, seq, hash)
	b.mu.Lock()
	val, hasValue := b.values[k]
	b.mu.Unlock()
	if !hasValue || val.Hash != hash {
		return nil
	}
	msg, err := p2p.NewMessage(Protocol, "DATA", k, b.ID, to, val)
	if err != nil {
		return err
	}
	return b.Transport.Send(ctx, to, msg)
}

func (b *Broadcaster) acceptValue(ctx context.Context, val ValueMessage) error {
	if val.Hash == "" || val.Value == nil || Digest(val.Value) != val.Hash {
		return nil
	}
	k := Instance(val.Dealer, val.Seq, val.Hash)
	var deliver Delivery
	var shouldDeliver bool
	b.mu.Lock()
	if _, ok := b.values[k]; !ok {
		b.values[k] = val
	}
	alreadyEcho := b.echoSent[k]
	b.echoSent[k] = true
	deliver, shouldDeliver = b.deliveryIfReadyLocked(k)
	b.mu.Unlock()

	if !alreadyEcho {
		if err := b.broadcastVote(ctx, "ECHO", val.Dealer, val.Seq, val.Hash); err != nil {
			return err
		}
	}
	if shouldDeliver {
		b.Deliveries <- deliver
	}
	return nil
}

func (b *Broadcaster) deliveryIfReadyLocked(k string) (Delivery, bool) {
	if b.delivered[k] || len(b.readies[k]) < 2*b.F+1 {
		return Delivery{}, false
	}
	val, ok := b.values[k]
	if !ok {
		return Delivery{}, false
	}
	b.delivered[k] = true
	return Delivery{Dealer: val.Dealer, Seq: val.Seq, Value: val.Value, Hash: val.Hash}, true
}

func (b *Broadcaster) broadcastVote(ctx context.Context, typ string, dealer p2p.NodeID, seq uint64, hash string) error {
	msg, err := p2p.NewMessage(Protocol, typ, Instance(dealer, seq, hash), b.ID, "", VoteMessage{Dealer: dealer, Seq: seq, Hash: hash})
	if err != nil {
		return err
	}
	return b.Transport.Broadcast(ctx, msg)
}

func (b *Broadcaster) observe(ctx context.Context, kind string, vote VoteMessage, from p2p.NodeID) {
	k := Instance(vote.Dealer, vote.Seq, vote.Hash)
	b.mu.Lock()
	if b.echoes[k] == nil {
		b.echoes[k] = make(map[p2p.NodeID]bool)
	}
	if b.readies[k] == nil {
		b.readies[k] = make(map[p2p.NodeID]bool)
	}
	if kind == "echo" {
		b.echoes[k][from] = true
	} else {
		b.readies[k][from] = true
	}
	echoCount := len(b.echoes[k])
	readyCount := len(b.readies[k])
	needReady := !b.readySent[k] && (echoCount >= 2*b.F+1 || readyCount >= b.F+1)
	if needReady {
		b.readySent[k] = true
	}
	_, hasValue := b.values[k]
	deliver, shouldDeliver := b.deliveryIfReadyLocked(k)
	needValue := !hasValue
	var fallback p2p.NodeID
	if needValue && readyCount >= 2*b.F+1 {
		if !b.requested[k][vote.Dealer] {
			fallback = vote.Dealer
		} else if kind == "ready" {
			fallback = from
		} else {
			for id := range b.readies[k] {
				if !b.requested[k][id] {
					fallback = id
					break
				}
			}
		}
	}
	b.mu.Unlock()

	if fallback != "" {
		_ = b.requestValue(ctx, vote.Dealer, vote.Seq, vote.Hash, fallback)
	}
	if needReady {
		_ = b.broadcastVote(ctx, "READY", vote.Dealer, vote.Seq, vote.Hash)
	}
	if shouldDeliver {
		b.Deliveries <- deliver
	}
}
