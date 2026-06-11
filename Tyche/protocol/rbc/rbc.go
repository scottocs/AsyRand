package rbc

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

const Protocol = "rbc"

type ValueMessage struct {
	Dealer p2p.NodeID `json:"dealer"`
	Seq    uint64     `json:"seq"`
	Value  []byte     `json:"value"`
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
	Deliveries chan Delivery
}

func New(id p2p.NodeID, n, f int, transport p2p.Transport) *Broadcaster {
	return &Broadcaster{
		ID: id, N: n, F: f, Transport: transport,
		values: make(map[string]ValueMessage), echoes: make(map[string]map[p2p.NodeID]bool),
		readies: make(map[string]map[p2p.NodeID]bool), echoSent: make(map[string]bool),
		readySent: make(map[string]bool), delivered: make(map[string]bool),
		Deliveries: make(chan Delivery, n*4),
	}
}

func Instance(dealer p2p.NodeID, seq uint64, hash string) string {
	return fmt.Sprintf("%s/%d/%s", dealer, seq, hash)
}

func parseInstance(instance string) (p2p.NodeID, uint64, bool) {
	last := strings.LastIndex(instance, "/")
	if last <= 0 {
		return "", 0, false
	}
	prev := strings.LastIndex(instance[:last], "/")
	if prev <= 0 {
		return "", 0, false
	}
	seq, err := strconv.ParseUint(instance[prev+1:last], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return p2p.NodeID(instance[:prev]), seq, true
}

func (b *Broadcaster) PruneThrough(consumed map[p2p.NodeID]uint64) {
	if len(consumed) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	shouldPrune := func(instance string) bool {
		dealer, seq, ok := parseInstance(instance)
		if !ok {
			return false
		}
		return seq <= consumed[dealer]
	}
	for instance := range b.values {
		if shouldPrune(instance) {
			delete(b.values, instance)
		}
	}
	for instance := range b.echoes {
		if shouldPrune(instance) {
			delete(b.echoes, instance)
		}
	}
	for instance := range b.readies {
		if shouldPrune(instance) {
			delete(b.readies, instance)
		}
	}
	for instance := range b.echoSent {
		if shouldPrune(instance) {
			delete(b.echoSent, instance)
		}
	}
	for instance := range b.readySent {
		if shouldPrune(instance) {
			delete(b.readySent, instance)
		}
	}
	for instance := range b.delivered {
		if shouldPrune(instance) {
			delete(b.delivered, instance)
		}
	}
}

func Digest(value []byte) string {
	return hex.EncodeToString(crypto.HashBytes(value))
}

func (b *Broadcaster) Broadcast(ctx context.Context, seq uint64, value []byte) error {
	hash := Digest(value)
	msg, err := p2p.NewMessage(Protocol, "VAL", Instance(b.ID, seq, hash), b.ID, "", ValueMessage{Dealer: b.ID, Seq: seq, Value: value, Hash: hash})
	if err != nil {
		return err
	}
	return b.Transport.Broadcast(ctx, msg)
}

func (b *Broadcaster) Handle(ctx context.Context, msg p2p.Message) error {
	switch msg.Type {
	case "VAL":
		val, err := p2p.DecodePayload[ValueMessage](msg)
		if err != nil {
			return err
		}
		if Digest(val.Value) != val.Hash {
			return nil
		}
		k := Instance(val.Dealer, val.Seq, val.Hash)
		var deliver Delivery
		var shouldDeliver bool
		b.mu.Lock()
		if _, ok := b.values[k]; !ok {
			b.values[k] = val
		}
		already := b.echoSent[k]
		b.echoSent[k] = true
		deliver, shouldDeliver = b.deliveryIfReadyLocked(k)
		b.mu.Unlock()
		if !already {
			if err := b.broadcastVote(ctx, "ECHO", val.Dealer, val.Seq, val.Hash); err != nil {
				return err
			}
		}
		if shouldDeliver {
			b.Deliveries <- deliver
		}
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
	deliver, shouldDeliver := b.deliveryIfReadyLocked(k)
	b.mu.Unlock()

	if needReady {
		_ = b.broadcastVote(ctx, "READY", vote.Dealer, vote.Seq, vote.Hash)
	}
	if shouldDeliver {
		b.Deliveries <- deliver
	}
}
