// Package rbc implements digest Bracha broadcast with transferable READY proofs.
// Application payloads must be validated before passing VAL/REPLY to Handle.
package rbc

import (
	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

const Protocol = "asyrand/rbc/v1"

type Signature struct {
	Signer    p2p.NodeID `json:"signer"`
	Signature string     `json:"signature"`
}
type Certificate struct {
	Context    string      `json:"context"`
	Dealer     p2p.NodeID  `json:"dealer"`
	Seq        uint64      `json:"seq"`
	Hash       string      `json:"hash"`
	Signatures []Signature `json:"signatures"`
}
type Packet struct {
	Context     string       `json:"context"`
	Dealer      p2p.NodeID   `json:"dealer"`
	Seq         uint64       `json:"seq"`
	Hash        string       `json:"hash"`
	Value       []byte       `json:"value,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	Signature   string       `json:"signature,omitempty"`
}
type Delivery struct {
	Dealer      p2p.NodeID
	Seq         uint64
	Hash        string
	Value       []byte
	Certificate Certificate
}
type Config struct {
	Verification  *verification.Cache
	Authenticated bool
	ID            p2p.NodeID
	F             int
	Members       []p2p.NodeID
	Context       string
	Private       ed25519.PrivateKey
	Public        map[string]ed25519.PublicKey
}
type valueState struct {
	value           []byte
	echoes, readies map[p2p.NodeID]string
	delivered       bool
	pending         bool
	attempts        uint64
	nextRequest     time.Time
}
type instance struct {
	values              map[string]*valueState
	echo, ready         string
	seenEcho, seenReady map[p2p.NodeID]string
}
type payloadKey struct {
	dealer p2p.NodeID
	seq    uint64
	hash   string
}
type Broadcaster struct {
	cfg     Config
	states  map[string]*instance
	missing map[*valueState]Packet
	pending map[payloadKey]bool
}

func New(cfg Config) *Broadcaster {
	cfg.Verification = verification.Select(cfg.Verification)
	return &Broadcaster{cfg: cfg, states: make(map[string]*instance), missing: make(map[*valueState]Packet), pending: make(map[payloadKey]bool)}
}
func Key(dealer p2p.NodeID, seq uint64) string { return fmt.Sprintf("%s/%d", dealer, seq) }
func Hash(value []byte) string                 { h := sha256.Sum256(value); return hex.EncodeToString(h[:]) }
func statement(typ string, from p2p.NodeID, p Packet) []byte {
	b, _ := json.Marshal(struct {
		Domain, Context, Type string
		From, Dealer          p2p.NodeID
		Seq                   uint64
		Hash                  string
	}{Protocol, p.Context, typ, from, p.Dealer, p.Seq, p.Hash})
	return b
}
func Authenticate(context string, public map[string]ed25519.PublicKey, msg p2p.Message, caches ...*verification.Cache) (Packet, bool) {
	p, err := p2p.DecodePayload[Packet](msg)
	pub := public[string(msg.From)]
	sig, err2 := hex.DecodeString(p.Signature)
	ok := err == nil && err2 == nil && len(pub) == 32 && msg.Protocol == Protocol && p.Context == context && p.Seq > 0 && public[string(p.Dealer)] != nil && msg.Instance == Key(p.Dealer, p.Seq) && len(p.Hash) == 64 && (p.Signature == "" && msg.Type != "READY" && msg.Authenticated() || p.Signature != "" && verification.Optional(caches...).Ed25519(pub, statement(msg.Type, msg.From, p), sig))
	if msg.Type == "VAL" {
		ok = ok && msg.From == p.Dealer
	}
	switch msg.Type {
	case "VAL", "REPLY":
		ok = ok && Hash(p.Value) == p.Hash
	case "ECHO", "READY", "REQUEST":
	default:
		ok = false
	}
	return p, ok
}
func VerifyCertificate(context string, public map[string]ed25519.PublicKey, f int, c Certificate, caches ...*verification.Cache) bool {
	if c.Context != context || c.Seq == 0 || public[string(c.Dealer)] == nil || len(c.Signatures) < len(public)-f || len(c.Signatures) > len(public) || len(c.Hash) != 64 {
		return false
	}
	p := Packet{Context: c.Context, Dealer: c.Dealer, Seq: c.Seq, Hash: c.Hash}
	for i, s := range c.Signatures {
		pub := public[string(s.Signer)]
		sig, err := hex.DecodeString(s.Signature)
		if (i > 0 && c.Signatures[i-1].Signer >= s.Signer) || err != nil || len(pub) != 32 || !verification.Optional(caches...).Ed25519(pub, statement("READY", s.Signer, p), sig) {
			return false
		}
	}
	return true
}
func (b *Broadcaster) message(typ string, to p2p.NodeID, p Packet) p2p.Message {
	p.Context = b.cfg.Context
	p.Signature = ""
	if typ == "READY" || !b.cfg.Authenticated {
		cryptoexec.WithCPUGroupFast(func() { p.Signature = hex.EncodeToString(ed25519.Sign(b.cfg.Private, statement(typ, b.cfg.ID, p))) })
	}
	m, _ := p2p.NewMessage(Protocol, typ, Key(p.Dealer, p.Seq), b.cfg.ID, to, p)
	return m
}
func (b *Broadcaster) Broadcast(seq uint64, value []byte) []p2p.Message {
	return []p2p.Message{b.message("VAL", "", Packet{Dealer: b.cfg.ID, Seq: seq, Hash: Hash(value), Value: value})}
}
func (b *Broadcaster) Request(dealer p2p.NodeID, seq uint64, hash string) p2p.Message {
	return b.message("REQUEST", "", Packet{Dealer: dealer, Seq: seq, Hash: hash})
}

// PayloadPending records receipt without admitting an unverified value or
// emitting ECHO. Verification in progress is not a missing network payload.
// Clearing a failed validation resumes retrieval if READY already requires it.
func (b *Broadcaster) PayloadPending(p Packet, pending bool) []p2p.Message {
	key := payloadKey{p.Dealer, p.Seq, p.Hash}
	if pending {
		b.pending[key] = true
	} else {
		delete(b.pending, key)
	}
	// An unverified VAL alone must not leave a permanent RBC/hash state.
	i := b.states[Key(p.Dealer, p.Seq)]
	if i == nil {
		return nil
	}
	v := i.values[p.Hash]
	if v == nil {
		return nil
	}
	v.pending = pending
	if pending {
		delete(b.missing, v)
	} else if i.ready == p.Hash && v.value == nil {
		return b.requestPayload(p, v, time.Now())
	}
	return nil
}

// RetryPayloads rotates through the full membership. Timers only retry data
// retrieval; they never supply a delivery or an agreement input. One holder at
// a time avoids n simultaneous full-payload replies to one missing value.
func (b *Broadcaster) RetryPayloads(now time.Time) []p2p.Message {
	var out []p2p.Message
	for v, p := range b.missing {
		if !v.pending && !now.Before(v.nextRequest) {
			out = append(out, b.requestPayload(p, v, now)...)
		}
	}
	return out
}

func (b *Broadcaster) requestPayload(p Packet, v *valueState, now time.Time) []p2p.Message {
	if len(b.cfg.Members) < 2 {
		return nil
	}
	local := 0
	for i, id := range b.cfg.Members {
		if id == b.cfg.ID {
			local = i
			break
		}
	}
	// Prefer an observed ECHO holder on the first try. Later tries cover every
	// member, including an honest holder when the first candidate is silent.
	var target p2p.NodeID
	for offset := 0; offset < len(b.cfg.Members); offset++ {
		id := b.cfg.Members[(local+1+int(v.attempts%uint64(len(b.cfg.Members)))+offset)%len(b.cfg.Members)]
		if id == b.cfg.ID {
			continue
		}
		if v.attempts == 0 {
			if _, ok := v.echoes[id]; !ok {
				continue
			}
		}
		target = id
		break
	}
	if target == "" {
		for _, id := range b.cfg.Members {
			if id != b.cfg.ID {
				target = id
				break
			}
		}
	}
	v.attempts++
	v.nextRequest = now.Add(time.Second)
	b.missing[v] = pVote(p)
	return []p2p.Message{b.message("REQUEST", target, pVote(p))}
}
func (b *Broadcaster) state(p Packet) (*instance, *valueState) {
	key := Key(p.Dealer, p.Seq)
	i := b.states[key]
	if i == nil {
		i = &instance{values: make(map[string]*valueState), seenEcho: make(map[p2p.NodeID]string), seenReady: make(map[p2p.NodeID]string)}
		b.states[key] = i
	}
	v := i.values[p.Hash]
	if v == nil {
		v = &valueState{echoes: make(map[p2p.NodeID]string), readies: make(map[p2p.NodeID]string), pending: b.pending[payloadKey{p.Dealer, p.Seq, p.Hash}]}
		i.values[p.Hash] = v
	}
	return i, v
}

// Admit avoids allocating a new hash state for equivocations or unsolicited
// payload replies. A full valid READY certificate can always recover a value.
func (b *Broadcaster) Admit(msg p2p.Message, p Packet) bool {
	i := b.states[Key(p.Dealer, p.Seq)]
	if i == nil {
		return msg.Type == "VAL" || msg.Type == "ECHO" || msg.Type == "READY" || (msg.Type == "REPLY" && p.Certificate != nil && VerifyCertificate(b.cfg.Context, b.cfg.Public, b.cfg.F, *p.Certificate, b.cfg.Verification))
	}
	switch msg.Type {
	case "VAL":
		return i.echo == "" || i.echo == p.Hash
	case "ECHO":
		old, ok := i.seenEcho[msg.From]
		return !ok || old == p.Hash
	case "READY":
		old, ok := i.seenReady[msg.From]
		return !ok || old == p.Hash
	case "REQUEST":
		return i.values[p.Hash] != nil
	case "REPLY":
		return i.values[p.Hash] != nil || (p.Certificate != nil && VerifyCertificate(b.cfg.Context, b.cfg.Public, b.cfg.F, *p.Certificate, b.cfg.Verification))
	}
	return false
}

// Handle counts at most one local ECHO and READY per dealer/sequence.
func (b *Broadcaster) Handle(msg p2p.Message, p Packet) ([]p2p.Message, []Delivery) {
	if !b.Admit(msg, p) {
		return nil, nil
	}
	i, v := b.state(p)
	var out []p2p.Message
	var deliveries []Delivery
	switch msg.Type {
	case "VAL", "REPLY":
		if v.value == nil {
			v.value = append([]byte(nil), p.Value...)
		}
		v.pending = false
		delete(b.pending, payloadKey{p.Dealer, p.Seq, p.Hash})
		delete(b.missing, v)
		if msg.Type == "VAL" && i.echo == "" {
			i.echo = p.Hash
			m := b.message("ECHO", "", pVote(p))
			x, _ := p2p.DecodePayload[Packet](m)
			v.echoes[b.cfg.ID] = x.Signature
			out = append(out, m)
		}
		if p.Certificate != nil && VerifyCertificate(b.cfg.Context, b.cfg.Public, b.cfg.F, *p.Certificate, b.cfg.Verification) && p.Certificate.Hash == p.Hash && p.Certificate.Dealer == p.Dealer && p.Certificate.Seq == p.Seq {
			for _, s := range p.Certificate.Signatures {
				v.readies[s.Signer] = s.Signature
			}
		}
	case "ECHO":
		if old, ok := i.seenEcho[msg.From]; !ok || old == p.Hash {
			i.seenEcho[msg.From] = p.Hash
			v.echoes[msg.From] = p.Signature
		}
	case "READY":
		if old, ok := i.seenReady[msg.From]; !ok || old == p.Hash {
			i.seenReady[msg.From] = p.Hash
			v.readies[msg.From] = p.Signature
		}
	case "REQUEST":
		if v.value != nil {
			reply := pVote(p)
			reply.Value = v.value
			if len(v.readies) >= len(b.cfg.Members)-b.cfg.F {
				c := b.certificate(p, v)
				reply.Certificate = &c
			}
			out = append(out, b.message("REPLY", msg.From, reply))
		}
		return out, nil
	}
	if i.ready == "" && (len(v.echoes) >= len(b.cfg.Members)-b.cfg.F || len(v.readies) >= b.cfg.F+1) {
		i.ready = p.Hash
		m := b.message("READY", "", pVote(p))
		x, _ := p2p.DecodePayload[Packet](m)
		v.readies[b.cfg.ID] = x.Signature
		out = append(out, m)
	}
	if i.ready == p.Hash && v.value == nil && !v.pending {
		if _, requested := b.missing[v]; !requested {
			out = append(out, b.requestPayload(p, v, time.Now())...)
		}
	}
	if !v.delivered && v.value != nil && len(v.readies) >= len(b.cfg.Members)-b.cfg.F {
		v.delivered = true
		deliveries = append(deliveries, Delivery{p.Dealer, p.Seq, p.Hash, v.value, b.certificate(p, v)})
	}
	return out, deliveries
}
func pVote(p Packet) Packet {
	return Packet{Context: p.Context, Dealer: p.Dealer, Seq: p.Seq, Hash: p.Hash}
}
func (b *Broadcaster) certificate(p Packet, v *valueState) Certificate {
	c := Certificate{Context: b.cfg.Context, Dealer: p.Dealer, Seq: p.Seq, Hash: p.Hash}
	for id, sig := range v.readies {
		c.Signatures = append(c.Signatures, Signature{id, sig})
	}
	sort.Slice(c.Signatures, func(i, j int) bool { return c.Signatures[i].Signer < c.Signatures[j].Signer })
	c.Signatures = c.Signatures[:len(b.cfg.Members)-b.cfg.F]
	return c
}
