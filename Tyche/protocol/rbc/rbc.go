package rbc

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

const Protocol = "rbc"

type ValueMessage struct {
	Value     []byte            `json:"value"`
	Hash      string            `json:"hash"`
	Signature crypto.SignedVote `json:"signature"`
}

type VoteMessage struct {
	Hash      string            `json:"hash"`
	Signature crypto.SignedVote `json:"signature"`
}

type DeliveryCertificate struct {
	ConfigVersion    uint64                         `json:"config_version"`
	Purpose          string                         `json:"purpose"`
	Instance         string                         `json:"instance"`
	Hash             string                         `json:"hash"`
	ReadyCertificate crypto.SignedQuorumCertificate `json:"ready_certificate,omitempty"`
	// ReadySenders is used only by the isolated unauthenticated test wrapper.
	ReadySenders []p2p.NodeID `json:"ready_senders,omitempty"`
}

type Delivery struct {
	ConfigVersion uint64
	Purpose       string
	Dealer        p2p.NodeID
	Seq           uint64
	Value         []byte
	Hash          string
	Certificate   DeliveryCertificate
}

type Broadcaster struct {
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

	mu         sync.Mutex
	values     map[string]ValueMessage
	echoes     map[string]map[p2p.NodeID]bool
	readies    map[string]map[p2p.NodeID]bool
	readyVotes map[string]map[p2p.NodeID]crypto.SignedVote
	echoSent   map[string]bool
	readySent  map[string]bool
	delivered  map[string]bool
	Deliveries chan Delivery
}

// New is retained for isolated legacy callers. Protocol code should use
// NewConfigured so messages are scoped to an immutable membership.
func New(id p2p.NodeID, n, f int, transport p2p.Transport) *Broadcaster {
	return newBroadcaster(id, 0, "legacy", nil, n, f, transport)
}

func NewConfigured(id p2p.NodeID, version uint64, purpose string, members []p2p.NodeID, f int, transport p2p.Transport) (*Broadcaster, error) {
	return newConfigured(id, version, purpose, members, f, transport, nil, nil)
}

func NewAuthenticated(id p2p.NodeID, version uint64, purpose string, members []p2p.NodeID, f int, transport p2p.Transport, private ed25519.PrivateKey, publicKeys map[string]ed25519.PublicKey) (*Broadcaster, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid RBC identity private key")
	}
	for _, member := range members {
		if len(publicKeys[string(member)]) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("missing RBC identity public key for %s", member)
		}
	}
	return newConfigured(id, version, purpose, members, f, transport, private, publicKeys)
}

func newConfigured(id p2p.NodeID, version uint64, purpose string, members []p2p.NodeID, f int, transport p2p.Transport, private ed25519.PrivateKey, publicKeys map[string]ed25519.PublicKey) (*Broadcaster, error) {
	if purpose == "" {
		return nil, fmt.Errorf("RBC purpose is required")
	}
	memberSet := make(map[p2p.NodeID]struct{}, len(members))
	for _, member := range members {
		if member == "" {
			return nil, fmt.Errorf("empty RBC member")
		}
		if _, duplicate := memberSet[member]; duplicate {
			return nil, fmt.Errorf("duplicate RBC member %s", member)
		}
		memberSet[member] = struct{}{}
	}
	if _, ok := memberSet[id]; !ok {
		return nil, fmt.Errorf("RBC node %s is not in configuration %d", id, version)
	}
	if f < 0 || len(members) < 3*f+1 {
		return nil, fmt.Errorf("invalid RBC fault bound n=%d f=%d", len(members), f)
	}
	b := newBroadcaster(id, version, purpose, memberSet, len(members), f, transport)
	if len(private) == ed25519.PrivateKeySize {
		b.PrivateKey = append(ed25519.PrivateKey(nil), private...)
		b.PublicKeys = make(map[string]ed25519.PublicKey, len(publicKeys))
		for signer, public := range publicKeys {
			b.PublicKeys[signer] = append(ed25519.PublicKey(nil), public...)
		}
		b.Authenticated = true
	}
	return b, nil
}

func newBroadcaster(id p2p.NodeID, version uint64, purpose string, members map[p2p.NodeID]struct{}, n, f int, transport p2p.Transport) *Broadcaster {
	return &Broadcaster{
		ID: id, N: n, F: f, Transport: transport, Version: version, Purpose: purpose, Members: members,
		values: make(map[string]ValueMessage), echoes: make(map[string]map[p2p.NodeID]bool),
		readies: make(map[string]map[p2p.NodeID]bool), echoSent: make(map[string]bool),
		readyVotes: make(map[string]map[p2p.NodeID]crypto.SignedVote),
		readySent:  make(map[string]bool), delivered: make(map[string]bool),
		Deliveries: make(chan Delivery, n*4),
	}
}

// Instance is fixed before the dealer chooses a value. The variadic argument
// is ignored for source compatibility with the former hash-scoped API.
func Instance(dealer p2p.NodeID, seq uint64, _ ...string) string {
	return fmt.Sprintf("rbc/legacy/%s/%d", dealer, seq)
}

func InstanceFor(version uint64, purpose string, dealer p2p.NodeID, seq uint64) string {
	return fmt.Sprintf("rbc/%d/%s/%s/%d", version, purpose, dealer, seq)
}

func parseInstance(instance string) (uint64, string, p2p.NodeID, uint64, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) == 4 && parts[0] == "rbc" && parts[1] == "legacy" && parts[2] != "" {
		seq, err := strconv.ParseUint(parts[3], 10, 64)
		return 0, "legacy", p2p.NodeID(parts[2]), seq, err == nil
	}
	if len(parts) != 5 || parts[0] != "rbc" || parts[2] == "" || parts[3] == "" {
		return 0, "", "", 0, false
	}
	version, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, "", "", 0, false
	}
	seq, err := strconv.ParseUint(parts[4], 10, 64)
	return version, parts[2], p2p.NodeID(parts[3]), seq, err == nil
}

func ConfigVersionFromInstance(instance string) (uint64, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) < 3 || parts[0] != "rbc" || parts[1] == "legacy" {
		return 0, false
	}
	version, err := strconv.ParseUint(parts[1], 10, 64)
	return version, err == nil
}

func PurposeFromInstance(instance string) (string, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) != 5 || parts[0] != "rbc" || parts[1] == "legacy" || parts[2] == "" {
		return "", false
	}
	return parts[2], true
}

func (b *Broadcaster) instance(dealer p2p.NodeID, seq uint64) string {
	if b.Purpose == "legacy" {
		return Instance(dealer, seq)
	}
	return InstanceFor(b.Version, b.Purpose, dealer, seq)
}

func voteBucket(instance, hash string) string {
	return instance + "/value/" + hash
}

func (b *Broadcaster) acceptsSender(id p2p.NodeID) bool {
	if b.Members == nil {
		return id != ""
	}
	_, ok := b.Members[id]
	return ok
}

func (b *Broadcaster) PruneThrough(consumed map[p2p.NodeID]uint64) {
	if len(consumed) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	shouldPrune := func(instance string) bool {
		version, purpose, dealer, seq, ok := parseInstance(instance)
		if !ok {
			return false
		}
		return version == b.Version && purpose == b.Purpose && seq <= consumed[dealer]
	}
	pruned := make(map[string]bool)
	for instance := range b.values {
		pruned[instance] = shouldPrune(instance)
	}
	for instance := range b.values {
		if pruned[instance] {
			delete(b.values, instance)
		}
	}
	for instance := range b.echoes {
		meta := b.instancesByBucketLocked(instance)
		if pruned[instance] || pruned[meta] {
			delete(b.echoes, instance)
		}
	}
	for instance := range b.readies {
		meta := b.instancesByBucketLocked(instance)
		if pruned[instance] || pruned[meta] {
			delete(b.readies, instance)
		}
	}
	for instance := range b.readyVotes {
		meta := b.instancesByBucketLocked(instance)
		if pruned[instance] || pruned[meta] {
			delete(b.readyVotes, instance)
		}
	}
	for instance := range b.echoSent {
		if pruned[instance] {
			delete(b.echoSent, instance)
		}
	}
	for instance := range b.readySent {
		if pruned[instance] {
			delete(b.readySent, instance)
		}
	}
	for instance := range b.delivered {
		if pruned[instance] {
			delete(b.delivered, instance)
		}
	}
}

func (b *Broadcaster) instancesByBucketLocked(bucket string) string {
	if _, ok := b.values[bucket]; ok {
		return bucket
	}
	if index := strings.LastIndex(bucket, "/value/"); index > 0 {
		return bucket[:index]
	}
	return ""
}

func Digest(value []byte) string {
	return hex.EncodeToString(crypto.HashBytes(value))
}

func (b *Broadcaster) Broadcast(ctx context.Context, seq uint64, value []byte) error {
	hash := Digest(value)
	instance := b.instance(b.ID, seq)
	body := ValueMessage{Value: value, Hash: hash}
	var err error
	if b.Authenticated {
		body.Signature, err = crypto.SignTranscript(string(b.ID), b.PrivateKey, b.transcript("VAL", instance, hash))
		if err != nil {
			return err
		}
	}
	msg, err := p2p.NewMessage(Protocol, "VAL", instance, b.ID, "", body)
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
		_, _, dealer, seq, valid := b.validMetadata(msg.Instance)
		if !valid || msg.From != dealer || !b.acceptsSender(msg.From) || Digest(val.Value) != val.Hash ||
			!b.verifyMessageSignature("VAL", msg.Instance, val.Hash, msg.From, val.Signature) {
			return nil
		}
		k := b.instance(dealer, seq)
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
			if err := b.broadcastVote(ctx, "ECHO", dealer, seq, val.Hash); err != nil {
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
		if b.acceptsSender(msg.From) {
			b.observe(ctx, "echo", vote, msg.From, msg.Instance)
		}
	case "READY":
		vote, err := p2p.DecodePayload[VoteMessage](msg)
		if err != nil {
			return err
		}
		if b.acceptsSender(msg.From) {
			b.observe(ctx, "ready", vote, msg.From, msg.Instance)
		}
	}
	return nil
}

func (b *Broadcaster) deliveryIfReadyLocked(k string) (Delivery, bool) {
	val, ok := b.values[k]
	if !ok {
		return Delivery{}, false
	}
	bucket := voteBucket(k, val.Hash)
	if b.delivered[k] || len(b.readies[bucket]) < b.quorum() {
		return Delivery{}, false
	}
	senders := make([]p2p.NodeID, 0, len(b.readies[bucket]))
	for sender := range b.readies[bucket] {
		senders = append(senders, sender)
	}
	sort.Slice(senders, func(i, j int) bool { return senders[i] < senders[j] })
	if len(senders) > b.quorum() {
		senders = senders[:b.quorum()]
	}
	readyVotes := make([]crypto.SignedVote, 0, len(senders))
	if b.Authenticated {
		for _, sender := range senders {
			readyVotes = append(readyVotes, b.readyVotes[bucket][sender])
		}
	}
	cert := DeliveryCertificate{
		ConfigVersion: b.Version,
		Purpose:       b.Purpose,
		Instance:      k,
		Hash:          val.Hash,
	}
	if b.Authenticated {
		// READY signatures were checked in observe before entering
		// readyVotes, so compact them without verifying the same Ed25519
		// signatures a second time on the delivery hot path.
		readyCertificate, err := crypto.EncodeVerifiedSignedQuorumCertificate(
			readyVotes,
			b.PublicKeys,
			b.quorum(),
		)
		if err != nil {
			return Delivery{}, false
		}
		cert.ReadyCertificate = readyCertificate
	} else {
		cert.ReadySenders = append([]p2p.NodeID(nil), senders...)
	}
	b.delivered[k] = true
	_, _, dealer, seq, ok := parseInstance(k)
	if !ok {
		return Delivery{}, false
	}
	return Delivery{
		ConfigVersion: b.Version,
		Purpose:       b.Purpose,
		Dealer:        dealer,
		Seq:           seq,
		Value:         val.Value,
		Hash:          val.Hash,
		Certificate:   cert,
	}, true
}

func (b *Broadcaster) broadcastVote(ctx context.Context, typ string, dealer p2p.NodeID, seq uint64, hash string) error {
	instance := b.instance(dealer, seq)
	body := VoteMessage{Hash: hash}
	var err error
	if b.Authenticated {
		body.Signature, err = crypto.SignTranscript(string(b.ID), b.PrivateKey, b.transcript(typ, instance, hash))
		if err != nil {
			return err
		}
	}
	msg, err := p2p.NewMessage(Protocol, typ, instance, b.ID, "", body)
	if err != nil {
		return err
	}
	return b.Transport.Broadcast(ctx, msg)
}

func (b *Broadcaster) observe(ctx context.Context, kind string, vote VoteMessage, from p2p.NodeID, wireInstance string) {
	_, _, dealer, seq, valid := b.validMetadata(wireInstance)
	if !valid {
		return
	}
	if !b.verifyMessageSignature(strings.ToUpper(kind), wireInstance, vote.Hash, from, vote.Signature) {
		return
	}
	k := b.instance(dealer, seq)
	bucket := voteBucket(k, vote.Hash)
	b.mu.Lock()
	if b.echoes[bucket] == nil {
		b.echoes[bucket] = make(map[p2p.NodeID]bool)
	}
	if b.readies[bucket] == nil {
		b.readies[bucket] = make(map[p2p.NodeID]bool)
	}
	if kind == "echo" {
		b.echoes[bucket][from] = true
	} else {
		b.readies[bucket][from] = true
		if b.Authenticated {
			if b.readyVotes[bucket] == nil {
				b.readyVotes[bucket] = make(map[p2p.NodeID]crypto.SignedVote)
			}
			b.readyVotes[bucket][from] = vote.Signature
		}
	}
	echoCount := len(b.echoes[bucket])
	readyCount := len(b.readies[bucket])
	needReady := !b.readySent[k] && (echoCount >= b.quorum() || readyCount >= b.F+1)
	if needReady {
		b.readySent[k] = true
	}
	deliver, shouldDeliver := b.deliveryIfReadyLocked(k)
	b.mu.Unlock()

	if needReady {
		_ = b.broadcastVote(ctx, "READY", dealer, seq, vote.Hash)
	}
	if shouldDeliver {
		b.Deliveries <- deliver
	}
}

func (b *Broadcaster) quorum() int {
	return b.N - b.F
}

func (b *Broadcaster) validMetadata(wireInstance string) (uint64, string, p2p.NodeID, uint64, bool) {
	version, purpose, dealer, seq, ok := parseInstance(wireInstance)
	if !ok || version != b.Version || purpose != b.Purpose || wireInstance != b.instance(dealer, seq) {
		return 0, "", "", 0, false
	}
	return version, purpose, dealer, seq, true
}

func (b *Broadcaster) VerifyDeliveryCertificate(cert DeliveryCertificate) error {
	if cert.ConfigVersion != b.Version || cert.Purpose != b.Purpose {
		return fmt.Errorf("RBC delivery certificate configuration mismatch")
	}
	if cert.Instance == "" || cert.Hash == "" {
		return fmt.Errorf("RBC delivery certificate is incomplete")
	}
	parts := strings.Split(cert.Instance, "/")
	if len(parts) != 5 || parts[0] != "rbc" || parts[1] != strconv.FormatUint(b.Version, 10) ||
		parts[2] != b.Purpose {
		return fmt.Errorf("RBC delivery certificate instance mismatch")
	}
	compact := len(cert.ReadyCertificate.SignerBitmap) > 0 || len(cert.ReadyCertificate.Signatures) > 0
	if b.Authenticated && compact {
		if len(cert.ReadySenders) != 0 {
			return fmt.Errorf("compact RBC delivery certificate contains legacy READY fields")
		}
		if err := crypto.VerifySignedQuorumCertificate(
			cert.ReadyCertificate,
			b.PublicKeys,
			b.quorum(),
			b.transcript("READY", cert.Instance, cert.Hash),
		); err != nil {
			return fmt.Errorf("invalid compact RBC READY certificate: %w", err)
		}
		return nil
	}

	if len(cert.ReadySenders) < b.quorum() {
		return fmt.Errorf("RBC delivery certificate below quorum")
	}
	seen := make(map[p2p.NodeID]struct{}, len(cert.ReadySenders))
	for _, sender := range cert.ReadySenders {
		if !b.acceptsSender(sender) {
			return fmt.Errorf("unknown RBC READY sender %s", sender)
		}
		if _, duplicate := seen[sender]; duplicate {
			return fmt.Errorf("duplicate RBC READY sender %s", sender)
		}
		seen[sender] = struct{}{}
	}
	if b.Authenticated {
		return fmt.Errorf("authenticated RBC certificate requires compact READY signatures")
	}
	return nil
}

func (b *Broadcaster) transcript(kind, instance, hash string) []byte {
	return messageTranscript(b.Version, b.Purpose, kind, instance, hash)
}

func messageTranscript(version uint64, purpose, kind, instance, hash string) []byte {
	return crypto.DomainHash(
		"Tyche/RBCMessage/v1",
		[]byte(fmt.Sprintf("%d", version)),
		[]byte(purpose),
		[]byte(kind),
		[]byte(instance),
		[]byte(hash),
	)
}

func (b *Broadcaster) verifyMessageSignature(kind, instance, hash string, sender p2p.NodeID, signature crypto.SignedVote) bool {
	if !b.Authenticated {
		return true
	}
	if signature.Signer != string(sender) {
		return false
	}
	return crypto.VerifySignedVote(signature, b.PublicKeys, b.transcript(kind, instance, hash)) == nil
}
