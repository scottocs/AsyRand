package tyche

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/Tyche/protocol/rbc"
	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

const Protocol = "tyche"

var pvssOpMu sync.Mutex

type Object struct {
	ConfigVersion uint64            `json:"config_version"`
	Producer      p2p.NodeID        `json:"producer"`
	Seq           uint64            `json:"seq"`
	Commitment    crypto.Commitment `json:"commitment"`
}

type CertifiedObject struct {
	Object      Object                  `json:"object"`
	Certificate rbc.DeliveryCertificate `json:"rbc_certificate"`
}

type Beacon struct {
	BeaconQC `json:"certificate"`
	Skipped  []SkippedTuple `json:"skipped,omitempty"`
}

type Config struct {
	ID                 p2p.NodeID
	Members            []p2p.NodeID
	F                  int
	QueueLen           int
	ProducerLow        int
	ProducerHigh       int
	ConfigVersion      uint64
	InitialRandom      []byte
	PVSS               crypto.PVSSScheme
	PVSSParams         crypto.PVSSParams
	PVSSBackend        string
	PVSSKeys           map[string]kyber.Scalar
	IdentityPrivate    ed25519.PrivateKey
	IdentityPublicKeys map[p2p.NodeID]ed25519.PublicKey
	// InsecureDeterministicIdentity is only for tests and reproducible
	// benchmarks. Production configurations must provide identity keys.
	InsecureDeterministicIdentity bool
	CryptoWorkers                 int
	Transport                     p2p.Transport
	// Store must be durable in production. Tests and explicitly insecure
	// experiments may omit it and receive an in-memory store.
	Store StateStore
}

type State struct {
	ConfigVersion uint64
	Members       []p2p.NodeID
	F             int
	Epoch         uint64
	RPrev         []byte
	SCL           []p2p.NodeID
	RSQ           []p2p.NodeID
	ComQ          map[p2p.NodeID]map[uint64]CertifiedObject
	Seqs          map[p2p.NodeID]uint64
	// PendingABAs is exactly the set of tuple ABA identifiers in coin-wait.
	PendingABAs map[string]struct{}
	// ABADecisions retains transferable decisions until their successor tuple
	// has been consumed or certified as skipped.
	ABADecisions map[string]aba.Decision
	QueueLen     int
	ProducerSeq  uint64
}

type SkippedTuple struct {
	Source      p2p.NodeID      `json:"source"`
	Seq         uint64          `json:"seq"`
	Certificate aba.Certificate `json:"certificate"`
}

type envelope struct {
	Kind   string  `json:"kind"`
	Object *Object `json:"object,omitempty"`
}

type ReconMessage struct {
	ObjectConfigVersion uint64                `json:"object_config_version"`
	Share               crypto.DecryptedShare `json:"share"`
}

type reconScope struct {
	ConfigVersion uint64
	Epoch         uint64
	ParentHash    string
	Source        p2p.NodeID
	Seq           uint64
}

type pendingReconBucket struct {
	ConfigVersion       uint64
	ObjectConfigVersion uint64
	Epoch               uint64
	Source              p2p.NodeID
	Seq                 uint64
	Messages            map[p2p.NodeID]pendingReconMessage
}

type pendingReconMessage struct {
	Instance string
	Body     ReconMessage
}

type signedBeaconMessage struct {
	ConfigVersion uint64            `json:"config_version"`
	Epoch         uint64            `json:"epoch"`
	ParentHash    string            `json:"parent_hash"`
	SkippedHash   string            `json:"skipped_hash"`
	Source        p2p.NodeID        `json:"source"`
	Seq           uint64            `json:"seq"`
	Random        []byte            `json:"random"`
	Signature     crypto.SignedVote `json:"signature"`
}

type certifiedABADecision struct {
	Certificate aba.Certificate `json:"certificate"`
}

type certifiedBeaconRecord struct {
	QC      BeaconQC       `json:"qc"`
	Skipped []SkippedTuple `json:"skipped,omitempty"`
}

// epochAttempt is the immutable Step-0 context for one opened Consumer
// epoch. A membership certificate may be delivered before its P_e, so all
// reconstruction and beacon votes remain bound to this captured parent and
// signing configuration rather than the receiver's instantaneous membership.
type epochAttempt struct {
	ConfigVersion uint64
	Epoch         uint64
	ParentHash    string
	Source        p2p.NodeID
	Seq           uint64
	PrevRandom    []byte
	Skipped       []SkippedTuple
}

var errRestartEpoch = errors.New("epoch control state changed; restart Step 0")
var errPriorDecisionPending = errors.New("prior tuple ABA decision is not yet available")

type Node struct {
	ID                 p2p.NodeID
	Transport          p2p.Transport
	PVSS               crypto.PVSSScheme
	Perf               *PerfMetrics
	RBC                *rbc.Broadcaster
	ABA                *aba.Agreement
	engineStarted      bool
	protocolContext    context.Context
	Crypto             *cryptoexec.Executor
	Configuration      Configuration
	Schedule           SchedulingState
	LatestBeaconQC     *BeaconQC
	HistoryAnchor      SchedulingState
	BeaconHistory      []BeaconHistoryLink
	IdentityPrivate    ed25519.PrivateKey
	allowInsecureSetup bool
	PVSSContext        *PVSSContext
	Store              StateStore

	mu                sync.Mutex
	State             *State
	recon             map[string]map[p2p.NodeID]crypto.DecryptedShare
	reconDone         map[string]bool
	reconClosing      map[string]bool
	pendingRecon      map[string]*pendingReconBucket
	pendingReconCount int
	beaconVotes       map[string]map[p2p.NodeID]crypto.SignedVote
	beaconVoteSent    map[string]bool
	reconSent         map[string]bool
	certified         map[string]bool
	pendingABACerts   map[string]aba.Decision
	abaCertRelayed    map[string]bool
	beaconCertRelayed map[string]bool
	epochAttempts     map[string]epochAttempt
	abaInputSent      map[string]bool
	abaInputs         map[string]bool
	pvssKeys          map[string]kyber.Scalar
	pvssBackend       string
	beaconSeeds       map[uint64][]byte
	verified          map[string]*verifiedObject
	verifiedShares    map[string]*verifiedShare
	producerBusy      map[uint64]bool
	producerLow       int
	producerHigh      int
	producing         bool
	waiters           map[string][]chan Beacon
	certBeacons       map[string]Beacon
	certifying        map[string]bool

	Beacons chan Beacon
}

type verifiedObject struct {
	version  uint64
	producer p2p.NodeID
	seq      uint64
	ready    chan struct{}
	valid    bool
}

type verifiedShare struct {
	version  uint64
	producer p2p.NodeID
	seq      uint64
	ready    chan struct{}
	valid    bool
}

type DebugSnapshot struct {
	Node          p2p.NodeID
	Completed     uint64
	NextEpoch     uint64
	ConfigVersion uint64
	Source        p2p.NodeID
	Seq           uint64
	Instance      string
	Object        bool
	NextObject    bool
	ReconSent     bool
	ReconDone     bool
	ReconCount    int
	ReconNeed     int
	BeaconVotes   int
	Certifying    bool
	Certified     bool
	Waiters       int
	PendingABAs   int
	ABAInputSent  bool
	ABAInput      bool
	ABADecided    bool
	ABACoinWait   bool
	ABARound      uint64
	ABAInputs     int
	ABAInputTrue  int
	ABAInputFalse int
	ABAFinish     int
	ABABValTrue   int
	ABABValFalse  int
	ABABinTrue    bool
	ABABinFalse   bool
	ABAAux        int
	ABAConf       int
	VerifiedCache int
	CryptoWorkers int
	CryptoActive  int64
	CryptoQueued  int64
}

func NewNode(cfg Config) (*Node, error) {
	if cfg.ID == "" || cfg.Transport == nil || cfg.PVSS == nil {
		return nil, errors.New("tyche node requires id, transport, and pvss")
	}
	members := normalizeMembers(cfg.Members)
	if len(members) == 0 {
		return nil, errors.New("tyche node requires members")
	}
	f := cfg.F
	if f == 0 {
		f = (len(members) - 1) / 3
	}
	queueLen := cfg.QueueLen
	if queueLen <= 0 {
		queueLen = 8
	}
	if queueLen < 2 {
		return nil, errors.New("Tyche requires queue length at least 2 for look-ahead ABA")
	}
	low, high := cfg.ProducerLow, cfg.ProducerHigh
	if high <= 0 {
		high = 4
	}
	if high <= 0 || high > queueLen {
		high = queueLen
	}
	if low <= 0 {
		low = 2
	}
	if low > high {
		low = high
	}
	if low <= 0 {
		low = 1
	}
	pvssBackend := cfg.PVSSBackend
	if pvssBackend == "" {
		pvssBackend = crypto.PVSSO1
	}
	seed := append([]byte(nil), cfg.InitialRandom...)
	if len(seed) == 0 {
		seed = crypto.HashBytes([]byte("Tyche-v1/genesis"), []byte(fmt.Sprint(members)))
	}
	st := &State{
		ConfigVersion: cfg.ConfigVersion,
		Members:       members,
		F:             f,
		RPrev:         seed,
		SCL:           append([]p2p.NodeID(nil), members...),
		RSQ:           make([]p2p.NodeID, 0, 2*f),
		ComQ:          make(map[p2p.NodeID]map[uint64]CertifiedObject),
		Seqs:          make(map[p2p.NodeID]uint64),
		PendingABAs:   make(map[string]struct{}),
		ABADecisions:  make(map[string]aba.Decision),
		QueueLen:      queueLen,
	}
	for _, id := range members {
		st.ComQ[id] = make(map[uint64]CertifiedObject)
	}
	params := cfg.PVSSParams
	if params.Epoch() == "" {
		var err error
		params, err = crypto.ParamsOf(cfg.PVSS)
		if err != nil {
			return nil, err
		}
	}
	identityPrivate, identityPublic, err := resolveIdentityConfiguration(cfg, members)
	if err != nil {
		return nil, err
	}
	configuration, err := NewConfiguration(cfg.ConfigVersion, members, f, params, identityPublic)
	if err != nil {
		return nil, err
	}
	var rbcEngine *rbc.Broadcaster
	var abaEngine *aba.Agreement
	if !configuration.Contains(cfg.ID) {
		return nil, fmt.Errorf("node %s is not a member of the fixed party set", cfg.ID)
	}
	rbcEngine, err = rbc.NewAuthenticated(cfg.ID, cfg.ConfigVersion, "pvss", members, f, cfg.Transport, identityPrivate, configuration.PublicKeys())
	if err != nil {
		return nil, err
	}
	abaEngine, err = aba.NewAuthenticated(cfg.ID, cfg.ConfigVersion, "control", members, f, cfg.Transport, identityPrivate, configuration.PublicKeys())
	if err != nil {
		return nil, err
	}
	schedule := schedulingStateFromRuntime(st, configuration)
	n := &Node{
		ID: cfg.ID, Transport: cfg.Transport, PVSS: cfg.PVSS, Perf: &PerfMetrics{},
		RBC:                rbcEngine,
		ABA:                abaEngine,
		Crypto:             cryptoexec.New(cfg.CryptoWorkers),
		State:              st,
		Configuration:      configuration,
		Schedule:           schedule,
		HistoryAnchor:      CloneSchedulingState(schedule),
		IdentityPrivate:    append(ed25519.PrivateKey(nil), identityPrivate...),
		allowInsecureSetup: cfg.InsecureDeterministicIdentity,
		PVSSContext: &PVSSContext{
			Configuration: configuration,
			Params:        params,
			Scheme:        cfg.PVSS,
		},
		Store: cfg.Store,
		recon: make(map[string]map[p2p.NodeID]crypto.DecryptedShare), reconDone: make(map[string]bool), reconClosing: make(map[string]bool),
		pendingRecon:   make(map[string]*pendingReconBucket),
		beaconVotes:    make(map[string]map[p2p.NodeID]crypto.SignedVote),
		beaconVoteSent: make(map[string]bool), reconSent: make(map[string]bool), certified: make(map[string]bool),
		pendingABACerts:   make(map[string]aba.Decision),
		abaCertRelayed:    make(map[string]bool),
		beaconCertRelayed: make(map[string]bool),
		epochAttempts:     make(map[string]epochAttempt),
		abaInputSent:      make(map[string]bool),
		abaInputs:         make(map[string]bool),
		beaconSeeds:       make(map[uint64][]byte),
		verified:          make(map[string]*verifiedObject),
		verifiedShares:    make(map[string]*verifiedShare),
		producerBusy:      make(map[uint64]bool),
		pvssKeys:          make(map[string]kyber.Scalar),
		pvssBackend:       pvssBackend,
		producerLow:       low,
		producerHigh:      high,
		producing:         true,
		waiters:           make(map[string][]chan Beacon),
		certBeacons:       make(map[string]Beacon),
		certifying:        make(map[string]bool),
		Beacons:           make(chan Beacon, len(members)*4),
	}
	for epoch, key := range cfg.PVSSKeys {
		if key != nil {
			n.pvssKeys[epoch] = key.Clone()
		}
	}
	if epoch := cfg.PVSS.Epoch(); epoch != "" && cfg.PVSS.PrivateKey() != nil {
		n.pvssKeys[epoch] = cfg.PVSS.PrivateKey()
	}
	if n.Store == nil {
		n.Store = NewMemoryStateStore()
	}
	if err := n.restorePersistentState(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	if err := n.persistLocked(); err != nil {
		n.mu.Unlock()
		return nil, err
	}
	n.mu.Unlock()
	return n, nil
}

func (n *Node) Start(ctx context.Context) {
	n.mu.Lock()
	n.protocolContext = ctx
	n.startProtocolEngineCollectorsLocked(ctx)
	n.mu.Unlock()
	abaInbox := make(chan p2p.Message, protocolQueueSize(len(n.State.Members), 4))
	controlInbox := make(chan p2p.Message, protocolQueueSize(len(n.State.Members), 2))
	rbcInbox := make(chan p2p.Message, protocolQueueSize(len(n.State.Members), 8))
	startMessageWorkers(ctx, abaInbox, 4, func(msg p2p.Message) {
		_ = n.handleABAMessage(ctx, msg)
	})
	startMessageWorkers(ctx, controlInbox, 4, func(msg p2p.Message) {
		_ = n.handleTyche(ctx, msg)
	})
	startMessageWorkers(ctx, rbcInbox, 4, func(msg p2p.Message) {
		_ = n.handleRBCMessage(ctx, msg)
	})
	go func() {
		for {
			select {
			case msg, ok := <-n.Transport.Inbox():
				if !ok {
					return
				}
				switch msg.Protocol {
				case aba.Protocol:
					enqueueProtocolMessage(ctx, abaInbox, msg)
				case Protocol:
					enqueueProtocolMessage(ctx, controlInbox, msg)
				case rbc.Protocol:
					enqueueProtocolMessage(ctx, rbcInbox, msg)
				default:
					_ = n.Handle(ctx, msg)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (n *Node) startProtocolEngineCollectorsLocked(ctx context.Context) {
	if n.engineStarted {
		return
	}
	rbcEngine := n.RBC
	abaEngine := n.ABA
	if rbcEngine == nil || abaEngine == nil {
		return
	}
	n.engineStarted = true
	go func() {
		for {
			select {
			case delivery := <-rbcEngine.Deliveries:
				if err := n.handleRBCDelivery(ctx, delivery); err != nil {
					debugf("node=%s reject RBC delivery config=%d dealer=%s seq=%d err=%v", n.ID, delivery.ConfigVersion, delivery.Dealer, delivery.Seq, err)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case decision := <-abaEngine.Decisions:
				n.handleABADecision(ctx, decision)
			case request := <-abaEngine.CoinRequests:
				n.handleCoinRequest(request)
			case <-ctx.Done():
				return
			}
		}
	}()
}

func protocolQueueSize(n int, factor int) int {
	size := n * n * factor
	if size < 1024 {
		return 1024
	}
	if size > 262144 {
		return 262144
	}
	return size
}

func startMessageWorkers(ctx context.Context, inbox <-chan p2p.Message, workers int, handle func(p2p.Message)) {
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case msg := <-inbox:
					handle(msg)
				case <-ctx.Done():
					return
				}
			}
		}()
	}
}

func enqueueProtocolMessage(ctx context.Context, inbox chan<- p2p.Message, msg p2p.Message) {
	select {
	case inbox <- msg:
	case <-ctx.Done():
	}
}

func (n *Node) Handle(ctx context.Context, msg p2p.Message) error {
	switch msg.Protocol {
	case rbc.Protocol:
		return n.handleRBCMessage(ctx, msg)
	case aba.Protocol:
		return n.handleABAMessage(ctx, msg)
	case Protocol:
		return n.handleTyche(ctx, msg)
	default:
		return nil
	}
}

func (n *Node) handleRBCMessage(ctx context.Context, msg p2p.Message) error {
	purpose, ok := rbc.PurposeFromInstance(msg.Instance)
	if !ok || purpose != "pvss" {
		return nil
	}
	engine := n.RBC
	if engine == nil {
		return nil
	}
	start := time.Now()
	err := engine.Handle(ctx, msg)
	if n.Perf != nil {
		n.Perf.addRBCHandle(time.Since(start))
	}
	return err
}

func (n *Node) handleABAMessage(ctx context.Context, msg p2p.Message) error {
	engine := n.ABA
	if engine == nil {
		return nil
	}
	start := time.Now()
	err := engine.Handle(ctx, msg)
	if n.Perf != nil {
		n.Perf.addABAHandle(time.Since(start))
	}
	return err
}

func (n *Node) Produce(ctx context.Context) (Object, error) {
	n.mu.Lock()
	if !n.producing || n.RBC == nil || !contains(n.State.Members, n.ID) {
		n.mu.Unlock()
		return Object{}, errors.New("local node is not an active producer in the certified configuration")
	}
	if n.producerOccupancyLocked() >= n.producerHigh {
		n.mu.Unlock()
		return Object{}, errors.New("local producer high watermark reached")
	}
	n.State.ProducerSeq++
	seq := n.State.ProducerSeq
	version := n.State.ConfigVersion
	n.producerBusy[seq] = true
	if err := n.persistLocked(); err != nil {
		delete(n.producerBusy, seq)
		n.State.ProducerSeq--
		n.mu.Unlock()
		return Object{}, err
	}
	n.mu.Unlock()
	obj, err := n.produceSeq(ctx, seq, version)
	n.finishProducerSeq(seq)
	if err != nil {
		n.rollbackProducerSeq(seq)
		return Object{}, err
	}
	return obj, nil
}

func (n *Node) SetProducing(enabled bool) {
	n.mu.Lock()
	n.producing = enabled
	n.mu.Unlock()
}

func (n *Node) IsProducing() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.producing
}

func (n *Node) EnsureCurrentObject(ctx context.Context) (uint64, error) {
	n.mu.Lock()
	if !n.producing || n.RBC == nil || !contains(n.State.Members, n.ID) {
		n.mu.Unlock()
		return 0, errors.New("local node is not an active producer in the certified configuration")
	}
	seq := n.State.Seqs[n.ID] + 1
	version := n.State.ConfigVersion
	if entry, ok := n.State.ComQ[n.ID][seq]; ok && entry.Object.ConfigVersion == version {
		n.mu.Unlock()
		return seq, nil
	}
	if !n.producerBusy[seq] {
		if n.State.ProducerSeq < seq {
			n.State.ProducerSeq = seq
		}
		n.producerBusy[seq] = true
		if err := n.persistLocked(); err != nil {
			delete(n.producerBusy, seq)
			n.mu.Unlock()
			return seq, err
		}
		n.mu.Unlock()
		_, err := n.produceSeq(ctx, seq, version)
		if err != nil {
			n.finishProducerSeq(seq)
			n.rollbackProducerSeq(seq)
			return seq, err
		}
		// Queue insertion is performed only by the authenticated RBC delivery
		// handler; do not bypass delivery by storing the dealer's local value.
	} else {
		n.mu.Unlock()
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		n.mu.Lock()
		entry, ok := n.State.ComQ[n.ID][seq]
		currentVersion := n.State.ConfigVersion
		n.mu.Unlock()
		if currentVersion != version {
			return seq, fmt.Errorf("configuration changed while producing current object: start=%d current=%d", version, currentVersion)
		}
		if ok && entry.Object.ConfigVersion == currentVersion {
			n.finishProducerSeq(seq)
			return seq, nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return seq, ctx.Err()
		}
	}
}

func (n *Node) produceSeq(ctx context.Context, seq uint64, version uint64) (Object, error) {
	pvssOpMu.Lock()
	start := time.Now()
	c, _, err := n.PVSS.Share(n.ID, seq, nil)
	if n.Perf != nil {
		n.Perf.addPVSSShare(time.Since(start))
	}
	pvssOpMu.Unlock()
	if err != nil {
		return Object{}, err
	}
	obj := Object{ConfigVersion: version, Producer: n.ID, Seq: seq, Commitment: c}
	raw, err := json.Marshal(envelope{Kind: "object", Object: &obj})
	if err != nil {
		return Object{}, err
	}
	if err := n.RBC.Broadcast(ctx, seq, raw); err != nil {
		return Object{}, err
	}
	return obj, nil
}

func (n *Node) rollbackProducerSeq(seq uint64) {
	n.mu.Lock()
	if n.State.ProducerSeq == seq {
		n.State.ProducerSeq--
	}
	n.mu.Unlock()
}

func (n *Node) finishProducerSeq(seq uint64) {
	n.mu.Lock()
	delete(n.producerBusy, seq)
	n.mu.Unlock()
}

func (n *Node) StartProducer(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		producing := true
		for {
			n.mu.Lock()
			storedDepth := n.outstandingQueueDepthLocked(n.ID)
			level := n.producerOccupancyLocked()
			low, high, queueLen := n.producerLow, n.producerHigh, n.State.QueueLen
			n.mu.Unlock()
			if level >= high {
				producing = false
			} else if level <= low {
				producing = true
			}
			if producing && level < high && storedDepth < queueLen {
				if _, err := n.Produce(ctx); err != nil {
					debugf("node=%s producer attempt failed: %v", n.ID, err)
				}
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
}

// producerOccupancyLocked counts every sequence reserved after the consumed
// prefix, including PVSS generation and RBC broadcasts that have not yet
// produced a delivery certificate. Slow production therefore cannot create an
// unbounded number of in-flight broadcasts outside the queue watermark.
func (n *Node) producerOccupancyLocked() int {
	consumed := n.State.Seqs[n.ID]
	if n.State.ProducerSeq <= consumed {
		return 0
	}
	return int(n.State.ProducerSeq - consumed)
}

func (n *Node) outstandingQueueDepthLocked(id p2p.NodeID) int {
	consumed := n.State.Seqs[id]
	depth := 0
	for seq := range n.State.ComQ[id] {
		if seq > consumed {
			depth++
		}
	}
	return depth
}

func (n *Node) QueueBacklog() (total int, max int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, q := range n.State.ComQ {
		pending := len(q)
		total += pending
		if pending > max {
			max = pending
		}
	}
	return total, max
}

func (n *Node) RunEpoch(ctx context.Context) (Beacon, error) {
	n.mu.Lock()
	epoch := n.State.Epoch + 1
	n.mu.Unlock()
	return n.RunEpochAt(ctx, epoch)
}

func (n *Node) RunEpochAt(ctx context.Context, epoch uint64) (Beacon, error) {
	// A newly admitted party may receive J before the last old-configuration
	// P_e.  It is already a member, but it must catch up that certified prefix
	// before opening the requested epoch.
	for {
		n.mu.Lock()
		completed := n.State.Epoch
		n.mu.Unlock()
		if completed+1 >= epoch {
			break
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			return Beacon{}, ctx.Err()
		}
	}
	n.mu.Lock()
	active := contains(n.Schedule.Members, n.ID) && n.RBC != nil && n.ABA != nil
	n.mu.Unlock()
	if !active {
		return Beacon{}, errors.New("node is not an active member of the fixed party set")
	}
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return b, nil
		}
		source, seq, instance, skipTuple, alreadyCertified, err := n.prepareEpoch(epoch)
		if err != nil {
			if errors.Is(err, errPriorDecisionPending) {
				select {
				case <-time.After(10 * time.Millisecond):
					continue
				case <-ctx.Done():
					return Beacon{}, ctx.Err()
				}
			}
			return Beacon{}, err
		}
		// Establishing the local instance may make an earlier transferable
		// certificate verifiable. Replay that certified event now.
		n.retryPendingABACertificates(ctx)
		wait := n.registerBeaconWaiter(epoch, source, seq)
		if alreadyCertified {
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, instance, wait)
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return b, err
		}
		var obj Object
		if !skipTuple {
			var certified *Beacon
			obj, certified, err = n.waitObjectOrBeacon(ctx, epoch, source, seq, instance, wait)
			if err != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, err
			}
			if certified != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return *certified, nil
			}
		}

		if certified, err := n.proposeEpochABAInputFromLookahead(ctx, epoch, source, seq, instance, wait); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return Beacon{}, err
		} else if certified != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return *certified, nil
		}
		if err := n.waitCurrentABAReady(ctx, instance); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return Beacon{}, err
		}
		if skipTuple {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			continue
		}
		select {
		case b := <-wait:
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return b, nil
		default:
		}
		if err := n.ensureVerified(obj); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return Beacon{}, err
		}
		key := epochKey(epoch, source, seq)
		n.mu.Lock()
		origin := n.PVSSContext
		canShare := origin != nil && origin.Scheme != nil &&
			origin.Configuration.Contains(n.ID)
		needRecon := canShare && !n.reconDone[key] && !n.reconSent[key]
		if needRecon {
			n.reconSent[key] = true
		}
		n.mu.Unlock()
		if needRecon {
			// The object was already verified locally before entering comq; this path only skips
			// the duplicate commitment proof check, not the required RBC-delivery validation.
			start := time.Now()
			sh, err := origin.Scheme.PreReconVerified(obj.Commitment, n.ID)
			if n.Perf != nil {
				n.Perf.addPVSSPreRecon(time.Since(start))
			}
			if err != nil {
				n.mu.Lock()
				delete(n.reconSent, key)
				n.mu.Unlock()
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, err
			}
			recon := ReconMessage{
				ObjectConfigVersion: obj.ConfigVersion,
				Share:               sh,
			}
			n.mu.Lock()
			attempt := n.epochAttempts[consumerEpochKey(abaVersion(instance), epoch)]
			n.mu.Unlock()
			reconInstance := reconInstance(abaVersion(instance), epoch, attempt.ParentHash, source, seq)
			msg, err := p2p.NewMessage(Protocol, "RECON", reconInstance, n.ID, "", recon)
			if err != nil {
				n.mu.Lock()
				delete(n.reconSent, key)
				n.mu.Unlock()
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, err
			}
			if err := n.Transport.Broadcast(ctx, msg); err != nil {
				n.mu.Lock()
				delete(n.reconSent, key)
				n.mu.Unlock()
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, err
			}
		}
		b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, instance, wait)
		n.unregisterBeaconWaiter(epoch, source, seq, wait)
		if errors.Is(err, errRestartEpoch) {
			continue
		}
		return b, err
	}
}

func (n *Node) certifiedBeaconForEpoch(epoch uint64) (Beacon, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, b := range n.certBeacons {
		if b.Epoch == epoch {
			return b, true
		}
	}
	return Beacon{}, false
}

func (n *Node) waitForEpochBeacon(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (Beacon, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case b := <-wait:
			return b, nil
		case <-ticker.C:
			if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
				return b, nil
			}
			if n.epochAttemptMustRestart(instance, source, seq) {
				return Beacon{}, errRestartEpoch
			}
		case <-ctx.Done():
			return Beacon{}, ctx.Err()
		}
	}
}

func (n *Node) epochAttemptMustRestart(instance string, source p2p.NodeID, seq uint64) bool {
	return false
}

func (n *Node) registerBeaconWaiter(epoch uint64, source p2p.NodeID, seq uint64) chan Beacon {
	key := epochKey(epoch, source, seq)
	ch := make(chan Beacon, 1)
	n.mu.Lock()
	if b, ok := n.certBeacons[key]; ok {
		ch <- b
	} else {
		n.waiters[key] = append(n.waiters[key], ch)
	}
	n.mu.Unlock()
	return ch
}

func (n *Node) unregisterBeaconWaiter(epoch uint64, source p2p.NodeID, seq uint64, ch chan Beacon) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	defer n.mu.Unlock()
	waiters := n.waiters[key]
	for i, w := range waiters {
		if w == ch {
			waiters = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(waiters) == 0 {
		delete(n.waiters, key)
	} else {
		n.waiters[key] = waiters
	}
}

func (n *Node) prepareEpoch(epoch uint64) (p2p.NodeID, uint64, string, bool, bool, error) {
	n.mu.Lock()
	if n.State.Epoch >= epoch {
		for _, b := range n.certBeacons {
			if b.Epoch == epoch {
				n.mu.Unlock()
				return b.Source, b.Seq, aba.TupleInstanceFor(b.ConfigVersion, epoch, b.Source, b.Seq), false, true, nil
			}
		}
		n.mu.Unlock()
		return "", 0, "", false, false, fmt.Errorf("epoch %d already certified but beacon was not retained", epoch)
	}
	if n.State.Epoch+1 != epoch {
		n.mu.Unlock()
		return "", 0, "", false, false, fmt.Errorf("cannot run epoch %d from local epoch %d", epoch, n.State.Epoch)
	}
	if len(n.State.SCL) == 0 {
		n.refillSCLLocked()
	}
	attemptKey := consumerEpochKey(n.State.ConfigVersion, epoch)
	attempt := n.epochAttempts[attemptKey]
	excluded := make(map[p2p.NodeID]bool)
	for _, item := range attempt.Skipped {
		excluded[item.Source] = true
	}
	minEpoch := uint64(1)
	if epoch > uint64(2*n.State.F) {
		minEpoch = epoch - uint64(2*n.State.F)
	}
	for _, link := range n.BeaconHistory {
		if link.QC.Epoch < minEpoch || link.QC.Epoch >= epoch {
			continue
		}
		for _, item := range link.Skipped {
			excluded[item.Source] = true
		}
	}
	candidates := make([]p2p.NodeID, 0, len(n.State.SCL))
	for _, candidate := range n.State.SCL {
		if !excluded[candidate] {
			candidates = append(candidates, candidate)
		}
	}
	if len(candidates) == 0 {
		n.mu.Unlock()
		return "", 0, "", false, false, errors.New("empty source candidate list")
	}
	idx := selectionIndex(epoch, n.State.RPrev, len(attempt.Skipped), len(candidates))
	source := candidates[idx]
	seq := n.State.Seqs[source] + 1
	instance := aba.TupleInstanceFor(n.State.ConfigVersion, epoch, source, seq)
	skipTuple := false
	if seq > 1 {
		priorInstance := n.Schedule.ControlInstances[source]
		decision, decided := n.State.ABADecisions[priorInstance]
		if priorInstance == "" || !decided {
			n.mu.Unlock()
			return "", 0, "", false, false, errPriorDecisionPending
		}
		if !decision.Value {
			skipTuple = true
			attempt.Skipped = append(attempt.Skipped, SkippedTuple{
				Source: source, Seq: seq, Certificate: decision.Certificate,
			})
		}
	}
	attempt.ConfigVersion = n.State.ConfigVersion
	attempt.Epoch = epoch
	attempt.ParentHash = n.Schedule.BeaconHead
	attempt.Source = source
	attempt.Seq = seq
	attempt.PrevRandom = append([]byte(nil), n.State.RPrev...)
	n.epochAttempts[attemptKey] = attempt
	if !skipTuple {
		// The final candidate fixes the exact skipped prefix signed in P_e.
		n.epochAttempts[attemptKey] = attempt
	}
	n.mu.Unlock()
	return source, seq, instance, skipTuple, false, nil
}

func (n *Node) waitObjectOrBeacon(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (Object, *Beacon, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	loggedWait := false
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return Object{}, &b, nil
		}
		if n.epochAttemptMustRestart(instance, source, seq) {
			return Object{}, nil, errRestartEpoch
		}
		if !loggedWait {
			debugf("node=%s step0-current-object-wait epoch=%d source=%s seq=%d instance=%s", n.ID, epoch, source, seq, instance)
			loggedWait = true
		}
		n.mu.Lock()
		entry, ok := n.State.ComQ[source][seq]
		n.mu.Unlock()
		if ok {
			debugf("node=%s step0-current-object-ready epoch=%d source=%s seq=%d instance=%s", n.ID, epoch, source, seq, instance)
			return entry.Object, nil, nil
		}
		select {
		case b := <-wait:
			return Object{}, &b, nil
		case <-ticker.C:
		case <-ctx.Done():
			return Object{}, nil, ctx.Err()
		}
	}
}

func (n *Node) proposeEpochABAInputFromLookahead(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (*Beacon, error) {
	next := seq + 1
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return &b, nil
		}
		if n.epochAttemptMustRestart(instance, source, seq) {
			return nil, errRestartEpoch
		}
		engine := n.abaEngineFor(instance)
		if engine == nil {
			return nil, errors.New("missing epoch ABA engine")
		}
		st := engine.Status(instance)
		if st.Decided || st.CoinWait {
			return nil, nil
		}
		n.mu.Lock()
		_, ok := n.State.ComQ[source][next]
		expired := !ok && n.lookForwardExpiredLocked(source, next)
		n.mu.Unlock()
		if ok {
			return nil, n.proposeEpochABAInput(ctx, instance, true)
		}
		if expired {
			return nil, n.proposeEpochABAInput(ctx, instance, false)
		}
		select {
		case b := <-wait:
			return &b, nil
		case <-ticker.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

const lookForwardEta = 1

// lookForwardExpiredLocked implements the queue-progress expiration rule from
// the protocol. The target is unavailable only after at least eta other
// unconsumed RBC-delivered objects are present from each of 2f+1 distinct
// producers. Counting producers, rather than only objects, prevents one fast
// or Byzantine producer from forcing input 0 by itself.
func (n *Node) lookForwardExpiredLocked(targetProducer p2p.NodeID, targetSeq uint64) bool {
	requiredProducers := 2*n.State.F + 1
	progressingProducers := 0
	for _, producer := range n.State.Members {
		count := 0
		consumed := n.State.Seqs[producer]
		for seq := range n.State.ComQ[producer] {
			// Neither the missing look-ahead object nor the current object being
			// consumed is evidence of forward queue progress.
			currentTarget := producer == targetProducer && targetSeq > 0 && seq == targetSeq-1
			if seq <= consumed || (producer == targetProducer && seq == targetSeq) || currentTarget {
				continue
			}
			count++
			if count >= lookForwardEta {
				progressingProducers++
				break
			}
		}
		if progressingProducers >= requiredProducers {
			return true
		}
	}
	return false
}

func (n *Node) proposeEpochABAInput(ctx context.Context, instance string, value bool) error {
	n.mu.Lock()
	if n.abaInputSent[instance] {
		n.mu.Unlock()
		return nil
	}
	n.abaInputSent[instance] = true
	n.abaInputs[instance] = value
	n.mu.Unlock()
	engine := n.abaEngineFor(instance)
	if engine == nil {
		return errors.New("missing epoch ABA engine")
	}
	return engine.Propose(ctx, instance, value)
}

func (n *Node) waitCurrentABAReady(ctx context.Context, instance string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	rebroadcast := time.NewTicker(100 * time.Millisecond)
	defer rebroadcast.Stop()
	for {
		engine := n.abaEngineFor(instance)
		if engine == nil {
			return errors.New("missing epoch ABA engine")
		}
		st := engine.Status(instance)
		if st.Decided {
			return nil
		}
		n.mu.Lock()
		input, hasInput := n.abaInputs[instance]
		if st.CoinWait {
			n.State.PendingABAs[instance] = struct{}{}
			n.mu.Unlock()
			return nil
		}
		n.mu.Unlock()
		select {
		case <-ticker.C:
		case <-rebroadcast.C:
			if hasInput {
				_ = engine.Propose(context.Background(), instance, input)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (n *Node) abaEngineFor(instance string) *aba.Agreement {
	if _, ok := aba.ConfigVersionFromInstance(instance); !ok {
		return nil
	}
	return n.ABA
}

type seedFeed struct {
	instance string
	round    uint64
	seed     []byte
}

func (n *Node) handleRBCDelivery(ctx context.Context, d rbc.Delivery) error {
	engine := n.RBC
	if d.Purpose != "pvss" {
		return nil
	}
	if engine == nil {
		return nil
	}
	if err := engine.VerifyDeliveryCertificate(d.Certificate); err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(d.Value, &env); err != nil {
		return err
	}
	switch env.Kind {
	case "object":
		if env.Object == nil {
			return nil
		}
		obj := *env.Object
		if obj.ConfigVersion != d.ConfigVersion || obj.Producer != d.Dealer {
			return nil
		}
		n.Crypto.Go(ctx, func() {
			if err := n.storeObject(obj, d.Certificate); err != nil {
				return
			}
			n.replayPendingRecon(ctx, obj)
		})
		return nil
	default:
		return nil
	}
}

func (n *Node) storeObject(obj Object, certificate rbc.DeliveryCertificate) error {
	if obj.Producer == "" || obj.Seq == 0 || obj.Commitment.Dealer != obj.Producer || obj.Commitment.Seq != obj.Seq {
		debugf("node=%s drop object producer=%s seq=%d reason=invalid", n.ID, obj.Producer, obj.Seq)
		return errors.New("invalid pvss object")
	}
	if obj.Producer == n.ID {
		defer n.finishProducerSeq(obj.Seq)
	}
	n.mu.Lock()
	origin := n.PVSSContext
	if origin == nil || !origin.Configuration.Contains(obj.Producer) ||
		!contains(n.State.Members, obj.Producer) {
		n.mu.Unlock()
		return nil
	}
	if n.State.ComQ[obj.Producer] == nil {
		n.mu.Unlock()
		return nil
	}
	nextSeq := n.State.Seqs[obj.Producer] + 1
	if obj.Seq < nextSeq {
		n.mu.Unlock()
		debugf("node=%s drop object producer=%s seq=%d reason=stale next=%d", n.ID, obj.Producer, obj.Seq, nextSeq)
		return nil
	}
	if _, exists := n.State.ComQ[obj.Producer][obj.Seq]; exists {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	if err := n.ensureVerified(obj); err != nil {
		debugf("node=%s drop object producer=%s seq=%d reason=verify err=%v", n.ID, obj.Producer, obj.Seq, err)
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.PVSSContext == nil ||
		!contains(n.State.Members, obj.Producer) {
		return nil
	}
	if n.State.ComQ[obj.Producer] == nil {
		return nil
	}
	nextSeq = n.State.Seqs[obj.Producer] + 1
	if obj.Seq < nextSeq {
		debugf("node=%s drop object producer=%s seq=%d reason=stale next=%d", n.ID, obj.Producer, obj.Seq, nextSeq)
		return nil
	}
	if _, exists := n.State.ComQ[obj.Producer][obj.Seq]; exists {
		return nil
	}
	n.State.ComQ[obj.Producer][obj.Seq] = CertifiedObject{Object: obj, Certificate: certificate}
	debugf("node=%s store object producer=%s seq=%d", n.ID, obj.Producer, obj.Seq)
	return nil
}

func (n *Node) ensureVerified(obj Object) error {
	n.mu.Lock()
	pvssContext := n.PVSSContext
	n.mu.Unlock()
	if pvssContext == nil || pvssContext.Scheme == nil {
		return fmt.Errorf("missing PVSS context for configuration %d", obj.ConfigVersion)
	}
	return n.verifyObjectOnce(obj, pvssContext.Scheme)
}

// verifyObjectOnce serializes concurrent verification of one PVSS object.
// Every caller observes the cached result; exactly one caller performs the
// cryptographic proof verification.
func (n *Node) verifyObjectOnce(obj Object, scheme crypto.PVSSScheme) error {
	key := objectCacheKey(obj)
	n.mu.Lock()
	if cached := n.verified[key]; cached != nil {
		ready := cached.ready
		n.mu.Unlock()
		<-ready
		n.mu.Lock()
		valid := cached.valid
		n.mu.Unlock()
		if valid {
			return nil
		}
		return errors.New("invalid pvss object")
	}
	cached := &verifiedObject{
		version: obj.ConfigVersion, producer: obj.Producer, seq: obj.Seq,
		ready: make(chan struct{}),
	}
	n.verified[key] = cached
	n.mu.Unlock()
	start := time.Now()
	valid := scheme.Verify(obj.Commitment)
	if n.Perf != nil {
		n.Perf.addPVSSVerify(time.Since(start))
	}
	n.mu.Lock()
	cached.valid = valid
	close(cached.ready)
	n.mu.Unlock()
	if !valid {
		return errors.New("invalid pvss object")
	}
	return nil
}

func (n *Node) handleTyche(ctx context.Context, msg p2p.Message) error {
	switch msg.Type {
	case "RECON":
		body, err := p2p.DecodePayload[ReconMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		instance := msg.Instance
		n.Crypto.GoPriority(ctx, func() { _ = n.handleRecon(ctx, from, instance, body) })
	case "BEACON":
		body, err := p2p.DecodePayload[signedBeaconMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		n.Crypto.GoPriority(ctx, func() {
			n.observeBeaconVote(ctx, from, body)
		})
	case "ABA_CERT":
		body, err := p2p.DecodePayload[certifiedABADecision](msg)
		if err != nil {
			return err
		}
		cert := body.Certificate
		return n.handleCertifiedABADecision(ctx, aba.Decision{
			ConfigVersion: cert.ConfigVersion, Instance: cert.Instance,
			Value: cert.Value, FastPath: cert.FastPath, Certificate: cert,
		})
	}
	return nil
}

func (n *Node) handleRecon(ctx context.Context, from p2p.NodeID, instance string, body ReconMessage) error {
	scope, ok := parseReconInstance(instance)
	if !ok {
		return nil
	}
	n.mu.Lock()
	if !n.validReconMetadataLocked(from, scope, body) {
		n.mu.Unlock()
		return nil
	}
	entry, available := n.State.ComQ[scope.Source][scope.Seq]
	if !available {
		n.bufferPendingReconLocked(from, instance, scope, body)
		n.mu.Unlock()
		return nil
	}
	obj := entry.Object
	if obj.ConfigVersion != body.ObjectConfigVersion || obj.Commitment.SecretID != body.Share.CommitmentID {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	key := epochKey(scope.Epoch, scope.Source, scope.Seq)
	n.mu.Lock()
	pvssContext := n.PVSSContext
	if pvssContext == nil || pvssContext.Scheme == nil {
		n.mu.Unlock()
		return nil
	}
	scheme := pvssContext.Scheme
	if n.reconDone[key] || n.reconClosing[key] || body.Share.CommitmentID != obj.Commitment.SecretID ||
		body.Share.Holder != from {
		n.mu.Unlock()
		return nil
	}
	if existing := n.recon[key]; existing != nil {
		if _, dup := existing[from]; dup {
			n.mu.Unlock()
			return nil
		}
	}
	n.mu.Unlock()
	validShare := n.verifyShareOnce(obj, body.Share, scheme)
	if !validShare {
		debugf("node=%s drop recon from=%s epoch=%d source=%s seq=%d holder=%s valid=%v", n.ID, from, scope.Epoch, scope.Source, scope.Seq, body.Share.Holder, validShare)
		return nil
	}
	n.mu.Lock()
	if n.reconDone[key] {
		n.mu.Unlock()
		return nil
	}
	if n.recon[key] == nil {
		n.recon[key] = make(map[p2p.NodeID]crypto.DecryptedShare)
	}
	n.recon[key][from] = body.Share
	if n.reconDone[key] || len(n.recon[key]) < obj.Commitment.Threshold {
		n.mu.Unlock()
		return nil
	}
	n.reconClosing[key] = true
	shares := make([]crypto.DecryptedShare, 0, len(n.recon[key]))
	for _, sh := range n.recon[key] {
		shares = append(shares, sh)
	}
	attempt, attemptOK := n.epochAttempts[consumerEpochKey(scope.ConfigVersion, scope.Epoch)]
	if !attemptOK {
		delete(n.reconClosing, key)
		n.mu.Unlock()
		return nil
	}
	prev := append([]byte(nil), attempt.PrevRandom...)
	configVersion := attempt.ConfigVersion
	n.mu.Unlock()
	if err := n.ensureVerified(obj); err != nil {
		n.mu.Lock()
		delete(n.reconClosing, key)
		n.mu.Unlock()
		return err
	}
	// These shares were inserted into n.recon only after this node verified
	// their decryption proofs in handleRecon, so reconstruction can reuse that
	// local validation instead of checking the same proofs again.
	start := time.Now()
	secret, err := scheme.ReconFromVerifiedShares(obj.Commitment, shares)
	if n.Perf != nil {
		n.Perf.addPVSSRecon(time.Since(start))
	}
	if err != nil {
		n.mu.Lock()
		delete(n.reconClosing, key)
		n.mu.Unlock()
		return err
	}
	n.mu.Lock()
	random := crypto.DomainHash(
		"Tyche/Beacon/v1",
		[]byte(fmt.Sprintf("%d", configVersion)),
		[]byte(fmt.Sprintf("%d", scope.Epoch)),
		prev,
		secret,
	)
	if n.reconDone[key] {
		n.mu.Unlock()
		return nil
	}
	n.reconDone[key] = true
	n.mu.Unlock()
	return n.broadcastBeaconVote(ctx, configVersion, scope.Epoch, scope.Source, scope.Seq, random)
}

// verifyShareOnce applies the same one-verification rule to a holder's
// decryption key/share for an object. An invalid first value from a holder is
// cached as an equivocation and that holder is ignored for this object.
func (n *Node) verifyShareOnce(obj Object, share crypto.DecryptedShare, scheme crypto.PVSSScheme) bool {
	key := fmt.Sprintf("%s/%s", objectCacheKey(obj), share.Holder)
	n.mu.Lock()
	if cached := n.verifiedShares[key]; cached != nil {
		ready := cached.ready
		n.mu.Unlock()
		<-ready
		n.mu.Lock()
		valid := cached.valid
		n.mu.Unlock()
		return valid
	}
	cached := &verifiedShare{
		version: obj.ConfigVersion, producer: obj.Producer, seq: obj.Seq,
		ready: make(chan struct{}),
	}
	n.verifiedShares[key] = cached
	n.mu.Unlock()
	start := time.Now()
	valid := scheme.VerifyShare(obj.Commitment, share)
	if n.Perf != nil {
		n.Perf.addPVSSVerify(time.Since(start))
	}
	n.mu.Lock()
	cached.valid = valid
	close(cached.ready)
	n.mu.Unlock()
	return valid
}

func pendingReconKey(version, epoch uint64, source p2p.NodeID, seq uint64) string {
	return fmt.Sprintf("%d/%d/%s/%d", version, epoch, source, seq)
}

func (n *Node) validReconMetadataLocked(from p2p.NodeID, scope reconScope, body ReconMessage) bool {
	attempt, opened := n.epochAttempts[consumerEpochKey(scope.ConfigVersion, scope.Epoch)]
	if !opened || body.ObjectConfigVersion > scope.ConfigVersion ||
		scope.Epoch != n.State.Epoch+1 ||
		scope.ParentHash != n.Schedule.BeaconHead || attempt.ParentHash != scope.ParentHash ||
		scope.Source != attempt.Source || scope.Seq != attempt.Seq ||
		scope.Seq != n.State.Seqs[scope.Source]+1 ||
		body.Share.CommitmentID == "" ||
		body.Share.Holder != from {
		return false
	}
	config := n.Configuration
	return scope.ConfigVersion == config.Version && body.ObjectConfigVersion == config.Version &&
		config.Contains(from) && config.Contains(scope.Source) &&
		contains(n.State.Members, scope.Source)
}

func (n *Node) bufferPendingReconLocked(from p2p.NodeID, instance string, scope reconScope, body ReconMessage) {
	key := pendingReconKey(body.ObjectConfigVersion, scope.Epoch, scope.Source, scope.Seq)
	bucket := n.pendingRecon[key]
	if bucket != nil {
		if _, duplicate := bucket.Messages[from]; duplicate {
			return
		}
	} else {
		// Only the next sequence of a configured source is accepted, so at
		// most n source buckets are live. Each bucket stores at most one share
		// per configured sender, giving a hard n^2 global bound.
		limit := len(n.State.Members) * len(n.State.Members)
		if limit < 1 || n.pendingReconCount >= limit {
			return
		}
		bucket = &pendingReconBucket{
			ConfigVersion:       scope.ConfigVersion,
			ObjectConfigVersion: body.ObjectConfigVersion,
			Epoch:               scope.Epoch,
			Source:              scope.Source,
			Seq:                 scope.Seq,
			Messages:            make(map[p2p.NodeID]pendingReconMessage),
		}
		n.pendingRecon[key] = bucket
	}
	if len(bucket.Messages) >= len(n.State.Members) {
		return
	}
	bucket.Messages[from] = pendingReconMessage{Instance: instance, Body: body}
	n.pendingReconCount++
}

func (n *Node) replayPendingRecon(ctx context.Context, obj Object) {
	n.mu.Lock()
	var pending []struct {
		from     p2p.NodeID
		instance string
		body     ReconMessage
	}
	for key, bucket := range n.pendingRecon {
		if bucket.ObjectConfigVersion != obj.ConfigVersion ||
			bucket.Source != obj.Producer ||
			bucket.Seq != obj.Seq {
			continue
		}
		for from, message := range bucket.Messages {
			if message.Body.Share.CommitmentID == obj.Commitment.SecretID {
				pending = append(pending, struct {
					from     p2p.NodeID
					instance string
					body     ReconMessage
				}{from: from, instance: message.Instance, body: message.Body})
			}
		}
		n.pendingReconCount -= len(bucket.Messages)
		delete(n.pendingRecon, key)
	}
	n.mu.Unlock()
	for _, item := range pending {
		if err := n.handleRecon(ctx, item.from, item.instance, item.body); err != nil {
			debugf("node=%s reject replayed recon from=%s config=%d source=%s seq=%d err=%v",
				n.ID, item.from, obj.ConfigVersion, obj.Producer, obj.Seq, err)
		}
	}
}

func debugf(format string, args ...any) {
	if os.Getenv("TYCHE_DEBUG") == "1" {
		log.Printf(format, args...)
	}
}

func (n *Node) broadcastBeaconVote(ctx context.Context, configVersion, epoch uint64, source p2p.NodeID, seq uint64, random []byte) error {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	attempt, opened := n.epochAttempts[consumerEpochKey(configVersion, epoch)]
	if n.beaconVoteSent[key] {
		n.mu.Unlock()
		return nil
	}
	if n.State.Epoch+1 != epoch {
		n.mu.Unlock()
		return errRestartEpoch
	}
	if !opened || attempt.Source != source || attempt.Seq != seq ||
		attempt.ParentHash != n.Schedule.BeaconHead {
		n.mu.Unlock()
		return errRestartEpoch
	}
	config := n.Configuration
	parentHash := attempt.ParentHash
	skippedHash := HashSkippedTuples(attempt.Skipped)
	n.mu.Unlock()
	if config.Version != configVersion {
		return errors.New("missing configuration for BEACON vote")
	}
	transcript := BeaconVoteTranscript(config.Version, epoch, parentHash, skippedHash, source, seq, random)
	voteHash := fmt.Sprintf("%x", crypto.DomainHash("Tyche/BeaconVoteReservation/v1", transcript))
	voteSlot := fmt.Sprintf("beacon/v2/epoch/%d", epoch)
	if err := n.Store.ReserveBeaconVote(voteSlot, voteHash); err != nil {
		return err
	}
	start := time.Now()
	signature, err := SignBeaconVote(n.ID, n.IdentityPrivate, config, epoch, parentHash, skippedHash, source, seq, random)
	if n.Perf != nil {
		n.Perf.addCertSign(time.Since(start))
	}
	if err != nil {
		return err
	}
	n.mu.Lock()
	if n.beaconVoteSent[key] {
		n.mu.Unlock()
		return nil
	}
	if n.Schedule.BeaconHead != parentHash {
		n.mu.Unlock()
		return errRestartEpoch
	}
	n.beaconVoteSent[key] = true
	n.mu.Unlock()
	message := signedBeaconMessage{
		ConfigVersion: config.Version, Epoch: epoch, ParentHash: parentHash,
		SkippedHash: skippedHash, Source: source, Seq: seq,
		Random: append([]byte(nil), random...), Signature: signature,
	}
	wire, err := p2p.NewMessage(Protocol, "BEACON", key, n.ID, "", message)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, wire)
}

func (n *Node) observeBeaconVote(ctx context.Context, from p2p.NodeID, body signedBeaconMessage) {
	voteKey := beaconVoteKey(body)
	n.mu.Lock()
	attempt, opened := n.beaconAttemptLocked(body)
	if n.State.Epoch+1 != body.Epoch ||
		body.ParentHash != n.Schedule.BeaconHead || body.Signature.Signer != string(from) ||
		!opened || attempt.ParentHash != body.ParentHash ||
		attempt.Source != body.Source || attempt.Seq != body.Seq ||
		HashSkippedTuples(attempt.Skipped) != body.SkippedHash || !contains(n.State.Members, body.Source) {
		n.mu.Unlock()
		return
	}
	config := n.Configuration
	if config.Version != body.ConfigVersion || !config.Contains(from) || !config.Contains(body.Source) ||
		body.Seq != n.State.Seqs[body.Source]+1 {
		n.mu.Unlock()
		return
	}
	if votes := n.beaconVotes[voteKey]; votes != nil {
		if _, duplicate := votes[from]; duplicate {
			n.mu.Unlock()
			return
		}
	}
	n.mu.Unlock()
	start := time.Now()
	err := crypto.VerifySignedVote(
		body.Signature, config.PublicKeys(),
		BeaconVoteTranscript(body.ConfigVersion, body.Epoch, body.ParentHash, body.SkippedHash, body.Source, body.Seq, body.Random),
	)
	if n.Perf != nil {
		n.Perf.addCertVerify(time.Since(start))
	}
	if err != nil {
		return
	}
	n.mu.Lock()
	attempt, opened = n.epochAttempts[consumerEpochKey(body.ConfigVersion, body.Epoch)]
	if n.State.Epoch+1 != body.Epoch || body.ParentHash != n.Schedule.BeaconHead ||
		!opened || attempt.Source != body.Source || attempt.Seq != body.Seq ||
		HashSkippedTuples(attempt.Skipped) != body.SkippedHash {
		n.mu.Unlock()
		return
	}
	if n.beaconVotes[voteKey] == nil {
		n.beaconVotes[voteKey] = make(map[p2p.NodeID]crypto.SignedVote)
	}
	n.beaconVotes[voteKey][from] = body.Signature
	if len(n.beaconVotes[voteKey]) < config.Q || n.certified[voteKey] {
		n.mu.Unlock()
		return
	}
	votes := make([]crypto.SignedVote, 0, len(n.beaconVotes[voteKey]))
	for signer, vote := range n.beaconVotes[voteKey] {
		_ = signer
		votes = append(votes, vote)
	}
	n.certified[voteKey] = true
	parent := CloneSchedulingState(n.Schedule)
	n.mu.Unlock()
	start = time.Now()
	qc, err := BuildBeaconQC(config, body.Epoch, body.ParentHash, body.SkippedHash, body.Source, body.Seq, body.Random, votes)
	if n.Perf != nil {
		n.Perf.addCertAggregate(time.Since(start))
	}
	if err != nil {
		return
	}
	skipped := append([]SkippedTuple(nil), attempt.Skipped...)
	child, err := entropySuccessorForRecord(parent, body.ConfigVersion, config.F, body.Random, body.Source, body.Seq, skipped)
	if err != nil {
		return
	}
	n.certifyBeacon(body.Epoch, body.Source, body.Seq, body.Random, child, qc, skipped)
	_ = ctx
}

// beaconAttemptLocked returns the immutable Step-0 context for a vote.
func (n *Node) beaconAttemptLocked(body signedBeaconMessage) (epochAttempt, bool) {
	instance := consumerEpochKey(body.ConfigVersion, body.Epoch)
	if attempt, ok := n.epochAttempts[instance]; ok {
		return attempt, true
	}
	if body.Epoch != n.State.Epoch+1 || body.ParentHash != n.Schedule.BeaconHead {
		return epochAttempt{}, false
	}
	if body.ConfigVersion != n.Configuration.Version {
		return epochAttempt{}, false
	}
	eligible := append([]p2p.NodeID(nil), n.State.SCL...)
	if len(eligible) == 0 {
		return epochAttempt{}, false
	}
	expectedSource := eligible[beaconIndex(n.State.RPrev, len(eligible))]
	expectedSeq := n.State.Seqs[expectedSource] + 1
	if body.Source != expectedSource || body.Seq != expectedSeq {
		return epochAttempt{}, false
	}
	attempt := epochAttempt{
		ConfigVersion: body.ConfigVersion,
		Epoch:         body.Epoch,
		ParentHash:    body.ParentHash,
		Source:        body.Source,
		Seq:           body.Seq,
		PrevRandom:    append([]byte(nil), n.State.RPrev...),
		Skipped:       nil,
	}
	n.epochAttempts[instance] = attempt
	return attempt, true
}

func (n *Node) certifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, child SchedulingState, qc BeaconQC, skipped []SkippedTuple) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch {
		n.mu.Unlock()
		return
	}
	if n.certifying[key] {
		n.mu.Unlock()
		return
	}
	n.certifying[key] = true
	n.mu.Unlock()
	go n.finishCertifyBeacon(epoch, source, seq, random, child, qc, skipped)
}

func (n *Node) finishCertifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, child SchedulingState, qc BeaconQC, skipped []SkippedTuple) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	parent := CloneSchedulingState(n.Schedule)
	parentConfig := n.Configuration
	n.mu.Unlock()
	if qc.ConfigVersion != parentConfig.Version || VerifyBeaconQC(parentConfig, qc) != nil ||
		qc.Epoch != epoch || qc.ParentHash != parent.BeaconHead ||
		qc.Source != source || qc.Seq != seq || string(qc.Random) != string(random) ||
		qc.SkippedHash != HashSkippedTuples(skipped) {
		n.mu.Lock()
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	n.mu.Lock()
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch ||
		n.Schedule.BeaconHead != qc.ParentHash {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	effectiveChild, err := entropySuccessorForRecord(n.Schedule, qc.ConfigVersion, parentConfig.F, random, source, seq, skipped)
	if err != nil {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	child = effectiveChild
	// Process 2 installs P_e before exposing R_e to the ABAs waiting for this
	// exact coin.  The still-present certifying entry is the local barrier that
	// prevents certification of P_{e+1} until every awakened continuation has
	// either decided or reached its next coin wait.
	n.installBeaconStateLocked(child, qc, skipped)
	if err := n.persistLocked(); err != nil {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	n.beaconSeeds[epoch] = append([]byte(nil), random...)
	feeds := n.processPendingABAsLocked(epoch)
	n.mu.Unlock()
	for _, feed := range feeds {
		engine := n.ABA
		if engine == nil {
			continue
		}
		engine.FeedSeed(context.Background(), feed.instance, feed.round, random)
		n.waitPendingABAAfterSeed(context.Background(), feed)
	}
	n.mu.Lock()
	if n.State.Epoch != epoch || n.Schedule.BeaconHead != child.BeaconHead {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	if err := n.persistLocked(); err != nil {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	n.cleanupEpochStateLocked(epoch)
	b := Beacon{BeaconQC: qc, Skipped: append([]SkippedTuple(nil), skipped...)}
	n.certBeacons[key] = b
	delete(n.certifying, key)
	waiters := append([]chan Beacon(nil), n.waiters[key]...)
	delete(n.waiters, key)
	select {
	case n.Beacons <- b:
	default:
	}
	n.mu.Unlock()
	n.retryPendingABACertificates(context.Background())
	for _, waiter := range waiters {
		select {
		case waiter <- b:
		default:
		}
	}
}

func (n *Node) safeBroadcast(ctx context.Context, msg p2p.Message) {
	defer func() {
		_ = recover()
	}()
	_ = n.Transport.Broadcast(ctx, msg)
}

type coinFeed struct {
	instance string
	round    uint64
}

func abaVersion(instance string) uint64 {
	version, _ := aba.ConfigVersionFromInstance(instance)
	return version
}

func (n *Node) processPendingABAsLocked(certEpoch uint64) []coinFeed {
	var feeds []coinFeed
	for instance := range n.State.PendingABAs {
		originEpoch, _, _, ok := aba.TupleFromInstance(instance)
		engine := n.ABA
		if !ok || engine == nil {
			continue
		}
		status := engine.Status(instance)
		if status.CoinWait && originEpoch+status.Round+1 == certEpoch {
			feeds = append(feeds, coinFeed{
				instance: instance,
				round:    status.Round,
			})
		}
	}
	return feeds
}

func (n *Node) waitPendingABAAfterSeed(ctx context.Context, feed coinFeed) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		engine := n.ABA
		if engine == nil {
			return
		}
		st := engine.Status(feed.instance)
		n.mu.Lock()
		_, _, _, ok := aba.TupleFromInstance(feed.instance)
		if _, pending := n.State.PendingABAs[feed.instance]; !ok || !pending {
			n.mu.Unlock()
			return
		}
		if st.Decided {
			n.State.ABADecisions[feed.instance] = aba.Decision{
				ConfigVersion: abaVersion(feed.instance), Instance: feed.instance,
				Value: st.Value, FastPath: st.Certificate.FastPath, Certificate: st.Certificate,
			}
			delete(n.State.PendingABAs, feed.instance)
			delete(n.abaInputSent, feed.instance)
			delete(n.abaInputs, feed.instance)
			_ = n.persistLocked()
			n.mu.Unlock()
			engine.Prune(feed.instance)
			return
		}
		if st.CoinWait && st.Round > feed.round {
			n.mu.Unlock()
			return
		}
		n.mu.Unlock()
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return
		}
	}
}

func (n *Node) exclusionWindowLocked() int {
	return 2 * n.State.F
}

func (n *Node) refillSCLLocked() {
	n.State.SCL = eligibleSourceList(n.State.Members, n.State.RSQ)
}

func (n *Node) cleanupEpochStateLocked(epoch uint64) {
	for instance, attempt := range n.epochAttempts {
		if attempt.Epoch <= epoch {
			delete(n.epochAttempts, instance)
		}
	}
	keepSeeds := uint64(n.exclusionWindowLocked() + 2)
	if epoch <= keepSeeds {
		return
	}
	minSeed := epoch - keepSeeds
	protectedSeeds := make(map[uint64]bool)
	for instance, decision := range n.State.ABADecisions {
		originEpoch, _, _, ok := aba.TupleFromInstance(instance)
		if ok && !decision.Certificate.FastPath {
			protectedSeeds[originEpoch+decision.Certificate.Round+1] = true
		}
	}
	for e := range n.beaconSeeds {
		if e < minSeed && !protectedSeeds[e] {
			delete(n.beaconSeeds, e)
		}
	}
	minRecon := epoch - 2
	for key := range n.reconDone {
		if keyEpoch(key) < minRecon {
			delete(n.recon, key)
			delete(n.reconDone, key)
			delete(n.reconClosing, key)
			delete(n.reconSent, key)
			delete(n.beaconVotes, key)
			delete(n.beaconVoteSent, key)
			delete(n.certBeacons, key)
		}
	}
	for key := range n.reconSent {
		if keyEpoch(key) < minRecon {
			delete(n.reconSent, key)
		}
	}
	for key := range n.beaconVotes {
		if keyEpoch(key) < minRecon {
			delete(n.beaconVotes, key)
		}
	}
	for key := range n.certified {
		if keyEpoch(key) < minRecon {
			delete(n.certified, key)
		}
	}
	for key, cached := range n.verified {
		if cached.seq <= n.State.Seqs[cached.producer] {
			delete(n.verified, key)
		}
	}
	for key, cached := range n.verifiedShares {
		if cached.seq <= n.State.Seqs[cached.producer] {
			delete(n.verifiedShares, key)
		}
	}
	for key, bucket := range n.pendingRecon {
		if bucket.ConfigVersion != n.State.ConfigVersion || bucket.Epoch <= n.State.Epoch {
			n.pendingReconCount -= len(bucket.Messages)
			delete(n.pendingRecon, key)
		}
	}
	consumed := make(map[p2p.NodeID]uint64, len(n.State.Seqs))
	for id, seq := range n.State.Seqs {
		consumed[id] = seq
	}
	if engine := n.RBC; engine != nil {
		engine.PruneThrough(consumed)
	}
}

func (n *Node) installBeaconStateLocked(child SchedulingState, qc BeaconQC, skipped []SkippedTuple) {
	n.Schedule = CloneSchedulingState(child)
	qcCopy := qc
	n.LatestBeaconQC = &qcCopy
	n.BeaconHistory = append(n.BeaconHistory, BeaconHistoryLink{Child: CloneSchedulingState(child), QC: qc, Skipped: append([]SkippedTuple(nil), skipped...)})
	n.State.ConfigVersion = child.ConfigVersion
	n.State.F = child.F
	n.State.Epoch = child.Epoch
	n.State.RPrev = append([]byte(nil), child.Random...)
	n.State.Members = append([]p2p.NodeID(nil), child.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), child.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), child.RSQ...)
	n.State.Seqs = cloneSeqMap(child.Seqs)
	for instance := range n.State.ABADecisions {
		_, source, seq, ok := aba.TupleFromInstance(instance)
		if ok && child.Seqs[source] >= seq+1 {
			delete(n.State.ABADecisions, instance)
		}
	}
	for id := range n.State.ComQ {
		if !contains(child.Members, id) {
			continue
		}
		consumed := child.Seqs[id]
		for seq := range n.State.ComQ[id] {
			if seq <= consumed {
				delete(n.State.ComQ[id], seq)
			}
		}
	}
}

func (n *Node) lookupEpochObject(epoch uint64, source p2p.NodeID, seq uint64) (Object, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if epoch != n.State.Epoch+1 {
		return Object{}, errors.New("unexpected epoch")
	}
	entry, ok := n.State.ComQ[source][seq]
	if !ok {
		return Object{}, errors.New("unknown object")
	}
	return entry.Object, nil
}

func (n *Node) CompletedEpoch() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.State.Epoch
}

func (n *Node) currentConfigVersion() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.State.ConfigVersion
}

func (n *Node) IsMember(id p2p.NodeID) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return contains(n.State.Members, id)
}

func (n *Node) MembershipSnapshot() ([]p2p.NodeID, int, uint64, uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]p2p.NodeID(nil), n.State.Members...), n.State.F, n.State.ConfigVersion, n.State.Epoch
}

func (n *Node) DebugSnapshot() DebugSnapshot {
	n.mu.Lock()
	s := DebugSnapshot{
		Node:          n.ID,
		Completed:     n.State.Epoch,
		NextEpoch:     n.State.Epoch + 1,
		ConfigVersion: n.State.ConfigVersion,
		PendingABAs:   len(n.State.PendingABAs),
		VerifiedCache: len(n.verified),
	}
	if len(n.State.SCL) > 0 {
		idx := beaconIndex(n.State.RPrev, len(n.State.SCL))
		s.Source = n.State.SCL[idx]
		s.Seq = n.State.Seqs[s.Source] + 1
		s.Instance = aba.TupleInstanceFor(n.State.ConfigVersion, s.NextEpoch, s.Source, s.Seq)
		key := epochKey(s.NextEpoch, s.Source, s.Seq)
		if entry, ok := n.State.ComQ[s.Source][s.Seq]; ok {
			s.Object = true
			s.ReconNeed = entry.Object.Commitment.Threshold
		}
		if _, ok := n.State.ComQ[s.Source][s.Seq+1]; ok {
			s.NextObject = true
		}
		s.ReconSent = n.reconSent[key]
		s.ReconDone = n.reconDone[key]
		s.ReconCount = len(n.recon[key])
		for voteKey, votes := range n.beaconVotes {
			if keyEpoch(voteKey) == s.NextEpoch && len(votes) > s.BeaconVotes {
				s.BeaconVotes = len(votes)
			}
		}
		s.Certifying = n.certifying[key]
		s.Waiters = len(n.waiters[key])
		s.ABAInputSent = n.abaInputSent[s.Instance]
		s.ABAInput = n.abaInputs[s.Instance]
		for voteKey, certified := range n.certified {
			if certified && keyEpoch(voteKey) == s.NextEpoch {
				s.Certified = true
				break
			}
		}
	}
	n.mu.Unlock()
	if engine := n.abaEngineFor(s.Instance); s.Instance != "" && engine != nil {
		st := engine.Status(s.Instance)
		s.ABADecided = st.Decided
		s.ABACoinWait = st.CoinWait
		s.ABARound = st.Round
		s.ABAInputs = st.Inputs
		s.ABAInputTrue = st.InputTrue
		s.ABAInputFalse = st.InputFalse
		s.ABAFinish = st.Finish
		s.ABABValTrue = st.BValTrue
		s.ABABValFalse = st.BValFalse
		s.ABABinTrue = st.BinTrue
		s.ABABinFalse = st.BinFalse
		s.ABAAux = st.Aux
		s.ABAConf = st.Conf
	}
	if n.Crypto != nil {
		stats := n.Crypto.Stats()
		s.CryptoWorkers = stats.Workers
		s.CryptoActive = stats.Active
		s.CryptoQueued = stats.Queued
	}
	return s
}

func (n *Node) handleABADecision(ctx context.Context, dec aba.Decision) {
	n.relayABADecision(ctx, dec)
	n.mu.Lock()
	engine := n.ABA
	_, _, _, isTuple := aba.TupleFromInstance(dec.Instance)
	if isTuple {
		n.State.ABADecisions[dec.Instance] = dec
		delete(n.State.PendingABAs, dec.Instance)
		delete(n.abaInputSent, dec.Instance)
		delete(n.abaInputs, dec.Instance)
		_ = n.persistLocked()
	}
	n.mu.Unlock()
	if engine != nil {
		engine.Prune(dec.Instance)
	}
}

func (n *Node) relayABADecision(ctx context.Context, dec aba.Decision) {
	if dec.Instance == "" || dec.Certificate.Instance != dec.Instance {
		return
	}
	n.mu.Lock()
	configuration := n.Configuration
	relay := false
	if configuration.Version == dec.ConfigVersion {
		for index, member := range configuration.Members {
			if index >= configuration.F+1 {
				break
			}
			if member == n.ID {
				relay = true
				break
			}
		}
	}
	if !relay {
		n.mu.Unlock()
		return
	}
	if n.abaCertRelayed[dec.Instance] {
		n.mu.Unlock()
		return
	}
	n.abaCertRelayed[dec.Instance] = true
	n.mu.Unlock()
	for _, member := range configuration.Members {
		if member == n.ID {
			continue
		}
		msg, err := p2p.NewMessage(
			Protocol, "ABA_CERT", dec.Instance, n.ID, member,
			certifiedABADecision{Certificate: dec.Certificate},
		)
		if err == nil {
			_ = n.Transport.Send(ctx, member, msg)
		}
	}
}

// handleCertifiedABADecision implements the paper's reliable dissemination
// of transferable ABA evidence. A recipient verifies the old configuration's
// quorum and the exact beacon assigned to the deciding round, then raises the
// same local Decide event; this is certificate catch-up, not another ABA.
func (n *Node) handleCertifiedABADecision(ctx context.Context, dec aba.Decision) error {
	cert := dec.Certificate
	if cert.Instance != dec.Instance || cert.ConfigVersion != dec.ConfigVersion ||
		cert.Value != dec.Value || cert.FastPath != dec.FastPath || cert.Purpose != "control" {
		return errors.New("malformed ABA decision certificate")
	}
	n.mu.Lock()
	configuration := n.Configuration
	engine := n.ABA
	seed, ready := n.abaDecisionSeedLocked(dec)
	if configuration.Version != dec.ConfigVersion || engine == nil {
		n.mu.Unlock()
		return nil
	}
	status := engine.Status(dec.Instance)
	if status.Decided {
		n.mu.Unlock()
		if status.Value != dec.Value {
			return errors.New("conflicting ABA decision certificate")
		}
		return nil
	}
	if !ready {
		n.pendingABACerts[dec.Instance] = dec
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	if err := aba.VerifyCertificate(cert, configuration.PublicKeys(), configuration.Q, seed); err != nil {
		return err
	}
	if !engine.AdoptVerifiedDecision(cert) {
		return errors.New("conflicting ABA decision certificate")
	}
	n.mu.Lock()
	delete(n.pendingABACerts, dec.Instance)
	n.mu.Unlock()
	n.handleABADecision(ctx, dec)
	return nil
}

// abaDecisionSeedLocked returns ready=false until both the local protocol
// context and the certified seed needed to validate a regular certificate are
// available. Fast-path certificates do not use a beacon seed.
func (n *Node) abaDecisionSeedLocked(dec aba.Decision) ([]byte, bool) {
	if originEpoch, _, _, ok := aba.TupleFromInstance(dec.Instance); ok {
		if dec.FastPath {
			return nil, true
		}
		seed := n.beaconSeeds[originEpoch+dec.Certificate.Round+1]
		return append([]byte(nil), seed...), len(seed) > 0
	}
	return nil, false
}

func (n *Node) retryPendingABACertificates(ctx context.Context) {
	n.mu.Lock()
	decisions := make([]aba.Decision, 0, len(n.pendingABACerts))
	for _, decision := range n.pendingABACerts {
		decisions = append(decisions, decision)
	}
	n.mu.Unlock()
	for _, decision := range decisions {
		_ = n.handleCertifiedABADecision(ctx, decision)
	}
}

func (n *Node) handleCoinRequest(req aba.CoinRequest) {
	n.mu.Lock()
	engine := n.ABA
	var seed []byte
	originEpoch, _, _, isTuple := aba.TupleFromInstance(req.Instance)
	if isTuple {
		n.State.PendingABAs[req.Instance] = struct{}{}
		target := originEpoch + req.Round + 1
		if known := n.beaconSeeds[target]; len(known) > 0 {
			seed = append([]byte(nil), known...)
		}
	}
	n.mu.Unlock()
	if engine != nil && len(seed) > 0 {
		engine.FeedSeed(context.Background(), req.Instance, req.Round, seed)
	}
}

func epochKey(epoch uint64, source p2p.NodeID, seq uint64) string {
	return fmt.Sprintf("epoch/%d/%s/%d", epoch, source, seq)
}

func reconInstance(configVersion, epoch uint64, parentHash string, source p2p.NodeID, seq uint64) string {
	return fmt.Sprintf("recon/%d/%d/%s/%s/%d", configVersion, epoch, parentHash, source, seq)
}

func parseReconInstance(instance string) (reconScope, bool) {
	parts := strings.Split(instance, "/")
	if len(parts) != 6 || parts[0] != "recon" || parts[3] == "" || parts[4] == "" {
		return reconScope{}, false
	}
	version, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return reconScope{}, false
	}
	epoch, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || epoch == 0 {
		return reconScope{}, false
	}
	seq, err := strconv.ParseUint(parts[5], 10, 64)
	if err != nil || seq == 0 {
		return reconScope{}, false
	}
	return reconScope{ConfigVersion: version, Epoch: epoch, ParentHash: parts[3], Source: p2p.NodeID(parts[4]), Seq: seq}, true
}

func beaconVoteKey(body signedBeaconMessage) string {
	transcript := BeaconVoteTranscript(
		body.ConfigVersion, body.Epoch, body.ParentHash, body.SkippedHash,
		body.Source, body.Seq, body.Random,
	)
	return fmt.Sprintf("epoch/%d/vote/%x", body.Epoch, crypto.DomainHash("Tyche/BeaconVoteBucket/v1", transcript))
}

func beaconIndex(random []byte, size int) int {
	if size <= 0 {
		return 0
	}
	x := new(big.Int).SetBytes(random)
	return int(new(big.Int).Mod(x, big.NewInt(int64(size))).Int64())
}

func consumerEpochKey(configVersion, epoch uint64) string {
	return fmt.Sprintf("consumer/%d/epoch/%d", configVersion, epoch)
}

func verifySkippedCertificates(configurations map[uint64]Configuration, seeds map[uint64][]byte, skipped []SkippedTuple) error {
	for _, item := range skipped {
		cert := item.Certificate
		originEpoch, source, seq, ok := aba.TupleFromInstance(cert.Instance)
		if !ok || source != item.Source || seq+1 != item.Seq || cert.Value || cert.FastPath {
			return errors.New("invalid tuple-bound skip certificate")
		}
		configuration, ok := configurations[cert.ConfigVersion]
		if !ok {
			return fmt.Errorf("missing configuration %d for skip certificate", cert.ConfigVersion)
		}
		seed := seeds[originEpoch+cert.Round+1]
		if err := aba.VerifyCertificate(cert, configuration.PublicKeys(), configuration.Q, seed); err != nil {
			return fmt.Errorf("invalid skip certificate for (%s,%d): %w", item.Source, item.Seq, err)
		}
	}
	return nil
}

func selectionIndex(epoch uint64, random []byte, attempt, size int) int {
	if size <= 0 {
		return 0
	}
	digest := crypto.DomainHash(
		"Tyche/SourceSelection/v1", random,
		[]byte(fmt.Sprintf("%d", epoch)), []byte(fmt.Sprintf("%d", attempt)),
	)
	return beaconIndex(digest, size)
}

func keyEpoch(key string) uint64 {
	var epoch uint64
	if _, err := fmt.Sscanf(key, "epoch/%d/", &epoch); err != nil {
		return 0
	}
	return epoch
}

func objectCacheKey(obj Object) string {
	// SecretID is protocol-visible metadata. Hash the complete commitment so a
	// malformed object cannot reuse another object's cached verification result.
	return fmt.Sprintf("%d/%x", obj.ConfigVersion,
		crypto.DomainHash("Tyche/PVSSObjectCache/v1", canonicalJSON(obj.Commitment)))
}

func normalizeMembers(in []p2p.NodeID) []p2p.NodeID {
	out := append([]p2p.NodeID(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func contains(ids []p2p.NodeID, id p2p.NodeID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

func sameMembers(a []p2p.NodeID, b []p2p.NodeID) bool {
	aa := normalizeMembers(a)
	bb := normalizeMembers(b)
	if len(aa) != len(bb) {
		return false
	}
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func removeID(ids []p2p.NodeID, id p2p.NodeID) []p2p.NodeID {
	out := ids[:0]
	for _, v := range ids {
		if v != id {
			out = append(out, v)
		}
	}
	return out
}

func canonicalJSON(v any) []byte {
	raw, _ := json.Marshal(v)
	return raw
}
