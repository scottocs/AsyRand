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

type Beacon struct {
	Epoch         uint64       `json:"epoch"`
	Source        p2p.NodeID   `json:"source"`
	Seq           uint64       `json:"seq"`
	PrevRandom    []byte       `json:"prev_random"`
	Random        []byte       `json:"random"`
	Secret        []byte       `json:"secret"`
	ObjectID      string       `json:"object_id"`
	BeaconSigners []p2p.NodeID `json:"beacon_signers"`
	ConfigVersion uint64       `json:"config_version"`
	QC            BeaconQC     `json:"beacon_qc"`
}

type Config struct {
	ID                 p2p.NodeID
	Members            []p2p.NodeID
	Learner            bool
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
	Store                    StateStore
	BootstrapCheckpoint      *CertifiedCheckpoint
	HistoricalConfigurations []Configuration
}

type State struct {
	ConfigVersion uint64
	Members       []p2p.NodeID
	F             int
	Epoch         uint64
	RPrev         []byte
	SCL           []p2p.NodeID
	RSQ           []p2p.NodeID
	ComQ          map[p2p.NodeID]map[uint64]Object
	Seqs          map[p2p.NodeID]uint64
	RmMark        map[p2p.NodeID]RemovalMark
	PendingABAs   map[uint64]*PendingABA
	QueueLen      int
	ProducerSeq   uint64
}

type PendingABA struct {
	ConfigVersion uint64     `json:"config_version"`
	Epoch         uint64     `json:"epoch"`
	Source        p2p.NodeID `json:"source"`
	Seq           uint64     `json:"seq"`
	Round         uint64     `json:"round"`
	CoinWait      bool       `json:"coin_wait"`
}

type RemovalMark struct {
	Seq           uint64          `json:"seq"`
	ConfigVersion uint64          `json:"config_version"`
	Epoch         uint64          `json:"epoch"`
	Certificate   aba.Certificate `json:"certificate"`
}

type envelope struct {
	Kind   string       `json:"kind"`
	Object *Object      `json:"object,omitempty"`
	Join   *JoinRequest `json:"join,omitempty"`
}

type ReconMessage struct {
	ConfigVersion       uint64                `json:"config_version"`
	ObjectConfigVersion uint64                `json:"object_config_version"`
	Epoch               uint64                `json:"epoch"`
	Source              p2p.NodeID            `json:"source"`
	Seq                 uint64                `json:"seq"`
	ObjectID            string                `json:"object_id"`
	Share               crypto.DecryptedShare `json:"share"`
}

type pendingReconBucket struct {
	ConfigVersion       uint64
	ObjectConfigVersion uint64
	Epoch               uint64
	Source              p2p.NodeID
	Seq                 uint64
	Messages            map[p2p.NodeID]ReconMessage
}

type signedBeaconMessage struct {
	ConfigVersion uint64            `json:"config_version"`
	Epoch         uint64            `json:"epoch"`
	ParentHash    string            `json:"parent_hash"`
	Source        p2p.NodeID        `json:"source"`
	Seq           uint64            `json:"seq"`
	Random        []byte            `json:"random"`
	Signature     crypto.SignedVote `json:"signature"`
}

type certifiedABADecision struct {
	Decision aba.Decision `json:"decision"`
}

type certifiedBeaconRecord struct {
	QC BeaconQC `json:"qc"`
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
}

var errRestartEpoch = errors.New("epoch control state changed; restart Step 0")

type Node struct {
	ID                  p2p.NodeID
	Transport           p2p.Transport
	PVSS                crypto.PVSSScheme
	Perf                *PerfMetrics
	RBC                 *rbc.Broadcaster
	JoinRBC             *rbc.Broadcaster
	ABA                 *aba.Agreement
	RBCs                map[uint64]*rbc.Broadcaster
	JoinRBCs            map[uint64]*rbc.Broadcaster
	ABAs                map[uint64]*aba.Agreement
	engineStarted       map[uint64]bool
	protocolContext     context.Context
	Crypto              *cryptoexec.Executor
	Configurations      map[uint64]Configuration
	ConfigurationSetups map[uint64]ConfigurationSetup
	CandidateSetups     map[string]ConfigurationSetup
	Schedule            SchedulingState
	LatestBeaconQC      *BeaconQC
	HistoryAnchor       SchedulingState
	BeaconHistory       []BeaconHistoryLink
	IdentityPrivate     ed25519.PrivateKey
	allowInsecureSetup  bool
	PVSSContexts        map[uint64]*PVSSContext
	RBCCertificates     map[string]rbc.DeliveryCertificate
	Store               StateStore

	mu                sync.Mutex
	State             *State
	recon             map[string]map[p2p.NodeID]crypto.DecryptedShare
	reconSecret       map[string][]byte
	reconDone         map[string]bool
	reconClosing      map[string]bool
	pendingRecon      map[string]*pendingReconBucket
	pendingReconCount int
	beaconVotes       map[string]map[p2p.NodeID]crypto.SignedVote
	beaconVoteSent    map[string]bool
	reconSent         map[string]bool
	certified         map[string]bool
	PendingJoin       *PendingJoin
	pendingJoinCert   *JoinDecisionCertificate
	joinProposals     map[string]JoinRequest
	deferredJoinABA   map[string][]p2p.Message
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
	Joins   chan JoinCertificate
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
		ComQ:          make(map[p2p.NodeID]map[uint64]Object),
		Seqs:          make(map[p2p.NodeID]uint64),
		RmMark:        make(map[p2p.NodeID]RemovalMark),
		PendingABAs:   make(map[uint64]*PendingABA),
		QueueLen:      queueLen,
	}
	for _, id := range members {
		st.ComQ[id] = make(map[uint64]Object)
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
	var joinRBCEngine *rbc.Broadcaster
	var abaEngine *aba.Agreement
	if configuration.Contains(cfg.ID) {
		rbcEngine, err = rbc.NewAuthenticated(cfg.ID, cfg.ConfigVersion, "pvss", members, f, cfg.Transport, identityPrivate, configuration.PublicKeys())
		if err != nil {
			return nil, err
		}
		joinRBCEngine, err = rbc.NewAuthenticated(cfg.ID, cfg.ConfigVersion, "join", members, f, cfg.Transport, identityPrivate, configuration.PublicKeys())
		if err != nil {
			return nil, err
		}
		abaEngine, err = aba.NewAuthenticated(cfg.ID, cfg.ConfigVersion, "control", members, f, cfg.Transport, identityPrivate, configuration.PublicKeys())
		if err != nil {
			return nil, err
		}
	} else if !cfg.Learner {
		return nil, fmt.Errorf("node %s is not a member; configure it explicitly as a learner", cfg.ID)
	}
	schedule := schedulingStateFromRuntime(st, configuration)
	n := &Node{
		ID: cfg.ID, Transport: cfg.Transport, PVSS: cfg.PVSS, Perf: &PerfMetrics{},
		RBC:            rbcEngine,
		JoinRBC:        joinRBCEngine,
		ABA:            abaEngine,
		RBCs:           make(map[uint64]*rbc.Broadcaster),
		JoinRBCs:       make(map[uint64]*rbc.Broadcaster),
		ABAs:           make(map[uint64]*aba.Agreement),
		engineStarted:  make(map[uint64]bool),
		Crypto:         cryptoexec.New(cfg.CryptoWorkers),
		State:          st,
		Configurations: map[uint64]Configuration{configuration.Version: configuration},
		ConfigurationSetups: map[uint64]ConfigurationSetup{
			configuration.Version: {
				Configuration: configuration,
				Params:        params,
				Scheme:        cfg.PVSS,
			},
		},
		CandidateSetups:    make(map[string]ConfigurationSetup),
		Schedule:           schedule,
		HistoryAnchor:      CloneSchedulingState(schedule),
		IdentityPrivate:    append(ed25519.PrivateKey(nil), identityPrivate...),
		allowInsecureSetup: cfg.InsecureDeterministicIdentity,
		PVSSContexts: map[uint64]*PVSSContext{
			cfg.ConfigVersion: {
				Configuration: configuration,
				Params:        params,
				Scheme:        cfg.PVSS,
				Status:        PVSSActive,
			},
		},
		RBCCertificates: make(map[string]rbc.DeliveryCertificate),
		Store:           cfg.Store,
		recon:           make(map[string]map[p2p.NodeID]crypto.DecryptedShare), reconSecret: make(map[string][]byte), reconDone: make(map[string]bool), reconClosing: make(map[string]bool),
		pendingRecon:   make(map[string]*pendingReconBucket),
		beaconVotes:    make(map[string]map[p2p.NodeID]crypto.SignedVote),
		beaconVoteSent: make(map[string]bool), reconSent: make(map[string]bool), certified: make(map[string]bool),
		joinProposals:     make(map[string]JoinRequest),
		deferredJoinABA:   make(map[string][]p2p.Message),
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
		producing:         configuration.Contains(cfg.ID),
		waiters:           make(map[string][]chan Beacon),
		certBeacons:       make(map[string]Beacon),
		certifying:        make(map[string]bool),
		Beacons:           make(chan Beacon, len(members)*4), Joins: make(chan JoinCertificate, len(members)*2),
	}
	if rbcEngine != nil {
		n.RBCs[cfg.ConfigVersion] = rbcEngine
		n.JoinRBCs[cfg.ConfigVersion] = joinRBCEngine
		n.ABAs[cfg.ConfigVersion] = abaEngine
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
	for _, historical := range cfg.HistoricalConfigurations {
		if err := historical.Validate(); err != nil {
			return nil, fmt.Errorf("invalid historical configuration %d: %w", historical.Version, err)
		}
		if existing, ok := n.Configurations[historical.Version]; ok && existing.Digest() != historical.Digest() {
			return nil, fmt.Errorf("conflicting historical configuration %d", historical.Version)
		}
		n.Configurations[historical.Version] = historical
	}
	if cfg.BootstrapCheckpoint != nil {
		if err := n.bootstrapCheckpoint(*cfg.BootstrapCheckpoint); err != nil {
			return nil, err
		}
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
	n.startProtocolEngineCollectorsLocked(ctx, n.State.ConfigVersion)
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

func (n *Node) startProtocolEngineCollectorsLocked(ctx context.Context, version uint64) {
	if n.engineStarted[version] {
		return
	}
	rbcEngine := n.RBCs[version]
	joinRBCEngine := n.JoinRBCs[version]
	abaEngine := n.ABAs[version]
	if rbcEngine == nil || joinRBCEngine == nil || abaEngine == nil {
		return
	}
	n.engineStarted[version] = true
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
			case delivery := <-joinRBCEngine.Deliveries:
				if err := n.handleRBCDelivery(ctx, delivery); err != nil {
					debugf("node=%s reject joining RBC delivery config=%d dealer=%s err=%v", n.ID, delivery.ConfigVersion, delivery.Dealer, err)
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
	version, ok := rbc.ConfigVersionFromInstance(msg.Instance)
	if !ok {
		return nil
	}
	n.mu.Lock()
	purpose, purposeOK := rbc.PurposeFromInstance(msg.Instance)
	engine := n.RBCs[version]
	if purposeOK && purpose == "join" {
		engine = n.JoinRBCs[version]
	}
	n.mu.Unlock()
	if engine == nil {
		return nil
	}
	if purposeOK && purpose == "join" && msg.Type == "VAL" {
		if err := n.prepareExternalJoinRBC(msg, engine); err != nil {
			return nil
		}
	}
	start := time.Now()
	err := engine.Handle(ctx, msg)
	if n.Perf != nil {
		n.Perf.addRBCHandle(time.Since(start))
	}
	return err
}

func (n *Node) handleABAMessage(ctx context.Context, msg p2p.Message) error {
	version, ok := aba.ConfigVersionFromInstance(msg.Instance)
	if !ok {
		return nil
	}
	n.mu.Lock()
	engine := n.ABAs[version]
	if joiner, isJoin := aba.JoinerFromInstance(msg.Instance); isJoin {
		if n.PendingJoin == nil {
			limit := len(n.State.Members) * 8
			_, known := n.deferredJoinABA[msg.Instance]
			if (known || len(n.deferredJoinABA) < len(n.State.Members)) &&
				len(n.deferredJoinABA[msg.Instance]) < limit {
				n.deferredJoinABA[msg.Instance] = append(n.deferredJoinABA[msg.Instance], msg)
			}
			n.mu.Unlock()
			return nil
		}
		req := n.PendingJoin.Proposal
		expected := aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner))
		if version != req.ConfigVersion || joiner != string(req.Joiner) || msg.Instance != expected {
			n.mu.Unlock()
			return nil
		}
		if n.PendingJoin.Phase == JoinReserved {
			limit := len(n.State.Members) * 8
			if len(n.deferredJoinABA[msg.Instance]) < limit {
				n.deferredJoinABA[msg.Instance] = append(n.deferredJoinABA[msg.Instance], msg)
			}
			n.mu.Unlock()
			return nil
		}
	}
	n.mu.Unlock()
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
	if obj, ok := n.State.ComQ[n.ID][seq]; ok && obj.ConfigVersion == version {
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
		obj, err := n.produceSeq(ctx, seq, version)
		if err != nil {
			n.finishProducerSeq(seq)
			n.rollbackProducerSeq(seq)
			return seq, err
		}
		if err := n.storeObject(obj); err != nil {
			n.finishProducerSeq(seq)
			n.rollbackProducerSeq(seq)
			return seq, err
		}
		n.finishProducerSeq(seq)
		return seq, nil
	}
	n.mu.Unlock()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		n.mu.Lock()
		obj, ok := n.State.ComQ[n.ID][seq]
		currentVersion := n.State.ConfigVersion
		n.mu.Unlock()
		if currentVersion != version {
			return seq, fmt.Errorf("configuration changed while producing current object: start=%d current=%d", version, currentVersion)
		}
		if ok && obj.ConfigVersion == currentVersion {
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
		return Beacon{}, errors.New("learner or removed node cannot drive an epoch before activation")
	}
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return b, nil
		}
		if err := n.maybeStartJoin(ctx); err != nil {
			return Beacon{}, err
		}
		if err := n.maybeInstallJoin(ctx); err != nil {
			return Beacon{}, err
		}
		source, seq, instance, skipCurrentABA, alreadyCertified, err := n.prepareEpoch(epoch)
		if err != nil {
			return Beacon{}, err
		}
		// Establishing the local instance may make an earlier transferable
		// certificate verifiable. Replay that certified event now.
		n.retryPendingABACertificates(ctx)
		if skipCurrentABA {
			if err := n.runCertifiedRemoval(ctx, source); err != nil {
				return Beacon{}, err
			}
			// REMOVE preserves the epoch and randomness. Re-evaluate the source
			// against the newly certified configuration for this same epoch.
			continue
		}
		wait := n.registerBeaconWaiter(epoch, source, seq)
		if alreadyCertified {
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, instance, wait)
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return b, err
		}
		obj, certified, err := n.waitObjectOrBeacon(ctx, epoch, source, seq, instance, wait)
		if err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if errors.Is(err, errRestartEpoch) {
				continue
			}
			return Beacon{}, err
		}
		if certified != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return *certified, nil
		}

		if !skipCurrentABA {
			if certified, err := n.proposeEpochABAInputFromLookahead(ctx, epoch, source, seq, instance, wait); err != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				if errors.Is(err, errRestartEpoch) {
					continue
				}
				return Beacon{}, err
			} else if certified != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return *certified, nil
			}
			if err := n.waitCurrentABAReady(ctx, instance); err != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				if errors.Is(err, errRestartEpoch) {
					continue
				}
				return Beacon{}, err
			}
		}
		if err := n.waitCoinBarrier(ctx, epoch); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if errors.Is(err, errRestartEpoch) {
				continue
			}
			return Beacon{}, err
		}
		if n.epochAttemptMustRestart(instance, source, seq) {
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
		origin := n.PVSSContexts[obj.ConfigVersion]
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
				ConfigVersion:       abaVersion(instance),
				ObjectConfigVersion: obj.ConfigVersion,
				Epoch:               epoch,
				Source:              source,
				Seq:                 seq,
				ObjectID:            obj.Commitment.SecretID,
				Share:               sh,
			}
			msg, err := p2p.NewMessage(Protocol, "RECON", instance, n.ID, "", recon)
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
	n.mu.Lock()
	defer n.mu.Unlock()
	mark, marked := n.State.RmMark[source]
	return marked && mark.Seq == seq
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
				return b.Source, b.Seq, aba.EpochInstanceFor(b.ConfigVersion, epoch), false, true, nil
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
	if len(n.State.SCL) == 0 {
		n.mu.Unlock()
		return "", 0, "", false, false, errors.New("empty source candidate list")
	}
	idx := beaconIndex(n.State.RPrev, len(n.State.SCL))
	source := n.State.SCL[idx]
	seq := n.State.Seqs[source] + 1
	instance := aba.EpochInstanceFor(n.State.ConfigVersion, epoch)
	mark, marked := n.State.RmMark[source]
	skipCurrentABA := marked && seq == mark.Seq
	if !skipCurrentABA {
		if _, exists := n.epochAttempts[instance]; !exists {
			n.epochAttempts[instance] = epochAttempt{
				ConfigVersion: n.State.ConfigVersion,
				Epoch:         epoch,
				ParentHash:    n.Schedule.BeaconHead,
				Source:        source,
				Seq:           seq,
				PrevRandom:    append([]byte(nil), n.State.RPrev...),
			}
		}
	}
	if !skipCurrentABA && n.State.PendingABAs[epoch] == nil {
		n.State.PendingABAs[epoch] = &PendingABA{
			ConfigVersion: n.State.ConfigVersion,
			Epoch:         epoch, Source: source, Seq: seq,
		}
	}
	n.mu.Unlock()
	return source, seq, instance, skipCurrentABA, false, nil
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
		obj, ok := n.State.ComQ[source][seq]
		n.mu.Unlock()
		if ok {
			debugf("node=%s step0-current-object-ready epoch=%d source=%s seq=%d instance=%s", n.ID, epoch, source, seq, instance)
			return obj, nil, nil
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
		n.mu.Lock()
		epoch, _ := aba.EpochFromInstance(instance)
		pending := n.State.PendingABAs[epoch]
		removalDue := false
		if pending != nil {
			mark, marked := n.State.RmMark[pending.Source]
			removalDue = marked && mark.Seq == pending.Seq
		}
		n.mu.Unlock()
		if removalDue {
			return errRestartEpoch
		}
		engine := n.abaEngineFor(instance)
		if engine == nil {
			return errors.New("missing epoch ABA engine")
		}
		st := engine.Status(instance)
		if st.Decided || st.CoinWait {
			return nil
		}
		n.mu.Lock()
		epoch, _ = aba.EpochFromInstance(instance)
		_, pendingExists := n.State.PendingABAs[epoch]
		input, hasInput := n.abaInputs[instance]
		n.mu.Unlock()
		if !pendingExists {
			return nil
		}
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

func (n *Node) waitCoinBarrier(ctx context.Context, currentEpoch uint64) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		blocked, feeds := n.refreshPendingABAs(currentEpoch)
		for _, feed := range feeds {
			if engine := n.abaEngineFor(feed.instance); engine != nil {
				engine.FeedSeed(ctx, feed.instance, feed.round, feed.seed)
			}
		}
		if !blocked {
			return nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (n *Node) abaEngineFor(instance string) *aba.Agreement {
	version, ok := aba.ConfigVersionFromInstance(instance)
	if !ok {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.ABAs[version]
}

type seedFeed struct {
	instance string
	round    uint64
	seed     []byte
}

func (n *Node) refreshPendingABAs(currentEpoch uint64) (bool, []seedFeed) {
	n.mu.Lock()
	epochs := make([]uint64, 0, len(n.State.PendingABAs))
	for epoch := range n.State.PendingABAs {
		epochs = append(epochs, epoch)
	}
	n.mu.Unlock()

	statuses := make(map[uint64]aba.Status, len(epochs))
	for _, epoch := range epochs {
		n.mu.Lock()
		p := n.State.PendingABAs[epoch]
		n.mu.Unlock()
		if p != nil {
			instance := aba.EpochInstanceFor(p.ConfigVersion, epoch)
			if engine := n.abaEngineFor(instance); engine != nil {
				statuses[epoch] = engine.Status(instance)
			}
		}
	}

	n.mu.Lock()
	var feeds []seedFeed
	var pruned []string
	blocked := false
	stateChanged := false
	for _, epoch := range epochs {
		p := n.State.PendingABAs[epoch]
		if p == nil {
			continue
		}
		instance := aba.EpochInstanceFor(p.ConfigVersion, epoch)
		st := statuses[epoch]
		if st.Decided {
			if !st.Value {
				n.markRemovalLocked(p, st.Certificate)
			}
			delete(n.State.PendingABAs, epoch)
			delete(n.abaInputSent, instance)
			delete(n.abaInputs, instance)
			pruned = append(pruned, instance)
			stateChanged = true
			continue
		}
		p.Round = st.Round
		p.CoinWait = st.CoinWait
		if st.CoinWait {
			target := p.Epoch + st.Round + 1
			if seed := n.beaconSeeds[target]; len(seed) > 0 {
				p.CoinWait = false
				feeds = append(feeds, seedFeed{instance: instance, round: st.Round, seed: append([]byte(nil), seed...)})
			} else {
				n.noteJoinControlLocked()
			}
		}
		if epoch != currentEpoch && !p.CoinWait {
			blocked = true
		}
	}
	if stateChanged {
		_ = n.persistLocked()
	}
	n.mu.Unlock()
	for _, inst := range pruned {
		n.mu.Lock()
		engine := n.ABAs[abaVersion(inst)]
		n.mu.Unlock()
		if engine != nil {
			engine.Prune(inst)
		}
	}
	return blocked, feeds
}

func (n *Node) handleRBCDelivery(ctx context.Context, d rbc.Delivery) error {
	n.mu.Lock()
	engine := n.RBCs[d.ConfigVersion]
	if d.Purpose == "join" {
		engine = n.JoinRBCs[d.ConfigVersion]
	}
	n.mu.Unlock()
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
		n.mu.Lock()
		n.RBCCertificates[rbcCertificateKey(obj.ConfigVersion, obj.Commitment.SecretID)] = d.Certificate
		n.mu.Unlock()
		n.Crypto.Go(ctx, func() {
			if err := n.storeObject(obj); err != nil {
				return
			}
			n.replayPendingRecon(ctx, obj)
		})
		return nil
	case "join":
		if env.Join == nil {
			return nil
		}
		return n.handleJoinDelivery(ctx, d, *env.Join)
	default:
		return nil
	}
}

func (n *Node) storeObject(obj Object) error {
	if obj.Producer == "" || obj.Seq == 0 || obj.Commitment.Dealer != obj.Producer || obj.Commitment.Seq != obj.Seq {
		debugf("node=%s drop object producer=%s seq=%d reason=invalid", n.ID, obj.Producer, obj.Seq)
		return errors.New("invalid pvss object")
	}
	if obj.Producer == n.ID {
		defer n.finishProducerSeq(obj.Seq)
	}
	n.mu.Lock()
	origin := n.PVSSContexts[obj.ConfigVersion]
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
	maxSeq := n.State.Seqs[obj.Producer] + uint64(n.State.QueueLen)
	if obj.Seq < nextSeq || obj.Seq > maxSeq {
		n.mu.Unlock()
		debugf("node=%s drop object producer=%s seq=%d reason=window next=%d max=%d", n.ID, obj.Producer, obj.Seq, nextSeq, maxSeq)
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
	if n.PVSSContexts[obj.ConfigVersion] == nil ||
		!contains(n.State.Members, obj.Producer) {
		return nil
	}
	if n.State.ComQ[obj.Producer] == nil {
		return nil
	}
	nextSeq = n.State.Seqs[obj.Producer] + 1
	maxSeq = n.State.Seqs[obj.Producer] + uint64(n.State.QueueLen)
	if obj.Seq < nextSeq || obj.Seq > maxSeq {
		debugf("node=%s drop object producer=%s seq=%d reason=window next=%d max=%d", n.ID, obj.Producer, obj.Seq, nextSeq, maxSeq)
		return nil
	}
	if _, exists := n.State.ComQ[obj.Producer][obj.Seq]; exists {
		return nil
	}
	n.State.ComQ[obj.Producer][obj.Seq] = obj
	debugf("node=%s store object producer=%s seq=%d", n.ID, obj.Producer, obj.Seq)
	return nil
}

func (n *Node) ensureVerified(obj Object) error {
	n.mu.Lock()
	pvssContext := n.PVSSContexts[obj.ConfigVersion]
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
		n.Crypto.GoPriority(ctx, func() { _ = n.handleRecon(ctx, from, body) })
	case "BEACON":
		body, err := p2p.DecodePayload[signedBeaconMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		n.Crypto.GoPriority(ctx, func() {
			n.observeBeaconVote(ctx, from, body)
		})
	case "BEACON_CERT":
		body, err := p2p.DecodePayload[certifiedBeaconRecord](msg)
		if err != nil {
			return err
		}
		return n.handleCertifiedBeacon(ctx, body.QC)
	case "JOIN_CERT":
		body, err := p2p.DecodePayload[JoinDecisionCertificate](msg)
		if err != nil {
			return err
		}
		return n.handleJoinCertificate(ctx, body)
	case "ABA_CERT":
		body, err := p2p.DecodePayload[certifiedABADecision](msg)
		if err != nil {
			return err
		}
		return n.handleCertifiedABADecision(ctx, body.Decision)
	}
	return nil
}

func (n *Node) handleRecon(ctx context.Context, from p2p.NodeID, body ReconMessage) error {
	n.mu.Lock()
	if !n.validReconMetadataLocked(from, body) {
		n.mu.Unlock()
		return nil
	}
	obj, available := n.State.ComQ[body.Source][body.Seq]
	if !available {
		n.bufferPendingReconLocked(from, body)
		n.mu.Unlock()
		return nil
	}
	if obj.ConfigVersion != body.ObjectConfigVersion || obj.Commitment.SecretID != body.ObjectID {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	n.broadcastOriginReconOnce(ctx, body, obj)

	key := epochKey(body.Epoch, body.Source, body.Seq)
	n.mu.Lock()
	pvssContext := n.PVSSContexts[obj.ConfigVersion]
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
		debugf("node=%s drop recon from=%s epoch=%d source=%s seq=%d holder=%s valid=%v", n.ID, from, body.Epoch, body.Source, body.Seq, body.Share.Holder, validShare)
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
	attempt, attemptOK := n.epochAttempts[aba.EpochInstanceFor(body.ConfigVersion, body.Epoch)]
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
		[]byte(fmt.Sprintf("%d", body.Epoch)),
		prev,
		secret,
	)
	if n.reconDone[key] {
		n.mu.Unlock()
		return nil
	}
	n.reconDone[key] = true
	n.reconSecret[key] = append([]byte(nil), secret...)
	n.mu.Unlock()
	return n.broadcastBeaconVote(ctx, configVersion, body.Epoch, body.Source, body.Seq, random)
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

// broadcastOriginReconOnce lets an honest historical shareholder contribute
// without introducing a RECON_REQUEST message. Active shareholders have
// already set reconSent on the consumer path, so this emits at most one share.
func (n *Node) broadcastOriginReconOnce(ctx context.Context, body ReconMessage, obj Object) {
	key := epochKey(body.Epoch, body.Source, body.Seq)
	n.mu.Lock()
	origin := n.PVSSContexts[obj.ConfigVersion]
	if origin == nil || origin.Scheme == nil ||
		!origin.Configuration.Contains(n.ID) ||
		contains(n.State.Members, n.ID) || n.reconSent[key] {
		n.mu.Unlock()
		return
	}
	n.reconSent[key] = true
	scheme := origin.Scheme
	n.mu.Unlock()
	share, err := scheme.PreReconVerified(obj.Commitment, n.ID)
	if err != nil {
		n.mu.Lock()
		delete(n.reconSent, key)
		n.mu.Unlock()
		return
	}
	message := ReconMessage{
		ConfigVersion:       body.ConfigVersion,
		ObjectConfigVersion: obj.ConfigVersion,
		Epoch:               body.Epoch,
		Source:              body.Source,
		Seq:                 body.Seq,
		ObjectID:            obj.Commitment.SecretID,
		Share:               share,
	}
	instance := aba.EpochInstanceFor(body.ConfigVersion, body.Epoch)
	wire, err := p2p.NewMessage(Protocol, "RECON", instance, n.ID, "", message)
	if err == nil {
		n.safeBroadcast(ctx, wire)
	}
}

func pendingReconKey(version, epoch uint64, source p2p.NodeID, seq uint64) string {
	return fmt.Sprintf("%d/%d/%s/%d", version, epoch, source, seq)
}

func (n *Node) validReconMetadataLocked(from p2p.NodeID, body ReconMessage) bool {
	instance := aba.EpochInstanceFor(body.ConfigVersion, body.Epoch)
	attempt, opened := n.epochAttempts[instance]
	mark, removalDue := n.State.RmMark[body.Source]
	if !opened || body.ObjectConfigVersion > body.ConfigVersion ||
		body.Epoch != n.State.Epoch+1 ||
		attempt.ParentHash != n.Schedule.BeaconHead ||
		body.Source != attempt.Source || body.Seq != attempt.Seq ||
		body.Seq != n.State.Seqs[body.Source]+1 ||
		(removalDue && mark.Seq == body.Seq) ||
		body.ObjectID == "" ||
		body.Share.CommitmentID != body.ObjectID ||
		body.Share.Holder != from {
		return false
	}
	signing, signingOK := n.Configurations[body.ConfigVersion]
	origin, originOK := n.Configurations[body.ObjectConfigVersion]
	return signingOK && signing.Contains(from) && signing.Contains(body.Source) &&
		originOK && origin.Contains(from) && origin.Contains(body.Source) &&
		contains(n.State.Members, body.Source)
}

func (n *Node) bufferPendingReconLocked(from p2p.NodeID, body ReconMessage) {
	key := pendingReconKey(body.ObjectConfigVersion, body.Epoch, body.Source, body.Seq)
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
			ConfigVersion:       body.ConfigVersion,
			ObjectConfigVersion: body.ObjectConfigVersion,
			Epoch:               body.Epoch,
			Source:              body.Source,
			Seq:                 body.Seq,
			Messages:            make(map[p2p.NodeID]ReconMessage),
		}
		n.pendingRecon[key] = bucket
	}
	if len(bucket.Messages) >= len(n.State.Members) {
		return
	}
	bucket.Messages[from] = body
	n.pendingReconCount++
}

func (n *Node) replayPendingRecon(ctx context.Context, obj Object) {
	n.mu.Lock()
	var pending []struct {
		from p2p.NodeID
		body ReconMessage
	}
	for key, bucket := range n.pendingRecon {
		if bucket.ObjectConfigVersion != obj.ConfigVersion ||
			bucket.Source != obj.Producer ||
			bucket.Seq != obj.Seq {
			continue
		}
		for from, body := range bucket.Messages {
			if body.ObjectID == obj.Commitment.SecretID {
				pending = append(pending, struct {
					from p2p.NodeID
					body ReconMessage
				}{from: from, body: body})
			}
		}
		n.pendingReconCount -= len(bucket.Messages)
		delete(n.pendingRecon, key)
	}
	n.mu.Unlock()
	for _, item := range pending {
		if err := n.handleRecon(ctx, item.from, item.body); err != nil {
			debugf("node=%s reject replayed recon from=%s config=%d source=%s seq=%d err=%v",
				n.ID, item.from, item.body.ConfigVersion, item.body.Source, item.body.Seq, err)
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
	mark, removalDue := n.State.RmMark[source]
	attempt, opened := n.epochAttempts[aba.EpochInstanceFor(configVersion, epoch)]
	if n.beaconVoteSent[key] {
		n.mu.Unlock()
		return nil
	}
	if n.State.Epoch+1 != epoch || (removalDue && mark.Seq == seq) {
		n.mu.Unlock()
		return errRestartEpoch
	}
	if !opened || attempt.Source != source || attempt.Seq != seq ||
		attempt.ParentHash != n.Schedule.BeaconHead {
		n.mu.Unlock()
		return errRestartEpoch
	}
	config, ok := n.Configurations[configVersion]
	parentHash := attempt.ParentHash
	n.mu.Unlock()
	if !ok {
		return errors.New("missing configuration for BEACON vote")
	}
	transcript := BeaconVoteTranscript(config.Version, epoch, parentHash, source, seq, random)
	voteHash := fmt.Sprintf("%x", crypto.DomainHash("Tyche/BeaconVoteReservation/v1", transcript))
	voteSlot := fmt.Sprintf("epoch/%d", epoch)
	if err := n.Store.ReserveBeaconVote(voteSlot, voteHash); err != nil {
		return err
	}
	start := time.Now()
	signature, err := SignBeaconVote(n.ID, n.IdentityPrivate, config, epoch, parentHash, source, seq, random)
	if n.Perf != nil {
		n.Perf.addCertSign(time.Since(start))
	}
	if err != nil {
		return err
	}
	n.mu.Lock()
	mark, removalDue = n.State.RmMark[source]
	if n.beaconVoteSent[key] {
		n.mu.Unlock()
		return nil
	}
	if n.Schedule.BeaconHead != parentHash || (removalDue && mark.Seq == seq) {
		n.mu.Unlock()
		return errRestartEpoch
	}
	n.beaconVoteSent[key] = true
	n.mu.Unlock()
	message := signedBeaconMessage{
		ConfigVersion: config.Version, Epoch: epoch, ParentHash: parentHash,
		Source: source, Seq: seq, Random: append([]byte(nil), random...), Signature: signature,
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
	mark, removalDue := n.State.RmMark[body.Source]
	attempt, opened := n.beaconAttemptLocked(body)
	if n.State.Epoch+1 != body.Epoch ||
		body.ParentHash != n.Schedule.BeaconHead || body.Signature.Signer != string(from) ||
		!opened || attempt.ParentHash != body.ParentHash ||
		attempt.Source != body.Source || attempt.Seq != body.Seq ||
		(removalDue && mark.Seq == body.Seq) || !contains(n.State.Members, body.Source) {
		n.mu.Unlock()
		return
	}
	config, configured := n.Configurations[body.ConfigVersion]
	if !configured || !config.Contains(from) || !config.Contains(body.Source) ||
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
		BeaconVoteTranscript(body.ConfigVersion, body.Epoch, body.ParentHash, body.Source, body.Seq, body.Random),
	)
	if n.Perf != nil {
		n.Perf.addCertVerify(time.Since(start))
	}
	if err != nil {
		return
	}
	n.mu.Lock()
	mark, removalDue = n.State.RmMark[body.Source]
	attempt, opened = n.epochAttempts[aba.EpochInstanceFor(body.ConfigVersion, body.Epoch)]
	if n.State.Epoch+1 != body.Epoch || body.ParentHash != n.Schedule.BeaconHead ||
		!opened || attempt.Source != body.Source || attempt.Seq != body.Seq ||
		(removalDue && mark.Seq == body.Seq) {
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
	senders := make([]p2p.NodeID, 0, len(n.beaconVotes[voteKey]))
	for signer, vote := range n.beaconVotes[voteKey] {
		senders = append(senders, signer)
		votes = append(votes, vote)
	}
	sort.Slice(senders, func(i, j int) bool { return senders[i] < senders[j] })
	n.certified[voteKey] = true
	parent := CloneSchedulingState(n.Schedule)
	n.mu.Unlock()
	start = time.Now()
	qc, err := BuildBeaconQC(config, body.Epoch, body.ParentHash, body.Source, body.Seq, body.Random, votes)
	if n.Perf != nil {
		n.Perf.addCertAggregate(time.Since(start))
	}
	if err != nil {
		return
	}
	n.relayBeaconCertificate(context.Background(), qc)
	child, err := entropySuccessorForRecord(parent, body.ConfigVersion, config.F, body.Random, body.Source, body.Seq)
	if err != nil {
		return
	}
	n.certifyBeacon(body.Epoch, body.Source, body.Seq, body.Random, child, qc, senders)
	_ = ctx
}

// relayBeaconCertificate disseminates the exact-parent certified record P_e.
// This is required by the paper's asynchronous delivery model: a member may
// install a membership decision before receiving the immediately following
// beacon record and must not depend on having observed every individual vote.
func (n *Node) relayBeaconCertificate(ctx context.Context, qc BeaconQC) {
	key := BeaconHeaderHash(qc.ConfigVersion, qc.Epoch, qc.ParentHash, qc.Source, qc.Seq, qc.Random)
	n.mu.Lock()
	configuration, configured := n.Configurations[qc.ConfigVersion]
	parent, hasParent := n.Configurations[qc.ConfigVersion-1]
	if !configured || !hasParent || len(configuration.Members) != len(parent.Members)+1 {
		n.mu.Unlock()
		return
	}
	var target p2p.NodeID
	for _, member := range configuration.Members {
		if !parent.Contains(member) {
			if target != "" {
				n.mu.Unlock()
				return
			}
			target = member
		}
	}
	relay := false
	for index, member := range configuration.Members {
		if index >= configuration.F+1 {
			break
		}
		if member == n.ID {
			relay = true
			break
		}
	}
	if target == "" || !relay {
		n.mu.Unlock()
		return
	}
	if n.beaconCertRelayed[key] {
		n.mu.Unlock()
		return
	}
	n.beaconCertRelayed[key] = true
	n.mu.Unlock()
	msg, err := p2p.NewMessage(
		Protocol, "BEACON_CERT", key, n.ID, target, certifiedBeaconRecord{QC: qc},
	)
	if err == nil {
		_ = n.Transport.Send(ctx, target, msg)
	}
}

func (n *Node) handleCertifiedBeacon(ctx context.Context, qc BeaconQC) error {
	n.mu.Lock()
	configuration, configured := n.Configurations[qc.ConfigVersion]
	if !configured {
		n.mu.Unlock()
		return nil
	}
	if n.State.Epoch >= qc.Epoch {
		n.mu.Unlock()
		return nil
	}
	body := signedBeaconMessage{
		ConfigVersion: qc.ConfigVersion,
		Epoch:         qc.Epoch,
		ParentHash:    qc.ParentHash,
		Source:        qc.Source,
		Seq:           qc.Seq,
		Random:        append([]byte(nil), qc.Random...),
	}
	attempt, opened := n.beaconAttemptLocked(body)
	mark, removalDue := n.State.RmMark[qc.Source]
	validNext := n.State.Epoch+1 == qc.Epoch &&
		n.Schedule.BeaconHead == qc.ParentHash && opened &&
		attempt.Source == qc.Source && attempt.Seq == qc.Seq &&
		(!removalDue || mark.Seq != qc.Seq)
	parent := CloneSchedulingState(n.Schedule)
	n.mu.Unlock()
	if !validNext {
		return nil
	}
	if err := VerifyBeaconQC(configuration, qc); err != nil {
		return err
	}
	signerStrings, err := crypto.SignedQuorumCertificateSigners(qc.Signature, configuration.PublicKeys())
	if err != nil {
		return err
	}
	signers := make([]p2p.NodeID, len(signerStrings))
	for i, signer := range signerStrings {
		signers[i] = p2p.NodeID(signer)
	}
	child, err := entropySuccessorForRecord(parent, qc.ConfigVersion, configuration.F, qc.Random, qc.Source, qc.Seq)
	if err != nil {
		return err
	}
	n.relayBeaconCertificate(ctx, qc)
	n.certifyBeacon(qc.Epoch, qc.Source, qc.Seq, qc.Random, child, qc, signers)
	return nil
}

// beaconAttemptLocked returns the immutable Step-0 context for a vote. A
// joiner or an old member that installed JOIN first may not have opened this
// old-configuration epoch locally. For a one-member addition, filtering the
// new member from the current scheduling lists exactly reconstructs the old
// parent schedule because joining leaves RSQ and all old sequence counters
// unchanged.
func (n *Node) beaconAttemptLocked(body signedBeaconMessage) (epochAttempt, bool) {
	instance := aba.EpochInstanceFor(body.ConfigVersion, body.Epoch)
	if attempt, ok := n.epochAttempts[instance]; ok {
		return attempt, true
	}
	if body.Epoch != n.State.Epoch+1 || body.ParentHash != n.Schedule.BeaconHead {
		return epochAttempt{}, false
	}
	signing, ok := n.Configurations[body.ConfigVersion]
	if !ok {
		return epochAttempt{}, false
	}
	eligible := append([]p2p.NodeID(nil), n.State.SCL...)
	if n.State.ConfigVersion != body.ConfigVersion {
		if len(n.State.Members) != len(signing.Members)+1 {
			return epochAttempt{}, false
		}
		for _, oldMember := range signing.Members {
			if !contains(n.State.Members, oldMember) {
				return epochAttempt{}, false
			}
		}
		filtered := make([]p2p.NodeID, 0, len(signing.Members))
		for _, candidate := range eligible {
			if signing.Contains(candidate) {
				filtered = append(filtered, candidate)
			}
		}
		eligible = filtered
	}
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
	}
	n.epochAttempts[instance] = attempt
	return attempt, true
}

func (n *Node) certifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, child SchedulingState, qc BeaconQC, senders []p2p.NodeID) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	mark, removalDue := n.State.RmMark[source]
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch ||
		(removalDue && mark.Seq == seq) {
		n.mu.Unlock()
		return
	}
	if n.certifying[key] {
		n.mu.Unlock()
		return
	}
	n.certifying[key] = true
	n.mu.Unlock()
	go n.finishCertifyBeacon(epoch, source, seq, random, child, qc, senders)
}

func (n *Node) finishCertifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, child SchedulingState, qc BeaconQC, senders []p2p.NodeID) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	mark, removalDue := n.State.RmMark[source]
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch ||
		(removalDue && mark.Seq == seq) {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	obj := n.State.ComQ[source][seq]
	parent := CloneSchedulingState(n.Schedule)
	parentConfig, configured := n.Configurations[qc.ConfigVersion]
	prev := append([]byte(nil), n.State.RPrev...)
	secret := append([]byte(nil), n.reconSecret[key]...)
	n.mu.Unlock()
	if !configured || VerifyBeaconQC(parentConfig, qc) != nil ||
		qc.Epoch != epoch || qc.ParentHash != parent.BeaconHead ||
		qc.Source != source || qc.Seq != seq || string(qc.Random) != string(random) {
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
	// A membership decision may have been delivered after this old
	// configuration signed P_e. Apply the record to the current scheduling
	// state, preserving the already-installed membership transition.
	effectiveChild, err := entropySuccessorForRecord(n.Schedule, qc.ConfigVersion, parentConfig.F, random, source, seq)
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
	n.installBeaconStateLocked(child, qc)
	if err := n.persistLocked(); err != nil {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	n.beaconSeeds[epoch] = append([]byte(nil), random...)
	feeds := n.processPendingABAsLocked(epoch)
	joinFeed, hasJoinFeed := n.pendingJoinCoinFeedLocked(epoch)
	n.mu.Unlock()
	for _, feed := range feeds {
		n.mu.Lock()
		engine := n.ABAs[abaVersion(feed.instance)]
		n.mu.Unlock()
		if engine == nil {
			continue
		}
		engine.FeedSeed(context.Background(), feed.instance, feed.round, random)
		n.waitPendingABAAfterSeed(context.Background(), feed)
	}
	if hasJoinFeed {
		n.mu.Lock()
		engine := n.ABAs[abaVersion(joinFeed.instance)]
		n.mu.Unlock()
		if engine != nil {
			engine.FeedSeed(context.Background(), joinFeed.instance, joinFeed.round, random)
			n.waitPendingJoinAfterSeed(context.Background(), joinFeed)
		}
	}
	n.mu.Lock()
	if n.State.Epoch != epoch || n.Schedule.BeaconHead != child.BeaconHead {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	// An awakened JOIN-ABA may already have installed c+1.  P_e remains the
	// certified beacon head, so never overwrite that forward transition with
	// the old-configuration child captured above.
	configVersion := qc.ConfigVersion
	if err := n.persistLocked(); err != nil {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	n.cleanupEpochStateLocked(epoch)
	b := Beacon{
		Epoch: epoch, Source: source, Seq: seq, PrevRandom: prev, Random: append([]byte(nil), random...),
		Secret: secret, ObjectID: obj.Commitment.SecretID, BeaconSigners: senders,
		ConfigVersion: configVersion, QC: qc,
	}
	n.certBeacons[key] = b
	delete(n.certifying, key)
	waiters := append([]chan Beacon(nil), n.waiters[key]...)
	delete(n.waiters, key)
	select {
	case n.Beacons <- b:
	default:
	}
	n.mu.Unlock()
	_ = n.maybeStartJoin(context.Background())
	_ = n.maybeInstallJoin(context.Background())
	n.retryPendingABACertificates(context.Background())
	n.retryPendingJoinCertificate(context.Background())
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
	for epoch, p := range n.State.PendingABAs {
		if p.CoinWait && p.Epoch+p.Round+1 == certEpoch {
			feeds = append(feeds, coinFeed{
				instance: aba.EpochInstanceFor(p.ConfigVersion, epoch),
				round:    p.Round,
			})
		}
	}
	return feeds
}

func (n *Node) waitPendingABAAfterSeed(ctx context.Context, feed coinFeed) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		n.mu.Lock()
		engine := n.ABAs[abaVersion(feed.instance)]
		n.mu.Unlock()
		if engine == nil {
			return
		}
		st := engine.Status(feed.instance)
		n.mu.Lock()
		epoch, ok := aba.EpochFromInstance(feed.instance)
		p := n.State.PendingABAs[epoch]
		if !ok || p == nil {
			n.mu.Unlock()
			return
		}
		if st.Decided {
			if !st.Value {
				n.markRemovalLocked(p, st.Certificate)
			}
			delete(n.State.PendingABAs, epoch)
			delete(n.abaInputSent, feed.instance)
			delete(n.abaInputs, feed.instance)
			n.mu.Unlock()
			engine.Prune(feed.instance)
			return
		}
		p.Round = st.Round
		p.CoinWait = st.CoinWait
		if st.CoinWait && st.Round > feed.round {
			if len(n.beaconSeeds[p.Epoch+st.Round+1]) == 0 {
				n.noteJoinControlLocked()
			}
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

func (n *Node) markRemovalLocked(p *PendingABA, certificate aba.Certificate) {
	if p == nil {
		return
	}
	if p.ConfigVersion != n.State.ConfigVersion {
		return
	}
	if _, exists := n.State.RmMark[p.Source]; exists {
		return
	}
	n.State.RmMark[p.Source] = RemovalMark{
		Seq: p.Seq + 1, ConfigVersion: p.ConfigVersion,
		Epoch: p.Epoch, Certificate: certificate,
	}
	n.noteJoinControlLocked()
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
	for _, mark := range n.State.RmMark {
		if !mark.Certificate.FastPath {
			protectedSeeds[mark.Epoch+mark.Certificate.Round+1] = true
		}
	}
	if n.PendingJoin != nil && n.PendingJoin.Phase == JoinDecided &&
		!n.PendingJoin.ABACert.FastPath {
		protectedSeeds[n.PendingJoin.Proposal.AnchorEpoch+n.PendingJoin.ABACert.Round] = true
	}
	for _, proposal := range n.joinProposals {
		for e := proposal.AnchorEpoch; e <= epoch; e++ {
			protectedSeeds[e] = true
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
			delete(n.reconSecret, key)
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
	if engine := n.RBCs[n.State.ConfigVersion]; engine != nil {
		engine.PruneThrough(consumed)
	}
}

func (n *Node) installBeaconStateLocked(child SchedulingState, qc BeaconQC) {
	localMarks := cloneMarkMap(n.State.RmMark)
	n.Schedule = CloneSchedulingState(child)
	qcCopy := qc
	n.LatestBeaconQC = &qcCopy
	n.BeaconHistory = append(n.BeaconHistory, BeaconHistoryLink{Child: CloneSchedulingState(child), QC: qc})
	n.State.ConfigVersion = child.ConfigVersion
	n.State.F = child.F
	n.State.Epoch = child.Epoch
	n.State.RPrev = append([]byte(nil), child.Random...)
	n.State.Members = append([]p2p.NodeID(nil), child.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), child.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), child.RSQ...)
	n.State.Seqs = cloneSeqMap(child.Seqs)
	// rmMark is ABA-certified local control state. It is deliberately not part
	// of P_e and therefore survives installation of the deterministic entropy
	// snapshot independently of the beacon certificate.
	n.State.RmMark = localMarks
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
	obj, ok := n.State.ComQ[source][seq]
	if !ok {
		return Object{}, errors.New("unknown object")
	}
	return obj, nil
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
		s.Instance = aba.EpochInstanceFor(n.State.ConfigVersion, s.NextEpoch)
		key := epochKey(s.NextEpoch, s.Source, s.Seq)
		if obj, ok := n.State.ComQ[s.Source][s.Seq]; ok {
			s.Object = true
			s.ReconNeed = obj.Commitment.Threshold
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
	if n.handleJoinDecision(ctx, dec) {
		n.mu.Lock()
		engine := n.ABAs[dec.ConfigVersion]
		n.mu.Unlock()
		if engine != nil {
			engine.Prune(dec.Instance)
		}
		return
	}
	n.mu.Lock()
	engine := n.ABAs[dec.ConfigVersion]
	epoch, isEpoch := aba.EpochFromInstance(dec.Instance)
	if p := n.State.PendingABAs[epoch]; isEpoch && p != nil &&
		p.ConfigVersion == dec.ConfigVersion {
		if !dec.Value {
			n.markRemovalLocked(p, dec.Certificate)
		}
		delete(n.State.PendingABAs, epoch)
		delete(n.abaInputSent, dec.Instance)
		delete(n.abaInputs, dec.Instance)
		_ = n.persistLocked()
	}
	n.mu.Unlock()
	if engine != nil {
		engine.Prune(dec.Instance)
	}
	_ = n.maybeInstallJoin(ctx)
}

func (n *Node) relayABADecision(ctx context.Context, dec aba.Decision) {
	if dec.Instance == "" || dec.Certificate.Instance != dec.Instance {
		return
	}
	n.mu.Lock()
	configuration, configured := n.Configurations[dec.ConfigVersion]
	relay := false
	if configured {
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
			certifiedABADecision{Decision: dec},
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
	configuration, configured := n.Configurations[dec.ConfigVersion]
	engine := n.ABAs[dec.ConfigVersion]
	seed, ready := n.abaDecisionSeedLocked(dec)
	if !configured || engine == nil {
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
	if epoch, ok := aba.EpochFromInstance(dec.Instance); ok {
		if pending := n.State.PendingABAs[epoch]; pending == nil ||
			pending.ConfigVersion != dec.ConfigVersion {
			return nil, false
		}
		if dec.FastPath {
			return nil, true
		}
		seed := n.beaconSeeds[epoch+dec.Certificate.Round+1]
		return append([]byte(nil), seed...), len(seed) > 0
	}
	joiner, ok := aba.JoinerFromInstance(dec.Instance)
	if !ok || n.PendingJoin == nil ||
		n.PendingJoin.Proposal.ConfigVersion != dec.ConfigVersion ||
		string(n.PendingJoin.Proposal.Joiner) != joiner {
		return nil, false
	}
	if dec.FastPath {
		return nil, true
	}
	seed := n.beaconSeeds[n.PendingJoin.Proposal.AnchorEpoch+dec.Certificate.Round]
	return append([]byte(nil), seed...), len(seed) > 0
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
	engine := n.ABAs[req.ConfigVersion]
	var seed []byte
	if n.PendingJoin != nil {
		join := n.PendingJoin.Proposal
		instance := aba.JoinInstanceFor(join.ConfigVersion, string(join.Joiner))
		if req.Instance == instance {
			target := join.AnchorEpoch + req.Round
			if known := n.beaconSeeds[target]; len(known) > 0 {
				seed = append([]byte(nil), known...)
				n.PendingJoin.CoinWait = false
			} else {
				n.PendingJoin.CoinRound = req.Round
				n.PendingJoin.CoinWait = true
			}
		}
	}
	epoch, isEpoch := aba.EpochFromInstance(req.Instance)
	if p := n.State.PendingABAs[epoch]; isEpoch && p != nil &&
		p.ConfigVersion == req.ConfigVersion {
		p.Round = req.Round
		p.CoinWait = true
		target := p.Epoch + req.Round + 1
		if known := n.beaconSeeds[target]; len(known) > 0 {
			seed = append([]byte(nil), known...)
			p.CoinWait = false
		} else {
			n.noteJoinControlLocked()
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

func beaconVoteKey(body signedBeaconMessage) string {
	transcript := BeaconVoteTranscript(
		body.ConfigVersion, body.Epoch, body.ParentHash,
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
