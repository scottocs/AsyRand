package tyche

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/Tyche/protocol/aba"
	"github.com/scottocs/Tyche/Tyche/protocol/rbc"
	"github.com/scottocs/Tyche/utils/cryptoexec"
	"github.com/scottocs/Tyche/utils/p2p"
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
	Epoch        uint64       `json:"epoch"`
	Source       p2p.NodeID   `json:"source"`
	Seq          uint64       `json:"seq"`
	PrevRandom   []byte       `json:"prev_random"`
	Random       []byte       `json:"random"`
	Secret       []byte       `json:"secret"`
	ObjectID     string       `json:"object_id"`
	ReadySenders []p2p.NodeID `json:"ready_senders"`
	// Signature is the compact READY quorum certificate. ReadySenders records
	// who voted; Signature proves those nodes signed the canonical READY
	// statement for this epoch/source/sequence/random hash.
	Signature     crypto.QuorumCertificate `json:"signature"`
	ConfigVersion uint64                   `json:"config_version"`
	State         CertifiedStateDigest     `json:"state"`
	StateHash     string                   `json:"state_hash"`
}

type BeaconCertificate struct {
	Epoch         uint64                   `json:"epoch"`
	Source        p2p.NodeID               `json:"source"`
	Seq           uint64                   `json:"seq"`
	Random        []byte                   `json:"random"`
	ObjectID      string                   `json:"object_id"`
	Signature     crypto.QuorumCertificate `json:"signature"`
	ConfigVersion uint64                   `json:"config_version"`
	StateHash     string                   `json:"state_hash"`
}

type CertifiedStateDigest struct {
	Members []p2p.NodeID          `json:"members"`
	SCL     []p2p.NodeID          `json:"scl"`
	RSQ     []p2p.NodeID          `json:"rsq"`
	Seqs    map[p2p.NodeID]uint64 `json:"seqs"`
	RmMark  map[p2p.NodeID]int64  `json:"rm_mark"`
}

type Config struct {
	ID           p2p.NodeID
	Members      []p2p.NodeID
	F            int
	QueueLen     int
	ProducerLow  int
	ProducerHigh int
	// RemovalExpiration is the local look-ahead expiration event used before
	// proposing 0 to the epoch-control ABA when the selected source's next FIFO
	// object is not yet available. It is an implementation policy, not a
	// network synchrony assumption.
	RemovalExpiration     time.Duration
	CurrentMissingRemoval bool
	ConfigVersion         uint64
	InitialRandom         []byte
	PVSS                  crypto.PVSSScheme
	PVSSBackend           string
	PVSSKeys              map[string]kyber.Scalar
	CryptoWorkers         int
	Transport             p2p.Transport
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
	RmMark        map[p2p.NodeID]int64
	PendingABAs   map[string]*PendingABA
	PendingReconf map[string]string
	QueueLen      int
	ProducerSeq   uint64
	TransitionSeq uint64
}

type PendingABA struct {
	Instance string     `json:"instance"`
	Epoch    uint64     `json:"epoch"`
	Source   p2p.NodeID `json:"source"`
	Seq      uint64     `json:"seq"`
	Round    uint64     `json:"round"`
	CoinWait bool       `json:"coin_wait"`
	Decided  bool       `json:"decided"`
	Decision bool       `json:"decision"`
}

type envelope struct {
	Kind   string       `json:"kind"`
	Object *Object      `json:"object,omitempty"`
	Join   *JoinRequest `json:"join,omitempty"`
}

type ReconMessage struct {
	Epoch  uint64                `json:"epoch"`
	Source p2p.NodeID            `json:"source"`
	Seq    uint64                `json:"seq"`
	Share  crypto.DecryptedShare `json:"share"`
}

type ReconEchoMessage struct {
	Epoch  uint64     `json:"epoch"`
	Source p2p.NodeID `json:"source"`
	Seq    uint64     `json:"seq"`
	Random []byte     `json:"random"`
}

type ReconReadyMessage ReconEchoMessage

// signedReconReadyMessage carries the signer identity counted for READY quorum
// certification. The READY amplification rule is unchanged.
type signedReconReadyMessage struct {
	Epoch     uint64           `json:"epoch"`
	Source    p2p.NodeID       `json:"source"`
	Seq       uint64           `json:"seq"`
	Random    []byte           `json:"random"`
	StateHash string           `json:"state_hash"`
	Signature crypto.VoteShare `json:"signature"`
}

type Node struct {
	ID        p2p.NodeID
	Transport p2p.Transport
	PVSS      crypto.PVSSScheme
	Perf      *PerfMetrics
	RBC       *rbc.Broadcaster
	ABA       *aba.Agreement
	Crypto    *cryptoexec.Executor

	mu           sync.Mutex
	State        *State
	recon        map[string]map[p2p.NodeID]crypto.DecryptedShare
	reconSecret  map[string][]byte
	reconDone    map[string]bool
	reconClosing map[string]bool
	echoes       map[string]map[string]map[p2p.NodeID]bool
	// readies stores verified READY votes rather than bare sender ids.
	// This lets certification aggregate the exact votes that justified the
	// Bracha-style READY threshold.
	readies               map[string]map[string]map[p2p.NodeID]crypto.VoteShare
	readySent             map[string]bool
	readySentEpoch        map[string]bool
	reconSent             map[string]bool
	certified             map[string]bool
	joinAcks              map[string]map[p2p.NodeID]JoinAck
	joinCommits           map[string]map[p2p.NodeID]JoinCommit
	joinRequests          map[string]JoinRequest
	pendingJoins          map[string]JoinCertificate
	joinCoinWait          map[string]uint64
	armSent               map[string]bool
	commitSent            map[string]bool
	abaInputSent          map[string]bool
	abaInputs             map[string]bool
	lockedFrom            uint64
	pvssKeys              map[string]kyber.Scalar
	pvssBackend           string
	beaconSeeds           map[uint64][]byte
	verified              map[string]verifiedObject
	producerBusy          map[uint64]bool
	producerLow           int
	producerHigh          int
	removalWait           time.Duration
	currentMissingRemoval bool
	producing             bool
	waiters               map[string][]chan Beacon
	certBeacons           map[string]Beacon
	pendingCerts          map[string]BeaconCertificate
	certifying            map[string]bool

	Beacons chan Beacon
	Joins   chan JoinCertificate
}

type verifiedObject struct {
	version  uint64
	producer p2p.NodeID
	seq      uint64
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
	EchoMax       int
	ReadyMax      int
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
	removalWait := cfg.RemovalExpiration
	if removalWait <= 0 {
		removalWait = 5 * time.Second
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
		RmMark:        make(map[p2p.NodeID]int64),
		PendingABAs:   make(map[string]*PendingABA),
		PendingReconf: make(map[string]string),
		QueueLen:      queueLen,
	}
	for _, id := range members {
		st.ComQ[id] = make(map[uint64]Object)
		st.RmMark[id] = -1
	}
	n := &Node{
		ID: cfg.ID, Transport: cfg.Transport, PVSS: cfg.PVSS, Perf: &PerfMetrics{},
		RBC:    rbc.New(cfg.ID, len(members), f, cfg.Transport),
		ABA:    aba.New(cfg.ID, len(members), f, cfg.Transport),
		Crypto: cryptoexec.New(cfg.CryptoWorkers),
		State:  st,
		recon:  make(map[string]map[p2p.NodeID]crypto.DecryptedShare), reconSecret: make(map[string][]byte), reconDone: make(map[string]bool), reconClosing: make(map[string]bool),
		echoes: make(map[string]map[string]map[p2p.NodeID]bool), readies: make(map[string]map[string]map[p2p.NodeID]crypto.VoteShare),
		readySent: make(map[string]bool), readySentEpoch: make(map[string]bool), reconSent: make(map[string]bool), certified: make(map[string]bool),
		joinAcks: make(map[string]map[p2p.NodeID]JoinAck), joinCommits: make(map[string]map[p2p.NodeID]JoinCommit),
		joinRequests: make(map[string]JoinRequest), pendingJoins: make(map[string]JoinCertificate),
		joinCoinWait: make(map[string]uint64),
		armSent:      make(map[string]bool), commitSent: make(map[string]bool),
		abaInputSent:          make(map[string]bool),
		abaInputs:             make(map[string]bool),
		beaconSeeds:           make(map[uint64][]byte),
		verified:              make(map[string]verifiedObject),
		producerBusy:          make(map[uint64]bool),
		pvssKeys:              make(map[string]kyber.Scalar),
		pvssBackend:           pvssBackend,
		producerLow:           low,
		producerHigh:          high,
		removalWait:           removalWait,
		currentMissingRemoval: cfg.CurrentMissingRemoval,
		producing:             true,
		waiters:               make(map[string][]chan Beacon),
		certBeacons:           make(map[string]Beacon),
		pendingCerts:          make(map[string]BeaconCertificate),
		certifying:            make(map[string]bool),
		Beacons:               make(chan Beacon, len(members)*4), Joins: make(chan JoinCertificate, len(members)*2),
	}
	for epoch, key := range cfg.PVSSKeys {
		if key != nil {
			n.pvssKeys[epoch] = key.Clone()
		}
	}
	if epoch := cfg.PVSS.Epoch(); epoch != "" && cfg.PVSS.PrivateKey() != nil {
		n.pvssKeys[epoch] = cfg.PVSS.PrivateKey()
	}
	return n, nil
}

func (n *Node) Start(ctx context.Context) {
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
	go func() {
		for {
			select {
			case d := <-n.RBC.Deliveries:
				_ = n.handleRBCDelivery(ctx, d)
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case dec := <-n.ABA.Decisions:
				n.handleABADecision(ctx, dec)
			case req := <-n.ABA.CoinRequests:
				n.handleCoinRequest(req)
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
	start := time.Now()
	err := n.RBC.Handle(ctx, msg)
	if n.Perf != nil {
		n.Perf.addRBCHandle(time.Since(start))
	}
	return err
}

func (n *Node) handleABAMessage(ctx context.Context, msg p2p.Message) error {
	start := time.Now()
	err := n.ABA.Handle(ctx, msg)
	if n.Perf != nil {
		n.Perf.addABAHandle(time.Since(start))
	}
	return err
}

func (n *Node) Produce(ctx context.Context) (Object, error) {
	n.mu.Lock()
	if !n.producing {
		n.mu.Unlock()
		return Object{}, errors.New("local producer is stopped")
	}
	if n.producerWindowDepthLocked() >= n.producerHigh {
		n.mu.Unlock()
		return Object{}, errors.New("local producer high watermark reached")
	}
	n.State.ProducerSeq++
	seq := n.State.ProducerSeq
	version := n.State.ConfigVersion
	n.producerBusy[seq] = true
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
		n.mu.Unlock()
		obj, err := n.produceSeq(ctx, seq, version)
		if err != nil {
			n.finishProducerSeq(seq)
			n.rollbackProducerSeq(seq)
			return seq, err
		}
		if err := n.storeObject(obj); err != nil {
			n.rollbackProducerSeq(seq)
			return seq, err
		}
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

func (n *Node) requestProduceSeq(ctx context.Context, seq uint64, version uint64) bool {
	n.mu.Lock()
	if !n.producing {
		n.mu.Unlock()
		return false
	}
	if _, ok := n.State.ComQ[n.ID][seq]; ok {
		n.mu.Unlock()
		return false
	}
	if n.producerBusy[seq] {
		n.mu.Unlock()
		return false
	}
	consumed := n.State.Seqs[n.ID]
	targetProduced := n.State.ProducerSeq
	if seq > targetProduced {
		targetProduced = seq
	}
	if targetProduced > consumed && int(targetProduced-consumed) > n.producerHigh {
		n.mu.Unlock()
		return false
	}
	if n.State.ProducerSeq < seq {
		n.State.ProducerSeq = seq
	}
	n.producerBusy[seq] = true
	n.mu.Unlock()

	go func() {
		obj, err := n.produceSeq(ctx, seq, version)
		n.finishProducerSeq(seq)
		if err == nil {
			_ = n.storeObject(obj)
		} else {
			n.rollbackProducerSeq(seq)
		}
	}()
	return true
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
			level := n.producerWindowDepthLocked()
			low, high, queueLen := n.producerLow, n.producerHigh, n.State.QueueLen
			n.mu.Unlock()
			if level >= high {
				producing = false
			} else if level <= low {
				producing = true
			}
			if producing && level < high && storedDepth < queueLen {
				_, _ = n.Produce(ctx)
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (n *Node) producerWindowDepthLocked() int {
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
	for {
		if b, ok := n.applyPendingBeaconCert(epoch); ok {
			return b, nil
		}
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return b, nil
		}
		if err := n.activatePendingJoins(ctx, epoch); err != nil {
			return Beacon{}, err
		}
		source, seq, instance, skipCurrentABA, alreadyCertified, err := n.prepareEpoch(ctx, epoch)
		if err != nil {
			return Beacon{}, err
		}
		wait := n.registerBeaconWaiter(epoch, source, seq)
		if alreadyCertified {
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, wait)
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return b, err
		}
		if skipCurrentABA {
			if err := n.startRemovalEpochEcho(ctx, epoch, source, seq); err != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, err
			}
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, wait)
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return b, err
		}
		if source == n.ID && n.IsProducing() {
			ensuredSeq, err := n.EnsureCurrentObject(ctx)
			if err != nil {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, err
			}
			if ensuredSeq != seq {
				n.unregisterBeaconWaiter(epoch, source, seq, wait)
				return Beacon{}, fmt.Errorf("ensured local seq %d while epoch %d needs seq %d", ensuredSeq, epoch, seq)
			}
		}

		obj, certified, err := n.waitObjectOrBeacon(ctx, epoch, source, seq, instance, wait)
		if err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return Beacon{}, err
		}
		if certified != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return *certified, nil
		}

		if !skipCurrentABA {
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
		}
		if err := n.waitCoinBarrier(ctx, instance); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return Beacon{}, err
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
		needRecon := !n.reconDone[key] && !n.reconSent[key]
		if needRecon {
			n.reconSent[key] = true
		}
		n.mu.Unlock()
		if needRecon {
			// The object was already verified locally before entering comq; this path only skips
			// the duplicate commitment proof check, not the required RBC-delivery validation.
			start := time.Now()
			sh, err := n.PVSS.PreReconVerified(obj.Commitment, n.ID)
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
			msg, err := p2p.NewMessage(Protocol, "RECON", instance, n.ID, "", ReconMessage{Epoch: epoch, Source: source, Seq: seq, Share: sh})
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
		b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, wait)
		n.unregisterBeaconWaiter(epoch, source, seq, wait)
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

func (n *Node) applyPendingBeaconCert(epoch uint64) (Beacon, bool) {
	n.mu.Lock()
	candidates := make([]BeaconCertificate, 0, len(n.pendingCerts))
	for _, b := range n.pendingCerts {
		if b.Epoch == epoch {
			candidates = append(candidates, b)
		}
	}
	n.mu.Unlock()
	for _, b := range candidates {
		if n.tryApplyBeaconCert(b) {
			if certified, ok := n.certifiedBeaconForEpoch(epoch); ok {
				return certified, true
			}
		}
	}
	return Beacon{}, false
}

func (n *Node) waitForEpochBeacon(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, wait <-chan Beacon) (Beacon, error) {
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
		case <-ctx.Done():
			return Beacon{}, ctx.Err()
		}
	}
}

func (n *Node) startRemovalEpochEcho(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64) error {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	if n.reconSent[key] || n.reconDone[key] {
		n.mu.Unlock()
		return nil
	}
	version := n.State.ConfigVersion
	prev := append([]byte(nil), n.State.RPrev...)
	n.reconSent[key] = true
	n.reconDone[key] = true
	n.mu.Unlock()
	random := crypto.HashBytes(prev, []byte(fmt.Sprintf("removal/%d/%s/%d", version, source, seq)))
	echo, err := p2p.NewMessage(Protocol, "RECON_ECHO", key, n.ID, "", ReconEchoMessage{Epoch: epoch, Source: source, Seq: seq, Random: random})
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, echo)
}

func (n *Node) startMissingCurrentRemovalEpochEcho(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64) error {
	key := epochKey(epoch, source, seq)
	instance := aba.EpochInstance(epoch, source)
	n.mu.Lock()
	if n.reconSent[key] || n.reconDone[key] {
		n.mu.Unlock()
		return nil
	}
	if n.State.RmMark[source] == -1 || n.State.RmMark[source] > int64(seq) {
		n.State.RmMark[source] = int64(seq)
	}
	delete(n.State.PendingABAs, instance)
	delete(n.abaInputSent, instance)
	delete(n.abaInputs, instance)
	version := n.State.ConfigVersion
	prev := append([]byte(nil), n.State.RPrev...)
	n.reconSent[key] = true
	n.reconDone[key] = true
	n.mu.Unlock()
	debugf("node=%s current-missing-removal epoch=%d source=%s seq=%d", n.ID, epoch, source, seq)
	random := crypto.HashBytes(prev, []byte(fmt.Sprintf("removal/%d/%s/%d", version, source, seq)))
	echo, err := p2p.NewMessage(Protocol, "RECON_ECHO", key, n.ID, "", ReconEchoMessage{Epoch: epoch, Source: source, Seq: seq, Random: random})
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, echo)
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

func (n *Node) prepareEpoch(ctx context.Context, epoch uint64) (p2p.NodeID, uint64, string, bool, bool, error) {
	n.mu.Lock()
	if n.State.Epoch >= epoch {
		for _, b := range n.certBeacons {
			if b.Epoch == epoch {
				n.mu.Unlock()
				return b.Source, b.Seq, aba.EpochInstance(epoch, b.Source), false, true, nil
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
	instance := aba.EpochInstance(epoch, source)
	skipCurrentABA := n.State.RmMark[source] != -1 && seq == uint64(n.State.RmMark[source])
	if !skipCurrentABA && n.State.PendingABAs[instance] == nil {
		n.State.PendingABAs[instance] = &PendingABA{Instance: instance, Epoch: epoch, Source: source, Seq: seq}
	}
	version := n.State.ConfigVersion
	obj, available := n.State.ComQ[source][seq]
	if available && obj.ConfigVersion != version {
		available = false
	}
	n.mu.Unlock()
	if !available && source == n.ID {
		n.requestProduceSeq(ctx, seq, version)
	}
	return source, seq, instance, skipCurrentABA, false, nil
}

func (n *Node) waitObjectOrBeacon(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (Object, *Beacon, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var expire <-chan time.Time
	var expireTimer *time.Timer
	n.mu.Lock()
	currentMissingRemoval := n.currentMissingRemoval
	n.mu.Unlock()
	if currentMissingRemoval && source != n.ID {
		expireTimer = time.NewTimer(n.removalWait)
		defer expireTimer.Stop()
		expire = expireTimer.C
	}
	loggedWait := false
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return Object{}, &b, nil
		}
		if !loggedWait {
			debugf("node=%s step0-current-object-wait epoch=%d source=%s seq=%d instance=%s", n.ID, epoch, source, seq, instance)
			loggedWait = true
		}
		n.mu.Lock()
		obj, ok := n.State.ComQ[source][seq]
		version := n.State.ConfigVersion
		n.mu.Unlock()
		if ok && obj.ConfigVersion == version {
			debugf("node=%s step0-current-object-ready epoch=%d source=%s seq=%d instance=%s", n.ID, epoch, source, seq, instance)
			return obj, nil, nil
		}
		select {
		case b := <-wait:
			return Object{}, &b, nil
		case <-ticker.C:
		case <-expire:
			if err := n.startMissingCurrentRemovalEpochEcho(ctx, epoch, source, seq); err != nil {
				return Object{}, nil, err
			}
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, wait)
			if err != nil {
				return Object{}, nil, err
			}
			return Object{}, &b, nil
		case <-ctx.Done():
			return Object{}, nil, ctx.Err()
		}
	}
}

func (n *Node) proposeEpochABAInputFromLookahead(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (*Beacon, error) {
	next := seq + 1
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	expire := time.NewTimer(n.removalWait)
	defer expire.Stop()
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return &b, nil
		}
		st := n.ABA.Status(instance)
		if st.Decided || st.CoinWait {
			return nil, nil
		}
		n.mu.Lock()
		obj, ok := n.State.ComQ[source][next]
		version := n.State.ConfigVersion
		n.mu.Unlock()
		if ok && obj.ConfigVersion == version {
			return nil, n.proposeEpochABAInput(ctx, instance, true)
		}
		select {
		case b := <-wait:
			return &b, nil
		case <-ticker.C:
		case <-expire.C:
			return nil, n.proposeEpochABAInput(context.Background(), instance, false)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
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
	return n.ABA.Propose(ctx, instance, value)
}

func (n *Node) waitCurrentABAReady(ctx context.Context, instance string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	rebroadcast := time.NewTicker(100 * time.Millisecond)
	defer rebroadcast.Stop()
	for {
		st := n.ABA.Status(instance)
		if st.Decided || st.CoinWait {
			return nil
		}
		n.mu.Lock()
		_, pending := n.State.PendingABAs[instance]
		input, hasInput := n.abaInputs[instance]
		n.mu.Unlock()
		if !pending {
			return nil
		}
		select {
		case <-ticker.C:
		case <-rebroadcast.C:
			if hasInput {
				_ = n.ABA.Propose(context.Background(), instance, input)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (n *Node) waitCoinBarrier(ctx context.Context, current string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		blocked, feeds := n.refreshPendingABAs(current)
		for _, feed := range feeds {
			n.ABA.FeedSeed(ctx, feed.instance, feed.round, feed.seed)
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

type seedFeed struct {
	instance string
	round    uint64
	seed     []byte
}

func (n *Node) refreshPendingABAs(current string) (bool, []seedFeed) {
	n.mu.Lock()
	instances := make([]string, 0, len(n.State.PendingABAs))
	for inst := range n.State.PendingABAs {
		instances = append(instances, inst)
	}
	n.mu.Unlock()

	statuses := make(map[string]aba.Status, len(instances))
	for _, inst := range instances {
		statuses[inst] = n.ABA.Status(inst)
	}

	n.mu.Lock()
	var feeds []seedFeed
	var pruned []string
	blocked := false
	for _, inst := range instances {
		p := n.State.PendingABAs[inst]
		if p == nil {
			continue
		}
		st := statuses[inst]
		if st.Decided {
			p.Decided = true
			p.Decision = st.Value
			if !st.Value && n.State.RmMark[p.Source] == -1 {
				n.markRemovalLocked(p.Source, p.Seq)
			}
			delete(n.State.PendingABAs, inst)
			delete(n.abaInputSent, inst)
			delete(n.abaInputs, inst)
			pruned = append(pruned, inst)
			continue
		}
		p.Round = st.Round
		p.CoinWait = st.CoinWait
		if st.CoinWait {
			target := p.Epoch + st.Round + 1
			if seed := n.beaconSeeds[target]; len(seed) > 0 {
				p.CoinWait = false
				feeds = append(feeds, seedFeed{instance: inst, round: st.Round, seed: append([]byte(nil), seed...)})
			}
		}
		if inst != current && !p.Decided && !p.CoinWait {
			blocked = true
		}
	}
	n.mu.Unlock()
	for _, inst := range pruned {
		n.ABA.Prune(inst)
	}
	return blocked, feeds
}

func (n *Node) handleRBCDelivery(ctx context.Context, d rbc.Delivery) error {
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
		n.Crypto.Go(ctx, func() { _ = n.storeObject(obj) })
		return nil
	case "join":
		if env.Join == nil {
			return nil
		}
		return n.HandleJoinRequest(ctx, *env.Join)
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
	if obj.ConfigVersion != n.State.ConfigVersion {
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
	if existing, exists := n.State.ComQ[obj.Producer][obj.Seq]; exists && existing.ConfigVersion == obj.ConfigVersion {
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
	if obj.ConfigVersion != n.State.ConfigVersion {
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
	if existing, exists := n.State.ComQ[obj.Producer][obj.Seq]; exists && existing.ConfigVersion == obj.ConfigVersion {
		return nil
	}
	n.State.ComQ[obj.Producer][obj.Seq] = obj
	debugf("node=%s store object producer=%s seq=%d", n.ID, obj.Producer, obj.Seq)
	return nil
}

func (n *Node) ensureVerified(obj Object) error {
	key := objectCacheKey(obj)
	n.mu.Lock()
	cached, ok := n.verified[key]
	n.mu.Unlock()
	if ok {
		if cached.valid {
			return nil
		}
		return errors.New("invalid pvss object")
	}
	start := time.Now()
	valid := n.PVSS.Verify(obj.Commitment)
	if n.Perf != nil {
		n.Perf.addPVSSVerify(time.Since(start))
	}
	n.mu.Lock()
	n.verified[key] = verifiedObject{version: obj.ConfigVersion, producer: obj.Producer, seq: obj.Seq, valid: valid}
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
	case "RECON_ECHO":
		body, err := p2p.DecodePayload[ReconEchoMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		n.Crypto.GoPriority(ctx, func() {
			n.observeEchoReady(ctx, "echo", from, body.Epoch, body.Source, body.Seq, body.Random, "", CertifiedStateDigest{}, crypto.VoteShare{})
		})
	case "RECON_READY":
		body, err := p2p.DecodePayload[signedReconReadyMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		n.Crypto.GoPriority(ctx, func() {
			n.observeEchoReady(ctx, "ready", from, body.Epoch, body.Source, body.Seq, body.Random, body.StateHash, CertifiedStateDigest{}, body.Signature)
		})
	case "JOIN_ACK":
		body, err := p2p.DecodePayload[JoinAck](msg)
		if err != nil {
			return err
		}
		return n.HandleJoinAck(ctx, body)
	case "JOIN_ARM":
		body, err := p2p.DecodePayload[JoinArm](msg)
		if err != nil {
			return err
		}
		return n.HandleJoinArm(ctx, body)
	case "JOIN_COMMIT":
		body, err := p2p.DecodePayload[JoinCommit](msg)
		if err != nil {
			return err
		}
		return n.HandleJoinCommit(ctx, body)
	case "JOIN_CERT":
		body, err := p2p.DecodePayload[JoinCertificate](msg)
		if err != nil {
			return err
		}
		return n.InstallJoinCertificate(body)
	case "BEACON_CERT":
		body, err := p2p.DecodePayload[BeaconCertificate](msg)
		if err != nil {
			return err
		}
		return n.handleBeaconCert(body)
	}
	return nil
}

func (n *Node) handleRecon(ctx context.Context, from p2p.NodeID, body ReconMessage) error {
	obj, err := n.lookupEpochObject(body.Epoch, body.Source, body.Seq)
	if err != nil {
		debugf("node=%s ignore recon from=%s epoch=%d source=%s seq=%d reason=%v", n.ID, from, body.Epoch, body.Source, body.Seq, err)
		return nil
	}
	key := epochKey(body.Epoch, body.Source, body.Seq)
	n.mu.Lock()
	if n.reconDone[key] || n.reconClosing[key] || body.Share.CommitmentID != obj.Commitment.SecretID {
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
	start := time.Now()
	validShare := n.PVSS.VerifyShare(obj.Commitment, body.Share)
	if n.Perf != nil {
		n.Perf.addPVSSVerify(time.Since(start))
	}
	if body.Share.Holder != from || !validShare {
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
	prev := append([]byte(nil), n.State.RPrev...)
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
	start = time.Now()
	secret, err := n.PVSS.ReconFromVerifiedShares(obj.Commitment, shares)
	if n.Perf != nil {
		n.Perf.addPVSSRecon(time.Since(start))
	}
	if err != nil {
		n.mu.Lock()
		delete(n.reconClosing, key)
		n.mu.Unlock()
		return err
	}
	random := crypto.HashBytes(prev, secret)
	n.mu.Lock()
	if n.reconDone[key] {
		n.mu.Unlock()
		return nil
	}
	n.reconDone[key] = true
	n.reconSecret[key] = append([]byte(nil), secret...)
	n.mu.Unlock()
	echo, err := p2p.NewMessage(Protocol, "RECON_ECHO", key, n.ID, "", ReconEchoMessage{Epoch: body.Epoch, Source: body.Source, Seq: body.Seq, Random: random})
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, echo)
}

func debugf(format string, args ...any) {
	if os.Getenv("TYCHE_DEBUG") == "1" {
		log.Printf(format, args...)
	}
}

func (n *Node) observeEchoReady(ctx context.Context, kind string, from p2p.NodeID, epoch uint64, source p2p.NodeID, seq uint64, random []byte, stateHash string, state CertifiedStateDigest, sig crypto.VoteShare) {
	key := epochKey(epoch, source, seq)
	rh := hex.EncodeToString(random)
	voteKey := rh + "/" + stateHash
	readyKey := key + "/" + voteKey
	n.mu.Lock()
	if n.State.Epoch >= epoch {
		n.mu.Unlock()
		return
	}
	n.mu.Unlock()
	if kind == "ready" {
		n.mu.Lock()
		duplicate := n.certified[readyKey]
		if !duplicate && n.readies[key] != nil && n.readies[key][voteKey] != nil {
			_, duplicate = n.readies[key][voteKey][from]
		}
		members := n.memberSetLocked()
		n.mu.Unlock()
		if duplicate {
			return
		}
		// A READY is counted only if it carries a valid signature over the exact
		// READY transcript. This preserves the original threshold rule while
		// preventing a bare sender id from becoming part of the certificate.
		start := time.Now()
		valid := sig.Signer == string(from) && crypto.VerifyVoteShare(sig, members)
		if n.Perf != nil {
			n.Perf.addCertVerify(time.Since(start))
		}
		if !valid {
			return
		}
	}
	n.mu.Lock()
	if kind == "echo" {
		state = n.certifiedStateDigestForBeaconLocked(source, seq)
		stateHash = stateDigestHash(state)
		voteKey = rh + "/" + stateHash
		readyKey = key + "/" + voteKey
	}
	if n.echoes[key] == nil {
		n.echoes[key] = make(map[string]map[p2p.NodeID]bool)
	}
	if n.readies[key] == nil {
		n.readies[key] = make(map[string]map[p2p.NodeID]crypto.VoteShare)
	}
	if n.echoes[key][rh] == nil {
		n.echoes[key][rh] = make(map[p2p.NodeID]bool)
	}
	if n.readies[key][voteKey] == nil {
		n.readies[key][voteKey] = make(map[p2p.NodeID]crypto.VoteShare)
	}
	if kind == "echo" {
		n.echoes[key][rh][from] = true
	} else {
		n.readies[key][voteKey][from] = sig
	}
	echoCount := len(n.echoes[key][rh])
	readyCount := len(n.readies[key][voteKey])
	needReady := !n.readySentEpoch[key] && !n.readySent[readyKey] && (echoCount >= 2*n.State.F+1 || readyCount >= n.State.F+1)
	if needReady {
		n.readySentEpoch[key] = true
		n.readySent[readyKey] = true
	}
	certify := !n.certified[readyKey] && readyCount >= 2*n.State.F+1
	var senders []p2p.NodeID
	var votes []crypto.VoteShare
	var members map[string]struct{}
	if certify {
		if len(state.Members) == 0 {
			state = n.certifiedStateDigestForBeaconLocked(source, seq)
			if stateDigestHash(state) != stateHash {
				certify = false
			}
		}
		members = n.memberSetLocked()
		if certify {
			for id := range n.readies[key][voteKey] {
				senders = append(senders, id)
				votes = append(votes, n.readies[key][voteKey][id])
			}
			sort.Slice(senders, func(i, j int) bool { return senders[i] < senders[j] })
		}
	}
	n.mu.Unlock()
	if needReady {
		// READY amplification is unchanged: once enough ECHO/READY evidence is
		// observed, this node broadcasts READY. The added vote signs the
		// same canonical statement that will later be aggregated.
		start := time.Now()
		sig, err := crypto.NewVoteShare(string(n.ID))
		if n.Perf != nil {
			n.Perf.addCertSign(time.Since(start))
		}
		if err == nil {
			msg, err := p2p.NewMessage(Protocol, "RECON_READY", key, n.ID, "", signedReconReadyMessage{Epoch: epoch, Source: source, Seq: seq, Random: random, StateHash: stateHash, Signature: sig})
			if err == nil {
				n.safeBroadcast(ctx, msg)
			}
		}
	}
	if certify {
		// Certification now outputs a compact aggregate quorum certificate for the
		// 2f+1 READY quorum. The quorum threshold and random reconstruction are
		// unchanged; only the representation of the READY certificate is smaller
		// and externally verifiable.
		start := time.Now()
		cert, err := crypto.BuildQuorumCertificate(votes, members, 2*n.State.F+1)
		if n.Perf != nil {
			n.Perf.addCertAggregate(time.Since(start))
		}
		if err != nil {
			return
		}
		n.mu.Lock()
		if n.certified[readyKey] {
			n.mu.Unlock()
			return
		}
		n.certified[readyKey] = true
		n.mu.Unlock()
		n.certifyBeacon(epoch, source, seq, random, state, senders, cert, true)
	}
}

func (n *Node) certifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, state CertifiedStateDigest, senders []p2p.NodeID, cert crypto.QuorumCertificate, broadcastCert bool) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch || (n.lockedFrom != 0 && epoch >= n.lockedFrom) {
		n.mu.Unlock()
		return
	}
	if n.certifying[key] {
		n.mu.Unlock()
		return
	}
	n.certifying[key] = true
	n.mu.Unlock()
	go n.finishCertifyBeacon(epoch, source, seq, random, state, senders, cert, broadcastCert)
}

func (n *Node) finishCertifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, state CertifiedStateDigest, senders []p2p.NodeID, cert crypto.QuorumCertificate, broadcastCert bool) {
	key := epochKey(epoch, source, seq)
	n.mu.Lock()
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch || (n.lockedFrom != 0 && epoch >= n.lockedFrom) {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	obj := n.State.ComQ[source][seq]
	prev := append([]byte(nil), n.State.RPrev...)
	secret := append([]byte(nil), n.reconSecret[key]...)
	n.beaconSeeds[epoch] = append([]byte(nil), random...)
	feeds := n.processPendingABAsLocked(epoch)
	joinFeeds := n.processJoinCoinWaitsLocked(epoch)
	n.discardCertifiedEpochABAsLocked(epoch)
	n.mu.Unlock()
	for _, feed := range feeds {
		n.ABA.FeedSeed(context.Background(), feed.instance, feed.round, random)
		n.waitPendingABAAfterSeed(context.Background(), feed)
	}
	for _, feed := range joinFeeds {
		n.ABA.FeedSeed(context.Background(), feed.instance, feed.round, random)
	}

	n.mu.Lock()
	if n.State.Epoch >= epoch || n.State.Epoch+1 != epoch || (n.lockedFrom != 0 && epoch >= n.lockedFrom) {
		delete(n.certifying, key)
		n.mu.Unlock()
		return
	}
	removalMarks := copyRemovalMarks(n.State.RmMark)
	configVersion := n.State.ConfigVersion
	n.installCertifiedStateLocked(state)
	n.mergeRemovalMarksLocked(removalMarks)
	n.State.Epoch = epoch
	n.State.RPrev = append([]byte(nil), random...)
	n.cleanupCertifiedStateLocked(epoch)
	b := Beacon{
		Epoch: epoch, Source: source, Seq: seq, PrevRandom: prev, Random: append([]byte(nil), random...),
		Secret: secret, ObjectID: obj.Commitment.SecretID, ReadySenders: senders, Signature: cert,
		ConfigVersion: configVersion, State: state, StateHash: stateDigestHash(state),
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
	for _, waiter := range waiters {
		select {
		case waiter <- b:
		default:
		}
	}
	if broadcastCert && n.shouldBroadcastBeaconCert(cert) {
		c := BeaconCertificate{
			Epoch: epoch, Source: source, Seq: seq, Random: append([]byte(nil), random...),
			ObjectID: obj.Commitment.SecretID, Signature: cert, ConfigVersion: configVersion,
			StateHash: stateDigestHash(state),
		}
		msg, err := p2p.NewMessage(Protocol, "BEACON_CERT", key, n.ID, "", c)
		if err == nil {
			n.safeBroadcast(context.Background(), msg)
		}
	}
}

func (n *Node) shouldBroadcastBeaconCert(cert crypto.QuorumCertificate) bool {
	relays := certificateSigners(cert)
	return len(relays) > 0 && relays[0] == n.ID
}

func certificateSigners(cert crypto.QuorumCertificate) []p2p.NodeID {
	signers := make([]string, 0, len(cert.Signers))
	signers = append(signers, cert.Signers...)
	sort.Strings(signers)
	ids := make([]p2p.NodeID, 0, len(signers))
	for _, signer := range signers {
		ids = append(ids, p2p.NodeID(signer))
	}
	return ids
}

func (n *Node) safeBroadcast(ctx context.Context, msg p2p.Message) {
	defer func() {
		_ = recover()
	}()
	_ = n.Transport.Broadcast(ctx, msg)
}

func (n *Node) handleBeaconCert(b BeaconCertificate) error {
	if b.Epoch == 0 || b.Source == "" || b.Seq == 0 || len(b.Random) == 0 {
		return nil
	}
	n.tryApplyBeaconCert(b)
	return nil
}

func (n *Node) tryApplyBeaconCert(b BeaconCertificate) bool {
	key := epochKey(b.Epoch, b.Source, b.Seq)
	n.mu.Lock()
	if n.State.Epoch >= b.Epoch || n.State.Epoch+1 != b.Epoch || b.ConfigVersion != n.State.ConfigVersion || (n.lockedFrom != 0 && b.Epoch >= n.lockedFrom) {
		if n.State.Epoch < b.Epoch && b.ConfigVersion == n.State.ConfigVersion {
			n.pendingCerts[key] = b
		}
		n.mu.Unlock()
		return false
	}
	obj, ok := n.State.ComQ[b.Source][b.Seq]
	removalEpoch := n.State.RmMark[b.Source] != -1 && b.Seq == uint64(n.State.RmMark[b.Source])
	threshold := 2*n.State.F + 1
	members := n.memberSetLocked()
	state := CertifiedStateDigest{}
	stateHash := ""
	if ok && obj.ConfigVersion == b.ConfigVersion {
		state = n.certifiedStateDigestForBeaconLocked(b.Source, b.Seq)
		stateHash = stateDigestHash(state)
	} else if removalEpoch {
		state = n.certifiedStateDigestForBeaconLocked(b.Source, b.Seq)
		stateHash = stateDigestHash(state)
	}
	n.mu.Unlock()

	if (!ok || obj.ConfigVersion != b.ConfigVersion) && !removalEpoch {
		n.mu.Lock()
		if n.State.Epoch < b.Epoch && b.ConfigVersion == n.State.ConfigVersion {
			n.pendingCerts[key] = b
		}
		n.mu.Unlock()
		return false
	}
	if removalEpoch {
		if b.ObjectID != "" {
			return false
		}
	} else if b.ObjectID != "" && b.ObjectID != obj.Commitment.SecretID {
		return false
	}
	if b.StateHash == "" || b.StateHash != stateHash {
		return false
	}
	if err := crypto.VerifyQuorumCertificate(b.Signature, members, threshold); err != nil {
		return false
	}
	n.mu.Lock()
	delete(n.pendingCerts, key)
	n.mu.Unlock()
	n.certifyBeacon(b.Epoch, b.Source, b.Seq, b.Random, state, certificateSigners(b.Signature), b.Signature, false)
	return true
}

type coinFeed struct {
	instance string
	round    uint64
}

func (n *Node) processPendingABAsLocked(certEpoch uint64) []coinFeed {
	var feeds []coinFeed
	for inst, p := range n.State.PendingABAs {
		if p.CoinWait && p.Epoch+p.Round+1 == certEpoch {
			feeds = append(feeds, coinFeed{instance: inst, round: p.Round})
		}
	}
	return feeds
}

func (n *Node) discardCertifiedEpochABAsLocked(epoch uint64) {
	for inst, p := range n.State.PendingABAs {
		if p.Epoch == epoch {
			delete(n.State.PendingABAs, inst)
			delete(n.abaInputSent, inst)
			delete(n.abaInputs, inst)
		}
	}
}

func (n *Node) waitPendingABAAfterSeed(ctx context.Context, feed coinFeed) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		st := n.ABA.Status(feed.instance)
		n.mu.Lock()
		p := n.State.PendingABAs[feed.instance]
		if p == nil {
			n.mu.Unlock()
			return
		}
		if st.Decided {
			p.Decided = true
			p.Decision = st.Value
			if !st.Value && n.State.RmMark[p.Source] == -1 {
				n.markRemovalLocked(p.Source, p.Seq)
			}
			delete(n.State.PendingABAs, feed.instance)
			delete(n.abaInputSent, feed.instance)
			delete(n.abaInputs, feed.instance)
			n.mu.Unlock()
			n.ABA.Prune(feed.instance)
			return
		}
		p.Round = st.Round
		p.CoinWait = st.CoinWait
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

func (n *Node) rotateSourcesLocked(epoch uint64, source p2p.NodeID, seq uint64) {
	var old p2p.NodeID
	window := n.exclusionWindowLocked()
	if window > 0 && len(n.State.RSQ) >= window && len(n.State.RSQ) > 0 {
		old = n.State.RSQ[0]
		n.State.RSQ = append([]p2p.NodeID(nil), n.State.RSQ[1:]...)
		if old != "" && contains(n.State.Members, old) && !contains(n.State.SCL, old) {
			n.State.SCL = append(n.State.SCL, old)
		}
	}
	if contains(n.State.Members, source) {
		if window > 0 && !contains(n.State.RSQ, source) {
			n.State.RSQ = append(n.State.RSQ, source)
			n.State.SCL = removeID(n.State.SCL, source)
		}
		n.State.Seqs[source] = seq
		delete(n.State.ComQ[source], seq)
	}
}

func (n *Node) exclusionWindowLocked() int {
	return 2 * n.State.F
}

func (n *Node) markRemovalLocked(source p2p.NodeID, seq uint64) {
	n.State.RmMark[source] = int64(seq + 1)
}

func (n *Node) refillSCLLocked() {
	for _, id := range n.State.Members {
		if n.State.RmMark[id] == -1 && !contains(n.State.SCL, id) {
			n.State.SCL = append(n.State.SCL, id)
		}
	}
}

func (n *Node) cleanupCertifiedStateLocked(epoch uint64) {
	keepSeeds := uint64(n.exclusionWindowLocked() + 2)
	if epoch <= keepSeeds {
		return
	}
	minSeed := epoch - keepSeeds
	for e := range n.beaconSeeds {
		if e < minSeed {
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
			delete(n.echoes, key)
			delete(n.readies, key)
			delete(n.certBeacons, key)
			delete(n.pendingCerts, key)
		}
	}
	for key := range n.readySent {
		if keyEpoch(key) < minRecon {
			delete(n.readySent, key)
		}
	}
	for key := range n.readySentEpoch {
		if keyEpoch(key) < minRecon {
			delete(n.readySentEpoch, key)
		}
	}
	for key := range n.reconSent {
		if keyEpoch(key) < minRecon {
			delete(n.reconSent, key)
		}
	}
	for key := range n.certified {
		if keyEpoch(key) < minRecon {
			delete(n.certified, key)
		}
	}
	for key, cached := range n.verified {
		if cached.version != n.State.ConfigVersion || cached.seq <= n.State.Seqs[cached.producer] {
			delete(n.verified, key)
		}
	}
	consumed := make(map[p2p.NodeID]uint64, len(n.State.Seqs))
	for id, seq := range n.State.Seqs {
		consumed[id] = seq
	}
	n.RBC.PruneThrough(consumed)
}

func (n *Node) removeMemberLocked(id p2p.NodeID) {
	n.State.Members = removeID(n.State.Members, id)
	n.State.SCL = removeID(n.State.SCL, id)
	n.State.RSQ = removeID(n.State.RSQ, id)
	delete(n.State.ComQ, id)
	delete(n.State.Seqs, id)
	delete(n.State.RmMark, id)
	n.State.ConfigVersion++
	n.State.F = (len(n.State.Members) - 1) / 3
	n.RBC.N, n.RBC.F = len(n.State.Members), n.State.F
	n.ABA.N, n.ABA.F = len(n.State.Members), n.State.F
	n.installRemovalPVSSLocked()
	n.resetConfigurationCachesLocked()
}

func (n *Node) memberSetLocked() map[string]struct{} {
	snapshot := make(map[string]struct{}, len(n.State.Members))
	for _, id := range n.State.Members {
		snapshot[string(id)] = struct{}{}
	}
	return snapshot
}

func (n *Node) installCertifiedStateLocked(d CertifiedStateDigest) {
	oldMembers := append([]p2p.NodeID(nil), n.State.Members...)
	for _, id := range oldMembers {
		if !contains(d.Members, id) {
			n.removeMemberLocked(id)
		}
	}
	n.State.Members = append([]p2p.NodeID(nil), d.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), d.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), d.RSQ...)
	n.State.Seqs = make(map[p2p.NodeID]uint64, len(d.Seqs))
	for id, seq := range d.Seqs {
		n.State.Seqs[id] = seq
	}
	n.State.RmMark = make(map[p2p.NodeID]int64, len(d.RmMark))
	for id, marker := range d.RmMark {
		n.State.RmMark[id] = marker
	}
	for _, id := range d.Members {
		if n.State.ComQ[id] == nil {
			n.State.ComQ[id] = make(map[uint64]Object)
		}
		if _, ok := n.State.RmMark[id]; !ok {
			n.State.RmMark[id] = -1
		}
	}
	for id := range n.State.ComQ {
		if !contains(d.Members, id) {
			delete(n.State.ComQ, id)
			continue
		}
		consumed := n.State.Seqs[id]
		for seq := range n.State.ComQ[id] {
			if seq <= consumed {
				delete(n.State.ComQ[id], seq)
			}
		}
	}
	n.State.F = (len(n.State.Members) - 1) / 3
	n.RBC.N, n.RBC.F = len(n.State.Members), n.State.F
	n.ABA.N, n.ABA.F = len(n.State.Members), n.State.F
}

func (n *Node) mergeRemovalMarksLocked(marks map[p2p.NodeID]int64) {
	for id, mark := range marks {
		if mark == -1 || !contains(n.State.Members, id) {
			continue
		}
		current, ok := n.State.RmMark[id]
		if !ok || current == -1 || mark < current {
			n.State.RmMark[id] = mark
		}
	}
}

func copyRemovalMarks(in map[p2p.NodeID]int64) map[p2p.NodeID]int64 {
	out := make(map[p2p.NodeID]int64, len(in))
	for id, mark := range in {
		out[id] = mark
	}
	return out
}

func (n *Node) installRemovalPVSSLocked() {
	if !contains(n.State.Members, n.ID) || len(n.State.Members) == 0 {
		n.producing = false
		return
	}
	epoch := fmt.Sprintf("Tyche-v1/removal-config/%d/%v", n.State.ConfigVersion, n.State.Members)
	pp, keys, err := crypto.SetupPVSS(n.pvssBackend, epoch, n.State.F+1, n.State.Members)
	if err != nil {
		return
	}
	key := keys[n.ID]
	if key.Private == nil {
		return
	}
	scheme, err := crypto.NewPVSSScheme(n.ID, key.Private, pp)
	if err != nil {
		return
	}
	n.PVSS = scheme
	n.pvssKeys[pp.Epoch()] = key.Private.Clone()
}

func (n *Node) resetConfigurationCachesLocked() {
	n.State.ProducerSeq = n.State.Seqs[n.ID]
	n.producerBusy = make(map[uint64]bool)
	n.recon = make(map[string]map[p2p.NodeID]crypto.DecryptedShare)
	n.reconSecret = make(map[string][]byte)
	n.reconDone = make(map[string]bool)
	n.reconClosing = make(map[string]bool)
	n.echoes = make(map[string]map[string]map[p2p.NodeID]bool)
	n.readies = make(map[string]map[string]map[p2p.NodeID]crypto.VoteShare)
	n.readySent = make(map[string]bool)
	n.reconSent = make(map[string]bool)
	n.certified = make(map[string]bool)
	n.verified = make(map[string]verifiedObject)
}

func (n *Node) lookupEpochObject(epoch uint64, source p2p.NodeID, seq uint64) (Object, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if epoch != n.State.Epoch+1 {
		return Object{}, errors.New("unexpected epoch")
	}
	obj, ok := n.State.ComQ[source][seq]
	if !ok || obj.ConfigVersion != n.State.ConfigVersion {
		return Object{}, errors.New("unknown object")
	}
	return obj, nil
}

func (n *Node) CompletedEpoch() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.State.Epoch
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
		s.Instance = aba.EpochInstance(s.NextEpoch, s.Source)
		key := epochKey(s.NextEpoch, s.Source, s.Seq)
		if obj, ok := n.State.ComQ[s.Source][s.Seq]; ok && obj.ConfigVersion == n.State.ConfigVersion {
			s.Object = true
			s.ReconNeed = obj.Commitment.Threshold
		}
		if obj, ok := n.State.ComQ[s.Source][s.Seq+1]; ok && obj.ConfigVersion == n.State.ConfigVersion {
			s.NextObject = true
		}
		s.ReconSent = n.reconSent[key]
		s.ReconDone = n.reconDone[key]
		s.ReconCount = len(n.recon[key])
		s.EchoMax = maxEchoCount(n.echoes[key])
		s.ReadyMax = maxReadyCount(n.readies[key])
		s.Certifying = n.certifying[key]
		s.Waiters = len(n.waiters[key])
		s.ABAInputSent = n.abaInputSent[s.Instance]
		s.ABAInput = n.abaInputs[s.Instance]
		for readyKey := range n.certified {
			if strings.HasPrefix(readyKey, key+"/") {
				s.Certified = true
				break
			}
		}
	}
	n.mu.Unlock()
	if s.Instance != "" {
		st := n.ABA.Status(s.Instance)
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

func maxEchoCount(votes map[string]map[p2p.NodeID]bool) int {
	max := 0
	for _, bySender := range votes {
		if len(bySender) > max {
			max = len(bySender)
		}
	}
	return max
}

func maxReadyCount(votes map[string]map[p2p.NodeID]crypto.VoteShare) int {
	max := 0
	for _, bySender := range votes {
		if len(bySender) > max {
			max = len(bySender)
		}
	}
	return max
}

func (n *Node) handleABADecision(ctx context.Context, dec aba.Decision) {
	n.mu.Lock()
	if p := n.State.PendingABAs[dec.Instance]; p != nil {
		p.Decided = true
		p.Decision = dec.Value
		if !dec.Value && n.State.RmMark[p.Source] == -1 {
			n.markRemovalLocked(p.Source, p.Seq)
		}
		delete(n.State.PendingABAs, dec.Instance)
		delete(n.abaInputSent, dec.Instance)
		delete(n.abaInputs, dec.Instance)
	}
	req, ok := n.joinRequestByInstanceLocked(dec.Instance)
	if ok {
		delete(n.joinCoinWait, dec.Instance)
	}
	n.mu.Unlock()
	n.ABA.Prune(dec.Instance)
	if ok && dec.Value {
		_ = n.broadcastJoinCommit(ctx, req)
	}
}

func (n *Node) handleCoinRequest(req aba.CoinRequest) {
	n.mu.Lock()
	var seed []byte
	if p := n.State.PendingABAs[req.Instance]; p != nil {
		p.Round = req.Round
		p.CoinWait = true
		target := p.Epoch + req.Round + 1
		if known := n.beaconSeeds[target]; len(known) > 0 {
			seed = append([]byte(nil), known...)
			p.CoinWait = false
		}
	} else if firstCoinEpoch, ok := aba.ParseJoinInstance(req.Instance); ok {
		target := firstCoinEpoch + req.Round
		if known := n.beaconSeeds[target]; len(known) > 0 {
			seed = append([]byte(nil), known...)
		} else {
			n.joinCoinWait[req.Instance] = req.Round
		}
	}
	n.mu.Unlock()
	if len(seed) > 0 {
		n.ABA.FeedSeed(context.Background(), req.Instance, req.Round, seed)
	}
}

func (n *Node) processJoinCoinWaitsLocked(certEpoch uint64) []coinFeed {
	var feeds []coinFeed
	for inst, round := range n.joinCoinWait {
		firstCoinEpoch, ok := aba.ParseJoinInstance(inst)
		if !ok {
			delete(n.joinCoinWait, inst)
			continue
		}
		if firstCoinEpoch+round == certEpoch {
			feeds = append(feeds, coinFeed{instance: inst, round: round})
			delete(n.joinCoinWait, inst)
		}
	}
	return feeds
}

func (n *Node) stateDigestLocked() CertifiedStateDigest {
	seqs := make(map[p2p.NodeID]uint64, len(n.State.Seqs))
	for id, v := range n.State.Seqs {
		seqs[id] = v
	}
	rm := make(map[p2p.NodeID]int64, len(n.State.RmMark))
	for id, v := range n.State.RmMark {
		rm[id] = v
	}
	return CertifiedStateDigest{
		Members: append([]p2p.NodeID(nil), n.State.Members...),
		SCL:     append([]p2p.NodeID(nil), n.State.SCL...),
		RSQ:     append([]p2p.NodeID(nil), n.State.RSQ...),
		Seqs:    seqs, RmMark: rm,
	}
}

func (n *Node) certifiedStateDigestForBeaconLocked(source p2p.NodeID, seq uint64) CertifiedStateDigest {
	d := n.stateDigestLocked()
	window := n.exclusionWindowLocked()
	if window > 0 && len(d.RSQ) >= window && len(d.RSQ) > 0 {
		old := d.RSQ[0]
		d.RSQ = append([]p2p.NodeID(nil), d.RSQ[1:]...)
		if old != "" && contains(d.Members, old) && !contains(d.SCL, old) {
			d.SCL = append(d.SCL, old)
		}
	}
	if contains(d.Members, source) {
		if window > 0 && !contains(d.RSQ, source) {
			d.RSQ = append(d.RSQ, source)
			d.SCL = removeID(d.SCL, source)
		}
		d.Seqs[source] = seq
	}
	if d.RmMark[source] != -1 && seq == uint64(d.RmMark[source]) {
		d.Members = removeID(d.Members, source)
		d.SCL = removeID(d.SCL, source)
		d.RSQ = removeID(d.RSQ, source)
		delete(d.Seqs, source)
		delete(d.RmMark, source)
	}
	return d
}

func stateDigestHash(d CertifiedStateDigest) string {
	return hex.EncodeToString(crypto.HashBytes([]byte("Tyche-v1/state"), canonicalJSON(d)))
}

func epochKey(epoch uint64, source p2p.NodeID, seq uint64) string {
	return fmt.Sprintf("epoch/%d/%s/%d", epoch, source, seq)
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
	return fmt.Sprintf("%d/%s", obj.ConfigVersion, obj.Commitment.SecretID)
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
