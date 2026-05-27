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
	Skipped      bool         `json:"skipped,omitempty"`
	SkipStage    string       `json:"skip_stage,omitempty"`
	SkipReason   string       `json:"skip_reason,omitempty"`
	SkipDiag     string       `json:"skip_diag,omitempty"`
	// Signature is the compact READY quorum certificate. ReadySenders records
	// who voted; Signature proves those nodes signed the canonical READY
	// statement for this epoch/source/sequence/random hash.
	Signature     crypto.BLSAggregateSignature `json:"signature"`
	ConfigVersion uint64                       `json:"config_version"`
	State         CertifiedStateDigest         `json:"state"`
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
	RemovalExpiration time.Duration
	ConfigVersion     uint64
	InitialRandom     []byte
	PVSS              crypto.PVSSScheme
	PVSSBackend       string
	PVSSKeys          map[string]kyber.Scalar
	CryptoWorkers     int
	// BLS and BLSPublic are only for READY certificate compression. They are
	// independent per-node BLS keys, not the PVSS key material and not a
	// threshold-BLS shared key.
	BLS       crypto.BLSKeyPair
	BLSPublic map[string]kyber.Point
	Transport p2p.Transport
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

// signedReconReadyMessage extends the original READY payload with a BLS share.
// The READY amplification rule is unchanged; the signature simply makes each
// counted READY vote externally auditable and aggregatable.
type signedReconReadyMessage struct {
	Epoch     uint64                   `json:"epoch"`
	Source    p2p.NodeID               `json:"source"`
	Seq       uint64                   `json:"seq"`
	Random    []byte                   `json:"random"`
	Signature crypto.BLSSignatureShare `json:"signature"`
}

type Node struct {
	ID        p2p.NodeID
	Transport p2p.Transport
	PVSS      crypto.PVSSScheme
	Perf      *PerfMetrics
	// BLS state supports the READY aggregate certificate attached to each
	// certified beacon. It is deliberately separate from the PVSS scheme so the
	// randomness protocol remains the same.
	BLS       crypto.BLSKeyPair
	BLSPublic map[string]kyber.Point
	RBC       *rbc.Broadcaster
	ABA       *aba.Agreement
	Crypto    *cryptoexec.Executor

	mu          sync.Mutex
	State       *State
	recon       map[string]map[p2p.NodeID]crypto.DecryptedShare
	reconSecret map[string][]byte
	reconDone   map[string]bool
	echoes      map[string]map[string]map[p2p.NodeID]bool
	// readies stores verified BLS READY shares rather than bare sender ids.
	// This lets certification aggregate the exact votes that justified the
	// Bracha-style READY threshold.
	readies      map[string]map[string]map[p2p.NodeID]crypto.BLSSignatureShare
	readySent    map[string]bool
	reconSent    map[string]bool
	certified    map[string]bool
	joinAcks     map[string]map[p2p.NodeID]JoinAck
	joinCommits  map[string]map[p2p.NodeID]JoinCommit
	joinRequests map[string]JoinRequest
	pendingJoins map[string]JoinCertificate
	joinCoinWait map[string]uint64
	armSent      map[string]bool
	commitSent   map[string]bool
	abaInputSent map[string]bool
	abaInputs    map[string]bool
	lockedFrom   uint64
	pvssKeys     map[string]kyber.Scalar
	pvssBackend  string
	beaconSeeds  map[uint64][]byte
	verified     map[string]verifiedObject
	producerLow  int
	producerHigh int
	removalWait  time.Duration
	producing    bool
	skipABA      bool
	waiters      map[string][]chan Beacon
	certBeacons  map[string]Beacon
	pendingCerts map[string]Beacon
	certifying   map[string]bool

	Beacons chan Beacon
	Joins   chan JoinCertificate
}

type verifiedObject struct {
	version uint64
	object  Object
	valid   bool
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
	// BLS keys are optional in tests and local benchmarks. If the caller does
	// not provide them, derive deterministic per-node keys so existing fixtures
	// keep working; production deployments should pass explicit keys.
	blsKey := cfg.BLS
	if blsKey.Private == nil {
		blsKey = crypto.NewBLSKeyPairFromSeed(crypto.HashBytes([]byte("Tyche-v1/default-bls/private"), []byte(cfg.ID)))
	}
	blsPublic := make(map[string]kyber.Point, len(members))
	for id, pub := range cfg.BLSPublic {
		if pub != nil {
			blsPublic[id] = pub.Clone()
		}
	}
	if len(blsPublic) == 0 {
		for _, id := range members {
			kp := crypto.NewBLSKeyPairFromSeed(crypto.HashBytes([]byte("Tyche-v1/default-bls/private"), []byte(id)))
			blsPublic[string(id)] = kp.Public
		}
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
		ID: cfg.ID, Transport: cfg.Transport, PVSS: cfg.PVSS, Perf: &PerfMetrics{}, BLS: blsKey, BLSPublic: blsPublic,
		RBC:    rbc.New(cfg.ID, len(members), f, cfg.Transport),
		ABA:    aba.New(cfg.ID, len(members), f, cfg.Transport),
		Crypto: cryptoexec.New(cfg.CryptoWorkers),
		State:  st,
		recon:  make(map[string]map[p2p.NodeID]crypto.DecryptedShare), reconSecret: make(map[string][]byte), reconDone: make(map[string]bool),
		echoes: make(map[string]map[string]map[p2p.NodeID]bool), readies: make(map[string]map[string]map[p2p.NodeID]crypto.BLSSignatureShare),
		readySent: make(map[string]bool), reconSent: make(map[string]bool), certified: make(map[string]bool),
		joinAcks: make(map[string]map[p2p.NodeID]JoinAck), joinCommits: make(map[string]map[p2p.NodeID]JoinCommit),
		joinRequests: make(map[string]JoinRequest), pendingJoins: make(map[string]JoinCertificate),
		joinCoinWait: make(map[string]uint64),
		armSent:      make(map[string]bool), commitSent: make(map[string]bool),
		abaInputSent: make(map[string]bool),
		abaInputs:    make(map[string]bool),
		beaconSeeds:  make(map[uint64][]byte),
		verified:     make(map[string]verifiedObject),
		pvssKeys:     make(map[string]kyber.Scalar),
		pvssBackend:  pvssBackend,
		producerLow:  low,
		producerHigh: high,
		removalWait:  removalWait,
		producing:    true,
		skipABA:      os.Getenv("TYCHE_SKIP_ABA") == "1",
		waiters:      make(map[string][]chan Beacon),
		certBeacons:  make(map[string]Beacon),
		pendingCerts: make(map[string]Beacon),
		certifying:   make(map[string]bool),
		Beacons:      make(chan Beacon, len(members)*4), Joins: make(chan JoinCertificate, len(members)*2),
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
	go func() {
		for {
			select {
			case msg, ok := <-n.Transport.Inbox():
				if !ok {
					return
				}
				_ = n.Handle(ctx, msg)
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

func (n *Node) Handle(ctx context.Context, msg p2p.Message) error {
	switch msg.Protocol {
	case rbc.Protocol:
		start := time.Now()
		err := n.RBC.Handle(ctx, msg)
		if n.Perf != nil {
			n.Perf.addRBCHandle(time.Since(start))
		}
		return err
	case aba.Protocol:
		start := time.Now()
		err := n.ABA.Handle(ctx, msg)
		if n.Perf != nil {
			n.Perf.addABAHandle(time.Since(start))
		}
		return err
	case Protocol:
		return n.handleTyche(ctx, msg)
	default:
		return nil
	}
}

func (n *Node) Produce(ctx context.Context) (Object, error) {
	n.mu.Lock()
	if !n.producing {
		n.mu.Unlock()
		return Object{}, errors.New("local producer is stopped")
	}
	if len(n.State.ComQ[n.ID]) >= n.State.QueueLen {
		n.mu.Unlock()
		return Object{}, errors.New("local producer queue is full")
	}
	n.State.ProducerSeq++
	seq := n.State.ProducerSeq
	version := n.State.ConfigVersion
	n.mu.Unlock()
	obj, err := n.produceSeq(ctx, seq, version)
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

func (n *Node) StartProducer(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Millisecond
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		var inFlight []uint64
		producing := true
		for {
			n.mu.Lock()
			depth := len(n.State.ComQ[n.ID])
			low, high, queueLen := n.producerLow, n.producerHigh, n.State.QueueLen
			kept := inFlight[:0]
			for _, seq := range inFlight {
				_, delivered := n.State.ComQ[n.ID][seq]
				consumed := n.State.Seqs[n.ID] >= seq
				if !delivered && !consumed {
					kept = append(kept, seq)
				}
			}
			inFlight = kept
			n.mu.Unlock()
			level := depth + len(inFlight)
			if level >= high {
				producing = false
			} else if level <= low {
				producing = true
			}
			if producing && level < high && depth < queueLen && len(inFlight) < high {
				obj, err := n.Produce(ctx)
				if err == nil {
					inFlight = append(inFlight, obj.Seq)
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
		source, seq, instance, alreadyCertified, err := n.prepareEpoch(ctx, epoch)
		if err != nil {
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "prepare", "timeout"), nil
			}
			return Beacon{}, err
		}
		wait := n.registerBeaconWaiter(epoch, source, seq)
		if alreadyCertified {
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, wait)
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "already_certified_wait", "timeout"), nil
			}
			return b, err
		}
		obj, certified, err := n.waitObjectOrBeacon(ctx, epoch, source, seq, instance, wait)
		if err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "object_wait", "timeout"), nil
			}
			return Beacon{}, err
		}
		if certified != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return *certified, nil
		}
		if certified, err := n.proposeEpochABAInputFromLookahead(ctx, epoch, source, seq, instance, wait); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "lookahead_aba_input", "timeout"), nil
			}
			return Beacon{}, err
		} else if certified != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			return *certified, nil
		}
		if err := n.waitCurrentABAReady(ctx, instance); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "aba_ready", "timeout"), nil
			}
			return Beacon{}, err
		}
		if err := n.waitCoinBarrier(ctx, instance); err != nil {
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "coin_barrier", "timeout"), nil
			}
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
				if isContextDone(err) {
					return n.skipCurrentEpoch(epoch, source, seq, "broadcast_recon", "timeout"), nil
				}
				return Beacon{}, err
			}
		}
		for {
			b, err := n.waitForEpochBeacon(ctx, epoch, source, seq, wait)
			n.unregisterBeaconWaiter(epoch, source, seq, wait)
			if isContextDone(err) {
				return n.skipCurrentEpoch(epoch, source, seq, "beacon_wait", "timeout"), nil
			}
			return b, err
		}
	}
}

func isContextDone(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (n *Node) skipCurrentEpoch(epoch uint64, source p2p.NodeID, seq uint64, stage string, reason string) Beacon {
	key := epochKey(epoch, source, seq)
	instance := aba.EpochInstance(epoch, source)
	diag := n.skipDiagnostics(epoch, source, seq, instance)
	n.mu.Lock()
	defer n.mu.Unlock()
	if b, ok := n.certBeacons[key]; ok {
		return b
	}
	if n.State.Epoch >= epoch {
		return Beacon{Epoch: epoch, Source: source, Seq: seq, Random: append([]byte(nil), n.State.RPrev...), Skipped: true}
	}
	if n.State.Epoch+1 != epoch {
		return Beacon{Epoch: epoch, Source: source, Seq: seq, Random: append([]byte(nil), n.State.RPrev...), Skipped: true}
	}
	prev := append([]byte(nil), n.State.RPrev...)
	random := crypto.HashBytes([]byte("Tyche-v1/skip"), prev, []byte(fmt.Sprintf("%d", epoch)), []byte(source), []byte(fmt.Sprintf("%d", seq)), []byte(stage), []byte(reason))
	if source != "" && seq > 0 {
		n.rotateSourcesLocked(epoch, source, seq)
	}
	n.State.Epoch = epoch
	n.State.RPrev = append([]byte(nil), random...)
	n.beaconSeeds[epoch] = append([]byte(nil), random...)
	delete(n.State.PendingABAs, instance)
	delete(n.recon, key)
	delete(n.reconSecret, key)
	delete(n.reconDone, key)
	delete(n.reconSent, key)
	delete(n.echoes, key)
	delete(n.readies, key)
	delete(n.readySent, key)
	delete(n.certified, key)
	delete(n.certifying, key)
	delete(n.waiters, key)
	n.cleanupCertifiedStateLocked(epoch)
	return Beacon{
		Epoch: epoch, Source: source, Seq: seq, PrevRandom: prev, Random: random,
		ObjectID: reason, Skipped: true, SkipStage: stage, SkipReason: reason, SkipDiag: diag,
		ConfigVersion: n.State.ConfigVersion,
		State:         n.stateDigestLocked(),
	}
}

func (n *Node) skipDiagnostics(epoch uint64, source p2p.NodeID, seq uint64, instance string) string {
	key := epochKey(epoch, source, seq)
	abaStatus := n.ABA.Status(instance)
	n.mu.Lock()
	defer n.mu.Unlock()

	obj, objectAvailable := n.State.ComQ[source][seq]
	sourceQueueDepth := len(n.State.ComQ[source])
	reconShares := len(n.recon[key])
	echoMax := 0
	for _, senders := range n.echoes[key] {
		if len(senders) > echoMax {
			echoMax = len(senders)
		}
	}
	readyMax := 0
	for _, senders := range n.readies[key] {
		if len(senders) > readyMax {
			readyMax = len(senders)
		}
	}
	waiters := len(n.waiters[key])
	pending := n.State.PendingABAs[instance]
	pendingRound := uint64(0)
	pendingCoinWait := false
	pendingDecided := false
	pendingDecision := false
	if pending != nil {
		pendingRound = pending.Round
		pendingCoinWait = pending.CoinWait
		pendingDecided = pending.Decided
		pendingDecision = pending.Decision
	}

	return fmt.Sprintf(
		"local_epoch=%d object_available=%t object_version=%d config_version=%d source_queue=%d scl=%d rsq=%d pending_abas=%d aba_input_sent=%t aba_input=%t aba_round=%d aba_decided=%t aba_value=%t aba_coin_wait=%t aba_inputs=%d aba_input_true=%d aba_input_false=%d aba_finish=%d aba_bval_true=%d aba_bval_false=%d aba_bin_true=%t aba_bin_false=%t aba_aux=%d aba_conf=%d pending_round=%d pending_decided=%t pending_value=%t pending_coin_wait=%t recon_sent=%t recon_done=%t recon_shares=%d echo_max=%d ready_max=%d waiters=%d",
		n.State.Epoch,
		objectAvailable,
		obj.ConfigVersion,
		n.State.ConfigVersion,
		sourceQueueDepth,
		len(n.State.SCL),
		len(n.State.RSQ),
		len(n.State.PendingABAs),
		n.abaInputSent[instance],
		n.abaInputs[instance],
		abaStatus.Round,
		abaStatus.Decided,
		abaStatus.Value,
		abaStatus.CoinWait,
		abaStatus.Inputs,
		abaStatus.InputTrue,
		abaStatus.InputFalse,
		abaStatus.Finish,
		abaStatus.BValTrue,
		abaStatus.BValFalse,
		abaStatus.BinTrue,
		abaStatus.BinFalse,
		abaStatus.Aux,
		abaStatus.Conf,
		pendingRound,
		pendingDecided,
		pendingDecision,
		pendingCoinWait,
		n.reconSent[key],
		n.reconDone[key],
		reconShares,
		echoMax,
		readyMax,
		waiters,
	)
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
	candidates := make([]Beacon, 0, len(n.pendingCerts))
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

func (n *Node) prepareEpoch(ctx context.Context, epoch uint64) (p2p.NodeID, uint64, string, bool, error) {
	n.mu.Lock()
	if n.State.Epoch >= epoch {
		for _, b := range n.certBeacons {
			if b.Epoch == epoch {
				n.mu.Unlock()
				return b.Source, b.Seq, aba.EpochInstance(epoch, b.Source), true, nil
			}
		}
		n.mu.Unlock()
		return "", 0, "", false, fmt.Errorf("epoch %d already certified but beacon was not retained", epoch)
	}
	if n.State.Epoch+1 != epoch {
		n.mu.Unlock()
		return "", 0, "", false, fmt.Errorf("cannot run epoch %d from local epoch %d", epoch, n.State.Epoch)
	}
	if len(n.State.SCL) == 0 {
		n.refillSCLLocked()
	}
	if len(n.State.SCL) == 0 {
		n.mu.Unlock()
		return "", 0, "", false, errors.New("empty source candidate list")
	}
	idx := beaconIndex(n.State.RPrev, len(n.State.SCL))
	source := n.State.SCL[idx]
	seq := n.State.Seqs[source] + 1
	instance := aba.EpochInstance(epoch, source)
	if !n.skipABA && n.State.PendingABAs[instance] == nil {
		n.State.PendingABAs[instance] = &PendingABA{Instance: instance, Epoch: epoch, Source: source, Seq: seq}
	}
	version := n.State.ConfigVersion
	obj, available := n.State.ComQ[source][seq]
	if available && obj.ConfigVersion != version {
		available = false
	}
	producing := n.producing
	n.mu.Unlock()
	if !available && source == n.ID && producing {
		obj, err := n.produceSeq(ctx, seq, version)
		if err != nil {
			return source, seq, instance, false, err
		}
		_ = n.storeObject(obj)
		n.mu.Lock()
		if n.State.ProducerSeq < seq {
			n.State.ProducerSeq = seq
		}
		n.mu.Unlock()
		available = true
	}
	return source, seq, instance, false, nil
}

func (n *Node) waitObject(ctx context.Context, source p2p.NodeID, seq uint64) (Object, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		n.mu.Lock()
		obj, ok := n.State.ComQ[source][seq]
		version := n.State.ConfigVersion
		n.mu.Unlock()
		if ok && obj.ConfigVersion == version {
			return obj, nil
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return Object{}, ctx.Err()
		}
	}
}

func (n *Node) waitObjectOrBeacon(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (Object, *Beacon, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
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
		case <-ctx.Done():
			return Object{}, nil, ctx.Err()
		}
	}
}

func (n *Node) proposeEpochABAInputFromLookahead(ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64, instance string, wait <-chan Beacon) (*Beacon, error) {
	if n.skipABA {
		return nil, nil
	}
	next := seq + 1
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	expire := time.NewTimer(n.removalWait)
	defer expire.Stop()
	for {
		if b, ok := n.certifiedBeaconForEpoch(epoch); ok {
			return &b, nil
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
	if n.skipABA {
		return nil
	}
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
	defer n.mu.Unlock()
	var feeds []seedFeed
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
				n.markRemovalLocked(p.Source, p.Epoch)
			}
			delete(n.State.PendingABAs, inst)
			delete(n.abaInputSent, inst)
			delete(n.abaInputs, inst)
			continue
		}
		p.Round = st.Round
		p.CoinWait = st.CoinWait
		if st.CoinWait {
			target := p.Epoch + st.Round
			if seed := n.beaconSeeds[target]; len(seed) > 0 {
				p.CoinWait = false
				feeds = append(feeds, seedFeed{instance: inst, round: st.Round, seed: append([]byte(nil), seed...)})
			}
		}
		if inst != current && !p.Decided && !p.CoinWait {
			blocked = true
		}
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
	n.mu.Lock()
	if obj.ConfigVersion != n.State.ConfigVersion {
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
		n.State.ComQ[obj.Producer] = make(map[uint64]Object)
	}
	nextSeq := n.State.Seqs[obj.Producer] + 1
	maxSeq := n.State.Seqs[obj.Producer] + uint64(n.State.QueueLen)
	if obj.Seq < nextSeq || obj.Seq > maxSeq {
		debugf("node=%s drop object producer=%s seq=%d reason=window next=%d max=%d", n.ID, obj.Producer, obj.Seq, nextSeq, maxSeq)
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
	n.verified[key] = verifiedObject{version: obj.ConfigVersion, object: obj, valid: valid}
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
		n.Crypto.Go(ctx, func() { _ = n.handleRecon(ctx, from, body) })
	case "RECON_ECHO":
		body, err := p2p.DecodePayload[ReconEchoMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		n.Crypto.Go(ctx, func() {
			n.observeEchoReady(ctx, "echo", from, body.Epoch, body.Source, body.Seq, body.Random, crypto.BLSSignatureShare{})
		})
	case "RECON_READY":
		body, err := p2p.DecodePayload[signedReconReadyMessage](msg)
		if err != nil {
			return err
		}
		from := msg.From
		n.Crypto.Go(ctx, func() {
			n.observeEchoReady(ctx, "ready", from, body.Epoch, body.Source, body.Seq, body.Random, body.Signature)
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
		body, err := p2p.DecodePayload[Beacon](msg)
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
	if n.reconDone[key] || body.Share.CommitmentID != obj.Commitment.SecretID {
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
	shares := make([]crypto.DecryptedShare, 0, len(n.recon[key]))
	for _, sh := range n.recon[key] {
		shares = append(shares, sh)
	}
	prev := append([]byte(nil), n.State.RPrev...)
	n.mu.Unlock()
	if err := n.ensureVerified(obj); err != nil {
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

func (n *Node) observeEchoReady(ctx context.Context, kind string, from p2p.NodeID, epoch uint64, source p2p.NodeID, seq uint64, random []byte, sig crypto.BLSSignatureShare) {
	key := epochKey(epoch, source, seq)
	rh := hex.EncodeToString(random)
	readyKey := key + "/" + rh
	if kind == "ready" {
		n.mu.Lock()
		duplicate := n.certified[readyKey]
		if !duplicate && n.readies[key] != nil && n.readies[key][rh] != nil {
			_, duplicate = n.readies[key][rh][from]
		}
		n.mu.Unlock()
		if duplicate {
			return
		}
		// A READY is counted only if it carries a valid signature over the exact
		// READY transcript. This preserves the original threshold rule while
		// preventing a bare sender id from becoming part of the certificate.
		start := time.Now()
		valid := sig.Signer == string(from) && crypto.VerifyBLSShare(sig, n.BLSPublic, readyVoteBytes(epoch, source, seq, rh))
		if n.Perf != nil {
			n.Perf.addBLSVerify(time.Since(start))
		}
		if !valid {
			return
		}
	}
	n.mu.Lock()
	if n.echoes[key] == nil {
		n.echoes[key] = make(map[string]map[p2p.NodeID]bool)
	}
	if n.readies[key] == nil {
		n.readies[key] = make(map[string]map[p2p.NodeID]crypto.BLSSignatureShare)
	}
	if n.echoes[key][rh] == nil {
		n.echoes[key][rh] = make(map[p2p.NodeID]bool)
	}
	if n.readies[key][rh] == nil {
		n.readies[key][rh] = make(map[p2p.NodeID]crypto.BLSSignatureShare)
	}
	if kind == "echo" {
		n.echoes[key][rh][from] = true
	} else {
		n.readies[key][rh][from] = sig
	}
	echoCount := len(n.echoes[key][rh])
	readyCount := len(n.readies[key][rh])
	needReady := !n.readySent[readyKey] && (echoCount >= 2*n.State.F+1 || readyCount >= n.State.F+1)
	if needReady {
		n.readySent[readyKey] = true
	}
	certify := !n.certified[readyKey] && readyCount >= 2*n.State.F+1
	var senders []p2p.NodeID
	var votes []crypto.BLSSignatureShare
	if certify {
		for id := range n.readies[key][rh] {
			senders = append(senders, id)
			votes = append(votes, n.readies[key][rh][id])
		}
		sort.Slice(senders, func(i, j int) bool { return senders[i] < senders[j] })
	}
	n.mu.Unlock()
	if needReady {
		// READY amplification is unchanged: once enough ECHO/READY evidence is
		// observed, this node broadcasts READY. The added BLS share signs the
		// same canonical statement that will later be aggregated.
		start := time.Now()
		sig, err := crypto.SignBLS(string(n.ID), n.BLS.Private, readyVoteBytes(epoch, source, seq, rh))
		if n.Perf != nil {
			n.Perf.addBLSSign(time.Since(start))
		}
		if err == nil {
			msg, err := p2p.NewMessage(Protocol, "RECON_READY", key, n.ID, "", signedReconReadyMessage{Epoch: epoch, Source: source, Seq: seq, Random: random, Signature: sig})
			if err == nil {
				_ = n.Transport.Broadcast(ctx, msg)
			}
		}
	}
	if certify {
		// Certification now outputs a compact aggregate BLS certificate for the
		// 2f+1 READY quorum. The quorum threshold and random reconstruction are
		// unchanged; only the representation of the READY certificate is smaller
		// and externally verifiable.
		start := time.Now()
		cert, err := crypto.AggregateBLSTrusted(votes, n.BLSPublic, readyVoteBytes(epoch, source, seq, rh), 2*n.State.F+1)
		if n.Perf != nil {
			n.Perf.addBLSAggregate(time.Since(start))
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
		n.certifyBeacon(epoch, source, seq, random, senders, cert)
	}
}

func (n *Node) certifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, senders []p2p.NodeID, cert crypto.BLSAggregateSignature) {
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
	go n.finishCertifyBeacon(epoch, source, seq, random, senders, cert)
}

func (n *Node) finishCertifyBeacon(epoch uint64, source p2p.NodeID, seq uint64, random []byte, senders []p2p.NodeID, cert crypto.BLSAggregateSignature) {
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
	n.removeSelectedSourceIfMarkedLocked(epoch, source)
	feeds := n.processPendingABAsLocked(epoch)
	joinFeeds := n.processJoinCoinWaitsLocked(epoch)
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
	n.rotateSourcesLocked(epoch, source, seq)
	n.State.Epoch = epoch
	n.State.RPrev = append([]byte(nil), random...)
	n.cleanupCertifiedStateLocked(epoch)
	b := Beacon{
		Epoch: epoch, Source: source, Seq: seq, PrevRandom: prev, Random: append([]byte(nil), random...),
		Secret: secret, ObjectID: obj.Commitment.SecretID, ReadySenders: senders, Signature: cert,
		ConfigVersion: n.State.ConfigVersion, State: n.stateDigestLocked(),
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
	msg, err := p2p.NewMessage(Protocol, "BEACON_CERT", key, n.ID, "", b)
	if err == nil {
		_ = n.Transport.Broadcast(context.Background(), msg)
	}
}

func (n *Node) handleBeaconCert(b Beacon) error {
	if b.Epoch == 0 || b.Source == "" || b.Seq == 0 || len(b.Random) == 0 {
		return nil
	}
	n.tryApplyBeaconCert(b)
	return nil
}

func (n *Node) tryApplyBeaconCert(b Beacon) bool {
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
	threshold := 2*n.State.F + 1
	n.mu.Unlock()
	if !ok || obj.ConfigVersion != b.ConfigVersion {
		n.mu.Lock()
		if n.State.Epoch < b.Epoch && b.ConfigVersion == n.State.ConfigVersion {
			n.pendingCerts[key] = b
		}
		n.mu.Unlock()
		return false
	}
	rh := hex.EncodeToString(b.Random)
	if err := crypto.VerifyBLSAggregate(b.Signature, n.BLSPublic, readyVoteBytes(b.Epoch, b.Source, b.Seq, rh), threshold); err != nil {
		return false
	}
	n.mu.Lock()
	delete(n.pendingCerts, key)
	n.mu.Unlock()
	n.certifyBeacon(b.Epoch, b.Source, b.Seq, b.Random, b.ReadySenders, b.Signature)
	return true
}

type coinFeed struct {
	instance string
	round    uint64
}

func (n *Node) processPendingABAsLocked(certEpoch uint64) []coinFeed {
	var feeds []coinFeed
	for inst, p := range n.State.PendingABAs {
		if p.CoinWait && p.Epoch+p.Round == certEpoch {
			feeds = append(feeds, coinFeed{instance: inst, round: p.Round})
		}
	}
	return feeds
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
				n.markRemovalLocked(p.Source, p.Epoch)
			}
			delete(n.State.PendingABAs, feed.instance)
			delete(n.abaInputSent, feed.instance)
			delete(n.abaInputs, feed.instance)
			n.mu.Unlock()
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

func (n *Node) markRemovalLocked(source p2p.NodeID, epoch uint64) {
	n.State.RmMark[source] = int64(epoch + uint64(n.exclusionWindowLocked()))
}

func (n *Node) removeSelectedSourceIfMarkedLocked(epoch uint64, source p2p.NodeID) {
	if n.State.RmMark[source] != -1 && epoch == uint64(n.State.RmMark[source]) {
		n.removeMemberLocked(source)
	}
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
		if cached.version != n.State.ConfigVersion || cached.object.Seq <= n.State.Seqs[cached.object.Producer] {
			delete(n.verified, key)
		}
	}
}

func (n *Node) removeMemberLocked(id p2p.NodeID) {
	n.State.Members = removeID(n.State.Members, id)
	n.State.SCL = removeID(n.State.SCL, id)
	n.State.RSQ = removeID(n.State.RSQ, id)
	delete(n.State.ComQ, id)
	delete(n.State.Seqs, id)
	delete(n.State.RmMark, id)
	delete(n.BLSPublic, string(id))
	n.State.ConfigVersion++
	n.State.F = (len(n.State.Members) - 1) / 3
	n.RBC.N, n.RBC.F = len(n.State.Members), n.State.F
	n.ABA.N, n.ABA.F = len(n.State.Members), n.State.F
	n.installRemovalPVSSLocked()
	n.resetConfigurationCachesLocked()
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
	n.recon = make(map[string]map[p2p.NodeID]crypto.DecryptedShare)
	n.reconSecret = make(map[string][]byte)
	n.reconDone = make(map[string]bool)
	n.echoes = make(map[string]map[string]map[p2p.NodeID]bool)
	n.readies = make(map[string]map[string]map[p2p.NodeID]crypto.BLSSignatureShare)
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

func (n *Node) currentEpoch() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.State.Epoch + 1
}

func (n *Node) CompletedEpoch() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.State.Epoch
}

func (n *Node) handleABADecision(ctx context.Context, dec aba.Decision) {
	n.mu.Lock()
	if p := n.State.PendingABAs[dec.Instance]; p != nil {
		p.Decided = true
		p.Decision = dec.Value
		if !dec.Value && n.State.RmMark[p.Source] == -1 {
			n.markRemovalLocked(p.Source, p.Epoch)
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
		target := p.Epoch + req.Round
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

func readyVoteBytes(epoch uint64, source p2p.NodeID, seq uint64, randomHash string) []byte {
	// Keep one canonical transcript for both individual READY signatures and
	// aggregate certificate verification. The random hash is used instead of the
	// full random value so signatures bind the same compact statement carried by
	// the READY threshold logic.
	return crypto.HashBytes(
		[]byte("Tyche-v1/READY"),
		[]byte(fmt.Sprintf("%d", epoch)),
		[]byte(source),
		[]byte(fmt.Sprintf("%d", seq)),
		[]byte(randomHash),
	)
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
