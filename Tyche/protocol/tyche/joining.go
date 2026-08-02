package tyche

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/Tyche/protocol/rbc"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

// CertifiedCheckpoint is an out-of-band state-transfer object, not joining
// admission evidence.
type CertifiedCheckpoint struct {
	Anchor      SchedulingState            `json:"anchor"`
	History     []BeaconHistoryLink        `json:"history,omitempty"`
	State       SchedulingState            `json:"state"`
	Certificate *BeaconQC                  `json:"certificate,omitempty"`
	RmMark      map[p2p.NodeID]RemovalMark `json:"rm_mark,omitempty"`
}

func (checkpoint CertifiedCheckpoint) Digest() string {
	return hex.EncodeToString(crypto.DomainHash("Tyche/Checkpoint/v1", canonicalJSON(checkpoint)))
}

// JoinRequest is the complete value fixed by the joiner-scoped RBC.
type JoinRequest struct {
	ConfigVersion uint64     `json:"config_version"`
	Joiner        p2p.NodeID `json:"joiner"`
	PublicKey     string     `json:"public_key"`
	AnchorEpoch   uint64     `json:"anchor_epoch"`
	Object        Object     `json:"object"`
}

type JoinPhase uint8

const (
	JoinReserved JoinPhase = iota + 1
	JoinStarted
	JoinDecided
)

type PendingJoin struct {
	Proposal        JoinRequest             `json:"proposal"`
	RBCCert         rbc.DeliveryCertificate `json:"rbc_certificate"`
	Phase           JoinPhase               `json:"phase"`
	QuietThroughout bool                    `json:"quiet_throughout"`
	Decision        bool                    `json:"decision"`
	ABACert         aba.Certificate         `json:"aba_certificate"`
	CoinRound       uint64                  `json:"coin_round"`
	CoinWait        bool                    `json:"coin_wait"`
}

func (n *Node) pendingJoinCoinFeedLocked(certEpoch uint64) (coinFeed, bool) {
	if n.PendingJoin == nil || n.PendingJoin.Phase != JoinStarted || !n.PendingJoin.CoinWait {
		return coinFeed{}, false
	}
	req := n.PendingJoin.Proposal
	if req.AnchorEpoch+n.PendingJoin.CoinRound != certEpoch {
		return coinFeed{}, false
	}
	n.PendingJoin.CoinWait = false
	return coinFeed{
		instance: aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner)),
		round:    n.PendingJoin.CoinRound,
	}, true
}

func (n *Node) waitPendingJoinAfterSeed(ctx context.Context, feed coinFeed) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		n.mu.Lock()
		engine := n.ABAs[abaVersion(feed.instance)]
		n.mu.Unlock()
		if engine == nil {
			return
		}
		status := engine.Status(feed.instance)
		n.mu.Lock()
		if n.PendingJoin == nil {
			n.mu.Unlock()
			return
		}
		if status.Decided {
			n.mu.Unlock()
			return
		}
		n.PendingJoin.CoinRound = status.Round
		n.PendingJoin.CoinWait = status.CoinWait
		if status.CoinWait && status.Round > feed.round {
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

// JoinDecisionCertificate is compact: the proposal is not retransmitted to
// the learner that created it.
type JoinDecisionCertificate struct {
	ConfigVersion uint64                  `json:"config_version"`
	Joiner        p2p.NodeID              `json:"joiner"`
	ProposalHash  string                  `json:"proposal_hash"`
	RBCCert       rbc.DeliveryCertificate `json:"rbc_certificate"`
	ABACert       aba.Certificate         `json:"aba_certificate"`
}

type JoinCertificate struct {
	Request  JoinRequest             `json:"request"`
	Evidence JoinDecisionCertificate `json:"evidence"`
}

func JoinDigest(req JoinRequest) string {
	return hex.EncodeToString(crypto.DomainHash("Tyche/JoinProposal/v1", canonicalJSON(req)))
}

func (n *Node) Checkpoint() CertifiedCheckpoint {
	n.mu.Lock()
	defer n.mu.Unlock()
	checkpoint := CertifiedCheckpoint{
		Anchor:  CloneSchedulingState(n.HistoryAnchor),
		History: append([]BeaconHistoryLink(nil), n.BeaconHistory...),
		State:   CloneSchedulingState(n.Schedule),
		RmMark:  cloneMarkMap(n.State.RmMark),
	}
	if n.LatestBeaconQC != nil {
		qc := *n.LatestBeaconQC
		checkpoint.Certificate = &qc
	}
	return checkpoint
}

func (n *Node) VerifyCheckpoint(checkpoint CertifiedCheckpoint) error {
	n.mu.Lock()
	configurations := make(map[uint64]Configuration, len(n.Configurations))
	for version, configuration := range n.Configurations {
		configurations[version] = configuration
	}
	anchor := CloneSchedulingState(n.HistoryAnchor)
	n.mu.Unlock()
	if HashSchedulingState(checkpoint.Anchor) != HashSchedulingState(anchor) {
		return errors.New("checkpoint anchor is not trusted")
	}
	current := checkpoint.Anchor
	for index, link := range checkpoint.History {
		config, ok := configurations[link.QC.ConfigVersion]
		if !ok {
			return fmt.Errorf("checkpoint link %d needs signing configuration %d", index, link.QC.ConfigVersion)
		}
		if err := VerifyBeaconQC(config, link.QC); err != nil {
			return fmt.Errorf("invalid checkpoint link %d: %w", index, err)
		}
		if link.QC.ParentHash != current.BeaconHead {
			return fmt.Errorf("checkpoint link %d has the wrong parent", index)
		}
		expected, err := entropySuccessorForRecord(current, link.QC.ConfigVersion, config.F, link.QC.Random, link.QC.Source, link.QC.Seq)
		if err != nil || HashSchedulingState(expected) != HashSchedulingState(link.Child) {
			return fmt.Errorf("checkpoint link %d has a non-deterministic child", index)
		}
		current = link.Child
	}
	if HashSchedulingState(current) != HashSchedulingState(checkpoint.State) {
		return errors.New("checkpoint history does not end at advertised state")
	}
	return nil
}

func (n *Node) InstallCheckpoint(checkpoint CertifiedCheckpoint) error {
	if err := n.VerifyCheckpoint(checkpoint); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if checkpoint.State.ConfigVersion != n.Schedule.ConfigVersion ||
		checkpoint.State.ConfigDigest != n.Schedule.ConfigDigest {
		return errors.New("checkpoint requires the active configuration setup")
	}
	if checkpoint.State.Epoch < n.Schedule.Epoch {
		return errors.New("checkpoint is older than local state")
	}
	n.HistoryAnchor = CloneSchedulingState(checkpoint.Anchor)
	n.BeaconHistory = append([]BeaconHistoryLink(nil), checkpoint.History...)
	n.Schedule = CloneSchedulingState(checkpoint.State)
	if checkpoint.Certificate != nil {
		qc := *checkpoint.Certificate
		n.LatestBeaconQC = &qc
	}
	n.State.Epoch = checkpoint.State.Epoch
	n.State.RPrev = append([]byte(nil), checkpoint.State.Random...)
	n.State.SCL = append([]p2p.NodeID(nil), checkpoint.State.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), checkpoint.State.RSQ...)
	n.State.Seqs = cloneSeqMap(checkpoint.State.Seqs)
	n.State.RmMark = cloneMarkMap(checkpoint.RmMark)
	if n.hasRemovalControlLocked() {
		n.noteJoinControlLocked()
	}
	return n.persistLocked()
}

func (n *Node) bootstrapCheckpoint(checkpoint CertifiedCheckpoint) error {
	n.mu.Lock()
	n.HistoryAnchor = CloneSchedulingState(checkpoint.Anchor)
	n.mu.Unlock()
	return n.InstallCheckpoint(checkpoint)
}

// ProposeJoin carries the proposal only in RBC VAL. ECHO/READY and ABA carry
// only a digest and signed protocol state.
func (n *Node) ProposeJoin(ctx context.Context, req JoinRequest) error {
	if err := n.verifyJoinProposal(req, false); err != nil {
		return err
	}
	raw, err := json.Marshal(envelope{Kind: "join", Join: &req})
	if err != nil {
		return err
	}
	msg, err := rbc.ExternalValueMessage(req.ConfigVersion, "join", req.Joiner, 1, raw, n.IdentityPrivate)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.joinProposals[JoinDigest(req)] = req
	n.mu.Unlock()
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) prepareExternalJoinRBC(msg p2p.Message, engine *rbc.Broadcaster) error {
	body, err := p2p.DecodePayload[rbc.ValueMessage](msg)
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(body.Value, &env); err != nil ||
		env.Kind != "join" || env.Join == nil {
		return errors.New("invalid join RBC value")
	}
	req := *env.Join
	if req.Joiner != body.Dealer || req.Joiner != msg.From ||
		req.ConfigVersion != body.ConfigVersion {
		return errors.New("join RBC dealer mismatch")
	}
	if err := n.verifyJoinProposal(req, true); err != nil {
		return err
	}
	public, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("invalid joiner public key")
	}
	return engine.RegisterExternalDealer(req.Joiner, ed25519.PublicKey(public))
}

func (n *Node) handleJoinDelivery(ctx context.Context, delivery rbc.Delivery, req JoinRequest) error {
	if err := n.verifyJoinProposal(req, true); err != nil {
		return nil
	}
	n.mu.Lock()
	if n.PendingJoin == nil {
		n.PendingJoin = &PendingJoin{
			Proposal: req, RBCCert: delivery.Certificate, Phase: JoinReserved,
			QuietThroughout: !n.hasRemovalControlLocked(),
		}
		n.joinProposals[JoinDigest(req)] = req
	}
	n.mu.Unlock()
	if err := n.maybeStartJoin(ctx); err != nil {
		return err
	}
	n.retryPendingABACertificates(ctx)
	return nil
}

func (n *Node) maybeStartJoin(ctx context.Context) error {
	n.mu.Lock()
	openEpoch := n.State.Epoch + 1
	if n.PendingJoin == nil || n.PendingJoin.Phase != JoinReserved ||
		n.PendingJoin.Proposal.ConfigVersion != n.State.ConfigVersion ||
		openEpoch < n.PendingJoin.Proposal.AnchorEpoch {
		n.mu.Unlock()
		return nil
	}
	req := n.PendingJoin.Proposal
	instance := aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner))
	input := openEpoch == req.AnchorEpoch
	engine := n.ABAs[req.ConfigVersion]
	// The transition precedes Propose, so the level-triggered epoch event
	// invokes this instance at most once.
	n.PendingJoin.Phase = JoinStarted
	n.abaInputSent[instance] = true
	n.abaInputs[instance] = input
	deferred := append([]p2p.Message(nil), n.deferredJoinABA[instance]...)
	delete(n.deferredJoinABA, instance)
	n.mu.Unlock()
	if engine == nil {
		return errors.New("missing JOIN-ABA engine")
	}
	if err := engine.Propose(ctx, instance, input); err != nil {
		return err
	}
	for _, msg := range deferred {
		if err := engine.Handle(ctx, msg); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) verifyJoinProposal(req JoinRequest, acceptCurrentOrOld bool) error {
	n.mu.Lock()
	current := n.State.ConfigVersion
	parent, parentOK := n.Configurations[req.ConfigVersion]
	setup, setupOK := n.joinCandidateSetupLocked(req, parent)
	n.mu.Unlock()
	if !parentOK || req.ConfigVersion > current ||
		(!acceptCurrentOrOld && req.ConfigVersion != current) {
		return errors.New("join proposal names an unavailable configuration")
	}
	if req.Joiner == "" || parent.Contains(req.Joiner) || req.AnchorEpoch == 0 {
		return errors.New("invalid join proposal")
	}
	public, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("invalid joiner identity public key")
	}
	if !setupOK || setup.Configuration.Version != req.ConfigVersion+1 {
		return errors.New("successor configuration setup is not registered")
	}
	expected := normalizeMembers(append(append([]p2p.NodeID(nil), parent.Members...), req.Joiner))
	if !sameMembers(expected, setup.Configuration.Members) {
		return errors.New("successor setup does not add exactly the joiner")
	}
	configured := setup.Configuration.IdentityKeys[req.Joiner]
	if len(configured) != ed25519.PublicKeySize ||
		!ed25519.PublicKey(configured).Equal(ed25519.PublicKey(public)) {
		return errors.New("joiner key does not match successor setup")
	}
	if req.Object.ConfigVersion != req.ConfigVersion+1 ||
		req.Object.Producer != req.Joiner || req.Object.Seq != 1 ||
		req.Object.Commitment.Dealer != req.Joiner ||
		req.Object.Commitment.Seq != 1 {
		return errors.New("invalid first joiner PVSS object")
	}
	if setup.Scheme == nil {
		return errors.New("missing successor PVSS verifier")
	}
	if err := n.verifyObjectOnce(req.Object, setup.Scheme); err != nil {
		return errors.New("invalid first joiner PVSS proof")
	}
	return nil
}

func (n *Node) joinCandidateSetupLocked(req JoinRequest, parent Configuration) (ConfigurationSetup, bool) {
	expected := normalizeMembers(append(append([]p2p.NodeID(nil), parent.Members...), req.Joiner))
	for _, setup := range n.CandidateSetups {
		if setup.Configuration.Version == req.ConfigVersion+1 &&
			sameMembers(setup.Configuration.Members, expected) &&
			hex.EncodeToString(setup.Configuration.IdentityKeys[req.Joiner]) == req.PublicKey &&
			setup.Params.Epoch() == req.Object.Commitment.Epoch {
			return setup, true
		}
	}
	return ConfigurationSetup{}, false
}

// hasRemovalControlLocked reports whether the paper-level pending control
// state is present. State.PendingABAs also retains actively executing ABAs;
// only an instance waiting for an unavailable future beacon belongs to the
// paper's pendingaba set.
func (n *Node) hasRemovalControlLocked() bool {
	for _, pending := range n.State.PendingABAs {
		if pending != nil && pending.CoinWait &&
			len(n.beaconSeeds[pending.Epoch+pending.Round+1]) == 0 {
			return true
		}
	}
	for _, mark := range n.State.RmMark {
		if mark.Seq > 0 {
			return true
		}
	}
	return false
}

// noteJoinControlLocked is a one-way latch for the current attempt. Once a
// paper-level pending ABA or removal marker appears after RBC delivery, that
// attempt cannot become installable again.
func (n *Node) noteJoinControlLocked() {
	if n.PendingJoin != nil {
		n.PendingJoin.QuietThroughout = false
	}
}

func (n *Node) handleJoinDecision(ctx context.Context, dec aba.Decision) bool {
	n.mu.Lock()
	if n.PendingJoin == nil {
		n.mu.Unlock()
		return false
	}
	req := n.PendingJoin.Proposal
	instance := aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner))
	if dec.ConfigVersion != req.ConfigVersion || dec.Instance != instance {
		n.mu.Unlock()
		return false
	}
	n.PendingJoin.Phase = JoinDecided
	n.PendingJoin.Decision = dec.Value
	n.PendingJoin.ABACert = dec.Certificate
	n.mu.Unlock()
	_ = n.maybeInstallJoin(ctx)
	return true
}

func (n *Node) handleJoinCertificate(ctx context.Context, evidence JoinDecisionCertificate) error {
	n.mu.Lock()
	req, ok := n.joinProposals[evidence.ProposalHash]
	parent, parentOK := n.Configurations[evidence.ConfigVersion]
	seed := append([]byte(nil), n.beaconSeeds[req.AnchorEpoch+evidence.ABACert.Round]...)
	n.mu.Unlock()
	if !ok || !parentOK || evidence.ProposalHash != JoinDigest(req) ||
		evidence.Joiner != req.Joiner || evidence.ConfigVersion != req.ConfigVersion {
		return nil
	}
	raw, err := json.Marshal(envelope{Kind: "join", Join: &req})
	if err != nil || evidence.RBCCert.Hash != rbc.Digest(raw) {
		return errors.New("JOIN certificate does not bind the proposal")
	}
	if err := rbc.VerifyDeliveryCertificate(
		parent.Version, "join", parent.Members, parent.F,
		parent.PublicKeys(), evidence.RBCCert,
	); err != nil {
		return err
	}
	instance := aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner))
	if evidence.ABACert.Instance != instance || !evidence.ABACert.Value {
		return errors.New("JOIN certificate carries the wrong ABA decision")
	}
	if !evidence.ABACert.FastPath && len(seed) == 0 {
		n.mu.Lock()
		copyEvidence := evidence
		n.pendingJoinCert = &copyEvidence
		n.mu.Unlock()
		return nil
	}
	if err := aba.VerifyCertificate(
		evidence.ABACert, parent.PublicKeys(), parent.Q, seed,
	); err != nil {
		return err
	}
	n.mu.Lock()
	if n.State.ConfigVersion != req.ConfigVersion {
		n.pendingJoinCert = nil
		delete(n.joinProposals, evidence.ProposalHash)
		n.mu.Unlock()
		return nil
	}
	if parent.Contains(n.ID) {
		if n.PendingJoin == nil || JoinDigest(n.PendingJoin.Proposal) != evidence.ProposalHash ||
			!n.PendingJoin.QuietThroughout {
			n.mu.Unlock()
			return nil
		}
	}
	if err := n.installJoinLocked(req); err != nil {
		n.mu.Unlock()
		return err
	}
	delete(n.joinProposals, evidence.ProposalHash)
	n.pendingJoinCert = nil
	n.mu.Unlock()
	select {
	case n.Joins <- JoinCertificate{Request: req, Evidence: evidence}:
	default:
	}
	_ = ctx
	return nil
}

func (n *Node) retryPendingJoinCertificate(ctx context.Context) {
	n.mu.Lock()
	if n.pendingJoinCert == nil {
		n.mu.Unlock()
		return
	}
	evidence := *n.pendingJoinCert
	n.mu.Unlock()
	_ = n.handleJoinCertificate(ctx, evidence)
}

func (n *Node) maybeInstallJoin(ctx context.Context) error {
	n.mu.Lock()
	if n.PendingJoin == nil || n.PendingJoin.Phase != JoinDecided {
		n.mu.Unlock()
		return nil
	}
	req := n.PendingJoin.Proposal
	if req.ConfigVersion != n.State.ConfigVersion {
		delete(n.joinProposals, JoinDigest(req))
		delete(n.deferredJoinABA, aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner)))
		n.PendingJoin = nil
		n.mu.Unlock()
		return nil
	}
	if !n.PendingJoin.QuietThroughout {
		delete(n.joinProposals, JoinDigest(req))
		delete(n.deferredJoinABA, aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner)))
		n.PendingJoin = nil
		n.mu.Unlock()
		return nil
	}
	if !n.PendingJoin.Decision {
		delete(n.joinProposals, JoinDigest(req))
		delete(n.deferredJoinABA, aba.JoinInstanceFor(req.ConfigVersion, string(req.Joiner)))
		n.PendingJoin = nil
		n.mu.Unlock()
		return nil
	}
	evidence := JoinDecisionCertificate{
		ConfigVersion: req.ConfigVersion,
		Joiner:        req.Joiner,
		ProposalHash:  JoinDigest(req),
		RBCCert:       n.PendingJoin.RBCCert,
		ABACert:       n.PendingJoin.ABACert,
	}
	if err := n.installJoinLocked(req); err != nil {
		n.mu.Unlock()
		return err
	}
	n.PendingJoin = nil
	delete(n.joinProposals, JoinDigest(req))
	certificate := JoinCertificate{Request: req, Evidence: evidence}
	oldConfig := n.Configurations[req.ConfigVersion]
	oldMembers := append([]p2p.NodeID(nil), oldConfig.Members...)
	oldF := oldConfig.F
	n.mu.Unlock()
	select {
	case n.Joins <- certificate:
	default:
	}
	relay := false
	for index, member := range oldMembers {
		if index >= oldF+1 {
			break
		}
		if member == n.ID {
			relay = true
			break
		}
	}
	// f+1 deterministic relays guarantee one honest delivery while avoiding a
	// full old-configuration broadcast of the certificate.
	if relay {
		msg, err := p2p.NewMessage(Protocol, "JOIN_CERT", evidence.ProposalHash, n.ID, req.Joiner, evidence)
		if err == nil {
			return n.Transport.Send(ctx, req.Joiner, msg)
		}
	}
	return nil
}

// installJoinLocked applies the ABA-certified one-member transition without a
// second state-consensus round. The caller holds n.mu and has checked the
// attempt's monotone QuietThroughout bit.
func (n *Node) installJoinLocked(req JoinRequest) error {
	parentConfiguration, parentOK := n.Configurations[req.ConfigVersion]
	if !parentOK {
		return errors.New("missing parent configuration")
	}
	setup, ok := n.joinCandidateSetupLocked(req, parentConfiguration)
	if !ok {
		return errors.New("missing successor setup")
	}
	if setup.Configuration.Contains(n.ID) && setup.Scheme == nil {
		return errors.New("missing local successor PVSS scheme")
	}
	parent := CloneSchedulingState(n.Schedule)
	child := CloneSchedulingState(parent)
	child.ConfigVersion = setup.Configuration.Version
	child.F = setup.Configuration.F
	child.Q = setup.Configuration.Q
	child.PVSSThreshold = setup.Configuration.PVSSThreshold
	child.ConfigDigest = setup.Configuration.Digest()
	child.Members = append([]p2p.NodeID(nil), setup.Configuration.Members...)
	child.Seqs[req.Joiner] = 0

	child = canonicalSchedulingState(child)
	if err := n.installReconfiguredStateLocked(child); err != nil {
		return err
	}
	if n.State.ComQ[req.Joiner] == nil {
		n.State.ComQ[req.Joiner] = make(map[uint64]Object)
	}
	n.State.ComQ[req.Joiner][1] = req.Object
	return n.persistLocked()
}

func (n *Node) RegisterPVSSKey(paramsEpoch string, private kyber.Scalar) {
	if paramsEpoch == "" || private == nil {
		return
	}
	n.mu.Lock()
	n.pvssKeys[paramsEpoch] = private.Clone()
	n.mu.Unlock()
}
