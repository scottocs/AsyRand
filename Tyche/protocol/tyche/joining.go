package tyche

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type CertifiedCheckpoint struct {
	Anchor      CertifiedState            `json:"anchor"`
	History     []StateCertificateMessage `json:"history,omitempty"`
	State       CertifiedState            `json:"state"`
	Certificate *StateQC                  `json:"certificate,omitempty"`
}

func (checkpoint CertifiedCheckpoint) Digest() string {
	return hex.EncodeToString(crypto.DomainHash("Tyche/Checkpoint/v1", canonicalJSON(checkpoint)))
}

type JoinRequest struct {
	ConfigVersion    uint64              `json:"config_version"`
	ParentHash       string              `json:"parent_hash"`
	Joiner           p2p.NodeID          `json:"joiner"`
	PublicKey        string              `json:"public_key"`
	CandidateParams  crypto.PVSSParams   `json:"candidate_params"`
	Object           Object              `json:"object"`
	Checkpoint       CertifiedCheckpoint `json:"checkpoint"`
	LearnerSignature crypto.SignedVote   `json:"learner_signature"`
}

type JoinAdmissionVote struct {
	RequestDigest string            `json:"request_digest"`
	ParentHash    string            `json:"parent_hash"`
	Vote          crypto.SignedVote `json:"vote"`
}

type JoinReadyCertificate struct {
	Request   JoinRequest                    `json:"request"`
	Admission crypto.SignedQuorumCertificate `json:"admission"`
}

// JoinCertificate is the installed JOIN event. It replaces the old Cert1/Cert2
// object; the only installation authority is the JOIN StateQC.
type JoinCertificate struct {
	Request JoinRequest    `json:"request"`
	Child   CertifiedState `json:"child"`
	StateQC StateQC        `json:"state_qc"`
}

func joinRequestUnsigned(req JoinRequest) any {
	return struct {
		ConfigVersion   uint64              `json:"config_version"`
		ParentHash      string              `json:"parent_hash"`
		Joiner          p2p.NodeID          `json:"joiner"`
		PublicKey       string              `json:"public_key"`
		CandidateParams crypto.PVSSParams   `json:"candidate_params"`
		Object          Object              `json:"object"`
		Checkpoint      CertifiedCheckpoint `json:"checkpoint"`
	}{
		ConfigVersion:   req.ConfigVersion,
		ParentHash:      req.ParentHash,
		Joiner:          req.Joiner,
		PublicKey:       req.PublicKey,
		CandidateParams: req.CandidateParams,
		Object:          req.Object,
		Checkpoint:      req.Checkpoint,
	}
}

func JoinDigest(req JoinRequest) string {
	return hex.EncodeToString(crypto.DomainHash("Tyche/JoinRequest/v2", canonicalJSON(joinRequestUnsigned(req))))
}

func learnerReadyTranscript(req JoinRequest) []byte {
	return crypto.DomainHash(
		"Tyche/LearnerReady/v1",
		[]byte(JoinDigest(req)),
		[]byte(req.ParentHash),
		[]byte(req.Checkpoint.Digest()),
	)
}

func joinAdmissionTranscript(parentVersion uint64, parentHash, requestDigest string) []byte {
	return crypto.DomainHash(
		"Tyche/JoinAdmission/v1",
		[]byte(fmt.Sprintf("%d", parentVersion)),
		[]byte(parentHash),
		[]byte(requestDigest),
	)
}

func SignLearnerReady(req JoinRequest, private ed25519.PrivateKey) (JoinRequest, error) {
	if req.Joiner == "" {
		return JoinRequest{}, errors.New("joiner is required")
	}
	signature, err := crypto.SignTranscript(string(req.Joiner), private, learnerReadyTranscript(req))
	if err != nil {
		return JoinRequest{}, err
	}
	req.LearnerSignature = signature
	return req, nil
}

func (n *Node) Checkpoint() CertifiedCheckpoint {
	n.mu.Lock()
	defer n.mu.Unlock()
	checkpoint := CertifiedCheckpoint{
		Anchor:  CloneCertifiedState(n.HistoryAnchor),
		History: append([]StateCertificateMessage(nil), n.StateHistory...),
		State:   CloneCertifiedState(n.Certified),
	}
	if n.StateCertificate != nil {
		certificate := *n.StateCertificate
		checkpoint.Certificate = &certificate
	}
	return checkpoint
}

// VerifyCheckpoint validates every exact-parent transition from the trusted
// anchor to the advertised state.
func (n *Node) VerifyCheckpoint(checkpoint CertifiedCheckpoint) error {
	n.mu.Lock()
	configurations := make(map[uint64]Configuration, len(n.Configurations))
	for version, configuration := range n.Configurations {
		configurations[version] = configuration
	}
	localAnchor := CloneCertifiedState(n.HistoryAnchor)
	n.mu.Unlock()
	if HashCertifiedState(checkpoint.Anchor) != HashCertifiedState(localAnchor) {
		return errors.New("checkpoint anchor is not trusted")
	}
	current := CloneCertifiedState(checkpoint.Anchor)
	for index, link := range checkpoint.History {
		config, ok := configurations[current.ConfigVersion]
		if !ok {
			return fmt.Errorf("checkpoint link %d needs unknown configuration %d", index, current.ConfigVersion)
		}
		if err := VerifyStateQC(config, current, link.Child, link.QC); err != nil {
			return fmt.Errorf("invalid checkpoint link %d: %w", index, err)
		}
		current = CloneCertifiedState(link.Child)
	}
	if HashCertifiedState(current) != HashCertifiedState(checkpoint.State) {
		return errors.New("checkpoint history does not end at advertised state")
	}
	if checkpoint.Certificate != nil && len(checkpoint.History) > 0 {
		last := checkpoint.History[len(checkpoint.History)-1].QC
		if last.ChildHash != checkpoint.Certificate.ChildHash {
			return errors.New("checkpoint terminal certificate mismatch")
		}
	}
	return nil
}

// InstallCheckpoint is the learner state-transfer path. Runtime queues are not
// copied; future objects arrive through authenticated RBC.
func (n *Node) InstallCheckpoint(checkpoint CertifiedCheckpoint) error {
	if err := n.VerifyCheckpoint(checkpoint); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if checkpoint.State.ConfigVersion != n.Certified.ConfigVersion ||
		checkpoint.State.ConfigDigest != n.Certified.ConfigDigest {
		return errors.New("checkpoint requires the exact active configuration setup")
	}
	if checkpoint.State.Epoch < n.Certified.Epoch {
		return errors.New("checkpoint is older than local certified state")
	}
	n.HistoryAnchor = CloneCertifiedState(checkpoint.Anchor)
	n.StateHistory = append([]StateCertificateMessage(nil), checkpoint.History...)
	n.Certified = CloneCertifiedState(checkpoint.State)
	if checkpoint.Certificate != nil {
		qc := *checkpoint.Certificate
		n.StateCertificate = &qc
	}
	n.State.Epoch = checkpoint.State.Epoch
	n.State.RPrev = append([]byte(nil), checkpoint.State.Random...)
	n.State.SCL = append([]p2p.NodeID(nil), checkpoint.State.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), checkpoint.State.RSQ...)
	n.State.Seqs = cloneSeqMap(checkpoint.State.Seqs)
	n.State.RmMark = cloneMarkMap(checkpoint.State.RmMark)
	return n.persistLocked()
}

func (n *Node) bootstrapCheckpoint(checkpoint CertifiedCheckpoint) error {
	n.mu.Lock()
	n.HistoryAnchor = CloneCertifiedState(checkpoint.Anchor)
	n.mu.Unlock()
	if err := n.InstallCheckpoint(checkpoint); err != nil {
		return fmt.Errorf("bootstrap checkpoint rejected: %w", err)
	}
	return nil
}

func (n *Node) ProposeJoin(ctx context.Context, req JoinRequest) error {
	if err := n.verifyJoinRequest(req); err != nil {
		return err
	}
	if err := n.HandleJoinRequest(ctx, req); err != nil {
		return err
	}
	msg, err := p2p.NewMessage(Protocol, "JOIN_REQUEST", JoinDigest(req), n.ID, "", req)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) HandleJoinRequest(ctx context.Context, req JoinRequest) error {
	if err := n.verifyJoinRequest(req); err != nil {
		return nil
	}
	digest := JoinDigest(req)
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig := n.Configurations[parent.ConfigVersion]
	parentHash := HashCertifiedState(parent)
	if choice := n.joinAdmissionChoice[parentHash]; choice != "" && choice != digest {
		n.mu.Unlock()
		return nil
	}
	n.joinAdmissionChoice[parentHash] = digest
	n.joinRequestsV2[digest] = req
	n.mu.Unlock()
	if !parentConfig.Contains(n.ID) {
		return nil
	}

	vote, err := crypto.SignTranscript(string(n.ID), n.IdentityPrivate, joinAdmissionTranscript(parent.ConfigVersion, parentHash, digest))
	if err != nil {
		return err
	}
	body := JoinAdmissionVote{RequestDigest: digest, ParentHash: req.ParentHash, Vote: vote}
	if err := n.HandleJoinAdmission(ctx, body); err != nil {
		return err
	}
	msg, err := p2p.NewMessage(Protocol, "JOIN_ADMISSION", digest, n.ID, "", body)
	if err != nil {
		return err
	}
	_ = parentConfig
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) HandleJoinAdmission(ctx context.Context, body JoinAdmissionVote) error {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig := n.Configurations[parent.ConfigVersion]
	req, exists := n.joinRequestsV2[body.RequestDigest]
	if !exists || body.ParentHash != req.ParentHash || body.ParentHash != HashCertifiedState(parent) {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	transcript := joinAdmissionTranscript(parent.ConfigVersion, body.ParentHash, body.RequestDigest)
	if err := crypto.VerifySignedVote(body.Vote, parentConfig.PublicKeys(), transcript); err != nil {
		return nil
	}
	n.mu.Lock()
	if n.joinAdmissions[body.RequestDigest] == nil {
		n.joinAdmissions[body.RequestDigest] = make(map[p2p.NodeID]crypto.SignedVote)
	}
	n.joinAdmissions[body.RequestDigest][p2p.NodeID(body.Vote.Signer)] = body.Vote
	ready := len(n.joinAdmissions[body.RequestDigest]) >= parentConfig.Q && !n.joinReadySent[body.RequestDigest]
	var votes []crypto.SignedVote
	if ready {
		n.joinReadySent[body.RequestDigest] = true
		for _, vote := range n.joinAdmissions[body.RequestDigest] {
			votes = append(votes, vote)
		}
	}
	n.mu.Unlock()
	if !ready {
		return nil
	}
	certificate, err := crypto.BuildSignedQuorumCertificate(votes, parentConfig.PublicKeys(), parentConfig.Q, transcript)
	if err != nil {
		return err
	}
	message := JoinReadyCertificate{Request: req, Admission: certificate}
	if err := n.HandleJoinReadyCertificate(message); err != nil {
		return err
	}
	wire, err := p2p.NewMessage(Protocol, "JOIN_READY_CERT", body.RequestDigest, n.ID, "", message)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, wire)
}

func (n *Node) HandleJoinReadyCertificate(message JoinReadyCertificate) error {
	if err := n.verifyJoinRequest(message.Request); err != nil {
		return err
	}
	digest := JoinDigest(message.Request)
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig := n.Configurations[parent.ConfigVersion]
	if message.Request.ParentHash != HashCertifiedState(parent) {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	transcript := joinAdmissionTranscript(parent.ConfigVersion, message.Request.ParentHash, digest)
	if err := crypto.VerifySignedQuorumCertificate(message.Admission, parentConfig.PublicKeys(), parentConfig.Q, transcript); err != nil {
		return err
	}
	childConfig, err := n.configurationForJoin(message.Request)
	if err != nil {
		return err
	}
	ready := JoinReady{
		ParentHash:      message.Request.ParentHash,
		RequestDigest:   digest,
		Joiner:          message.Request.Joiner,
		CheckpointHash:  message.Request.Checkpoint.Digest(),
		CandidateConfig: childConfig.Digest(),
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pendingJReady == nil || ready.RequestDigest < n.pendingJReady.RequestDigest {
		readyCopy := ready
		n.pendingJReady = &readyCopy
	}
	n.joinRequestsV2[digest] = message.Request
	return nil
}

func (n *Node) verifyJoinRequest(req JoinRequest) error {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	n.mu.Unlock()
	if req.ConfigVersion != parent.ConfigVersion || req.ParentHash != HashCertifiedState(parent) {
		return errors.New("join request is stale")
	}
	if req.Joiner == "" || contains(parent.Members, req.Joiner) {
		return errors.New("invalid joiner")
	}
	publicRaw, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(publicRaw) != ed25519.PublicKeySize {
		return errors.New("invalid joiner identity public key")
	}
	if req.Checkpoint.Digest() == "" || HashCertifiedState(req.Checkpoint.State) != req.ParentHash {
		return errors.New("learner checkpoint does not match exact parent")
	}
	if err := n.VerifyCheckpoint(req.Checkpoint); err != nil {
		return fmt.Errorf("invalid learner checkpoint: %w", err)
	}
	if req.LearnerSignature.Signer != string(req.Joiner) ||
		crypto.VerifySignedVote(req.LearnerSignature, map[string]ed25519.PublicKey{string(req.Joiner): publicRaw}, learnerReadyTranscript(req)) != nil {
		return errors.New("invalid learner readiness signature")
	}
	if req.CandidateParams.Epoch() == "" || !crypto.VerifyPVSSSetup(req.CandidateParams) {
		return errors.New("invalid candidate PVSS parameters")
	}
	targetMembers := normalizeMembers(append(append([]p2p.NodeID(nil), parent.Members...), req.Joiner))
	if !sameMembers(req.CandidateParams.Members(), targetMembers) {
		return errors.New("candidate PVSS member set mismatch")
	}
	targetF := req.CandidateParams.Threshold() - 1
	if targetF < 0 || len(targetMembers) < 3*targetF+1 {
		return errors.New("candidate configuration violates Byzantine bound")
	}
	if req.Object.Producer != "" {
		if req.Object.ConfigVersion != parent.ConfigVersion+1 ||
			req.Object.Producer != req.Joiner ||
			req.Object.Commitment.Dealer != req.Joiner ||
			req.Object.Commitment.Epoch != req.CandidateParams.Epoch() {
			return errors.New("invalid candidate first PVSS object")
		}
		verifierPrivate := crypto.KeyPairFromSeed(crypto.DomainHash("Tyche/JoinObjectVerifier/v1", []byte(n.ID))).Private
		verifier, err := crypto.NewPVSSScheme(n.ID, verifierPrivate, req.CandidateParams)
		if err != nil || !verifier.Verify(req.Object.Commitment) {
			return errors.New("invalid candidate first PVSS object proof")
		}
	}
	_, err = n.configurationForJoin(req)
	return err
}

func (n *Node) configurationForJoin(req JoinRequest) (Configuration, error) {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig := n.Configurations[parent.ConfigVersion]
	if existing, ok := n.ConfigurationSetups[parent.ConfigVersion+1]; ok {
		n.mu.Unlock()
		if existing.Params.Epoch() != req.CandidateParams.Epoch() {
			return Configuration{}, errors.New("conflicting candidate setup for next configuration")
		}
		return existing.Configuration, nil
	}
	private := n.pvssKeys[req.CandidateParams.Epoch()]
	n.mu.Unlock()

	publicRaw, _ := hex.DecodeString(req.PublicKey)
	publicKeys := parentConfig.PublicKeys()
	publicKeys[string(req.Joiner)] = append(ed25519.PublicKey(nil), publicRaw...)
	typedKeys := make(map[p2p.NodeID]ed25519.PublicKey, len(publicKeys))
	for signer, public := range publicKeys {
		typedKeys[p2p.NodeID(signer)] = public
	}
	members := req.CandidateParams.Members()
	f := req.CandidateParams.Threshold() - 1
	configuration, err := NewConfiguration(parent.ConfigVersion+1, members, f, req.CandidateParams, typedKeys)
	if err != nil {
		return Configuration{}, err
	}
	if !configuration.Contains(n.ID) {
		return configuration, nil
	}
	if private == nil {
		return Configuration{}, errors.New("missing local PVSS key for candidate configuration")
	}
	if err := n.RegisterConfigurationSetup(configuration, req.CandidateParams, private); err != nil {
		return Configuration{}, err
	}
	return configuration, nil
}

func (n *Node) runCertifiedJoin(ctx context.Context) error {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	if parent.JReady == nil {
		n.mu.Unlock()
		return nil
	}
	for _, mark := range parent.RmMark {
		if mark >= 0 {
			n.mu.Unlock()
			return errors.New("certified removal has priority over JOIN")
		}
	}
	setup, ok := n.ConfigurationSetups[parent.ConfigVersion+1]
	if !ok || setup.Configuration.Digest() != parent.JReady.CandidateConfig {
		n.mu.Unlock()
		return errors.New("missing candidate setup for certified JReady")
	}
	child, err := JoinSuccessor(parent, *parent.JReady, setup.Configuration)
	n.mu.Unlock()
	if err != nil {
		return err
	}
	if err := n.proposeCertifiedState(ctx, child); err != nil {
		return err
	}
	if err := n.waitForStateChange(ctx, HashCertifiedState(parent)); err != nil {
		return err
	}
	n.mu.Lock()
	req := n.joinRequestsV2[parent.JReady.RequestDigest]
	certificate := JoinCertificate{Request: req, Child: child}
	if n.StateCertificate != nil {
		certificate.StateQC = *n.StateCertificate
	}
	n.mu.Unlock()
	select {
	case n.Joins <- certificate:
	default:
	}
	return nil
}

func (n *Node) InstallJoinCertificate(certificate JoinCertificate) error {
	if certificate.Child.Transition != TransitionJoin {
		return errors.New("join certificate does not carry a JOIN successor")
	}
	return n.InstallStateCertificate(StateCertificateMessage{Child: certificate.Child, QC: certificate.StateQC})
}

func (n *Node) RegisterPVSSKey(paramsEpoch string, private kyber.Scalar) {
	if paramsEpoch == "" || private == nil {
		return
	}
	n.mu.Lock()
	n.pvssKeys[paramsEpoch] = private.Clone()
	n.mu.Unlock()
}

// ActivatePendingJoins is retained as an API shim: activation is driven by an
// exact-parent JOIN StateQC, never by a future epoch number.
func (n *Node) ActivatePendingJoins(ctx context.Context, _ uint64) error {
	return n.activatePendingJoins(ctx, 0)
}

func (n *Node) activatePendingJoins(ctx context.Context, _ uint64) error {
	n.mu.Lock()
	ready := n.Certified.JReady != nil
	n.mu.Unlock()
	if !ready {
		return nil
	}
	return n.runCertifiedJoin(ctx)
}
