package tyche

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/Tyche/protocol/rbc"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type ConfigurationSetup struct {
	Configuration Configuration
	Params        crypto.PVSSParams
	Scheme        crypto.PVSSScheme
}

type StateProposalMessage struct {
	Child CertifiedState `json:"child"`
}

type StateVoteMessage struct {
	ParentConfigVersion uint64            `json:"parent_config_version"`
	Transition          TransitionType    `json:"transition"`
	ParentHash          string            `json:"parent_hash"`
	ChildHash           string            `json:"child_hash"`
	Vote                crypto.SignedVote `json:"vote"`
}

type StateCertificateMessage struct {
	Child CertifiedState `json:"child"`
	QC    StateQC        `json:"qc"`
}

func (n *Node) entropySuccessorWithControlLocked(parent CertifiedState, random []byte, source p2p.NodeID, seq uint64) (CertifiedState, error) {
	child, err := EntropySuccessor(parent, random, source, seq)
	if err != nil {
		return CertifiedState{}, err
	}
	hasRemoval := false
	for _, member := range parent.Members {
		if parent.RmMark[member] >= 0 {
			hasRemoval = true
			continue
		}
		if mark := n.State.RmMark[member]; mark >= int64(parent.Seqs[member]+1) {
			child.RmMark[member] = mark
			hasRemoval = true
		}
	}
	if !hasRemoval && parent.JReady == nil && n.pendingJReady != nil &&
		n.pendingJReady.ParentHash == HashCertifiedState(parent) {
		child.JReady = cloneReady(n.pendingJReady)
	}
	return canonicalCertifiedState(child), nil
}

func (n *Node) RegisterConfigurationSetup(configuration Configuration, params crypto.PVSSParams, localPrivate kyber.Scalar) error {
	if err := configuration.Validate(); err != nil {
		return err
	}
	if params.Epoch() == "" || !crypto.VerifyPVSSSetup(params) {
		return errors.New("invalid registered PVSS parameters")
	}
	expectedDigest := fmt.Sprintf("%x", crypto.DomainHash("Tyche/PVSSParams/v1", canonicalJSON(params)))
	if configuration.PVSSParamsDigest != expectedDigest {
		return errors.New("registered PVSS parameters do not match configuration digest")
	}
	var scheme crypto.PVSSScheme
	var err error
	if configuration.Contains(n.ID) {
		if localPrivate == nil {
			return fmt.Errorf("missing local PVSS key for configuration %d", configuration.Version)
		}
		scheme, err = crypto.NewPVSSScheme(n.ID, localPrivate, params)
		if err != nil {
			return err
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if existing, ok := n.Configurations[configuration.Version]; ok && existing.Digest() != configuration.Digest() {
		return fmt.Errorf("conflicting setup for configuration version %d", configuration.Version)
	}
	n.Configurations[configuration.Version] = configuration
	n.ConfigurationSetups[configuration.Version] = ConfigurationSetup{
		Configuration: configuration,
		Params:        params,
		Scheme:        scheme,
	}
	return nil
}

func (n *Node) signStateVoteOnce(parent Configuration, transition TransitionType, parentHash, childHash string) (crypto.SignedVote, error) {
	n.mu.Lock()
	if signed := n.signedParents[parentHash]; signed != "" && signed != childHash {
		n.mu.Unlock()
		return crypto.SignedVote{}, fmt.Errorf("refusing conflicting child %s for parent %s; already signed %s", childHash, parentHash, signed)
	}
	if err := n.Store.ReserveStateVote(parentHash, childHash); err != nil {
		n.mu.Unlock()
		return crypto.SignedVote{}, err
	}
	n.signedParents[parentHash] = childHash
	private := append(ed25519.PrivateKey(nil), n.IdentityPrivate...)
	n.mu.Unlock()
	return SignStateVote(n.ID, private, parent, transition, parentHash, childHash)
}

func (n *Node) proposeCertifiedState(ctx context.Context, child CertifiedState) error {
	childHash := HashCertifiedState(child)
	n.mu.Lock()
	if child.ParentHash != HashCertifiedState(n.Certified) {
		n.mu.Unlock()
		return errors.New("cannot propose a child of a non-current parent")
	}
	n.stateProposals[childHash] = CloneCertifiedState(child)
	n.mu.Unlock()
	proposal := StateProposalMessage{Child: child}
	if err := n.HandleStateProposal(ctx, proposal); err != nil {
		return err
	}
	msg, err := p2p.NewMessage(Protocol, "STATE_PROPOSAL", childHash, n.ID, "", proposal)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) HandleStateProposal(ctx context.Context, proposal StateProposalMessage) error {
	child := canonicalCertifiedState(proposal.Child)
	childHash := HashCertifiedState(child)
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig := n.Configurations[parent.ConfigVersion]
	if child.ParentHash != HashCertifiedState(parent) {
		n.mu.Unlock()
		return nil
	}
	if err := n.validateProposedChildLocked(parent, child); err != nil {
		n.mu.Unlock()
		return nil
	}
	n.stateProposals[childHash] = child
	n.mu.Unlock()

	vote, err := n.signStateVoteOnce(parentConfig, child.Transition, child.ParentHash, childHash)
	if err != nil {
		return nil
	}
	body := StateVoteMessage{
		ParentConfigVersion: parent.ConfigVersion,
		Transition:          child.Transition,
		ParentHash:          child.ParentHash,
		ChildHash:           childHash,
		Vote:                vote,
	}
	if err := n.HandleStateVote(ctx, body); err != nil {
		return err
	}
	msg, err := p2p.NewMessage(Protocol, "STATE_VOTE", childHash, n.ID, "", body)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) HandleStateVote(ctx context.Context, body StateVoteMessage) error {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig, configured := n.Configurations[parent.ConfigVersion]
	child, proposed := n.stateProposals[body.ChildHash]
	if !configured || !proposed || body.ParentConfigVersion != parent.ConfigVersion ||
		body.ParentHash != HashCertifiedState(parent) || body.Transition != child.Transition ||
		body.ChildHash != HashCertifiedState(child) {
		n.mu.Unlock()
		return nil
	}
	n.mu.Unlock()
	transcript := StateVoteTranscript(parent.ConfigVersion, body.Transition, body.ParentHash, body.ChildHash)
	if err := crypto.VerifySignedVote(body.Vote, parentConfig.PublicKeys(), transcript); err != nil {
		return nil
	}

	n.mu.Lock()
	if n.stateVotes[body.ChildHash] == nil {
		n.stateVotes[body.ChildHash] = make(map[p2p.NodeID]crypto.SignedVote)
	}
	n.stateVotes[body.ChildHash][p2p.NodeID(body.Vote.Signer)] = body.Vote
	ready := len(n.stateVotes[body.ChildHash]) >= parentConfig.Q && !n.stateCertSent[body.ChildHash]
	var votes []crypto.SignedVote
	if ready {
		n.stateCertSent[body.ChildHash] = true
		for _, vote := range n.stateVotes[body.ChildHash] {
			votes = append(votes, vote)
		}
	}
	n.mu.Unlock()
	if !ready {
		return nil
	}
	qc, err := BuildStateQC(parentConfig, child.Transition, body.ParentHash, body.ChildHash, votes)
	if err != nil {
		return err
	}
	certificate := StateCertificateMessage{Child: child, QC: qc}
	if err := n.InstallStateCertificate(certificate); err != nil {
		return err
	}
	msg, err := p2p.NewMessage(Protocol, "STATE_CERT", body.ChildHash, n.ID, "", certificate)
	if err != nil {
		return err
	}
	return n.Transport.Broadcast(ctx, msg)
}

func (n *Node) InstallStateCertificate(message StateCertificateMessage) error {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	parentConfig, configured := n.Configurations[parent.ConfigVersion]
	child := canonicalCertifiedState(message.Child)
	if !configured {
		n.mu.Unlock()
		return errors.New("unknown parent configuration")
	}
	if child.ParentHash != HashCertifiedState(parent) {
		n.mu.Unlock()
		return nil
	}
	if err := n.validateProposedChildLocked(parent, child); err != nil {
		n.mu.Unlock()
		return err
	}
	n.mu.Unlock()
	if err := VerifyStateQC(parentConfig, parent, child, message.QC); err != nil {
		return err
	}

	n.mu.Lock()
	defer n.mu.Unlock()
	if HashCertifiedState(n.Certified) != message.QC.ParentHash {
		return nil
	}
	switch child.Transition {
	case TransitionRemove, TransitionJoin:
		if err := n.installReconfiguredStateLocked(child, message.QC); err != nil {
			return err
		}
	default:
		return fmt.Errorf("STATE_CERT cannot install transition %s through control path", child.Transition)
	}
	n.notifyStateChangeLocked()
	if len(child.Retiring) > 0 && n.protocolContext != nil {
		ctx := n.protocolContext
		go func() { _ = n.broadcastRetirementShares(ctx) }()
	}
	return nil
}

func (n *Node) validateProposedChildLocked(parent, child CertifiedState) error {
	if err := ValidateSuccessor(parent, child); err != nil {
		return err
	}
	setup, exists := n.ConfigurationSetups[child.ConfigVersion]
	if !exists || setup.Configuration.Digest() != child.ConfigDigest {
		return fmt.Errorf("missing exact setup for child configuration %d", child.ConfigVersion)
	}
	switch child.Transition {
	case TransitionRemove:
		removed := removedMember(parent.Members, child.Members)
		if removed == "" {
			return errors.New("REMOVE does not identify exactly one removed member")
		}
		expected, err := RemoveSuccessor(parent, removed, setup.Configuration)
		if err != nil {
			return err
		}
		if err := validateRetirementReferences(parent, child.Retiring); err != nil {
			return err
		}
		expected.Retiring = append([]RetirementReference(nil), child.Retiring...)
		expected = canonicalCertifiedState(expected)
		if HashCertifiedState(expected) != HashCertifiedState(child) {
			return errors.New("non-deterministic REMOVE successor")
		}
	case TransitionJoin:
		if parent.JReady == nil {
			return errors.New("JOIN parent has no certified JReady")
		}
		expected, err := JoinSuccessor(parent, *parent.JReady, setup.Configuration)
		if err != nil {
			return err
		}
		if HashCertifiedState(expected) != HashCertifiedState(child) {
			return errors.New("non-deterministic JOIN successor")
		}
	default:
		return fmt.Errorf("unsupported control transition %s", child.Transition)
	}
	return nil
}

func (n *Node) installReconfiguredStateLocked(child CertifiedState, qc StateQC) error {
	setup, ok := n.ConfigurationSetups[child.ConfigVersion]
	if !ok {
		return fmt.Errorf("missing configuration setup %d", child.ConfigVersion)
	}
	if setup.Configuration.Contains(n.ID) && setup.Scheme == nil {
		return fmt.Errorf("missing local PVSS scheme for configuration %d", child.ConfigVersion)
	}
	if setup.Scheme != nil {
		n.PVSS = setup.Scheme
	}
	if err := n.registerRetirementReferencesLocked(child.Retiring); err != nil {
		return err
	}
	if err := n.persistCertifiedLocked(child, qc); err != nil {
		return err
	}
	oldVersion := n.Certified.ConfigVersion
	if oldContext := n.PVSSContexts[oldVersion]; oldContext != nil {
		oldContext.Status = PVSSRetiring
		hasObligation := false
		for _, obligation := range n.Retirement {
			if obligation.Reference.ConfigVersion == oldVersion && !obligation.Consumed {
				hasObligation = true
				break
			}
		}
		if !hasObligation {
			oldContext.Scheme = nil
			oldContext.Status = PVSSErased
			delete(n.pvssKeys, oldContext.Params.Epoch())
		}
	}
	n.PVSSContexts[child.ConfigVersion] = &PVSSContext{
		Configuration: setup.Configuration,
		Params:        setup.Params,
		Scheme:        setup.Scheme,
		Status:        PVSSActive,
	}
	n.Certified = CloneCertifiedState(child)
	qcCopy := qc
	n.StateCertificate = &qcCopy
	n.StateHistory = append(n.StateHistory, StateCertificateMessage{Child: CloneCertifiedState(child), QC: qc})
	n.State.ConfigVersion = child.ConfigVersion
	n.State.F = child.F
	n.State.Epoch = child.Epoch
	n.State.RPrev = append([]byte(nil), child.Random...)
	n.State.Members = append([]p2p.NodeID(nil), child.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), child.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), child.RSQ...)
	n.State.Seqs = cloneSeqMap(child.Seqs)
	n.State.RmMark = cloneMarkMap(child.RmMark)
	for _, member := range child.Members {
		if n.State.ComQ[member] == nil {
			n.State.ComQ[member] = make(map[uint64]Object)
		}
	}
	for member := range n.State.ComQ {
		if !contains(child.Members, member) {
			delete(n.State.ComQ, member)
		}
	}
	if setup.Configuration.Contains(n.ID) {
		rbcEngine, err := rbc.NewAuthenticated(n.ID, child.ConfigVersion, "pvss", child.Members, child.F, n.Transport, n.IdentityPrivate, setup.Configuration.PublicKeys())
		if err != nil {
			return err
		}
		abaEngine, err := aba.NewAuthenticated(n.ID, child.ConfigVersion, "control", child.Members, child.F, n.Transport, n.IdentityPrivate, setup.Configuration.PublicKeys())
		if err != nil {
			return err
		}
		n.RBC = rbcEngine
		n.ABA = abaEngine
		n.RBCs[child.ConfigVersion] = rbcEngine
		n.ABAs[child.ConfigVersion] = abaEngine
		if n.protocolContext != nil {
			n.startProtocolEngineCollectorsLocked(n.protocolContext, child.ConfigVersion)
		}
	} else {
		// A removed process still installs the certificate and retains the old
		// PVSS/RBC context long enough to satisfy retirement obligations, but it
		// must not participate in the child configuration.
		n.RBC = nil
		n.ABA = nil
		n.producing = false
	}
	n.resetCurrentConfigurationCachesLocked()
	return n.persistLocked()
}

func (n *Node) resetCurrentConfigurationCachesLocked() {
	n.State.PendingABAs = make(map[string]*PendingABA)
	n.abaInputSent = make(map[string]bool)
	n.abaInputs = make(map[string]bool)
	n.readySentEpoch = make(map[string]bool)
	n.stateProposals = make(map[string]CertifiedState)
	n.stateVotes = make(map[string]map[p2p.NodeID]crypto.SignedVote)
	n.stateCertSent = make(map[string]bool)
}

func (n *Node) notifyStateChangeLocked() {
	close(n.stateNotify)
	n.stateNotify = make(chan struct{})
}

func (n *Node) waitForStateChange(ctx context.Context, parentHash string) error {
	for {
		n.mu.Lock()
		if HashCertifiedState(n.Certified) != parentHash {
			n.mu.Unlock()
			return nil
		}
		wait := n.stateNotify
		n.mu.Unlock()
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func removedMember(parent, child []p2p.NodeID) p2p.NodeID {
	var removed p2p.NodeID
	for _, member := range parent {
		if contains(child, member) {
			continue
		}
		if removed != "" {
			return ""
		}
		removed = member
	}
	return removed
}

func identityKeysForMembers(configuration Configuration, members []p2p.NodeID) map[p2p.NodeID]ed25519.PublicKey {
	out := make(map[p2p.NodeID]ed25519.PublicKey, len(members))
	for _, member := range members {
		out[member] = append(ed25519.PublicKey(nil), configuration.IdentityKeys[member]...)
	}
	return out
}

func (n *Node) ensureRemovalSetupLocked(removed p2p.NodeID) (ConfigurationSetup, error) {
	version := n.Certified.ConfigVersion + 1
	members := removeIDCopy(n.Certified.Members, removed)
	if setup, ok := n.ConfigurationSetups[version]; ok {
		if sameMembers(setup.Configuration.Members, members) {
			return setup, nil
		}
		return ConfigurationSetup{}, fmt.Errorf("configuration version %d is registered for a different successor", version)
	}
	if !n.allowInsecureSetup {
		return ConfigurationSetup{}, fmt.Errorf("configuration %d must be registered before REMOVE", version)
	}
	f := (len(members) - 1) / 3
	epoch := fmt.Sprintf("tyche/remove/v%d/%s/%s", version, removed, HashCertifiedState(n.Certified))
	params, keys, err := crypto.SetupPVSS(n.pvssBackend, epoch, f+1, members)
	if err != nil {
		return ConfigurationSetup{}, err
	}
	parentConfig := n.Configurations[n.Certified.ConfigVersion]
	configuration, err := NewConfiguration(version, members, f, params, identityKeysForMembers(parentConfig, members))
	if err != nil {
		return ConfigurationSetup{}, err
	}
	var scheme crypto.PVSSScheme
	if configuration.Contains(n.ID) {
		key := keys[n.ID]
		if key.Private == nil {
			return ConfigurationSetup{}, fmt.Errorf("missing generated local PVSS key for %s", n.ID)
		}
		scheme, err = crypto.NewPVSSScheme(n.ID, key.Private, params)
		if err != nil {
			return ConfigurationSetup{}, err
		}
		n.pvssKeys[params.Epoch()] = key.Private.Clone()
	}
	setup := ConfigurationSetup{Configuration: configuration, Params: params, Scheme: scheme}
	n.Configurations[version] = configuration
	n.ConfigurationSetups[version] = setup
	return setup, nil
}

func (n *Node) runCertifiedRemoval(ctx context.Context, removed p2p.NodeID) error {
	n.mu.Lock()
	parent := CloneCertifiedState(n.Certified)
	if parent.RmMark[removed] < 0 {
		n.mu.Unlock()
		return fmt.Errorf("removal marker for %s is not certified", removed)
	}
	setup, err := n.ensureRemovalSetupLocked(removed)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	child, err := RemoveSuccessor(parent, removed, setup.Configuration)
	if err == nil {
		seq := parent.Seqs[removed] + 1
		if object, exists := n.State.ComQ[removed][seq]; exists && object.ConfigVersion == parent.ConfigVersion {
			if certificate, delivered := n.RBCCertificates[rbcCertificateKey(object.ConfigVersion, object.Commitment.SecretID)]; delivered {
				child.Retiring = append(child.Retiring, RetirementReference{
					ConfigVersion: object.ConfigVersion,
					TargetEpoch:   parent.Epoch + 1,
					ObjectID:      object.Commitment.SecretID,
					RBCDigest:     certificate.Hash,
					Object:        object,
					Delivery:      certificate,
				})
				child = canonicalCertifiedState(child)
			}
		}
	}
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
	if err := n.broadcastRetirementShares(ctx); err != nil {
		return err
	}
	return n.waitRetirementComplete(ctx)
}
