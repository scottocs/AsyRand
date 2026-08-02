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

// BeaconHistoryLink is a persisted P_e link used only for checkpoint
// transfer. The certificate signs the BEACON tuple, not the child snapshot.
type BeaconHistoryLink struct {
	Child SchedulingState `json:"child"`
	QC    BeaconQC        `json:"qc"`
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
	}
	verifierPrivate := localPrivate
	if verifierPrivate == nil && n.PVSS != nil {
		verifierPrivate = n.PVSS.PrivateKey()
	}
	if verifierPrivate != nil {
		scheme, err = crypto.NewPVSSScheme(n.ID, verifierPrivate, params)
		if err != nil {
			return err
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	setup := ConfigurationSetup{
		Configuration: configuration, Params: params, Scheme: scheme,
	}
	if installed, ok := n.Configurations[configuration.Version]; ok {
		if installed.Digest() != configuration.Digest() {
			if configuration.Version <= n.State.ConfigVersion {
				return fmt.Errorf("conflicting installed configuration version %d", configuration.Version)
			}
			n.CandidateSetups[configuration.Digest()] = setup
			return nil
		}
		n.ConfigurationSetups[configuration.Version] = setup
		n.PVSSContexts[configuration.Version] = &PVSSContext{
			Configuration: configuration,
			Params:        params,
			Scheme:        scheme,
			Status:        PVSSHistorical,
		}
		if configuration.Version == n.State.ConfigVersion {
			n.PVSSContexts[configuration.Version].Status = PVSSActive
		}
		return nil
	}
	// A proposal is only a candidate. It must not reserve version c+1,
	// because a higher-priority removal may install a different c+1 first.
	n.CandidateSetups[configuration.Digest()] = setup
	return nil
}

// installReconfiguredStateLocked changes exactly one configuration and starts
// its RBC/ABA engines. The ABA decision is the transition authority; a
// membership change does not replace the latest certified beacon head.
func (n *Node) installReconfiguredStateLocked(child SchedulingState) error {
	setup, ok := n.ConfigurationSetups[child.ConfigVersion]
	if !ok || setup.Configuration.Digest() != child.ConfigDigest {
		setup, ok = n.CandidateSetups[child.ConfigDigest]
	}
	if !ok {
		return fmt.Errorf("missing configuration setup %d", child.ConfigVersion)
	}
	if setup.Configuration.Contains(n.ID) && setup.Scheme == nil {
		return fmt.Errorf("missing local PVSS scheme for configuration %d", child.ConfigVersion)
	}
	if setup.Scheme != nil {
		n.PVSS = setup.Scheme
	}
	n.Configurations[child.ConfigVersion] = setup.Configuration
	n.ConfigurationSetups[child.ConfigVersion] = setup
	for digest, candidate := range n.CandidateSetups {
		if candidate.Configuration.Version <= child.ConfigVersion {
			delete(n.CandidateSetups, digest)
		}
	}
	for digest, proposal := range n.joinProposals {
		if proposal.ConfigVersion < child.ConfigVersion {
			delete(n.joinProposals, digest)
		}
	}
	for instance := range n.deferredJoinABA {
		if version, ok := aba.ConfigVersionFromInstance(instance); ok && version < child.ConfigVersion {
			delete(n.deferredJoinABA, instance)
		}
	}
	n.PVSSContexts[child.ConfigVersion] = &PVSSContext{
		Configuration: setup.Configuration, Params: setup.Params,
		Scheme: setup.Scheme, Status: PVSSActive,
	}
	n.Schedule = CloneSchedulingState(child)
	// Reconfiguration is not another beacon-history link.  Start a checkpoint
	// segment at the transitioned snapshot while retaining the latest P_e QC.
	n.HistoryAnchor = CloneSchedulingState(child)
	n.BeaconHistory = nil
	n.State.ConfigVersion = child.ConfigVersion
	n.State.F = child.F
	n.State.Epoch = child.Epoch
	n.State.RPrev = append([]byte(nil), child.Random...)
	n.State.Members = append([]p2p.NodeID(nil), child.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), child.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), child.RSQ...)
	n.State.Seqs = cloneSeqMap(child.Seqs)
	// Pending ABA certificates are local control state and survive a
	// configuration transition. The consumed marker is removed by the caller.
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
		pvssRBC, err := rbc.NewAuthenticated(
			n.ID, child.ConfigVersion, "pvss", child.Members, child.F,
			n.Transport, n.IdentityPrivate, setup.Configuration.PublicKeys(),
		)
		if err != nil {
			return err
		}
		joinRBC, err := rbc.NewAuthenticated(
			n.ID, child.ConfigVersion, "join", child.Members, child.F,
			n.Transport, n.IdentityPrivate, setup.Configuration.PublicKeys(),
		)
		if err != nil {
			return err
		}
		agreement, err := aba.NewAuthenticated(
			n.ID, child.ConfigVersion, "control", child.Members, child.F,
			n.Transport, n.IdentityPrivate, setup.Configuration.PublicKeys(),
		)
		if err != nil {
			return err
		}
		n.RBC, n.JoinRBC, n.ABA = pvssRBC, joinRBC, agreement
		n.RBCs[child.ConfigVersion] = pvssRBC
		n.JoinRBCs[child.ConfigVersion] = joinRBC
		n.ABAs[child.ConfigVersion] = agreement
		if n.protocolContext != nil {
			n.startProtocolEngineCollectorsLocked(n.protocolContext, child.ConfigVersion)
		}
	} else {
		n.RBC, n.JoinRBC, n.ABA = nil, nil, nil
		n.producing = false
	}
	n.resetCurrentConfigurationCachesLocked()
	return n.persistLocked()
}

func (n *Node) resetCurrentConfigurationCachesLocked() {
	n.pendingRecon = make(map[string]*pendingReconBucket)
	n.pendingReconCount = 0
}

func identityKeysForMembers(configuration Configuration, members []p2p.NodeID) map[p2p.NodeID]ed25519.PublicKey {
	out := make(map[p2p.NodeID]ed25519.PublicKey, len(members))
	for _, member := range members {
		out[member] = append(ed25519.PublicKey(nil), configuration.IdentityKeys[member]...)
	}
	return out
}

func (n *Node) ensureRemovalSetupLocked(removed p2p.NodeID) (ConfigurationSetup, error) {
	version := n.Schedule.ConfigVersion + 1
	members := removeIDCopy(n.Schedule.Members, removed)
	for _, setup := range n.CandidateSetups {
		if setup.Configuration.Version == version && sameMembers(setup.Configuration.Members, members) {
			return setup, nil
		}
	}
	if !n.allowInsecureSetup {
		return ConfigurationSetup{}, fmt.Errorf("configuration %d must be registered before REMOVE", version)
	}
	f := (len(members) - 1) / 3
	epoch := fmt.Sprintf("tyche/remove/v%d/%s/%s", version, removed, HashSchedulingState(n.Schedule))
	params, keys, err := crypto.SetupPVSS(n.pvssBackend, epoch, f+1, members)
	if err != nil {
		return ConfigurationSetup{}, err
	}
	parentConfig := n.Configurations[n.Schedule.ConfigVersion]
	configuration, err := NewConfiguration(
		version, members, f, params, identityKeysForMembers(parentConfig, members),
	)
	if err != nil {
		return ConfigurationSetup{}, err
	}
	var scheme crypto.PVSSScheme
	if configuration.Contains(n.ID) {
		key := keys[n.ID]
		if key.Private == nil {
			return ConfigurationSetup{}, fmt.Errorf("missing generated PVSS key for %s", n.ID)
		}
		scheme, err = crypto.NewPVSSScheme(n.ID, key.Private, params)
		if err != nil {
			return ConfigurationSetup{}, err
		}
		n.pvssKeys[params.Epoch()] = key.Private.Clone()
	}
	setup := ConfigurationSetup{Configuration: configuration, Params: params, Scheme: scheme}
	n.CandidateSetups[configuration.Digest()] = setup
	return setup, nil
}

func (n *Node) runCertifiedRemoval(ctx context.Context, removed p2p.NodeID) error {
	n.mu.Lock()
	parent := CloneSchedulingState(n.Schedule)
	mark, marked := n.State.RmMark[removed]
	if !marked {
		n.mu.Unlock()
		return fmt.Errorf("removal marker for %s is not certified", removed)
	}
	parentConfig, configured := n.Configurations[mark.ConfigVersion]
	if !configured {
		n.mu.Unlock()
		return errors.New("removal marker names an unavailable configuration")
	}
	seed := append([]byte(nil), n.beaconSeeds[mark.Epoch+mark.Certificate.Round+1]...)
	expected := aba.EpochInstanceFor(mark.ConfigVersion, mark.Epoch)
	if mark.Certificate.Instance != expected || mark.Certificate.Value {
		n.mu.Unlock()
		return errors.New("removal marker carries invalid ABA evidence")
	}
	if err := aba.VerifyCertificate(mark.Certificate, parentConfig.PublicKeys(), parentConfig.Q, seed); err != nil {
		n.mu.Unlock()
		return fmt.Errorf("invalid removal ABA certificate: %w", err)
	}
	setup, err := n.ensureRemovalSetupLocked(removed)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	child, err := RemoveSuccessor(parent, removed, setup.Configuration)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	// The due marker replaces the locally opened Step-0 attempt for this same
	// logical epoch. It never rolls back a certified P_e; only uncertified
	// reconstruction, vote, and ABA state bound to P_{e-1} is retired before
	// the epoch is restarted under the successor configuration.
	openEpoch := parent.Epoch + 1
	for instance, attempt := range n.epochAttempts {
		if attempt.Epoch != openEpoch || attempt.ParentHash != parent.BeaconHead {
			continue
		}
		key := epochKey(attempt.Epoch, attempt.Source, attempt.Seq)
		delete(n.epochAttempts, instance)
		delete(n.abaInputSent, instance)
		delete(n.abaInputs, instance)
		delete(n.recon, key)
		delete(n.reconSecret, key)
		delete(n.reconDone, key)
		delete(n.reconClosing, key)
		delete(n.reconSent, key)
		delete(n.beaconVoteSent, key)
		delete(n.certifying, key)
	}
	for key := range n.beaconVotes {
		if keyEpoch(key) == openEpoch {
			delete(n.beaconVotes, key)
		}
	}
	for key := range n.certified {
		if keyEpoch(key) == openEpoch {
			delete(n.certified, key)
		}
	}
	if pending := n.State.PendingABAs[openEpoch]; pending != nil &&
		pending.Epoch == openEpoch {
		delete(n.State.PendingABAs, openEpoch)
	}
	if err := n.installReconfiguredStateLocked(child); err != nil {
		n.mu.Unlock()
		return err
	}
	delete(n.State.RmMark, removed)
	if n.PendingJoin != nil && n.PendingJoin.Proposal.ConfigVersion != n.State.ConfigVersion {
		delete(n.joinProposals, JoinDigest(n.PendingJoin.Proposal))
		n.PendingJoin = nil
	}
	n.mu.Unlock()
	_ = ctx
	return nil
}
