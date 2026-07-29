package tyche

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

type PVSSContextStatus string

const (
	PVSSActive   PVSSContextStatus = "active"
	PVSSRetiring PVSSContextStatus = "retiring"
	PVSSErased   PVSSContextStatus = "erased"
)

type PVSSContext struct {
	Configuration Configuration
	Params        crypto.PVSSParams
	Scheme        crypto.PVSSScheme
	Status        PVSSContextStatus
}

type RetirementObligation struct {
	Reference RetirementReference
	Shares    map[p2p.NodeID]crypto.DecryptedShare
	Secret    []byte
	Complete  bool
	Consumed  bool
}

type RetirementShareMessage struct {
	ConfigVersion uint64                `json:"config_version"`
	ObjectID      string                `json:"object_id"`
	Share         crypto.DecryptedShare `json:"share"`
	Signature     crypto.SignedVote     `json:"signature"`
}

func retirementKey(version uint64, objectID string) string {
	return fmt.Sprintf("%d/%s", version, objectID)
}

func rbcCertificateKey(version uint64, objectID string) string {
	return retirementKey(version, objectID)
}

func retirementShareTranscript(body RetirementShareMessage) []byte {
	return crypto.DomainHash(
		"Tyche/RetirementShare/v1",
		[]byte(fmt.Sprintf("%d", body.ConfigVersion)),
		[]byte(body.ObjectID),
		canonicalJSON(body.Share),
	)
}

func (n *Node) registerRetirementReferencesLocked(references []RetirementReference) error {
	for _, reference := range references {
		key := retirementKey(reference.ConfigVersion, reference.ObjectID)
		if existing := n.Retirement[key]; existing != nil {
			continue
		}
		context := n.PVSSContexts[reference.ConfigVersion]
		engine := n.RBCs[reference.ConfigVersion]
		if context == nil || engine == nil {
			return fmt.Errorf("missing legacy context for retirement object %s", key)
		}
		if reference.Object.ConfigVersion != reference.ConfigVersion ||
			reference.Object.Commitment.SecretID != reference.ObjectID {
			return fmt.Errorf("retirement object %s is not bound to its configuration", key)
		}
		if reference.Delivery.Hash != reference.RBCDigest ||
			reference.Delivery.ConfigVersion != reference.ConfigVersion {
			return fmt.Errorf("retirement RBC reference mismatch for %s", key)
		}
		if err := engine.VerifyDeliveryCertificate(reference.Delivery); err != nil {
			return fmt.Errorf("invalid retirement delivery certificate for %s: %w", key, err)
		}
		context.Status = PVSSRetiring
		n.Retirement[key] = &RetirementObligation{
			Reference: reference,
			Shares:    make(map[p2p.NodeID]crypto.DecryptedShare),
		}
	}
	return nil
}

func (n *Node) broadcastRetirementShares(ctx context.Context) error {
	n.mu.Lock()
	type pending struct {
		key       string
		reference RetirementReference
		scheme    crypto.PVSSScheme
		config    Configuration
	}
	var work []pending
	for key, obligation := range n.Retirement {
		if obligation.Complete {
			continue
		}
		pvssContext := n.PVSSContexts[obligation.Reference.ConfigVersion]
		if pvssContext == nil || pvssContext.Scheme == nil || !pvssContext.Configuration.Contains(n.ID) {
			continue
		}
		work = append(work, pending{key: key, reference: obligation.Reference, scheme: pvssContext.Scheme, config: pvssContext.Configuration})
	}
	n.mu.Unlock()

	for _, item := range work {
		share, err := item.scheme.PreReconVerified(item.reference.Object.Commitment, n.ID)
		if err != nil {
			return err
		}
		body := RetirementShareMessage{
			ConfigVersion: item.reference.ConfigVersion,
			ObjectID:      item.reference.ObjectID,
			Share:         share,
		}
		body.Signature, err = crypto.SignTranscript(string(n.ID), n.IdentityPrivate, retirementShareTranscript(body))
		if err != nil {
			return err
		}
		if err := n.HandleRetirementShare(body, n.ID); err != nil {
			return err
		}
		msg, err := p2p.NewMessage(Protocol, "RETIRE_SHARE", item.key, n.ID, "", body)
		if err != nil {
			return err
		}
		if err := n.Transport.Broadcast(ctx, msg); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) HandleRetirementShare(body RetirementShareMessage, from p2p.NodeID) error {
	key := retirementKey(body.ConfigVersion, body.ObjectID)
	n.mu.Lock()
	obligation := n.Retirement[key]
	pvssContext := n.PVSSContexts[body.ConfigVersion]
	if obligation == nil || pvssContext == nil || pvssContext.Scheme == nil ||
		obligation.Complete || body.Share.Holder != from ||
		body.Share.CommitmentID != body.ObjectID {
		n.mu.Unlock()
		return nil
	}
	if _, duplicate := obligation.Shares[from]; duplicate {
		n.mu.Unlock()
		return nil
	}
	publicKeys := pvssContext.Configuration.PublicKeys()
	scheme := pvssContext.Scheme
	object := obligation.Reference.Object
	n.mu.Unlock()

	if body.Signature.Signer != string(from) ||
		crypto.VerifySignedVote(body.Signature, publicKeys, retirementShareTranscript(body)) != nil ||
		!scheme.VerifyShare(object.Commitment, body.Share) {
		return nil
	}

	n.mu.Lock()
	obligation = n.Retirement[key]
	if obligation == nil || obligation.Complete {
		n.mu.Unlock()
		return nil
	}
	obligation.Shares[from] = body.Share
	if len(obligation.Shares) < object.Commitment.Threshold {
		n.mu.Unlock()
		return nil
	}
	shares := make([]crypto.DecryptedShare, 0, len(obligation.Shares))
	for _, share := range obligation.Shares {
		shares = append(shares, share)
	}
	n.mu.Unlock()
	secret, err := scheme.ReconFromVerifiedShares(object.Commitment, shares)
	if err != nil {
		return err
	}
	n.mu.Lock()
	if current := n.Retirement[key]; current != nil && !current.Complete {
		current.Secret = append([]byte(nil), secret...)
		current.Complete = true
		if err := n.persistLocked(); err != nil {
			n.mu.Unlock()
			return err
		}
		n.notifyStateChangeLocked()
	}
	n.mu.Unlock()
	return nil
}

func (n *Node) waitRetirementComplete(ctx context.Context) error {
	for {
		n.mu.Lock()
		complete := true
		for _, obligation := range n.Retirement {
			if !obligation.Complete {
				complete = false
				break
			}
		}
		if complete {
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

func (n *Node) mixRetirementEntropyLocked(previous, currentSecret []byte, targetEpoch uint64) []byte {
	type contribution struct {
		key    string
		secret []byte
	}
	var contributions []contribution
	for key, obligation := range n.Retirement {
		if obligation.Complete && !obligation.Consumed && obligation.Reference.TargetEpoch <= targetEpoch {
			contributions = append(contributions, contribution{key: key, secret: append([]byte(nil), obligation.Secret...)})
		}
	}
	sort.Slice(contributions, func(i, j int) bool { return contributions[i].key < contributions[j].key })
	parts := make([][]byte, 0, len(contributions)+2)
	parts = append(parts, previous, currentSecret)
	for _, item := range contributions {
		parts = append(parts, []byte(item.key), item.secret)
	}
	return crypto.DomainHash("Tyche/BeaconEntropy/v2", parts...)
}

func (n *Node) consumeRetirementEntropyLocked(epoch uint64) {
	versions := make(map[uint64]bool)
	for _, obligation := range n.Retirement {
		if obligation.Complete && !obligation.Consumed && obligation.Reference.TargetEpoch <= epoch {
			obligation.Consumed = true
			versions[obligation.Reference.ConfigVersion] = true
		}
	}
	for version := range versions {
		allConsumed := true
		for _, obligation := range n.Retirement {
			if obligation.Reference.ConfigVersion == version && !obligation.Consumed {
				allConsumed = false
				break
			}
		}
		if !allConsumed {
			continue
		}
		if context := n.PVSSContexts[version]; context != nil && context.Status == PVSSRetiring {
			context.Scheme = nil
			context.Status = PVSSErased
			delete(n.pvssKeys, context.Params.Epoch())
		}
	}
	// Entropy installation has already persisted the certified child. Persist
	// the consumption and key-erasure tombstones before returning.
	_ = n.persistLocked()
}

func retirementDigest(reference RetirementReference) string {
	return hex.EncodeToString(crypto.DomainHash("Tyche/RetirementReference/v1", canonicalJSON(reference)))
}

func validateRetirementReferences(parent CertifiedState, references []RetirementReference) error {
	seen := make(map[string]bool)
	for _, reference := range references {
		key := retirementKey(reference.ConfigVersion, reference.ObjectID)
		if seen[key] {
			return errors.New("duplicate retirement reference")
		}
		seen[key] = true
		if reference.ConfigVersion > parent.ConfigVersion ||
			reference.ObjectID == "" ||
			reference.RBCDigest == "" ||
			reference.Object.Commitment.SecretID != reference.ObjectID {
			return fmt.Errorf("invalid retirement reference %s", key)
		}
	}
	return nil
}
