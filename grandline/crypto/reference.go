package crypto

import (
	"Tyche/utils/p2p"
	"errors"
	"fmt"
	"go.dedis.ch/kyber/v3"
)

// ReferenceCommitments extends the existing PRIVATE benchmark setup snapshot.
// Each Node receives only the public commitments and its own alpha. The common
// snapshot is test scaffolding, not production key provisioning.
type ReferenceCommitments struct {
	Commitments map[p2p.NodeID]BeaconCommitment `json:"commitments"`
	Alphas      map[p2p.NodeID]string           `json:"alphas"`
}

func DecodeReferenceAlpha(raw string) (kyber.Scalar, error) {
	a, err := scalarFromHex(raw)
	if err != nil {
		return nil, err
	}
	if a.Equal(suite().G1().Scalar().Zero()) {
		return nil, errors.New("reference alpha must be nonzero")
	}
	return a, nil
}

func PrepareReferenceCommitments(r *GRandResult, members []p2p.NodeID) error {
	if r == nil {
		return errors.New("missing GRand setup")
	}
	ref := &ReferenceCommitments{Commitments: make(map[p2p.NodeID]BeaconCommitment), Alphas: make(map[p2p.NodeID]string)}
	for _, id := range members {
		c, a, err := NewBeaconCommitment(id, r.SecretShares[id])
		if err != nil {
			return err
		}
		ref.Commitments[id], ref.Alphas[id] = c, mustScalarHex(a)
	}
	r.Reference = ref
	return ValidateReferenceCommitments(*r, members)
}

func ValidateReferenceCommitments(r GRandResult, members []p2p.NodeID) error {
	if r.Reference == nil || len(r.Reference.Commitments) != len(members) || len(r.Reference.Alphas) != len(members) {
		return errors.New("reference mode needs a complete fixed-commitment setup")
	}
	for _, id := range members {
		c, ok := r.Reference.Commitments[id]
		if !ok || c.Signer != id || r.PublicShares[id] == "" {
			return fmt.Errorf("invalid reference commitment for %s", id)
		}
		checked, ok := DecodeAndVerifyBeaconCommitment(r.PublicShares[id], c)
		if !ok {
			return fmt.Errorf("invalid reference commitment equation for %s", id)
		}
		a, err := DecodeReferenceAlpha(r.Reference.Alphas[id])
		if err != nil {
			return err
		}
		if _, err := NewBeaconSigner(id, r.SecretShares[id], a, checked); err != nil {
			return fmt.Errorf("reference setup %s: %w", id, err)
		}
	}
	return nil
}
