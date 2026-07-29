package tyche

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

type Configuration struct {
	Version          uint64                `json:"version"`
	Members          []p2p.NodeID          `json:"members"`
	F                int                   `json:"f"`
	Q                int                   `json:"q"`
	PVSSThreshold    int                   `json:"pvss_threshold"`
	PVSSParamsDigest string                `json:"pvss_params_digest"`
	IdentityKeys     map[p2p.NodeID][]byte `json:"identity_keys"`
}

func NewConfiguration(version uint64, members []p2p.NodeID, f int, params crypto.PVSSParams, identityKeys map[p2p.NodeID]ed25519.PublicKey) (Configuration, error) {
	members = normalizeMembers(members)
	if f < 0 {
		return Configuration{}, errors.New("negative fault bound")
	}
	if len(members) == 0 || len(members) < 3*f+1 {
		return Configuration{}, fmt.Errorf("configuration n=%d does not satisfy n >= 3f+1 for f=%d", len(members), f)
	}
	if hasDuplicateMembers(members) {
		return Configuration{}, errors.New("configuration contains duplicate members")
	}
	if params.Epoch() == "" || !crypto.VerifyPVSSSetup(params) {
		return Configuration{}, errors.New("invalid PVSS parameters")
	}
	if !sameMembers(params.Members(), members) {
		return Configuration{}, errors.New("PVSS member set does not match configuration")
	}
	if params.Threshold() != f+1 {
		return Configuration{}, fmt.Errorf("PVSS threshold=%d, want f+1=%d", params.Threshold(), f+1)
	}
	keys := make(map[p2p.NodeID][]byte, len(members))
	for _, member := range members {
		public := identityKeys[member]
		if len(public) != ed25519.PublicKeySize {
			return Configuration{}, fmt.Errorf("missing or invalid identity public key for %s", member)
		}
		keys[member] = append([]byte(nil), public...)
	}
	return Configuration{
		Version:          version,
		Members:          members,
		F:                f,
		Q:                len(members) - f,
		PVSSThreshold:    f + 1,
		PVSSParamsDigest: hex.EncodeToString(crypto.DomainHash("Tyche/PVSSParams/v1", canonicalJSON(params))),
		IdentityKeys:     keys,
	}, nil
}

func (c Configuration) Validate() error {
	if c.Q != len(c.Members)-c.F {
		return fmt.Errorf("invalid quorum q=%d, want n-f=%d", c.Q, len(c.Members)-c.F)
	}
	if c.PVSSThreshold != c.F+1 {
		return fmt.Errorf("invalid PVSS threshold=%d, want %d", c.PVSSThreshold, c.F+1)
	}
	if len(c.Members) < 3*c.F+1 {
		return fmt.Errorf("configuration n=%d does not satisfy n >= 3f+1", len(c.Members))
	}
	if hasDuplicateMembers(c.Members) {
		return errors.New("configuration contains duplicate members")
	}
	for _, member := range c.Members {
		if len(c.IdentityKeys[member]) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid identity key for %s", member)
		}
	}
	return nil
}

func (c Configuration) PublicKeys() map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(c.IdentityKeys))
	for id, raw := range c.IdentityKeys {
		out[string(id)] = append(ed25519.PublicKey(nil), raw...)
	}
	return out
}

func (c Configuration) Contains(id p2p.NodeID) bool {
	for _, member := range c.Members {
		if member == id {
			return true
		}
	}
	return false
}

func (c Configuration) Digest() string {
	return hex.EncodeToString(crypto.DomainHash("Tyche/Configuration/v1", canonicalJSON(c)))
}

func hasDuplicateMembers(members []p2p.NodeID) bool {
	for i := 1; i < len(members); i++ {
		if members[i] == members[i-1] {
			return true
		}
	}
	return false
}
