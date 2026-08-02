package tyche

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

func resolveIdentityConfiguration(cfg Config, members []p2p.NodeID) (ed25519.PrivateKey, map[p2p.NodeID]ed25519.PublicKey, error) {
	public := make(map[p2p.NodeID]ed25519.PublicKey, len(members))
	for id, key := range cfg.IdentityPublicKeys {
		public[id] = append(ed25519.PublicKey(nil), key...)
	}
	private := append(ed25519.PrivateKey(nil), cfg.IdentityPrivate...)
	if cfg.InsecureDeterministicIdentity {
		identities := append([]p2p.NodeID(nil), members...)
		if !contains(identities, cfg.ID) {
			identities = append(identities, cfg.ID)
		}
		for _, member := range identities {
			seed := crypto.DomainHash("Tyche/InsecureTestIdentity/v1", []byte(member))
			pair, err := crypto.IdentityKeyPairFromSeed(seed[:ed25519.SeedSize])
			if err != nil {
				return nil, nil, err
			}
			public[member] = pair.Public
			if member == cfg.ID {
				private = pair.Private
			}
		}
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, nil, errors.New("missing node identity private key")
	}
	derived := private.Public().(ed25519.PublicKey)
	if configured := public[cfg.ID]; len(configured) != ed25519.PublicKeySize || !ed25519.PublicKey(configured).Equal(derived) {
		return nil, nil, fmt.Errorf("identity private key does not match public key for %s", cfg.ID)
	}
	for _, member := range members {
		if len(public[member]) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("missing identity public key for %s", member)
		}
	}
	return private, public, nil
}

func schedulingStateFromRuntime(state *State, configuration Configuration) SchedulingState {
	return canonicalSchedulingState(SchedulingState{
		ConfigVersion: state.ConfigVersion,
		F:             configuration.F,
		Q:             configuration.Q,
		PVSSThreshold: configuration.PVSSThreshold,
		Epoch:         state.Epoch,
		Random:        append([]byte(nil), state.RPrev...),
		BeaconHead:    GenesisBeaconHead(state.ConfigVersion, state.RPrev, state.Members),
		Members:       append([]p2p.NodeID(nil), state.Members...),
		SCL:           append([]p2p.NodeID(nil), state.SCL...),
		RSQ:           append([]p2p.NodeID(nil), state.RSQ...),
		Seqs:          cloneSeqMap(state.Seqs),
		ConfigDigest:  configuration.Digest(),
	})
}
