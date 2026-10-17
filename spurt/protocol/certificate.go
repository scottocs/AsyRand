package spurt

import (
	"crypto/ed25519"
	"encoding/hex"
	"sort"

	asig "Tyche/spurt/crypto"
	"Tyche/utils/verification"
)

// BeaconCertificate is SPURT Section VI's native public-verification evidence.
// It is retrieved on demand; collecting it never delays local reconstruction.
type BeaconCertificate struct {
	Epoch      uint64                `json:"epoch"`
	Digest     string                `json:"digest"`
	Random     []byte                `json:"random"`
	Signatures []asig.SignatureShare `json:"signatures"`
}

func (n *Node) BeaconCertificate(epoch uint64) (BeaconCertificate, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	es := n.epochs[epoch]
	if es == nil || es.random == nil {
		return BeaconCertificate{}, false
	}
	votes := es.beaconVotes[es.digest+"/"+randomHash(es.random)]
	if len(votes) < n.State.Threshold() {
		return BeaconCertificate{}, false
	}
	cert := BeaconCertificate{Epoch: epoch, Digest: es.digest, Random: append([]byte(nil), es.random...)}
	for _, sig := range votes {
		cert.Signatures = append(cert.Signatures, sig)
	}
	sort.Slice(cert.Signatures, func(i, j int) bool { return cert.Signatures[i].Signer < cert.Signatures[j].Signer })
	cert.Signatures = cert.Signatures[:n.State.Threshold()]
	return cert, true
}

func VerifyBeaconCertificate(cert BeaconCertificate, public map[string]ed25519.PublicKey, f int, caches ...*verification.Cache) bool {
	if f < 0 || len(public) < 3*f+1 || len(cert.Signatures) < f+1 || len(cert.Signatures) > len(public) || len(cert.Random) == 0 || cert.Digest == "" {
		return false
	}
	seen := make(map[string]bool)
	statement := beaconVoteBytes(cert.Epoch, cert.Digest, randomHash(cert.Random))
	for _, vote := range cert.Signatures {
		key := public[vote.Signer]
		sig, err := hex.DecodeString(vote.SigHex)
		if seen[vote.Signer] || len(key) != ed25519.PublicKeySize || err != nil || !asig.Verify(key, statement, sig, verification.Optional(caches...)) {
			return false
		}
		seen[vote.Signer] = true
	}
	return true
}

// VerifyBeaconCertificate reuses this node's already verified BEACON signatures.
func (n *Node) VerifyBeaconCertificate(cert BeaconCertificate) bool {
	return VerifyBeaconCertificate(cert, n.Public, n.State.F, n.checks)
}
