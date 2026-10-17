package crypto

import (
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"go.dedis.ch/kyber/v3"
	"testing"
)

func TestCommitmentShareAndSignedAPVSSChecksAreReused(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	schemes := make(map[p2p.NodeID]*PVSSPairingFreeScheme)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}
	for _, id := range ids {
		var err error
		schemes[id], err = NewPVSSScheme(id, 2, keys[id].Private, public, testSigningKeys(id, ids))
		if err != nil {
			t.Fatal(err)
		}
	}
	s := schemes["n0"]
	c, _, err := s.Share("n0", 1, ids)
	if err != nil || !s.Verify(c) {
		t.Fatal("honest APVSS rejected", err)
	}
	before := s.checks.Stats().Executions
	if !s.Verify(c) || s.checks.Stats().Executions != before {
		t.Fatal("signed APVSS reverified")
	}
	proof := c.Contributions[0].Proof
	if !schnorrVerify(suite(), "n0", 1, proof, s.signing.Public["n0"], s.checks) || s.checks.Stats().Executions != before {
		t.Fatal("contribution proof was reverified separately")
	}
	setup, err := SetupGRandFromAPVSS(ids, schemes, 2)
	if err != nil {
		t.Fatal(err)
	}
	commitment, alpha, err := NewBeaconCommitment("n0", setup.SecretShares["n0"])
	if err != nil {
		t.Fatal(err)
	}
	cache := verification.New()
	verified, ok := DecodeAndVerifyBeaconCommitment(setup.PublicShares["n0"], commitment, cache)
	if !ok {
		t.Fatal("honest commitment rejected")
	}
	before = cache.Stats().Executions
	if !VerifyBeaconCommitment(setup.PublicShares["n0"], commitment, cache) || cache.Stats().Executions != before {
		t.Fatal("commitment pairing equation repeated")
	}
	msg := []byte("epoch-1")
	share, err := NewBeaconShare(1, msg, "n0", setup.SecretShares["n0"], alpha)
	if err != nil || !VerifyBeaconShareWithCommitment(msg, verified, share, cache) {
		t.Fatal("honest share rejected", err)
	}
	before = cache.Stats().Executions
	if !VerifyBeaconShare(msg, setup.PublicShares["n0"], commitment, share, cache) || cache.Stats().Executions != before {
		t.Fatal("share/commitment check repeated through another API")
	}
	share.Proof.Response = "00"
	if VerifyBeaconShareWithCommitment(msg, verified, share, cache) {
		t.Fatal("cached share admitted altered proof")
	}
	commitment.CM2 = commitment.CM1
	if VerifyBeaconCommitment(setup.PublicShares["n0"], commitment, cache) {
		t.Fatal("cached commitment admitted altered group element")
	}
}
