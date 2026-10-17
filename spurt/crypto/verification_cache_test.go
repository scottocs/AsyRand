package crypto

import (
	"Tyche/utils/p2p"
	"encoding/json"
	"go.dedis.ch/kyber/v3"
	"testing"
)

func TestPVSSDuplicateVerificationAndMutatedKnowledgeProof(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}
	s, err := NewPVSSScheme("n0", 2, keys["n0"].Private, public)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := s.Share("n0", 1, ids)
	if err != nil || !s.Verify(c) {
		t.Fatal("honest transcript rejected", err)
	}
	count := s.checks.Stats().Executions
	for i := 0; i < 5; i++ {
		if !s.Verify(c) {
			t.Fatal("duplicate transcript rejected")
		}
	}
	if s.checks.Stats().Executions != count {
		t.Fatal("duplicate PVSS was reverified")
	}
	sh, err := s.PreReconTrusted(c, "n0")
	if err != nil || !s.VerifyShare(c, sh) {
		t.Fatal("honest decrypted share rejected", err)
	}
	count = s.checks.Stats().Executions
	if !s.VerifyShare(c, sh) || s.checks.Stats().Executions != count {
		t.Fatal("decrypted share was reverified")
	}
	// SecretID deliberately does not cover DLEQ. A cache keyed only by that
	// identifier would admit this replacement proof after the first success.
	raw, _ := json.Marshal(c)
	var bad PVSSCommitment
	if err := json.Unmarshal(raw, &bad); err != nil {
		t.Fatal(err)
	}
	proof := bad.DLEQ["n0"]
	proof.A = "00"
	bad.DLEQ["n0"] = proof
	if commitmentID(bad) != c.SecretID {
		t.Fatal("test no longer exercises omitted-proof binding")
	}
	if s.Verify(bad) {
		t.Fatal("cached transcript admitted a replacement DLEQ proof")
	}
}
