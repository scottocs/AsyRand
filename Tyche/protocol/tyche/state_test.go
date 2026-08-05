package tyche

import (
	"crypto/ed25519"
	"testing"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/utils/p2p"
)

func testConfiguration(t *testing.T, version uint64, members []p2p.NodeID, f int, epoch string) (Configuration, map[p2p.NodeID]crypto.IdentityKeyPair) {
	t.Helper()
	params, _, err := crypto.SetupPVSS(crypto.PVSSO1, epoch, f+1, members)
	if err != nil {
		t.Fatal(err)
	}
	identities := make(map[p2p.NodeID]crypto.IdentityKeyPair, len(members))
	public := make(map[p2p.NodeID]ed25519.PublicKey, len(members))
	for _, member := range members {
		seed := crypto.DomainHash("Tyche/StateTestIdentity/v1", []byte(member))
		pair, err := crypto.IdentityKeyPairFromSeed(seed[:ed25519.SeedSize])
		if err != nil {
			t.Fatal(err)
		}
		identities[member] = pair
		public[member] = pair.Public
	}
	configuration, err := NewConfiguration(version, members, f, params, public)
	if err != nil {
		t.Fatal(err)
	}
	return configuration, identities
}

func genesisForConfiguration(configuration Configuration) SchedulingState {
	seqs := make(map[p2p.NodeID]uint64, len(configuration.Members))
	for _, member := range configuration.Members {
		seqs[member] = 0
	}
	return canonicalSchedulingState(SchedulingState{
		ConfigVersion: configuration.Version,
		F:             configuration.F, Q: configuration.Q, PVSSThreshold: configuration.PVSSThreshold,
		Random:     []byte("genesis"),
		BeaconHead: GenesisBeaconHead(configuration.Version, []byte("genesis"), configuration.Members),
		Members:    configuration.Members, SCL: configuration.Members, Seqs: seqs,
		ControlInstances: make(map[p2p.NodeID]string), ConfigDigest: configuration.Digest(),
	})
}

func TestBeaconQCBindsSkippedDigestAndPaperTuple(t *testing.T) {
	members := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	configuration, identities := testConfiguration(t, 7, members, 1, "state-qc")
	parentHash := genesisForConfiguration(configuration).BeaconHead
	random := []byte("random-1")
	skippedHash := HashSkippedTuples(nil)
	var votes []crypto.SignedVote
	for _, member := range members[:configuration.Q] {
		vote, err := SignBeaconVote(member, identities[member].Private, configuration, 1, parentHash, skippedHash, "n0", 1, random)
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	qc, err := BuildBeaconQC(configuration, 1, parentHash, skippedHash, "n0", 1, random, votes)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBeaconQC(configuration, qc); err != nil {
		t.Fatalf("valid BeaconQC rejected: %v", err)
	}
	for name, mutate := range map[string]func(*BeaconQC){
		"random": func(q *BeaconQC) { q.Random = []byte("different") },
		"parent": func(q *BeaconQC) { q.ParentHash = "wrong-parent" },
		"skips":  func(q *BeaconQC) { q.SkippedHash = "wrong-skipped-list" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := qc
			mutate(&tampered)
			if err := VerifyBeaconQC(configuration, tampered); err == nil {
				t.Fatal("BeaconQC accepted a modified signed field")
			}
		})
	}
}

func TestBeaconVoteBucketBindsEverySignedField(t *testing.T) {
	base := signedBeaconMessage{ConfigVersion: 4, Epoch: 9, ParentHash: "parent", SkippedHash: "skips", Source: "n1", Seq: 3, Random: []byte("r9")}
	tests := []signedBeaconMessage{
		func() signedBeaconMessage { v := base; v.ConfigVersion++; return v }(),
		func() signedBeaconMessage { v := base; v.ParentHash = "other"; return v }(),
		func() signedBeaconMessage { v := base; v.SkippedHash = "other"; return v }(),
		func() signedBeaconMessage { v := base; v.Source = "n2"; return v }(),
		func() signedBeaconMessage { v := base; v.Seq++; return v }(),
		func() signedBeaconMessage { v := base; v.Random = []byte("other"); return v }(),
	}
	baseKey := beaconVoteKey(base)
	for _, changed := range tests {
		if beaconVoteKey(changed) == baseKey {
			t.Fatal("different BEACON statements shared one vote bucket")
		}
	}
}

func TestEntropySuccessorAppliesCertifiedSkipsWithoutRemovingParty(t *testing.T) {
	members := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	configuration, _ := testConfiguration(t, 2, members, 1, "skip-successor")
	parent := genesisForConfiguration(configuration)
	parent.Epoch = 3
	parent.Seqs["n1"] = 1
	prior := aba.TupleInstanceFor(configuration.Version, 2, "n1", 1)
	parent.ControlInstances["n1"] = prior
	skipped := []SkippedTuple{{
		Source: "n1", Seq: 2,
		Certificate: aba.Certificate{ConfigVersion: configuration.Version, Purpose: "control", Instance: prior, Value: false},
	}}
	child, err := EntropySuccessor(parent, []byte("r4"), "n0", 1, skipped)
	if err != nil {
		t.Fatal(err)
	}
	if child.Seqs["n1"] != 2 || child.Seqs["n0"] != 1 {
		t.Fatalf("wrong certified prefixes after skip: %v", child.Seqs)
	}
	if !contains(child.Members, "n1") || contains(child.RSQ, "n1") {
		t.Fatalf("a skipped source was removed or rotated as a contributor: members=%v rsq=%v", child.Members, child.RSQ)
	}
	if child.ControlInstances["n1"] != aba.TupleInstanceFor(configuration.Version, 4, "n1", 2) {
		t.Fatal("skipped tuple did not create its successor-control instance")
	}
}
