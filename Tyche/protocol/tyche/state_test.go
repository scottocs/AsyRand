package tyche

import (
	"crypto/ed25519"
	"testing"

	"Tyche/Tyche/crypto"
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

func genesisForConfiguration(configuration Configuration) CertifiedState {
	marks := make(map[p2p.NodeID]int64, len(configuration.Members))
	seqs := make(map[p2p.NodeID]uint64, len(configuration.Members))
	for _, member := range configuration.Members {
		marks[member] = -1
		seqs[member] = 0
	}
	return canonicalCertifiedState(CertifiedState{
		ConfigVersion: configuration.Version,
		F:             configuration.F,
		Q:             configuration.Q,
		PVSSThreshold: configuration.PVSSThreshold,
		Random:        []byte("genesis"),
		Members:       configuration.Members,
		SCL:           configuration.Members,
		Seqs:          seqs,
		RmMark:        marks,
		ConfigDigest:  configuration.Digest(),
		Transition:    TransitionGenesis,
	})
}

func TestStateQCExactParentAndSignedTranscript(t *testing.T) {
	members := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	configuration, identities := testConfiguration(t, 7, members, 1, "state-qc")
	parent := genesisForConfiguration(configuration)
	child, err := EntropySuccessor(parent, []byte("random-1"), "n0", 1)
	if err != nil {
		t.Fatal(err)
	}
	parentHash := HashCertifiedState(parent)
	childHash := HashCertifiedState(child)
	var votes []crypto.SignedVote
	for _, member := range members[:configuration.Q] {
		vote, err := SignStateVote(member, identities[member].Private, configuration, TransitionEntropy, parentHash, childHash)
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	qc, err := BuildStateQC(configuration, TransitionEntropy, parentHash, childHash, votes)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStateQC(configuration, parent, child, qc); err != nil {
		t.Fatalf("valid StateQC rejected: %v", err)
	}
	tampered := CloneCertifiedState(child)
	tampered.Random = []byte("different")
	if err := VerifyStateQC(configuration, parent, tampered, qc); err == nil {
		t.Fatal("StateQC accepted a tampered child")
	}
	wrongParent := CloneCertifiedState(parent)
	wrongParent.Random = []byte("wrong-parent")
	if err := VerifyStateQC(configuration, wrongParent, child, qc); err == nil {
		t.Fatal("StateQC accepted a different parent")
	}
}

func TestRemoveSuccessorPreservesEpochAndRandomness(t *testing.T) {
	parentMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	parentConfiguration, _ := testConfiguration(t, 3, parentMembers, 1, "remove-parent")
	parent := genesisForConfiguration(parentConfiguration)
	parent.Epoch = 19
	parent.Random = []byte("r19")
	parent.RmMark["n3"] = 1

	childMembers := []p2p.NodeID{"n0", "n1", "n2"}
	childConfiguration, _ := testConfiguration(t, 4, childMembers, 0, "remove-child")
	child, err := RemoveSuccessor(parent, "n3", childConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if child.Epoch != parent.Epoch || string(child.Random) != string(parent.Random) {
		t.Fatalf("REMOVE changed entropy state: parent=(%d,%q), child=(%d,%q)", parent.Epoch, parent.Random, child.Epoch, child.Random)
	}
	if child.ConfigVersion != parent.ConfigVersion+1 || contains(child.Members, "n3") {
		t.Fatalf("invalid REMOVE successor: %+v", child)
	}
}

func TestJoinSuccessorRequiresExactCertifiedReady(t *testing.T) {
	parentMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	parentConfiguration, _ := testConfiguration(t, 1, parentMembers, 1, "join-parent")
	parent := genesisForConfiguration(parentConfiguration)

	childMembers := []p2p.NodeID{"n0", "n1", "n2", "n3", "n4"}
	childConfiguration, _ := testConfiguration(t, 2, childMembers, 1, "join-child")
	ready := JoinReady{
		ParentHash:      HashCertifiedState(parent),
		RequestDigest:   "request",
		Joiner:          "n4",
		CheckpointHash:  "checkpoint",
		CandidateConfig: childConfiguration.Digest(),
	}
	parent.JReady = &ready
	ready = *parent.JReady
	child, err := JoinSuccessor(parent, ready, childConfiguration)
	if err != nil {
		t.Fatal(err)
	}
	if child.Epoch != parent.Epoch || string(child.Random) != string(parent.Random) {
		t.Fatal("JOIN changed epoch or randomness")
	}
	stale := ready
	stale.ParentHash = "stale"
	if _, err := JoinSuccessor(parent, stale, childConfiguration); err == nil {
		t.Fatal("JOIN accepted stale JReady")
	}
}

func TestConcurrentRemovalsAreSerializedAcrossConfigurations(t *testing.T) {
	members := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	config0, _ := testConfiguration(t, 10, members, 1, "remove-two-parent")
	parent := genesisForConfiguration(config0)
	parent.Epoch = 8
	parent.Random = []byte("r8")
	parent.RmMark["n2"] = 1
	parent.RmMark["n3"] = 1

	config1, _ := testConfiguration(t, 11, []p2p.NodeID{"n0", "n1", "n3"}, 0, "remove-two-first")
	first, err := RemoveSuccessor(parent, "n2", config1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Epoch != 8 || first.RmMark["n3"] != 1 {
		t.Fatalf("first REMOVE lost concurrent marker: %+v", first)
	}
	config2, _ := testConfiguration(t, 12, []p2p.NodeID{"n0", "n1"}, 0, "remove-two-second")
	second, err := RemoveSuccessor(first, "n3", config2)
	if err != nil {
		t.Fatal(err)
	}
	if second.Epoch != 8 || second.ConfigVersion != 12 {
		t.Fatalf("serialized REMOVE changed epoch or skipped version: %+v", second)
	}
}

func TestRemovalMarkerPreventsSameParentJoin(t *testing.T) {
	members := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	config0, _ := testConfiguration(t, 1, members, 1, "join-remove-parent")
	parent := genesisForConfiguration(config0)
	parent.RmMark["n3"] = 1
	childMembers := []p2p.NodeID{"n0", "n1", "n2", "n3", "n4"}
	config1, _ := testConfiguration(t, 2, childMembers, 1, "join-remove-child")
	ready := JoinReady{
		ParentHash: HashCertifiedState(parent), RequestDigest: "request",
		Joiner: "n4", CheckpointHash: "checkpoint", CandidateConfig: config1.Digest(),
	}
	parent.JReady = &ready
	if _, err := JoinSuccessor(parent, ready, config1); err == nil {
		t.Fatal("JOIN was allowed while a certified removal marker was pending")
	}
}
