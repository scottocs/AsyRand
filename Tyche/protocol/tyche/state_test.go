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

func genesisForConfiguration(configuration Configuration) SchedulingState {
	seqs := make(map[p2p.NodeID]uint64, len(configuration.Members))
	for _, member := range configuration.Members {
		seqs[member] = 0
	}
	return canonicalSchedulingState(SchedulingState{
		ConfigVersion: configuration.Version,
		F:             configuration.F,
		Q:             configuration.Q,
		PVSSThreshold: configuration.PVSSThreshold,
		Random:        []byte("genesis"),
		BeaconHead:    GenesisBeaconHead(configuration.Version, []byte("genesis"), configuration.Members),
		Members:       configuration.Members,
		SCL:           configuration.Members,
		Seqs:          seqs,
		ConfigDigest:  configuration.Digest(),
	})
}

func TestBeaconQCBindsPaperTuple(t *testing.T) {
	members := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	configuration, identities := testConfiguration(t, 7, members, 1, "state-qc")
	parent := genesisForConfiguration(configuration)
	parentHash := parent.BeaconHead
	random := []byte("random-1")
	var votes []crypto.SignedVote
	for _, member := range members[:configuration.Q] {
		vote, err := SignBeaconVote(member, identities[member].Private, configuration, 1, parentHash, "n0", 1, random)
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	qc, err := BuildBeaconQC(configuration, 1, parentHash, "n0", 1, random, votes)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBeaconQC(configuration, qc); err != nil {
		t.Fatalf("valid BeaconQC rejected: %v", err)
	}
	tampered := qc
	tampered.Random = []byte("different")
	if err := VerifyBeaconQC(configuration, tampered); err == nil {
		t.Fatal("BeaconQC accepted a tampered beacon value")
	}
	tampered = qc
	tampered.ParentHash = "wrong-parent"
	if err := VerifyBeaconQC(configuration, tampered); err == nil {
		t.Fatal("BeaconQC accepted a different parent")
	}
}

func TestBeaconVoteBucketBindsEverySignedField(t *testing.T) {
	base := signedBeaconMessage{
		ConfigVersion: 4,
		Epoch:         9,
		ParentHash:    "parent",
		Source:        "n1",
		Seq:           3,
		Random:        []byte("r9"),
	}
	tests := []signedBeaconMessage{
		func() signedBeaconMessage { v := base; v.ConfigVersion++; return v }(),
		func() signedBeaconMessage { v := base; v.ParentHash = "other"; return v }(),
		func() signedBeaconMessage { v := base; v.Source = "n2"; return v }(),
		func() signedBeaconMessage { v := base; v.Seq++; return v }(),
		func() signedBeaconMessage { v := base; v.Random = []byte("other-random"); return v }(),
	}
	baseKey := beaconVoteKey(base)
	for _, changed := range tests {
		if beaconVoteKey(changed) == baseKey {
			t.Fatalf("different BEACON tuple shared vote bucket: base=%+v changed=%+v", base, changed)
		}
	}
}

func TestRemoveSuccessorPreservesEpochAndRandomness(t *testing.T) {
	parentMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	parentConfiguration, _ := testConfiguration(t, 3, parentMembers, 1, "remove-parent")
	parent := genesisForConfiguration(parentConfiguration)
	parent.Epoch = 19
	parent.Random = []byte("r19")

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

func TestDelayedBeaconRecordPreservesInstalledJoin(t *testing.T) {
	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	oldConfiguration, _ := testConfiguration(t, 2, oldMembers, 1, "delayed-beacon-old")
	current := genesisForConfiguration(oldConfiguration)
	current.ConfigVersion = 3
	current.Members = append(current.Members, "joiner")
	current.SCL = append(current.SCL, "joiner")
	current.Seqs["joiner"] = 0

	child, err := entropySuccessorForRecord(current, oldConfiguration.Version, oldConfiguration.F, []byte("r1"), "n0", 1)
	if err != nil {
		t.Fatal(err)
	}
	if child.ConfigVersion != 3 || !contains(child.Members, "joiner") || child.Seqs["joiner"] != 0 {
		t.Fatalf("delayed old-configuration BeaconQC rolled back joining: %+v", child)
	}
	wantHead := BeaconHeaderHash(oldConfiguration.Version, 1, current.BeaconHead, "n0", 1, []byte("r1"))
	if child.BeaconHead != wantHead {
		t.Fatalf("beacon head used current configuration instead of signing configuration: got %s want %s", child.BeaconHead, wantHead)
	}
}

func TestJoinCommutesWithDelayedOldConfigurationBeacon(t *testing.T) {
	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	oldConfiguration, _ := testConfiguration(t, 2, oldMembers, 1, "join-commute-old")
	newMembers := append(append([]p2p.NodeID(nil), oldMembers...), "joiner")
	newConfiguration, _ := testConfiguration(t, 3, newMembers, 1, "join-commute-new")
	parent := genesisForConfiguration(oldConfiguration)

	installJoin := func(state SchedulingState) SchedulingState {
		state.ConfigVersion = newConfiguration.Version
		state.F = newConfiguration.F
		state.Q = newConfiguration.Q
		state.PVSSThreshold = newConfiguration.PVSSThreshold
		state.ConfigDigest = newConfiguration.Digest()
		state.Members = append([]p2p.NodeID(nil), newConfiguration.Members...)
		state.Seqs["joiner"] = 0
		return canonicalSchedulingState(state)
	}

	beaconFirst, err := entropySuccessorForRecord(
		parent, oldConfiguration.Version, oldConfiguration.F,
		[]byte("r1"), "n0", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	beaconThenJoin := installJoin(beaconFirst)

	joinFirst := installJoin(CloneSchedulingState(parent))
	joinThenBeacon, err := entropySuccessorForRecord(
		joinFirst, oldConfiguration.Version, oldConfiguration.F,
		[]byte("r1"), "n0", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := HashSchedulingState(joinThenBeacon), HashSchedulingState(beaconThenJoin); got != want {
		t.Fatalf("JOIN and delayed P_e do not commute: got %s want %s\njoin-first=%+v\nbeacon-first=%+v", got, want, joinThenBeacon, beaconThenJoin)
	}
}

func TestConfigurationShrinkTrimsRecentQueueAndKeepsEligibleSources(t *testing.T) {
	state := SchedulingState{
		F:       1,
		Members: []p2p.NodeID{"n0", "n1", "n2", "n3"},
		RSQ:     []p2p.NodeID{"n0", "n1", "n2", "n3"},
		Seqs:    map[p2p.NodeID]uint64{"n0": 1, "n1": 1, "n2": 1, "n3": 1},
	}
	state = canonicalSchedulingState(state)
	if got, want := state.RSQ, []p2p.NodeID{"n2", "n3"}; !sameNodeIDsInOrder(got, want) {
		t.Fatalf("recent queue was not trimmed to current 2f suffix: got %v want %v", got, want)
	}
	if got, want := state.SCL, []p2p.NodeID{"n0", "n1"}; !sameNodeIDsInOrder(got, want) {
		t.Fatalf("eligible list after shrink: got %v want %v", got, want)
	}
}

func sameNodeIDsInOrder(a, b []p2p.NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
