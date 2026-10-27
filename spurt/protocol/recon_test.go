package spurt

import (
	"Tyche/utils/cryptoexec"
	"crypto/ed25519"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	asig "Tyche/spurt/crypto"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type countingPVSSScheme struct {
	verifyShares atomic.Int32
}

func TestEightNodeQuorumRequiresSixVotes(t *testing.T) {
	n, es, _ := beaconTestNode(t)
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7"}
	n.State = NewState(ids, 2, nil)
	if n.State.Quorum() != 6 {
		t.Fatal("unsafe eight-node quorum")
	}
	for _, id := range ids[:5] {
		es.prepare[id] = struct{}{}
	}
	n.progressVotes(es)
	if es.precommitSent {
		t.Fatal("five PREPAREs advanced an eight-node committee")
	}
	es.prepare[ids[5]] = struct{}{}
	n.progressVotes(es)
	if !es.precommitSent {
		t.Fatal("six PREPAREs did not advance")
	}
	for _, id := range ids[:5] {
		es.finalize[id] = struct{}{}
	}
	n.progressVotes(es)
	if es.decided {
		t.Fatal("five FINALIZEs decided in an eight-node committee")
	}
	es.finalize[ids[5]] = struct{}{}
	n.progressVotes(es)
	if !es.decided {
		t.Fatal("six FINALIZEs did not decide")
	}
}

func TestFinalizeAmplificationDoesNotRequireLocalCommitQuorum(t *testing.T) {
	n, es, _ := beaconTestNode(t)
	es.finalize["n1"], es.finalize["n2"] = struct{}{}, struct{}{}
	n.progressVotes(es)
	if !es.finalizeSent || es.decided {
		t.Fatal("f+1 FINALIZE relay or decision threshold incorrect")
	}
	es.finalize["n3"] = struct{}{}
	n.progressVotes(es)
	if !es.decided {
		t.Fatal("matching FINALIZE quorum did not decide")
	}
}

func beaconTestNode(t *testing.T) (*Node, *epochState, map[p2p.NodeID]asig.KeyPair) {
	t.Helper()
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	keys := make(map[p2p.NodeID]asig.KeyPair)
	public := make(map[string]ed25519.PublicKey)
	for _, id := range ids {
		k, err := asig.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = k
		public[string(id)] = k.Public
	}
	network := p2p.NewMemoryNetwork()
	transport := network.NewTransport("n0", 32)
	for _, id := range ids[1:] {
		network.NewTransport(id, 32)
	}
	n, err := NewNode(NodeConfig{ID: "n0", Members: ids, F: 1, Keys: keys["n0"], Public: public, Transport: transport, PVSS: &countingPVSSScheme{}})
	if err != nil {
		t.Fatal(err)
	}
	es := n.stateAt(0)
	es.digest = "digest"
	es.selected = []CommitmentRef{{Dealer: "n0", Seq: 1}}
	es.leaderProposal = &AgreementMessage{Epoch: 0, Leader: "n0", Digest: "digest", Selected: es.selected}
	es.proposalBroadcast = true
	es.aggregate = &asig.PVSSCommitment{SecretID: "aggregate"}
	return n, es, keys
}

func TestLocallyReconstructedBeaconDoesNotWaitForVotes(t *testing.T) {
	n, es, _ := beaconTestNode(t)
	es.random = []byte("locally reconstructed output")
	n.tryBroadcastBeacon(es)
	select {
	case b := <-n.beacons:
		if string(b.Random) != string(es.random) {
			t.Fatal("wrong output")
		}
	case <-time.After(time.Second):
		t.Fatal("output waited for votes")
	}
	if len(es.beaconVotes[es.randomHash]) > 1 {
		t.Fatal("test unexpectedly obtained remote votes")
	}
}

func TestBeaconFallbackNeedsDistinctMatchingSigners(t *testing.T) {
	n, es, keys := beaconTestNode(t)
	random := []byte("fallback output")
	rh := randomHash(random)
	message := func(id p2p.NodeID) BeaconMessage {
		return BeaconMessage{Epoch: 0, Leader: "n0", Digest: "digest", Random: random, RandomHash: rh, Signature: asig.SignatureShare{Signer: string(id), SigHex: hex.EncodeToString(asig.Sign(keys[id].Private, beaconVoteBytes(0, "digest", rh)))}}
	}
	n.handleBeacon(message("n1"), "n1")
	n.handleBeacon(message("n1"), "n1")
	n.handleBeacon(message("n1"), "n2")
	if es.random != nil {
		t.Fatal("one signature poisoned or completed output")
	}
	select {
	case <-n.beacons:
		t.Fatal("output before threshold")
	default:
	}
	n.handleBeacon(message("n2"), "n2")
	select {
	case b := <-n.beacons:
		if string(b.Random) != string(random) {
			t.Fatal("wrong fallback")
		}
	case <-time.After(time.Second):
		t.Fatal("fallback did not complete")
	}
}

func TestBeaconFallbackWithoutProposalAndPublicCertificate(t *testing.T) {
	n, es, keys := beaconTestNode(t)
	es.leaderProposal = nil
	es.aggregate = nil
	es.digest = ""
	random := []byte("output learned without the leader proposal")
	rh := randomHash(random)
	for _, id := range []p2p.NodeID{"n1", "n2"} {
		msg := BeaconMessage{Epoch: 0, Leader: "n0", Digest: "decided", Random: random, RandomHash: rh,
			Signature: asig.SignatureShare{Signer: string(id), SigHex: hex.EncodeToString(asig.Sign(keys[id].Private, beaconVoteBytes(0, "decided", rh)))}}
		n.handleBeacon(msg, id)
	}
	select {
	case b := <-n.beacons:
		if string(b.Random) != string(random) {
			t.Fatal("wrong fallback output")
		}
	case <-time.After(time.Second):
		t.Fatal("fallback waited for a proposal")
	}
	cert, ok := n.BeaconCertificate(0)
	if !ok || !VerifyBeaconCertificate(cert, n.Public, 1) {
		t.Fatal("native public certificate unavailable or invalid")
	}
	cert.Random[0] ^= 1
	if VerifyBeaconCertificate(cert, n.Public, 1) {
		t.Fatal("tampered public certificate accepted")
	}
}

func TestUnsignedVoteRequiresAuthenticatedDelivery(t *testing.T) {
	n, es, _ := beaconTestNode(t)
	msg, err := p2p.NewMessage(Protocol, "PREPARE", epochInstance(0), "n1", "n0", VoteMessage{Epoch: 0, Leader: "n0", Digest: es.digest})
	if err != nil {
		t.Fatal(err)
	}
	n.dispatchSpurt(msg)
	if len(es.prepare) != 0 {
		t.Fatal("unauthenticated vote counted")
	}
	net := p2p.NewMemoryNetwork()
	a, b := net.NewTransport("n1", 4), net.NewTransport("n0", 4)
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchSpurt(<-b.Inbox())
	if len(es.prepare) != 1 {
		t.Fatal("authenticated unsigned vote not counted")
	}
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchSpurt(<-b.Inbox())
	if len(es.prepare) != 1 {
		t.Fatal("duplicate vote counted twice")
	}
	if n.PerfSnapshot().MessageVerifyCount != 0 {
		t.Fatal("ordinary vote triggered Ed25519 verification")
	}
	msg.From = "n2"
	if err := a.Send(t.Context(), "n0", msg); err == nil {
		t.Fatal("forged sender accepted")
	}
}

func TestPrivateDataVerificationCannotAuthorizeAnotherDigest(t *testing.T) {
	n, es, _ := beaconTestNode(t)
	es.leaderProposal = nil
	es.privateVerified = true
	es.digest = "verified-private-data"
	n.handleProposal(AgreementMessage{Epoch: 0, Leader: "n0", Digest: "different-proposal", Selected: []CommitmentRef{{Dealer: "n0", Seq: 1}, {Dealer: "n1", Seq: 1}}})
	if es.prepareSent || es.leaderProposal != nil {
		t.Fatal("private proof reused for a different proposal")
	}
}

func TestLookaheadDistributesAndVerifiesPrivateDataBeforeItsEpoch(t *testing.T) {
	n, _, keys := beaconTestNode(t)
	ids := n.State.MembersSnapshot()
	public := make(map[p2p.NodeID]kyber.Point)
	pvssKeys := make(map[p2p.NodeID]asig.PVSSKeyPair)
	schemes := make(map[p2p.NodeID]*asig.PVSSPairingFreeScheme)
	for _, id := range ids {
		pvssKeys[id] = asig.PVSSKeyPairFromSeed(asig.HashBytes([]byte(id)))
		public[id] = pvssKeys[id].Public
	}
	for _, id := range ids {
		var err error
		schemes[id], err = asig.NewPVSSScheme(id, 2, pvssKeys[id].Private, public)
		if err != nil {
			t.Fatal(err)
		}
	}
	net := p2p.NewMemoryNetwork()
	n.Transport = net.NewTransport("n0", 32)
	followerTransport := net.NewTransport("n1", 32)
	net.NewTransport("n2", 32)
	net.NewTransport("n3", 32)
	n.PVSS = schemes["n0"]
	const future = uint64(4) // n0 leads this epoch, while every node is still at 0.
	inputs := make([]asig.PVSSCommitment, 0, 2)
	for _, id := range ids[:2] {
		commit, _, err := schemes[id].Share(id, 1, ids)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, commit)
	}
	n.finishPreAggregate(n.stateAt(future), future, 2, inputs, ids)
	var packet p2p.Message
	select {
	case packet = <-followerTransport.Inbox():
	case <-time.After(2 * time.Second):
		t.Fatal("pre-aggregated data waited for its epoch")
	}
	if packet.Type != "PVSS_DATA" {
		t.Fatal("unexpected precomputation packet", packet.Type)
	}
	if !packet.Authenticated() {
		t.Fatal("private data lacks authenticated delivery")
	}
	data, err := p2p.DecodePayload[PrivateDataMessage](packet)
	if err != nil {
		t.Fatal(err)
	}
	follower, err := NewNode(NodeConfig{ID: "n1", Members: ids, F: 1, Keys: keys["n1"], Public: n.Public, Transport: followerTransport, PVSS: schemes["n1"]})
	if err != nil {
		t.Fatal(err)
	}
	follower.handlePrivateData(data, "n0")
	es := follower.stateAt(future)
	if !es.privateVerified {
		t.Fatal("future private data was not verified in advance")
	}
	if es.prepareSent || es.reconSent || es.leaderProposal != nil {
		t.Fatal("precomputation advanced the future agreement")
	}
}

func (s *countingPVSSScheme) Share(p2p.NodeID, uint64, []p2p.NodeID) (asig.PVSSCommitment, []byte, error) {
	return asig.PVSSCommitment{}, nil, nil
}

func (s *countingPVSSScheme) Verify(asig.PVSSCommitment) bool { return true }

func (s *countingPVSSScheme) Aggregate(p2p.NodeID, uint64, []asig.PVSSCommitment, []p2p.NodeID) (asig.PVSSCommitment, error) {
	return asig.PVSSCommitment{}, nil
}

func (s *countingPVSSScheme) AggregateTrusted(p2p.NodeID, uint64, []asig.PVSSCommitment, []p2p.NodeID) (asig.PVSSCommitment, error) {
	return asig.PVSSCommitment{}, nil
}

func (s *countingPVSSScheme) PreRecon(asig.PVSSCommitment, p2p.NodeID) (asig.PVSSDecryptedShare, error) {
	return asig.PVSSDecryptedShare{}, nil
}

func (s *countingPVSSScheme) PreReconTrusted(asig.PVSSCommitment, p2p.NodeID) (asig.PVSSDecryptedShare, error) {
	return asig.PVSSDecryptedShare{}, nil
}

func (s *countingPVSSScheme) VerifyShare(_ asig.PVSSCommitment, share asig.PVSSDecryptedShare) bool {
	s.verifyShares.Add(1)
	return share.Value != "invalid"
}

func (s *countingPVSSScheme) Recon(asig.PVSSCommitment, []asig.PVSSDecryptedShare, int) ([]byte, error) {
	return []byte("secret"), nil
}

func (s *countingPVSSScheme) ReconTrusted(asig.PVSSCommitment, []asig.PVSSDecryptedShare, int) ([]byte, error) {
	return []byte("secret"), nil
}

func (s *countingPVSSScheme) VerifyAggregationColumn(p2p.NodeID, asig.PVSSCommitment, []asig.PVSSColumnEntry) bool {
	return true
}

func TestHandleReconStopsVerifyingAfterThreshold(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pvss := &countingPVSSScheme{}
	node := &Node{
		ID:     "n0",
		Perf:   &PerfMetrics{},
		State:  NewState(ids, 1, []byte{1}),
		PVSS:   pvss,
		epochs: make(map[uint64]*epochState),
	}
	aggregate := asig.PVSSCommitment{Dealer: "n0", Seq: 1, Threshold: 2, Members: ids, SecretID: "agg/1"}
	es := node.stateAt(1)
	es.aggregate = &aggregate
	es.digest = "digest"

	for _, id := range []p2p.NodeID{"n1", "n2", "n3"} {
		node.handleRecon(ReconMessage{
			Epoch:  1,
			Digest: "digest",
			Share:  asig.PVSSDecryptedShare{CommitmentID: "agg/1", Holder: id},
		}, id)
	}

	if got, want := pvss.verifyShares.Load(), int32(2); got != want {
		t.Fatalf("VerifyShare calls = %d, want %d", got, want)
	}
}

func TestParallelReconRefillsInvalidCandidateAndReservesOwnShare(t *testing.T) {
	n, es, _ := beaconTestNode(t)
	n.Crypto = cryptoexec.New(2)
	es.reconLocalPending = true
	entered, release, drained := make(chan struct{}, 2), make(chan struct{}), make(chan struct{})
	for i := 0; i < 2; i++ {
		n.Crypto.Go(t.Context(), func() { entered <- struct{}{}; <-release })
	}
	<-entered
	<-entered
	for _, id := range []p2p.NodeID{"n1", "n2", "n3"} {
		msg := ReconMessage{Epoch: 0, Digest: "digest", Share: asig.PVSSDecryptedShare{CommitmentID: "aggregate", Holder: id}}
		if id == "n1" {
			bad := msg
			bad.Share.Value = "invalid"
			n.handleRecon(bad, id)
		}
		n.handleRecon(msg, id)
	}
	n.mu.Lock()
	if len(es.reconChecking) != 1 {
		t.Error("surplus concurrent reconstruction checks", len(es.reconChecking))
	}
	n.mu.Unlock()
	// Priority work and its invalid-candidate refill drain before this marker.
	n.Crypto.Go(t.Context(), func() { close(drained) })
	close(release)
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("candidate verification stalled")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		n.mu.Lock()
		done := len(es.reconShares) == 1 && len(es.reconChecking) == 0
		n.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("invalid proof blocked honest threshold candidate")
		}
		time.Sleep(time.Millisecond)
	}
	if n.PVSS.(*countingPVSSScheme).verifyShares.Load() != 2 {
		t.Fatal("did not stop at one valid foreign share")
	}
}
