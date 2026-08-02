package tyche

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/utils/p2p"
)

func TestJoinRBCStartsABAOnceAndInstallsOneMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	currentParams, currentKeys, err := crypto.Setup("join-current", 2, oldMembers)
	if err != nil {
		t.Fatal(err)
	}
	network := p2p.NewMemoryNetwork()
	nodes := make([]*Node, 0, len(oldMembers))
	for _, id := range oldMembers {
		scheme, err := crypto.NewScheme(id, currentKeys[id].Private, currentParams)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{
			ID: id, Members: oldMembers, F: 1, QueueLen: 8,
			PVSS: scheme, Transport: network.NewTransport(id, 4096),
			InsecureDeterministicIdentity: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
	}

	joiner := p2p.NodeID("theta")
	successorMembers := append(append([]p2p.NodeID(nil), oldMembers...), joiner)
	successorParams, successorKeys, err := crypto.SetupPVSS(crypto.PVSSO1, "join-successor", 2, successorMembers)
	if err != nil {
		t.Fatal(err)
	}
	identitySeed := crypto.DomainHash("Tyche/JoinTestIdentity/v2", []byte(joiner))
	identity, err := crypto.IdentityKeyPairFromSeed(identitySeed[:32])
	if err != nil {
		t.Fatal(err)
	}
	identityKeys := identityKeysForMembers(nodes[0].Configurations[0], oldMembers)
	identityKeys[joiner] = identity.Public
	successor, err := NewConfiguration(1, successorMembers, 1, successorParams, identityKeys)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if err := node.RegisterConfigurationSetup(successor, successorParams, successorKeys[node.ID].Private); err != nil {
			t.Fatal(err)
		}
		node.mu.Lock()
		_, prematurelyInstalled := node.ConfigurationSetups[successor.Version]
		_, candidateStored := node.CandidateSetups[successor.Digest()]
		node.mu.Unlock()
		if prematurelyInstalled || !candidateStored {
			t.Fatalf("node %s let an undecided JOIN reserve configuration version %d", node.ID, successor.Version)
		}
	}

	observerPrivate := crypto.KeyPairFromSeed(crypto.DomainHash("Tyche/JoinObserver/v1", []byte(joiner))).Private
	observer, err := crypto.NewScheme(joiner, observerPrivate, currentParams)
	if err != nil {
		t.Fatal(err)
	}
	learner, err := NewNode(Config{
		ID: joiner, Members: oldMembers, Learner: true, F: 1,
		QueueLen: 8, PVSS: observer, Transport: network.NewTransport(joiner, 4096),
		IdentityPrivate: identity.Private, IdentityPublicKeys: identityKeys,
		BootstrapCheckpoint: func() *CertifiedCheckpoint {
			checkpoint := nodes[0].Checkpoint()
			return &checkpoint
		}(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := learner.RegisterConfigurationSetup(successor, successorParams, successorKeys[joiner].Private); err != nil {
		t.Fatal(err)
	}
	for _, node := range append(nodes, learner) {
		node.Start(ctx)
	}

	joinerScheme, err := crypto.NewPVSSScheme(joiner, successorKeys[joiner].Private, successorParams)
	if err != nil {
		t.Fatal(err)
	}
	commitment, _, err := joinerScheme.Share(joiner, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion: 0,
		Joiner:        joiner,
		PublicKey:     hex.EncodeToString(identity.Public),
		AnchorEpoch:   1,
		Object: Object{
			ConfigVersion: 1, Producer: joiner, Seq: 1, Commitment: commitment,
		},
	}
	if err := learner.ProposeJoin(ctx, req); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, ctx, func() bool {
		for _, node := range append(nodes, learner) {
			node.mu.Lock()
			installed := node.State.ConfigVersion == 1 &&
				contains(node.State.Members, joiner) &&
				node.State.ComQ[joiner][1].Commitment.SecretID == commitment.SecretID
			node.mu.Unlock()
			if !installed {
				return false
			}
		}
		return true
	})
	for _, node := range append(nodes, learner) {
		node.mu.Lock()
		installed := node.ConfigurationSetups[successor.Version].Configuration.Digest() == successor.Digest()
		node.mu.Unlock()
		if !installed {
			t.Fatalf("node %s did not promote the decided JOIN candidate", node.ID)
		}
	}

	instance := aba.JoinInstanceFor(0, string(joiner))
	for _, node := range nodes {
		node.mu.Lock()
		proposed := node.abaInputSent[instance]
		pending := node.PendingJoin
		node.mu.Unlock()
		if !proposed || pending != nil {
			t.Fatalf("node %s did not close its single JOIN-ABA invocation", node.ID)
		}
	}
}

func TestJoinCoinWaitIsWokenOnlyByAssignedBeacon(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := newTestNodes(t, ctx)[0]
	joiner := p2p.NodeID("theta")
	anchor := uint64(7)
	instance := aba.JoinInstanceFor(0, string(joiner))
	node.mu.Lock()
	node.PendingJoin = &PendingJoin{
		Proposal: JoinRequest{ConfigVersion: 0, Joiner: joiner, AnchorEpoch: anchor},
		Phase:    JoinStarted,
	}
	node.mu.Unlock()

	node.handleCoinRequest(aba.CoinRequest{ConfigVersion: 0, Instance: instance, Round: 0})
	node.mu.Lock()
	if !node.PendingJoin.CoinWait || node.PendingJoin.CoinRound != 0 {
		node.mu.Unlock()
		t.Fatal("JOIN-ABA did not retain its unresolved coin request")
	}
	if _, ok := node.pendingJoinCoinFeedLocked(anchor - 1); ok {
		node.mu.Unlock()
		t.Fatal("JOIN-ABA accepted the wrong beacon epoch")
	}
	feed, ok := node.pendingJoinCoinFeedLocked(anchor)
	node.mu.Unlock()
	if !ok || feed.instance != instance || feed.round != 0 {
		t.Fatalf("assigned beacon did not wake JOIN-ABA: feed=%+v ok=%v", feed, ok)
	}
}

func TestJoinQuietThroughoutTracksOnlyPaperPendingControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := newTestNodes(t, ctx)[0]
	node.mu.Lock()
	node.PendingJoin = &PendingJoin{
		Proposal:        JoinRequest{ConfigVersion: 0, Joiner: "theta", AnchorEpoch: 1},
		Phase:           JoinStarted,
		QuietThroughout: true,
	}
	node.mu.Unlock()

	if _, _, _, _, _, err := node.prepareEpoch(1); err != nil {
		t.Fatal(err)
	}
	node.mu.Lock()
	remainsEligibleWhileRunning := node.PendingJoin.QuietThroughout
	node.mu.Unlock()
	if !remainsEligibleWhileRunning {
		t.Fatal("an actively executing epoch ABA was mistaken for paper-level pending control")
	}

	instance := aba.EpochInstanceFor(0, 1)
	node.handleCoinRequest(aba.CoinRequest{ConfigVersion: 0, Instance: instance, Round: 0})
	node.mu.Lock()
	latchedAtCoinWait := !node.PendingJoin.QuietThroughout
	delete(node.State.PendingABAs, 1)
	stillLatched := !node.PendingJoin.QuietThroughout
	node.mu.Unlock()
	if !latchedAtCoinWait || !stillLatched {
		t.Fatalf("QuietThroughout was not monotone: at_coin_wait=%t still_latched=%t",
			latchedAtCoinWait, stillLatched)
	}
}

func TestQueueLengthOneIsRejected(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	params, keys, err := crypto.Setup("queue-one", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	scheme, err := crypto.NewScheme("n0", keys["n0"].Private, params)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewNode(Config{
		ID: "n0", Members: ids, F: 1, QueueLen: 1, PVSS: scheme,
		Transport:                     p2p.NewMemoryNetwork().NewTransport("n0", 1024),
		InsecureDeterministicIdentity: true,
	})
	if err == nil {
		t.Fatal("queue length one silently disabled the paper's epoch ABA")
	}
}
