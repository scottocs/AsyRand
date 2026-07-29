package tyche

import (
	"bytes"
	"context"
	"encoding/hex"
	"strconv"
	"testing"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/utils/p2p"
)

type beaconTestResult struct {
	beacon Beacon
	err    error
}

func waitUntil(t *testing.T, ctx context.Context, predicate func() bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if predicate() {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

type countingPVSSScheme struct {
	crypto.PVSSScheme
	verifyShareCount int
}

func (s *countingPVSSScheme) VerifyShare(c crypto.Commitment, sh crypto.DecryptedShare) bool {
	s.verifyShareCount++
	return s.PVSSScheme.VerifyShare(c, sh)
}

func TestBeaconProducerConsumerCertifiesEpoch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	source := nextSource(nodes[0])
	var producer *Node
	for _, n := range nodes {
		if n.ID == source {
			producer = n
			break
		}
	}
	if producer == nil {
		t.Fatalf("missing producer %s", source)
	}
	obj, err := producer.Produce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitStored(t, ctx, nodes, source, obj.Seq)
	lookahead, err := producer.Produce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitStored(t, ctx, nodes, source, lookahead.Seq)

	results := make(chan Beacon, len(nodes))
	for _, n := range nodes {
		go func(n *Node) {
			b, err := n.RunEpoch(ctx)
			if err != nil {
				t.Errorf("RunEpoch(%s): %v", n.ID, err)
				return
			}
			results <- b
		}(n)
	}

	var first Beacon
	for i := range nodes {
		select {
		case b := <-results:
			if i == 0 {
				first = b
			} else if !bytes.Equal(first.Random, b.Random) || first.Source != b.Source || first.Seq != b.Seq {
				t.Fatalf("beacon mismatch: first=%+v got=%+v", first, b)
			}
			if len(b.ReadySenders) < 3 {
				t.Fatalf("weak ready certificate: %+v", b.ReadySenders)
			}
			nodes[0].mu.Lock()
			parentConfig := nodes[0].Configurations[b.StateQC.ParentConfigVersion]
			nodes[0].mu.Unlock()
			if len(b.StateQC.Signature.Votes) < parentConfig.Q {
				t.Fatalf("invalid StateQC quorum size: %d", len(b.StateQC.Signature.Votes))
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for certified beacon\n%s", dumpNodes(nodes))
		}
	}
	if first.Epoch != 1 || first.Source != source || first.Seq != 1 {
		t.Fatalf("bad beacon tuple: %+v", first)
	}
}

func TestHandleReconStopsVerifyingAfterThreshold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	source := nextSource(nodes[0])
	var producer *Node
	for _, n := range nodes {
		if n.ID == source {
			producer = n
			break
		}
	}
	if producer == nil {
		t.Fatalf("missing producer %s", source)
	}
	obj, err := producer.Produce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitStored(t, ctx, nodes, source, obj.Seq)

	target := nodes[0]
	counter := &countingPVSSScheme{PVSSScheme: target.PVSS}
	target.PVSS = counter
	target.mu.Lock()
	target.PVSSContexts[target.State.ConfigVersion].Scheme = counter
	target.mu.Unlock()
	for i := 0; i < obj.Commitment.Threshold+1; i++ {
		holder := nodes[i]
		share, err := holder.PVSS.PreReconVerified(obj.Commitment, holder.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := target.handleRecon(ctx, holder.ID, ReconMessage{Epoch: 1, Source: source, Seq: obj.Seq, Share: share}); err != nil {
			t.Fatal(err)
		}
	}
	if counter.verifyShareCount != obj.Commitment.Threshold {
		t.Fatalf("VerifyShare count = %d, want threshold %d", counter.verifyShareCount, obj.Commitment.Threshold)
	}
}

func TestHandleReconStoresMissingObjectFromMessage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	source := nextSource(nodes[0])
	var producer *Node
	for _, n := range nodes {
		if n.ID == source {
			producer = n
			break
		}
	}
	if producer == nil {
		t.Fatalf("missing producer %s", source)
	}
	obj, err := producer.Produce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	waitStored(t, ctx, nodes, source, obj.Seq)

	target := nodes[0]
	holder := nodes[1]
	if holder.ID == target.ID {
		holder = nodes[2]
	}
	target.mu.Lock()
	delete(target.State.ComQ[source], obj.Seq)
	target.mu.Unlock()

	share, err := holder.PVSS.PreReconVerified(obj.Commitment, holder.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.handleRecon(ctx, holder.ID, ReconMessage{Epoch: 1, Source: source, Seq: obj.Seq, Share: share, Object: &obj}); err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	_, stored := target.State.ComQ[source][obj.Seq]
	target.mu.Unlock()
	if !stored {
		t.Fatalf("recon did not restore missing object %s/%d", source, obj.Seq)
	}
}

func TestBeaconAutoProducerCertifiesEpochN4(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	for _, node := range nodes {
		node.StartProducer(ctx, time.Millisecond)
	}
	waitAllQueuesNonEmpty(t, ctx, nodes)

	results := make(chan Beacon, len(nodes))
	for _, n := range nodes {
		go func(n *Node) {
			b, err := n.RunEpoch(ctx)
			if err != nil {
				t.Errorf("RunEpoch(%s): %v\n%s", n.ID, err, dumpNodes(nodes))
				return
			}
			results <- b
		}(n)
	}

	var first Beacon
	for i := range nodes {
		select {
		case b := <-results:
			if i == 0 {
				first = b
			} else if !bytes.Equal(first.Random, b.Random) || first.Source != b.Source || first.Seq != b.Seq {
				t.Fatalf("beacon mismatch: first=%+v got=%+v", first, b)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for certified beacon\n%s", dumpNodes(nodes))
		}
	}
}

func TestProducerDefaultWatermarks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node := newTestNodes(t, ctx)[0]
	if node.producerLow != 2 || node.producerHigh != 4 {
		t.Fatalf("producer watermarks low=%d high=%d, want low=2 high=4", node.producerLow, node.producerHigh)
	}
}

func TestProducerHighWatermarkBoundsAllocatedObjects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	producer := nodes[0]
	producer.producerHigh = 2
	producer.producerLow = 1

	if _, err := producer.Produce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Produce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := producer.Produce(ctx); err == nil {
		t.Fatal("expected producer high watermark to block third object")
	}

	producer.mu.Lock()
	window := producer.producerWindowDepthLocked()
	seq := producer.State.ProducerSeq
	producer.mu.Unlock()
	if window != 2 || seq != 2 {
		t.Fatalf("producer window=%d seq=%d, want window=2 seq=2", window, seq)
	}

	typed, ok := producer.Transport.(interface {
		MessageTypeMetrics() map[string]p2p.MessageTypeMetrics
	})
	if !ok {
		t.Fatal("transport does not expose message-type metrics")
	}
	sent := typed.MessageTypeMetrics()["rbc/VAL"].SentMessages
	want := uint64(2 * len(nodes))
	if sent != want {
		t.Fatalf("rbc/VAL sent=%d, want %d", sent, want)
	}
}

func TestBeaconAutoProducerRunnerIDsCertifiesEpochsN4(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ids := []p2p.NodeID{"node0", "node1", "node2", "node3"}
	pp, keys, err := crypto.Setup("tyche-runner-n4-f1", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		s, err := crypto.NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{ID: id, Members: ids, F: 1, QueueLen: 8, PVSS: s, Transport: net.NewTransport(id, 16384), InsecureDeterministicIdentity: true})
		if err != nil {
			t.Fatal(err)
		}
		node.Start(ctx)
		node.StartProducer(ctx, 20*time.Millisecond)
		nodes = append(nodes, node)
	}
	time.Sleep(3 * time.Second)

	for epoch := 1; epoch <= 5; epoch++ {
		results := make(chan beaconTestResult, len(nodes))
		for _, n := range nodes {
			go func(n *Node) {
				b, err := n.RunEpochAt(ctx, uint64(epoch))
				results <- beaconTestResult{beacon: b, err: err}
			}(n)
		}

		for range nodes {
			select {
			case res := <-results:
				if res.err != nil {
					t.Fatalf("RunEpochAt(%d): %v\n%s", epoch, res.err, dumpNodes(nodes))
				}
			case <-ctx.Done():
				t.Fatalf("timed out waiting for epoch %d\n%s", epoch, dumpNodes(nodes))
			}
		}
	}
}

func TestBeaconAutoProducerRunnerIDsCertifiesEpochN16(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	ids := make([]p2p.NodeID, 16)
	for i := range ids {
		ids[i] = p2p.NodeID("node" + strconv.Itoa(i))
	}
	pp, keys, err := crypto.Setup("tyche-runner-n16-f5", 6, ids)
	if err != nil {
		t.Fatal(err)
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		s, err := crypto.NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{ID: id, Members: ids, F: 5, QueueLen: 32, PVSS: s, Transport: net.NewTransport(id, 32768), InsecureDeterministicIdentity: true})
		if err != nil {
			t.Fatal(err)
		}
		node.Start(ctx)
		node.StartProducer(ctx, 20*time.Millisecond)
		nodes = append(nodes, node)
	}
	time.Sleep(3 * time.Second)

	results := make(chan beaconTestResult, len(nodes))
	for _, n := range nodes {
		go func(n *Node) {
			b, err := n.RunEpochAt(ctx, 1)
			results <- beaconTestResult{beacon: b, err: err}
		}(n)
	}

	var first Beacon
	for i := range nodes {
		select {
		case res := <-results:
			if res.err != nil {
				t.Fatalf("RunEpochAt(1): %v\n%s", res.err, dumpNodes(nodes))
			}
			b := res.beacon
			if i == 0 {
				first = b
			} else if !bytes.Equal(first.Random, b.Random) || first.Source != b.Source || first.Seq != b.Seq {
				t.Fatalf("beacon mismatch: first=%+v got=%+v", first, b)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for epoch 1\n%s", dumpNodes(nodes))
		}
	}
}

func TestRunnerIDNode1ObjectStores(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids := []p2p.NodeID{"node0", "node1", "node2", "node3"}
	pp, keys, err := crypto.Setup("tyche-runner-n4-f1", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Node, 0, len(ids))
	var producer *Node
	for _, id := range ids {
		s, err := crypto.NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{ID: id, Members: ids, F: 1, QueueLen: 8, PVSS: s, Transport: net.NewTransport(id, 16384), InsecureDeterministicIdentity: true})
		if err != nil {
			t.Fatal(err)
		}
		node.Start(ctx)
		nodes = append(nodes, node)
		if id == "node1" {
			producer = node
		}
	}
	obj, err := producer.Produce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if obj.Seq != 1 {
		t.Fatalf("unexpected seq %d", obj.Seq)
	}
	waitStored(t, ctx, nodes, "node1", 1)
}

func TestJoinUsesCertifiedJReadyAndStateQC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodes := newTestNodes(t, ctx)
	parent := nodes[0].Checkpoint()
	targetMembers := []p2p.NodeID{"n0", "n1", "n2", "n3", "theta"}
	params, targetKeys, err := crypto.SetupPVSS(crypto.PVSSO1, "join-v2", 2, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.RegisterPVSSKey(params.Epoch(), targetKeys[node.ID].Private)
	}
	seed := crypto.DomainHash("Tyche/JoinTestIdentity/v1", []byte("theta"))
	identity, err := crypto.IdentityKeyPairFromSeed(seed[:32])
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewPVSSScheme("theta", targetKeys["theta"].Private, params)
	if err != nil {
		t.Fatal(err)
	}
	commitment, _, err := joinerScheme.Share("theta", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   parent.State.ConfigVersion,
		ParentHash:      HashCertifiedState(parent.State),
		Joiner:          "theta",
		PublicKey:       hex.EncodeToString(identity.Public),
		CandidateParams: params,
		Object:          Object{ConfigVersion: 1, Producer: "theta", Seq: 1, Commitment: commitment},
		Checkpoint:      parent,
	}
	req, err = SignLearnerReady(req, identity.Private)
	if err != nil {
		t.Fatal(err)
	}
	parentSetup := nodes[0].ConfigurationSetups[parent.State.ConfigVersion]
	observerPrivate := crypto.KeyPairFromSeed(crypto.DomainHash("Tyche/JoinTestObserver/v1", []byte("theta"))).Private
	observerScheme, err := crypto.NewPVSSScheme("theta", observerPrivate, parentSetup.Params)
	if err != nil {
		t.Fatal(err)
	}
	parentIdentityKeys := identityKeysForMembers(nodes[0].Configurations[parent.State.ConfigVersion], parent.State.Members)
	parentIdentityKeys["theta"] = identity.Public
	learner, err := NewNode(Config{
		ID: "theta", Members: parent.State.Members, Learner: true, F: parent.State.F,
		QueueLen: 8, PVSS: observerScheme, Transport: p2p.NewMemoryNetwork().NewTransport("theta", 1024),
		IdentityPrivate: identity.Private, IdentityPublicKeys: parentIdentityKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	learner.RegisterPVSSKey(params.Epoch(), targetKeys["theta"].Private)
	if err := learner.HandleJoinRequest(ctx, req); err != nil {
		t.Fatal(err)
	}
	if err := nodes[0].ProposeJoin(ctx, req); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, ctx, func() bool {
		for _, node := range nodes {
			node.mu.Lock()
			ready := node.pendingJReady != nil
			node.mu.Unlock()
			if !ready {
				return false
			}
		}
		return true
	})

	parentState := CloneCertifiedState(nodes[0].Certified)
	var child CertifiedState
	for i, node := range nodes {
		node.mu.Lock()
		next, err := node.entropySuccessorWithControlLocked(node.Certified, []byte("join-ready-random"), "n0", 1)
		node.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			child = next
		} else if HashCertifiedState(next) != HashCertifiedState(child) {
			t.Fatal("nodes constructed different JReady states")
		}
	}
	config := nodes[0].Configurations[parentState.ConfigVersion]
	var votes []crypto.SignedVote
	for _, node := range nodes[:config.Q] {
		vote, err := SignStateVote(node.ID, node.IdentityPrivate, config, TransitionEntropy, HashCertifiedState(parentState), HashCertifiedState(child))
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	qc, err := BuildStateQC(config, TransitionEntropy, HashCertifiedState(parentState), HashCertifiedState(child), votes)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		node.mu.Lock()
		node.installCertifiedEntropyLocked(child, qc)
		node.mu.Unlock()
	}
	if err := learner.InstallCheckpoint(nodes[0].Checkpoint()); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, len(nodes))
	for _, node := range nodes {
		go func(node *Node) { results <- node.runCertifiedJoin(ctx) }(node)
	}
	for range nodes {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range nodes {
		if !contains(node.State.Members, "theta") || node.State.ConfigVersion != 1 || node.State.Epoch != child.Epoch {
			t.Fatalf("JOIN StateQC not installed on %s: version=%d epoch=%d members=%v", node.ID, node.State.ConfigVersion, node.State.Epoch, node.State.Members)
		}
	}
	nodes[0].mu.Lock()
	installed := StateCertificateMessage{Child: CloneCertifiedState(nodes[0].Certified), QC: *nodes[0].StateCertificate}
	nodes[0].mu.Unlock()
	if err := learner.InstallStateCertificate(installed); err != nil {
		t.Fatal(err)
	}
	learner.mu.Lock()
	activated := learner.RBC != nil && learner.ABA != nil && contains(learner.Certified.Members, learner.ID)
	learner.mu.Unlock()
	if !activated {
		t.Fatal("learner did not activate from JOIN StateQC")
	}
}

func TestCertifiedRemovalMarkerSuppressesPendingJReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	node := newTestNodes(t, ctx)[0]
	node.mu.Lock()
	node.pendingJReady = &JoinReady{ParentHash: HashCertifiedState(node.Certified), RequestDigest: "join", Joiner: "theta"}
	node.State.RmMark["n1"] = 1
	child, err := node.entropySuccessorWithControlLocked(node.Certified, []byte("r"), "n0", 1)
	node.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if child.JReady != nil || child.RmMark["n1"] != 1 {
		t.Fatalf("removal did not take priority: ready=%+v marks=%v", child.JReady, child.RmMark)
	}
	node.mu.Lock()
	node.Certified = CloneCertifiedState(child)
	node.pendingJReady = &JoinReady{ParentHash: HashCertifiedState(node.Certified), RequestDigest: "later-join", Joiner: "theta"}
	next, err := node.entropySuccessorWithControlLocked(node.Certified, []byte("r2"), "n0", 2)
	node.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if next.JReady != nil {
		t.Fatal("an already-certified removal marker did not retain priority over JOIN")
	}
}

func TestCertifiedRemovalUsesStateQCAcrossNodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	nodes := newTestNodes(t, ctx)
	for _, node := range nodes {
		node.mu.Lock()
		node.Certified.RmMark["n3"] = 1
		node.State.RmMark["n3"] = 1
		node.mu.Unlock()
	}
	results := make(chan error, len(nodes))
	for _, node := range nodes {
		go func(node *Node) {
			results <- node.runCertifiedRemoval(ctx, "n3")
		}(node)
	}
	for range nodes {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range nodes {
		node.mu.Lock()
		state := CloneCertifiedState(node.Certified)
		qc := node.StateCertificate
		activeRBC := node.RBC
		node.mu.Unlock()
		if state.ConfigVersion != 1 || state.Epoch != 0 || contains(state.Members, "n3") {
			t.Fatalf("node %s installed invalid REMOVE state: %+v", node.ID, state)
		}
		if qc == nil || qc.Transition != TransitionRemove || qc.ParentConfigVersion != 0 {
			t.Fatalf("node %s lacks exact REMOVE StateQC: %+v", node.ID, qc)
		}
		if node.ID == "n3" && activeRBC != nil {
			t.Fatal("removed process retained an active child RBC engine")
		}
	}
}

func TestCoinBarrierIgnoresCurrentABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	current := aba.EpochInstanceFor(0, 1, "n0", 1)
	nodes[0].mu.Lock()
	nodes[0].State.PendingABAs[current] = &PendingABA{Instance: current, Epoch: 1, Source: "n0", Seq: 1}
	nodes[0].mu.Unlock()

	if err := nodes[0].waitCoinBarrier(ctx, current); err != nil {
		t.Fatal(err)
	}
}

func TestCoinBarrierFeedsLateCoinRequestFromCertifiedBeacon(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	inst := aba.EpochInstanceFor(0, 1, "n0", 1)
	nodes[0].mu.Lock()
	nodes[0].State.PendingABAs[inst] = &PendingABA{Instance: inst, Epoch: 1, Source: "n0", Seq: 1}
	nodes[0].mu.Unlock()

	for _, node := range nodes {
		if err := node.ABA.Propose(ctx, inst, false); err != nil {
			t.Fatal(err)
		}
	}
	waitABAStatus(t, ctx, nodes[0], inst, func(st aba.Status) bool { return st.CoinWait })

	st := nodes[0].ABA.Status(inst)
	seed := []byte("certified-beacon-seed")
	for i := 0; aba.CoinFromSeed(inst, st.Round, seed); i++ {
		seed = []byte("certified-beacon-seed-" + string(rune('a'+i)))
	}
	nodes[0].mu.Lock()
	nodes[0].beaconSeeds[1+st.Round+1] = seed
	nodes[0].mu.Unlock()

	if err := nodes[0].waitCoinBarrier(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	nodes[0].mu.Lock()
	_, pending := nodes[0].State.PendingABAs[inst]
	rm := nodes[0].State.RmMark["n0"]
	nodes[0].mu.Unlock()
	if pending || rm != 2 {
		t.Fatalf("cached seed did not advance pending ABA to sequence marker: pending=%v rm=%d", pending, rm)
	}
}

func TestBeaconIndexUsesFullRandomValue(t *testing.T) {
	if got := beaconIndex([]byte{1, 0}, 257); got != 256 {
		t.Fatalf("beaconIndex used only a suffix byte: got=%d", got)
	}
}

func TestQueueLenOneSkipsLookaheadABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-epoch", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(Config{
		ID:                            "n0",
		Members:                       ids,
		F:                             1,
		QueueLen:                      1,
		LookaheadExpiration:           time.Hour,
		PVSS:                          s,
		Transport:                     p2p.NewMemoryNetwork().NewTransport("n0", 1024),
		InsecureDeterministicIdentity: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if certified, err := node.proposeEpochABAInputFromLookahead(ctx, 1, "n0", 1, "test-instance", make(chan Beacon, 1)); err != nil {
		t.Fatal(err)
	} else if certified != nil {
		t.Fatalf("unexpected certified beacon: %+v", *certified)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("queue_len=1 waited for lookahead: %s", elapsed)
	}
	node.mu.Lock()
	sent := node.abaInputSent["test-instance"]
	_, inputStored := node.abaInputs["test-instance"]
	node.mu.Unlock()
	if sent || inputStored {
		t.Fatalf("queue_len=1 created lookahead ABA input: sent=%v stored=%v", sent, inputStored)
	}
}

func TestMissingCurrentObjectDoesNotTriggerUncertifiedRemoval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-explicit-current", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(Config{
		ID:                            "n0",
		Members:                       ids,
		F:                             1,
		QueueLen:                      8,
		PVSS:                          s,
		Transport:                     p2p.NewMemoryNetwork().NewTransport("n0", 1024),
		InsecureDeterministicIdentity: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	missingCtx, cancelMissing := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelMissing()
	source := p2p.NodeID("n1")
	seq := uint64(1)
	_, _, err = node.waitObjectOrBeacon(missingCtx, 1, source, seq, aba.EpochInstanceFor(0, 1, source, seq), make(chan Beacon, 1))
	if err == nil {
		t.Fatal("expected missing current object to wait for context")
	}
	node.mu.Lock()
	mark := node.State.RmMark[source]
	node.mu.Unlock()
	if mark != -1 {
		t.Fatalf("missing object auto-marked source without ABA evidence %s: mark=%d", source, mark)
	}
}

func TestPrepareEpochDoesNotCreateLookaheadABAAtQueueLenOne(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-epoch", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(Config{
		ID:                            "n0",
		Members:                       ids,
		F:                             1,
		QueueLen:                      1,
		PVSS:                          s,
		Transport:                     p2p.NewMemoryNetwork().NewTransport("n0", 1024),
		InsecureDeterministicIdentity: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, instance, skip, certified, err := node.prepareEpoch(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if skip || certified {
		t.Fatalf("unexpected skip/certified flags: skip=%v certified=%v", skip, certified)
	}
	node.mu.Lock()
	_, pending := node.State.PendingABAs[instance]
	node.mu.Unlock()
	if pending {
		t.Fatalf("queue_len=1 created pending lookahead ABA %s", instance)
	}
}

func TestEnsureCurrentObjectReleasesProducerBusy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	node := nodes[0]
	seq, err := node.EnsureCurrentObject(ctx)
	if err != nil {
		t.Fatal(err)
	}
	node.mu.Lock()
	busy := node.producerBusy[seq]
	node.mu.Unlock()
	if busy {
		t.Fatalf("producer busy mark leaked for seq %d", seq)
	}
}

func newTestNodes(t *testing.T, ctx context.Context) []*Node {
	t.Helper()
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-epoch", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		s, err := crypto.NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{ID: id, Members: ids, F: 1, QueueLen: 8, PVSS: s, Transport: net.NewTransport(id, 1024), InsecureDeterministicIdentity: true})
		if err != nil {
			t.Fatal(err)
		}
		node.Start(ctx)
		nodes = append(nodes, node)
	}
	return nodes
}

func nextSource(n *Node) p2p.NodeID {
	n.mu.Lock()
	defer n.mu.Unlock()
	idx := beaconIndex(n.State.RPrev, len(n.State.SCL))
	return n.State.SCL[idx]
}

func waitStored(t *testing.T, ctx context.Context, nodes []*Node, source p2p.NodeID, seq uint64) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		ok := true
		for _, n := range nodes {
			n.mu.Lock()
			_, has := n.State.ComQ[source][seq]
			n.mu.Unlock()
			ok = ok && has
		}
		if ok {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for stored object %s/%d", source, seq)
		}
	}
}

func waitAllQueuesNonEmpty(t *testing.T, ctx context.Context, nodes []*Node) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		ok := true
		for _, observer := range nodes {
			observer.mu.Lock()
			for _, id := range observer.State.Members {
				if len(observer.State.ComQ[id]) == 0 {
					ok = false
					break
				}
			}
			observer.mu.Unlock()
			if !ok {
				break
			}
		}
		if ok {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for producer queues\n%s", dumpNodes(nodes))
		}
	}
}

func waitABAStatus(t *testing.T, ctx context.Context, node *Node, instance string, ok func(aba.Status) bool) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if st := node.ABA.Status(instance); ok(st) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for ABA status on %s: %+v", instance, node.ABA.Status(instance))
		}
	}
}
