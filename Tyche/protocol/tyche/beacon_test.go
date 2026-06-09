package tyche

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/Tyche/protocol/aba"
	"github.com/scottocs/Tyche/utils/p2p"
)

type beaconTestResult struct {
	beacon Beacon
	err    error
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
			members := nodes[0].memberSetLocked()
			nodes[0].mu.Unlock()
			if err := crypto.VerifyQuorumCertificate(b.Signature, members, 3); err != nil {
				t.Fatalf("invalid ready quorum certificate: %v", err)
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
		node, err := NewNode(Config{ID: id, Members: ids, F: 1, QueueLen: 8, PVSS: s, Transport: net.NewTransport(id, 16384)})
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

func TestInstallCertifiedStatePreservesLocalRemovalMarks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node := newTestNodes(t, ctx)[0]
	node.mu.Lock()
	state := node.stateDigestLocked()
	state.RmMark["n2"] = -1
	node.State.RmMark["n2"] = 3
	marks := copyRemovalMarks(node.State.RmMark)
	node.installCertifiedStateLocked(state)
	node.mergeRemovalMarksLocked(marks)
	got := node.State.RmMark["n2"]
	node.mu.Unlock()

	if got != 3 {
		t.Fatalf("removal mark was lost after installing certified state: got %d", got)
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
		node, err := NewNode(Config{ID: id, Members: ids, F: 5, QueueLen: 32, PVSS: s, Transport: net.NewTransport(id, 32768)})
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
		node, err := NewNode(Config{ID: id, Members: ids, F: 1, QueueLen: 8, PVSS: s, Transport: net.NewTransport(id, 16384)})
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

func TestJoinCertificateActivatesMember(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	targetMembers := append(append([]p2p.NodeID(nil), oldMembers...), "theta")
	candidate, targetKeys, err := crypto.Setup("join-epoch", 2, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewScheme("theta", targetKeys["theta"].Private, candidate)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := joinerScheme.Share("theta", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   0,
		ContextEpoch:    0,
		Joiner:          "theta",
		PublicKey:       "theta-pk",
		CandidateParams: crypto.WrapPVSSParams(candidate),
		Object:          Object{ConfigVersion: 1, Producer: "theta", Seq: 1, Commitment: c},
		FirstCoinEpoch:  0,
		ActivationEpoch: 1,
	}
	rho := JoinDigest(req)
	tau := TransitionIndex{ConfigVersion: 0, Seq: 1}
	cert := JoinCertificate{Request: req}
	for _, n := range nodes[:3] {
		cert.Cert1 = append(cert.Cert1, signedJoinAck(t, n, tau, rho))
		cert.Cert2 = append(cert.Cert2, signedJoinCommit(t, n, tau, rho, 1))
	}
	for _, n := range nodes {
		n.RegisterPVSSKey(candidate.Epoch, targetKeys[n.ID].Private)
	}
	for _, n := range nodes {
		if err := n.InstallJoinCertificate(cert); err != nil {
			t.Fatal(err)
		}
		if !contains(n.State.Members, "theta") || !contains(n.State.SCL, "theta") || n.State.ComQ["theta"][1].Producer != "theta" || n.State.ConfigVersion != 1 {
			t.Fatalf("join not installed on %s: %+v", n.ID, n.State)
		}
		if n.State.Seqs["theta"] != 0 || n.State.RmMark["theta"] != -1 {
			t.Fatalf("joiner state not initialized on %s: seq=%d rm=%d", n.ID, n.State.Seqs["theta"], n.State.RmMark["theta"])
		}
		if n.RBC.N != len(targetMembers) || n.ABA.N != len(targetMembers) || n.RBC.F != n.State.F || n.ABA.F != n.State.F {
			t.Fatalf("protocol thresholds not updated on %s: stateF=%d rbc=(%d,%d) aba=(%d,%d)",
				n.ID, n.State.F, n.RBC.N, n.RBC.F, n.ABA.N, n.ABA.F)
		}
		select {
		case got := <-n.Joins:
			if got.Request.Joiner != "theta" {
				t.Fatalf("unexpected join event on %s: %+v", n.ID, got.Request)
			}
		default:
			t.Fatalf("missing join event on %s", n.ID)
		}
		if err := n.InstallJoinCertificate(cert); err != nil {
			t.Fatal(err)
		}
		if n.State.ConfigVersion != 1 {
			t.Fatalf("duplicate join changed config version on %s: %d", n.ID, n.State.ConfigVersion)
		}
	}
}

func TestJoinCertificateActivatesOnlyAtFutureEpoch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	targetMembers := append(append([]p2p.NodeID(nil), oldMembers...), "theta")
	candidate, targetKeys, err := crypto.Setup("join-future-epoch", 2, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewScheme("theta", targetKeys["theta"].Private, candidate)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := joinerScheme.Share("theta", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   0,
		ContextEpoch:    0,
		Joiner:          "theta",
		PublicKey:       "theta-pk",
		CandidateParams: crypto.WrapPVSSParams(candidate),
		Object:          Object{ConfigVersion: 1, Producer: "theta", Seq: 1, Commitment: c},
		FirstCoinEpoch:  1,
		ActivationEpoch: 3,
	}
	rho := JoinDigest(req)
	tau := TransitionIndex{ConfigVersion: 0, Seq: 1}
	cert := JoinCertificate{Request: req}
	for _, n := range nodes[:3] {
		cert.Cert1 = append(cert.Cert1, signedJoinAck(t, n, tau, rho))
		cert.Cert2 = append(cert.Cert2, signedJoinCommit(t, n, tau, rho, 3))
	}
	for _, n := range nodes {
		n.RegisterPVSSKey(candidate.Epoch, targetKeys[n.ID].Private)
	}
	for _, n := range nodes {
		if err := n.InstallJoinCertificate(cert); err != nil {
			t.Fatal(err)
		}
		if contains(n.State.Members, "theta") || n.State.ConfigVersion != 0 {
			t.Fatalf("future join activated early on %s: members=%v version=%d", n.ID, n.State.Members, n.State.ConfigVersion)
		}
	}

	runTestEpoch := func(epoch uint64) {
		source, seq := nextSourceSeq(nodes[0])
		var producer *Node
		for _, n := range nodes {
			if n.ID == source {
				producer = n
				break
			}
		}
		if _, err := producer.Produce(ctx); err != nil {
			t.Fatal(err)
		}
		waitStored(t, ctx, nodes, source, seq)
		if _, err := producer.Produce(ctx); err != nil {
			t.Fatal(err)
		}
		waitStored(t, ctx, nodes, source, seq+1)
		results := make(chan beaconTestResult, len(nodes))
		for _, n := range nodes {
			go func(n *Node) {
				b, err := n.RunEpochAt(ctx, epoch)
				results <- beaconTestResult{beacon: b, err: err}
			}(n)
		}
		for range nodes {
			select {
			case res := <-results:
				if res.err != nil {
					t.Fatalf("RunEpochAt(%d): %v", epoch, res.err)
				}
			case <-ctx.Done():
				t.Fatalf("timed out before future activation\n%s", dumpNodes(nodes))
			}
		}
	}
	runTestEpoch(1)
	for _, n := range nodes {
		if contains(n.State.Members, "theta") || n.State.ConfigVersion != 0 {
			t.Fatalf("join activated before E2 on %s: members=%v version=%d", n.ID, n.State.Members, n.State.ConfigVersion)
		}
	}
	runTestEpoch(2)
	for _, n := range nodes {
		if err := n.activatePendingJoins(ctx, 3); err != nil {
			t.Fatal(err)
		}
		if !contains(n.State.Members, "theta") || n.State.ConfigVersion != 1 {
			t.Fatalf("join did not activate at E2 on %s: members=%v version=%d", n.ID, n.State.Members, n.State.ConfigVersion)
		}
	}
}

func TestJoinCertificateStaleWhenRemovalHasPriority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	targetMembers := append(append([]p2p.NodeID(nil), oldMembers...), "theta")
	candidate, targetKeys, err := crypto.Setup("join-removal-priority", 2, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewScheme("theta", targetKeys["theta"].Private, candidate)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := joinerScheme.Share("theta", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   0,
		ContextEpoch:    0,
		Joiner:          "theta",
		PublicKey:       "theta-pk",
		CandidateParams: crypto.WrapPVSSParams(candidate),
		Object:          Object{ConfigVersion: 1, Producer: "theta", Seq: 1, Commitment: c},
		FirstCoinEpoch:  1,
		ActivationEpoch: 3,
	}
	rho := JoinDigest(req)
	tau := TransitionIndex{ConfigVersion: 0, Seq: 1}
	cert := JoinCertificate{Request: req}
	for _, n := range nodes[:3] {
		cert.Cert1 = append(cert.Cert1, signedJoinAck(t, n, tau, rho))
		cert.Cert2 = append(cert.Cert2, signedJoinCommit(t, n, tau, rho, 3))
	}

	for _, n := range nodes {
		n.RegisterPVSSKey(candidate.Epoch, targetKeys[n.ID].Private)
	}
	for _, n := range nodes {
		n.mu.Lock()
		n.State.RmMark["n0"] = 3
		n.mu.Unlock()
		if err := n.InstallJoinCertificate(cert); err != nil {
			t.Fatal(err)
		}
		n.mu.Lock()
		joined := contains(n.State.Members, "theta")
		version := n.State.ConfigVersion
		lockedFrom := n.lockedFrom
		n.mu.Unlock()
		if joined || version != 0 || lockedFrom != 0 {
			t.Fatalf("stale join installed on %s: joined=%t version=%d lockedFrom=%d", n.ID, joined, version, lockedFrom)
		}
	}
}

func TestPendingJoinClearsLockWhenConfigurationChanges(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	oldMembers := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	targetMembers := append(append([]p2p.NodeID(nil), oldMembers...), "theta")
	candidate, targetKeys, err := crypto.Setup("join-stale-config-change", 2, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewScheme("theta", targetKeys["theta"].Private, candidate)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := joinerScheme.Share("theta", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   0,
		ContextEpoch:    0,
		Joiner:          "theta",
		PublicKey:       "theta-pk",
		CandidateParams: crypto.WrapPVSSParams(candidate),
		Object:          Object{ConfigVersion: 1, Producer: "theta", Seq: 1, Commitment: c},
		FirstCoinEpoch:  1,
		ActivationEpoch: 3,
	}
	rho := JoinDigest(req)
	tau := TransitionIndex{ConfigVersion: 0, Seq: 1}
	cert := JoinCertificate{Request: req}
	for _, n := range nodes[:3] {
		cert.Cert1 = append(cert.Cert1, signedJoinAck(t, n, tau, rho))
		cert.Cert2 = append(cert.Cert2, signedJoinCommit(t, n, tau, rho, 3))
	}

	node := nodes[0]
	node.RegisterPVSSKey(candidate.Epoch, targetKeys[node.ID].Private)
	if err := node.InstallJoinCertificate(cert); err != nil {
		t.Fatal(err)
	}
	node.mu.Lock()
	if node.lockedFrom != 3 {
		t.Fatalf("future join did not lock activation: lockedFrom=%d", node.lockedFrom)
	}
	node.removeMemberLocked("n3")
	node.mu.Unlock()

	if err := node.activatePendingJoins(ctx, 3); err != nil {
		t.Fatal(err)
	}
	node.mu.Lock()
	joined := contains(node.State.Members, "theta")
	version := node.State.ConfigVersion
	lockedFrom := node.lockedFrom
	node.mu.Unlock()
	if joined || version != 1 || lockedFrom != 0 {
		t.Fatalf("stale pending join not cleared: joined=%t version=%d lockedFrom=%d", joined, version, lockedFrom)
	}
}

func TestCoinBarrierIgnoresCurrentABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	current := aba.EpochInstance(1, "n0")
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
	inst := aba.EpochInstance(1, "n0")
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

func TestJoinABAFeedsCoinFromConfiguredBeaconEpoch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	inst := aba.JoinInstance("0/1", "rho", 2)
	for _, node := range nodes {
		if err := node.ABA.Propose(ctx, inst, false); err != nil {
			t.Fatal(err)
		}
	}
	waitABAStatus(t, ctx, nodes[0], inst, func(st aba.Status) bool { return st.CoinWait })

	st := nodes[0].ABA.Status(inst)
	seed := []byte("join-certified-beacon-seed")
	for i := 0; aba.CoinFromSeed(inst, st.Round, seed); i++ {
		seed = []byte("join-certified-beacon-seed-" + strconv.Itoa(i))
	}
	target := uint64(2) + st.Round
	nodes[0].mu.Lock()
	nodes[0].beaconSeeds[target] = seed
	nodes[0].mu.Unlock()

	nodes[0].handleCoinRequest(aba.CoinRequest{Instance: inst, Round: st.Round})
	waitABAStatus(t, ctx, nodes[0], inst, func(st aba.Status) bool { return st.Decided && !st.Value })
}

func TestBeaconIndexUsesFullRandomValue(t *testing.T) {
	if got := beaconIndex([]byte{1, 0}, 257); got != 256 {
		t.Fatalf("beaconIndex used only a suffix byte: got=%d", got)
	}
}

func TestMarkedSelectedSourceRemovedAtMarkedSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	node := nodes[0]

	node.mu.Lock()
	node.State.RSQ = []p2p.NodeID{"n2", "n3"}
	node.State.SCL = []p2p.NodeID{"n0", "n1"}
	node.State.RmMark["n0"] = 2
	node.State.ComQ["n0"][1] = Object{Producer: "n0", Seq: 1}
	node.State.Seqs["n0"] = 1
	state := node.certifiedStateDigestForBeaconLocked("n0", 2)
	node.installCertifiedStateLocked(state)
	members := append([]p2p.NodeID(nil), node.State.Members...)
	scl := append([]p2p.NodeID(nil), node.State.SCL...)
	rsq := append([]p2p.NodeID(nil), node.State.RSQ...)
	_, hasComQ := node.State.ComQ["n0"]
	_, hasSeq := node.State.Seqs["n0"]
	_, hasRm := node.State.RmMark["n0"]
	f, rbcF, abaF := node.State.F, node.RBC.F, node.ABA.F
	rbcN, abaN := node.RBC.N, node.ABA.N
	node.mu.Unlock()

	if contains(members, "n0") || contains(scl, "n0") || contains(rsq, "n0") {
		t.Fatalf("marked member still present: members=%v scl=%v rsq=%v", members, scl, rsq)
	}
	if hasComQ || hasSeq || hasRm {
		t.Fatalf("marked member state not deleted: comq=%v seq=%v rm=%v", hasComQ, hasSeq, hasRm)
	}
	if f != 0 || rbcF != 0 || abaF != 0 || rbcN != 3 || abaN != 3 {
		t.Fatalf("thresholds not updated after removal: stateF=%d rbc=(%d,%d) aba=(%d,%d)", f, rbcN, rbcF, abaN, abaF)
	}
}

func TestCertifiedStateDigestIgnoresUnconsumedRemovalMarks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	left := nodes[0]
	right := nodes[1]

	for _, node := range []*Node{left, right} {
		node.mu.Lock()
		node.State.RSQ = []p2p.NodeID{"n2", "n3"}
		node.State.SCL = []p2p.NodeID{"n0", "n1"}
		node.State.ComQ["n0"][1] = Object{Producer: "n0", Seq: 1}
		node.mu.Unlock()
	}

	left.mu.Lock()
	left.State.RmMark["n2"] = 4
	leftDigest := left.certifiedStateDigestForBeaconLocked("n0", 1)
	leftHash := stateDigestHash(leftDigest)
	leftRm := leftDigest.RmMark["n2"]
	left.mu.Unlock()

	right.mu.Lock()
	rightDigest := right.certifiedStateDigestForBeaconLocked("n0", 1)
	rightHash := stateDigestHash(rightDigest)
	rightRm := rightDigest.RmMark["n2"]
	right.mu.Unlock()

	if leftHash != rightHash {
		t.Fatalf("unconsumed removal mark changed certified state hash: left=%s right=%s", leftHash, rightHash)
	}
	if leftRm != -1 || rightRm != -1 {
		t.Fatalf("unconsumed removal marks leaked into certified digest: left=%d right=%d", leftRm, rightRm)
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
		ID:                  "n0",
		Members:             ids,
		F:                   1,
		QueueLen:            1,
		LookaheadExpiration: time.Hour,
		PVSS:                s,
		Transport:           p2p.NewMemoryNetwork().NewTransport("n0", 1024),
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

func TestExplicitRemovalOnlyKeepsLookaheadABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-explicit-lookahead", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(Config{
		ID:                  "n0",
		Members:             ids,
		F:                   1,
		QueueLen:            8,
		LookaheadExpiration: time.Hour,
		ExplicitRemovalOnly: true,
		PVSS:                s,
		Transport:           p2p.NewMemoryNetwork().NewTransport("n0", 1024),
	})
	if err != nil {
		t.Fatal(err)
	}

	source, seq, instance, skip, certified, err := node.prepareEpoch(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if skip || certified {
		t.Fatalf("unexpected skip/certified flags: skip=%v certified=%v", skip, certified)
	}
	node.mu.Lock()
	_, pending := node.State.PendingABAs[instance]
	node.mu.Unlock()
	if !pending {
		t.Fatalf("explicit removal mode did not create lookahead ABA %s", instance)
	}

	node.mu.Lock()
	version := node.State.ConfigVersion
	node.State.ComQ[source][seq+1] = Object{Producer: source, Seq: seq + 1, ConfigVersion: version}
	node.mu.Unlock()

	start := time.Now()
	if certifiedBeacon, err := node.proposeEpochABAInputFromLookahead(ctx, 1, source, seq, instance, make(chan Beacon, 1)); err != nil {
		t.Fatal(err)
	} else if certifiedBeacon != nil {
		t.Fatalf("unexpected certified beacon: %+v", *certifiedBeacon)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("explicit removal mode waited for lookahead: %s", elapsed)
	}
	node.mu.Lock()
	sent := node.abaInputSent[instance]
	input, inputStored := node.abaInputs[instance]
	node.mu.Unlock()
	if !sent || !inputStored || !input {
		t.Fatalf("explicit removal mode did not propose lookahead true input: sent=%v stored=%v input=%v", sent, inputStored, input)
	}
}

func TestExplicitRemovalOnlyDropsMissingLookaheadABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-explicit-missing-lookahead", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(Config{
		ID:                  "n0",
		Members:             ids,
		F:                   1,
		QueueLen:            8,
		LookaheadExpiration: time.Millisecond,
		ExplicitRemovalOnly: true,
		PVSS:                s,
		Transport:           p2p.NewMemoryNetwork().NewTransport("n0", 1024),
	})
	if err != nil {
		t.Fatal(err)
	}

	source, seq, instance, skip, certified, err := node.prepareEpoch(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if skip || certified {
		t.Fatalf("unexpected skip/certified flags: skip=%v certified=%v", skip, certified)
	}

	start := time.Now()
	if certifiedBeacon, err := node.proposeEpochABAInputFromLookahead(ctx, 1, source, seq, instance, make(chan Beacon, 1)); err != nil {
		t.Fatal(err)
	} else if certifiedBeacon != nil {
		t.Fatalf("unexpected certified beacon: %+v", *certifiedBeacon)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("explicit removal mode waited too long for missing lookahead: %s", elapsed)
	}
	node.mu.Lock()
	_, pending := node.State.PendingABAs[instance]
	sent := node.abaInputSent[instance]
	_, inputStored := node.abaInputs[instance]
	mark := node.State.RmMark[source]
	node.mu.Unlock()
	if pending || sent || inputStored {
		t.Fatalf("missing lookahead left ABA state: pending=%v sent=%v input=%v", pending, sent, inputStored)
	}
	if mark != -1 {
		t.Fatalf("missing lookahead marked source for removal: source=%s mark=%d", source, mark)
	}
}

func TestExplicitRemovalOnlyDropsUnreadyLookaheadABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := crypto.Setup("test-explicit-unready-lookahead", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	s, err := crypto.NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewNode(Config{
		ID:                  "n0",
		Members:             ids,
		F:                   1,
		QueueLen:            8,
		LookaheadExpiration: time.Millisecond,
		ExplicitRemovalOnly: true,
		PVSS:                s,
		Transport:           p2p.NewMemoryNetwork().NewTransport("n0", 1024),
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
	if err := node.proposeEpochABAInput(ctx, instance, true); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := node.waitCurrentABAReady(ctx, instance); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("explicit removal mode waited too long for unready lookahead ABA: %s", elapsed)
	}
	node.mu.Lock()
	_, pending := node.State.PendingABAs[instance]
	_, inputStored := node.abaInputs[instance]
	node.mu.Unlock()
	if pending || inputStored {
		t.Fatalf("unready lookahead left pending ABA state: pending=%v input=%v", pending, inputStored)
	}
}

func TestExplicitRemovalOnlyDoesNotAutoRemoveMissingCurrentObject(t *testing.T) {
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
		ID:                    "n0",
		Members:               ids,
		F:                     1,
		QueueLen:              8,
		RemovalExpiration:     time.Millisecond,
		CurrentMissingRemoval: true,
		ExplicitRemovalOnly:   true,
		PVSS:                  s,
		Transport:             p2p.NewMemoryNetwork().NewTransport("n0", 1024),
	})
	if err != nil {
		t.Fatal(err)
	}

	missingCtx, cancelMissing := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelMissing()
	source := p2p.NodeID("n1")
	seq := uint64(1)
	_, _, err = node.waitObjectOrBeacon(missingCtx, 1, source, seq, aba.EpochInstance(1, source), make(chan Beacon, 1))
	if err == nil {
		t.Fatal("expected missing current object to wait for context")
	}
	node.mu.Lock()
	mark := node.State.RmMark[source]
	node.mu.Unlock()
	if mark != -1 {
		t.Fatalf("explicit removal mode auto-marked missing source %s: mark=%d", source, mark)
	}
}

func TestForceReconfigurationRemovalMarksCurrentSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	node := nodes[0]
	source := nextSource(node)

	seq, applied, err := node.ForceReconfigurationRemoval(1, source)
	if err != nil {
		t.Fatal(err)
	}
	if !applied {
		t.Fatalf("expected forced ABA false for selected source %s", source)
	}
	node.mu.Lock()
	mark := node.State.RmMark[source]
	_, pending := node.State.PendingABAs[aba.EpochInstance(1, source)]
	_, inputStored := node.abaInputs[aba.EpochInstance(1, source)]
	node.mu.Unlock()
	if mark != int64(seq) {
		t.Fatalf("removal mark mismatch: got %d want %d", mark, seq)
	}
	if pending || inputStored {
		t.Fatalf("forced removal left pending state: pending=%v input=%v", pending, inputStored)
	}
}

func TestForceReconfigurationRemovalIgnoresOtherSources(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	node := nodes[0]
	selected := nextSource(node)
	other := p2p.NodeID("")
	for _, id := range []p2p.NodeID{"n0", "n1", "n2", "n3"} {
		if id != selected {
			other = id
			break
		}
	}
	if other == "" {
		t.Fatal("missing alternate source")
	}
	if _, applied, err := node.ForceReconfigurationRemoval(1, other); err != nil {
		t.Fatal(err)
	} else if applied {
		t.Fatalf("forced removal for non-selected source %s", other)
	}
	node.mu.Lock()
	mark := node.State.RmMark[other]
	node.mu.Unlock()
	if mark != -1 {
		t.Fatalf("non-selected source was marked for removal: %s mark=%d", other, mark)
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
		ID:        "n0",
		Members:   ids,
		F:         1,
		QueueLen:  1,
		PVSS:      s,
		Transport: p2p.NewMemoryNetwork().NewTransport("n0", 1024),
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
		node, err := NewNode(Config{ID: id, Members: ids, F: 1, QueueLen: 8, RemovalExpiration: 50 * time.Millisecond, PVSS: s, Transport: net.NewTransport(id, 1024)})
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
