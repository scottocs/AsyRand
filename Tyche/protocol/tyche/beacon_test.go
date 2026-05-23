package tyche

import (
	"bytes"
	"context"
	"encoding/hex"
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
			msg := readyVoteBytes(b.Epoch, b.Source, b.Seq, hex.EncodeToString(b.Random))
			if err := crypto.VerifyBLSAggregate(b.Signature, nodes[0].BLSPublic, msg, 3); err != nil {
				t.Fatalf("invalid ready aggregate certificate: %v", err)
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for certified beacon\n%s", dumpNodes(nodes))
		}
	}
	if first.Epoch != 1 || first.Source != source || first.Seq != 1 {
		t.Fatalf("bad beacon tuple: %+v", first)
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
		BLSPublicKey:    defaultBLSPublicHex("theta"),
		CandidateParams: candidate,
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
		if err := n.InstallJoinCertificate(cert); err != nil {
			t.Fatal(err)
		}
		if !contains(n.State.Members, "theta") || !contains(n.State.SCL, "theta") || n.State.ComQ["theta"][1].Producer != "theta" || n.State.ConfigVersion != 1 {
			t.Fatalf("join not installed on %s: %+v", n.ID, n.State)
		}
		if n.State.Seqs["theta"] != 0 || n.State.RmMark["theta"] != -1 {
			t.Fatalf("joiner state not initialized on %s: seq=%d rm=%d", n.ID, n.State.Seqs["theta"], n.State.RmMark["theta"])
		}
		if n.BLSPublic["theta"] == nil {
			t.Fatalf("joiner bls public key not installed on %s", n.ID)
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
		BLSPublicKey:    defaultBLSPublicHex("theta"),
		CandidateParams: candidate,
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
		BLSPublicKey:    defaultBLSPublicHex("theta"),
		CandidateParams: candidate,
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
		BLSPublicKey:    defaultBLSPublicHex("theta"),
		CandidateParams: candidate,
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
	nodes[0].beaconSeeds[1+st.Round] = seed
	nodes[0].mu.Unlock()

	if err := nodes[0].waitCoinBarrier(ctx, "other"); err != nil {
		t.Fatal(err)
	}
	nodes[0].mu.Lock()
	_, pending := nodes[0].State.PendingABAs[inst]
	rm := nodes[0].State.RmMark["n0"]
	nodes[0].mu.Unlock()
	if pending || rm == -1 {
		t.Fatalf("cached seed did not advance pending ABA to removal marker: pending=%v rm=%d", pending, rm)
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

func TestMarkedSourceRemovedWhenRSQExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	node := nodes[0]

	node.mu.Lock()
	node.State.RSQ = []p2p.NodeID{"n0"}
	node.State.SCL = []p2p.NodeID{"n0", "n1", "n2", "n3"}
	node.State.RmMark["n0"] = 2
	node.State.ComQ["n0"][1] = Object{Producer: "n0", Seq: 1}
	node.State.Seqs["n0"] = 1
	node.rotateSourcesLocked(2, "n1", 1)
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
