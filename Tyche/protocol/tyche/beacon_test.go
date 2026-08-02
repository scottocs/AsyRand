package tyche

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
	"Tyche/Tyche/protocol/rbc"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
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
	mu                sync.Mutex
	verifyObjectCount int
	verifyShareCount  int
}

func (s *countingPVSSScheme) Verify(c crypto.Commitment) bool {
	s.mu.Lock()
	s.verifyObjectCount++
	s.mu.Unlock()
	return s.PVSSScheme.Verify(c)
}

func (s *countingPVSSScheme) VerifyShare(c crypto.Commitment, sh crypto.DecryptedShare) bool {
	s.mu.Lock()
	s.verifyShareCount++
	s.mu.Unlock()
	return s.PVSSScheme.VerifyShare(c, sh)
}

func (s *countingPVSSScheme) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifyObjectCount, s.verifyShareCount
}

type blockingPVSSScheme struct {
	crypto.PVSSScheme
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingPVSSScheme) Share(dealer p2p.NodeID, seq uint64, secret kyber.Scalar) (crypto.Commitment, []byte, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.PVSSScheme.Share(dealer, seq, secret)
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
			if len(b.BeaconSigners) < 3 {
				t.Fatalf("weak beacon certificate: %+v", b.BeaconSigners)
			}
			nodes[0].mu.Lock()
			parentConfig := nodes[0].Configurations[b.QC.ConfigVersion]
			nodes[0].mu.Unlock()
			signerCount := crypto.SignedQuorumCertificateSignerCount(b.QC.Signature)
			if signerCount < parentConfig.Q {
				t.Fatalf("invalid beacon certificate quorum size: %d", signerCount)
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
	if _, _, _, _, _, err := target.prepareEpoch(1); err != nil {
		t.Fatal(err)
	}
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
		if err := target.handleRecon(ctx, holder.ID, ReconMessage{
			ConfigVersion: obj.ConfigVersion, ObjectConfigVersion: obj.ConfigVersion,
			Epoch: 1, Source: source, Seq: obj.Seq,
			ObjectID: obj.Commitment.SecretID, Share: share,
		}); err != nil {
			t.Fatal(err)
		}
	}
	_, shareCount := counter.counts()
	if shareCount != obj.Commitment.Threshold {
		t.Fatalf("VerifyShare count = %d, want threshold %d", shareCount, obj.Commitment.Threshold)
	}
}

func TestHandleReconBuffersUntilRBCDelivery(t *testing.T) {
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
	if _, _, _, _, _, err := target.prepareEpoch(1); err != nil {
		t.Fatal(err)
	}
	holder := nodes[1]
	if holder.ID == target.ID {
		holder = nodes[2]
	}
	target.mu.Lock()
	delete(target.State.ComQ[source], obj.Seq)
	certificate := target.RBCCertificates[rbcCertificateKey(obj.ConfigVersion, obj.Commitment.SecretID)]
	target.mu.Unlock()

	share, err := holder.PVSS.PreReconVerified(obj.Commitment, holder.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.handleRecon(ctx, holder.ID, ReconMessage{
		ConfigVersion: obj.ConfigVersion, ObjectConfigVersion: obj.ConfigVersion,
		Epoch: 1, Source: source, Seq: obj.Seq,
		ObjectID: obj.Commitment.SecretID, Share: share,
	}); err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	pendingBefore := target.pendingReconCount
	_, reconstructedBefore := target.recon[epochKey(1, source, obj.Seq)][holder.ID]
	target.mu.Unlock()
	if pendingBefore != 1 || reconstructedBefore {
		t.Fatalf("missing-object recon was not buffered: pending=%d reconstructed=%v", pendingBefore, reconstructedBefore)
	}

	raw, err := json.Marshal(envelope{Kind: "object", Object: &obj})
	if err != nil {
		t.Fatal(err)
	}
	delivery := rbc.Delivery{
		ConfigVersion: obj.ConfigVersion,
		Purpose:       "pvss",
		Dealer:        obj.Producer,
		Seq:           obj.Seq,
		Value:         raw,
		Hash:          rbc.Digest(raw),
		Certificate:   certificate,
	}
	if err := target.handleRBCDelivery(ctx, delivery); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, ctx, func() bool {
		target.mu.Lock()
		defer target.mu.Unlock()
		_, stored := target.State.ComQ[source][obj.Seq]
		_, replayed := target.recon[epochKey(1, source, obj.Seq)][holder.ID]
		return stored && replayed && target.pendingReconCount == 0
	})
}

func TestPendingReconIsBoundedAndDeduplicated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	target := nodes[0]
	target.mu.Lock()
	version := target.State.ConfigVersion
	epoch := target.State.Epoch + 1
	target.mu.Unlock()
	source, seq, _, _, _, err := target.prepareEpoch(epoch)
	if err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	members := append([]p2p.NodeID(nil), target.State.Members...)
	target.mu.Unlock()

	for _, from := range members {
		objectID := "pending-" + string(source) + "-" + string(from)
		body := ReconMessage{
			ConfigVersion:       version,
			ObjectConfigVersion: version,
			Epoch:               epoch,
			Source:              source,
			Seq:                 seq,
			ObjectID:            objectID,
			Share: crypto.DecryptedShare{
				CommitmentID: objectID,
				Holder:       from,
			},
		}
		if err := target.handleRecon(ctx, from, body); err != nil {
			t.Fatal(err)
		}
		body.ObjectID += "-conflict"
		body.Share.CommitmentID = body.ObjectID
		if err := target.handleRecon(ctx, from, body); err != nil {
			t.Fatal(err)
		}
	}
	target.mu.Lock()
	defer target.mu.Unlock()
	want := len(members)
	if target.pendingReconCount != want {
		t.Fatalf("pending recon count=%d, want hard bound %d", target.pendingReconCount, want)
	}
	if len(target.pendingRecon) != 1 {
		t.Fatalf("pending recon buckets=%d, want 1", len(target.pendingRecon))
	}
}

func TestPendingReconClearsAcrossConfigurationReset(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	target := nodes[0]
	target.mu.Lock()
	version := target.State.ConfigVersion
	epoch := target.State.Epoch + 1
	// Open the immutable Step-0 context before accepting reconstruction events.
	from := target.State.Members[1]
	target.mu.Unlock()
	source, seq, _, _, _, err := target.prepareEpoch(epoch)
	if err != nil {
		t.Fatal(err)
	}
	body := ReconMessage{
		ConfigVersion:       version,
		ObjectConfigVersion: version,
		Epoch:               epoch,
		Source:              source,
		Seq:                 seq,
		ObjectID:            "pending-reset",
		Share: crypto.DecryptedShare{
			CommitmentID: "pending-reset",
			Holder:       from,
		},
	}
	if err := target.handleRecon(ctx, from, body); err != nil {
		t.Fatal(err)
	}
	target.mu.Lock()
	if target.pendingReconCount != 1 {
		target.mu.Unlock()
		t.Fatalf("pending recon count=%d, want 1 before reset", target.pendingReconCount)
	}
	target.resetCurrentConfigurationCachesLocked()
	count := target.pendingReconCount
	buckets := len(target.pendingRecon)
	target.mu.Unlock()
	if count != 0 || buckets != 0 {
		t.Fatalf("pending recon survived configuration reset: count=%d buckets=%d", count, buckets)
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
	window := producer.producerOccupancyLocked()
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

func TestProducerReservationOccupiesCapacityBeforeRBCCertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	node := newTestNodes(t, ctx)[0]
	blocking := &blockingPVSSScheme{
		PVSSScheme: node.PVSS,
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	node.PVSS = blocking
	node.producerHigh = 1
	node.producerLow = 1

	done := make(chan error, 1)
	go func() {
		_, err := node.Produce(ctx)
		done <- err
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	node.mu.Lock()
	occupancy := node.producerOccupancyLocked()
	stored := node.outstandingQueueDepthLocked(node.ID)
	node.mu.Unlock()
	if occupancy != 1 || stored != 0 {
		t.Fatalf("in-flight occupancy=%d stored=%d, want 1 and 0", occupancy, stored)
	}
	if _, err := node.Produce(ctx); err == nil {
		t.Fatal("expected in-flight, uncertified object to occupy producer capacity")
	}
	close(blocking.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPVSSObjectAndShareVerificationAreSingleFlight(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodes := newTestNodes(t, ctx)
	target := nodes[0]
	commitment, _, err := target.PVSS.Share(target.ID, 500, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj := Object{
		ConfigVersion: target.State.ConfigVersion,
		Producer:      target.ID,
		Seq:           500,
		Commitment:    commitment,
	}
	counter := &countingPVSSScheme{PVSSScheme: target.PVSS}

	const copies = 16
	var wg sync.WaitGroup
	errs := make(chan error, copies)
	for i := 0; i < copies; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- target.verifyObjectOnce(obj, counter)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	share, err := nodes[1].PVSS.PreReconVerified(commitment, nodes[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	shareErrs := make(chan error, copies)
	for i := 0; i < copies; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !target.verifyShareOnce(obj, share, counter) {
				shareErrs <- errors.New("valid share rejected")
			}
		}()
	}
	wg.Wait()
	close(shareErrs)
	for err := range shareErrs {
		t.Fatal(err)
	}
	objectCount, shareCount := counter.counts()
	if objectCount != 1 || shareCount != 1 {
		t.Fatalf("verification counts object=%d share=%d, want 1 and 1", objectCount, shareCount)
	}
}

func TestLookForwardExpirationRequiresDistinctProducers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	node := newTestNodes(t, ctx)[0]
	members := append([]p2p.NodeID(nil), node.State.Members...)
	target := members[0]
	node.mu.Lock()
	node.State.ComQ[target][1] = Object{Producer: target, Seq: 1}
	for seq := uint64(1); seq <= 3; seq++ {
		node.State.ComQ[members[1]][seq] = Object{Producer: members[1], Seq: seq}
	}
	if node.lookForwardExpiredLocked(target, 2) {
		node.mu.Unlock()
		t.Fatal("objects from one producer must not satisfy the distinct-producer rule")
	}
	node.State.ComQ[members[2]][1] = Object{Producer: members[2], Seq: 1}
	if node.lookForwardExpiredLocked(target, 2) {
		node.mu.Unlock()
		t.Fatal("the current target plus two progressing producers must not satisfy 2f+1")
	}
	node.State.ComQ[members[3]][1] = Object{Producer: members[3], Seq: 1}
	expired := node.lookForwardExpiredLocked(target, 2)
	node.mu.Unlock()
	if !expired {
		t.Fatal("three distinct progressing producers should satisfy look-forward expiration")
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

func TestCoinBarrierIgnoresCurrentABA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	nodes[0].mu.Lock()
	nodes[0].State.PendingABAs[1] = &PendingABA{ConfigVersion: 0, Epoch: 1, Source: "n0", Seq: 1}
	nodes[0].mu.Unlock()

	if err := nodes[0].waitCoinBarrier(ctx, 1); err != nil {
		t.Fatal(err)
	}
}

func TestCoinBarrierFeedsLateCoinRequestFromCertifiedBeacon(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodes := newTestNodes(t, ctx)
	inst := aba.EpochInstanceFor(0, 1)
	nodes[0].mu.Lock()
	nodes[0].State.PendingABAs[1] = &PendingABA{ConfigVersion: 0, Epoch: 1, Source: "n0", Seq: 1}
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

	if err := nodes[0].waitCoinBarrier(ctx, 2); err != nil {
		t.Fatal(err)
	}
	nodes[0].mu.Lock()
	_, pending := nodes[0].State.PendingABAs[1]
	rm := nodes[0].State.RmMark["n0"]
	nodes[0].mu.Unlock()
	if pending || rm.Seq != 2 {
		t.Fatalf("cached seed did not advance pending ABA to sequence marker: pending=%v rm=%+v", pending, rm)
	}
}

func TestRemovalInstallsDirectlyFromABACertificate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nodes := newTestNodes(t, ctx)
	inst := aba.EpochInstanceFor(0, 1)
	for _, node := range nodes {
		node.mu.Lock()
		node.State.PendingABAs[1] = &PendingABA{
			ConfigVersion: 0, Epoch: 1, Source: "n0", Seq: 1,
		}
		node.mu.Unlock()
		if err := node.ABA.Propose(ctx, inst, false); err != nil {
			t.Fatal(err)
		}
	}
	waitABAStatus(t, ctx, nodes[0], inst, func(st aba.Status) bool { return st.CoinWait })
	round := nodes[0].ABA.Status(inst).Round
	seed := []byte("remove-coin")
	for aba.CoinFromSeed(inst, round, seed) {
		seed = append(seed, byte(len(seed)))
	}
	for _, node := range nodes {
		node.mu.Lock()
		node.beaconSeeds[1+round+1] = append([]byte(nil), seed...)
		node.mu.Unlock()
		node.ABA.FeedSeed(ctx, inst, round, seed)
	}
	waitUntil(t, ctx, func() bool {
		for _, node := range nodes {
			node.mu.Lock()
			mark, ok := node.State.RmMark["n0"]
			node.mu.Unlock()
			if !ok || mark.Seq != 2 || mark.Certificate.Value {
				return false
			}
		}
		return true
	})
	for _, node := range nodes {
		node.mu.Lock()
		node.Schedule.Seqs["n0"] = 1
		node.State.Seqs["n0"] = 1
		node.mu.Unlock()
	}
	results := make(chan error, len(nodes))
	for _, node := range nodes {
		go func(node *Node) { results <- node.runCertifiedRemoval(ctx, "n0") }(node)
	}
	for range nodes {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range nodes {
		node.mu.Lock()
		removed := !contains(node.State.Members, "n0") && node.State.ConfigVersion == 1
		node.mu.Unlock()
		if !removed {
			t.Fatalf("node %s did not install ABA-certified removal", node.ID)
		}
	}
}

func TestBeaconIndexUsesFullRandomValue(t *testing.T) {
	if got := beaconIndex([]byte{1, 0}, 257); got != 256 {
		t.Fatalf("beaconIndex used only a suffix byte: got=%d", got)
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
	_, _, err = node.waitObjectOrBeacon(missingCtx, 1, source, seq, aba.EpochInstanceFor(0, 1), make(chan Beacon, 1))
	if err == nil {
		t.Fatal("expected missing current object to wait for context")
	}
	node.mu.Lock()
	_, marked := node.State.RmMark[source]
	node.mu.Unlock()
	if marked {
		t.Fatalf("missing object auto-marked source without ABA evidence %s", source)
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
