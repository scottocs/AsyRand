package tyche

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/Tyche/protocol/aba"
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

func TestBeaconChurnCrashAndJoin10000Epochs(t *testing.T) {
	if os.Getenv("TYCHE_CHURN_TEST") != "1" {
		t.Skip("set TYCHE_CHURN_TEST=1 to run the 8-node/f=2 crash-and-join churn test")
	}
	epochs := envInt("TYCHE_CHURN_EPOCHS", 10000)
	reportEvery := envInt("TYCHE_CHURN_REPORT_EVERY", 1000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(epochs)*2*time.Second)
	defer cancel()

	cluster := newChurnCluster(t, ctx, 8, 2)
	failures := map[int]p2p.NodeID{
		max(2, epochs/4): "node6",
		max(3, epochs/2): "node7",
	}
	joins := map[int]p2p.NodeID{
		max(2, epochs/4) + 1: "node8",
		max(3, epochs/2) + 1: "node9",
	}

	start := time.Now()
	for epoch := 1; epoch <= epochs; epoch++ {
		if failed := failures[epoch]; failed != "" {
			t.Logf("epoch=%d event=delete node=%s active_before=%v members_before=%v", epoch, failed, cluster.activeIDs(), cluster.members())
			cluster.crashAndRemove(t, failed)
			t.Logf("epoch=%d event=deleted node=%s active_after=%v members_after=%v", epoch, failed, cluster.activeIDs(), cluster.members())
		}
		if joiner := joins[epoch]; joiner != "" {
			t.Logf("epoch=%d event=join node=%s active_before=%v members_before=%v", epoch, joiner, cluster.activeIDs(), cluster.members())
			cluster.join(t, ctx, joiner)
			t.Logf("epoch=%d event=joined node=%s active_after=%v members_after=%v", epoch, joiner, cluster.activeIDs(), cluster.members())
		}
		cluster.runEpoch(t, ctx, uint64(epoch), 10*time.Second)
		if reportEvery > 0 && epoch%reportEvery == 0 {
			t.Logf("completed %d/%d churn epochs in %s active=%v members=%v", epoch, epochs, time.Since(start), cluster.activeIDs(), cluster.members())
		}
	}
}

func TestBeaconRandomChurn1000Epochs(t *testing.T) {
	if os.Getenv("TYCHE_RANDOM_CHURN_TEST") != "1" {
		t.Skip("set TYCHE_RANDOM_CHURN_TEST=1 to run the random crash-and-join churn test")
	}
	epochs := envInt("TYCHE_CHURN_EPOCHS", 1000)
	reportEvery := envInt("TYCHE_CHURN_REPORT_EVERY", 100)
	eventEvery := envInt("TYCHE_CHURN_EVENT_EVERY", 10)
	epochTimeout := time.Duration(envInt("TYCHE_CHURN_EPOCH_TIMEOUT_MS", 10000)) * time.Millisecond
	minN := envInt("TYCHE_CHURN_MIN_N", 4)
	maxN := envInt("TYCHE_CHURN_MAX_N", 13)
	seed := int64(envInt("TYCHE_CHURN_SEED", 20260521))
	rng := rand.New(rand.NewSource(seed))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(epochs)*2*time.Second)
	defer cancel()

	cluster := newChurnCluster(t, ctx, 8, 2)
	nextJoin := 8
	start := time.Now()
	t.Logf("random churn seed=%d epochs=%d initial_n=8 min_n=%d max_n=%d event_every=%d", seed, epochs, minN, maxN, eventEvery)
	for epoch := 1; epoch <= epochs; epoch++ {
		if eventEvery > 0 && epoch%eventEvery == 0 {
			if cluster.randomChurn(t, ctx, rng, uint64(epoch), minN, maxN, &nextJoin) {
				cluster.assertMembershipBounds(t, minN, maxN)
			}
		}
		cluster.assertMembershipBounds(t, minN, maxN)
		cluster.runEpoch(t, ctx, uint64(epoch), epochTimeout)
		cluster.reconcileProtocolRemovals(t, uint64(epoch))
		if reportEvery > 0 && epoch%reportEvery == 0 {
			t.Logf("completed %d/%d random churn epochs in %s active=%v members=%v", epoch, epochs, time.Since(start), cluster.activeIDs(), cluster.members())
		}
	}
}

func TestBeaconReconfigurationBenchmark200Epochs(t *testing.T) {
	if os.Getenv("TYCHE_RECONFIG_BENCH_TEST") != "1" {
		t.Skip("set TYCHE_RECONFIG_BENCH_TEST=1 to run the reconfiguration benchmark")
	}
	epochs := envInt("TYCHE_CHURN_EPOCHS", 200)
	initialN := envInt("TYCHE_CHURN_INITIAL_N", 8)
	initialF := envInt("TYCHE_CHURN_INITIAL_F", (initialN-1)/3)
	reconfigTarget := envInt("TYCHE_CHURN_RECONFIG_EVENTS", max(1, epochs/20))
	epochTimeout := time.Duration(envInt("TYCHE_CHURN_EPOCH_TIMEOUT_MS", 10000)) * time.Millisecond
	prefill := time.Duration(envInt("TYCHE_CHURN_PREFILL_MS", 0)) * time.Millisecond
	minN := envInt("TYCHE_CHURN_MIN_N", initialN-initialF)
	maxN := envInt("TYCHE_CHURN_MAX_N", initialN+initialF)
	if maxN < initialN {
		maxN = initialN
	}
	seed := int64(envInt("TYCHE_CHURN_SEED", 20260521))

	runChurnBenchmarkCase(t, "reconfig", epochs, reconfigTarget, epochTimeout, prefill, minN, maxN, seed, initialN, initialF)
}

type churnCluster struct {
	net       *p2p.MemoryNetwork
	nodes     map[p2p.NodeID]*Node
	active    map[p2p.NodeID]bool
	stopped   map[p2p.NodeID]bool
	cancels   map[p2p.NodeID]context.CancelFunc
	pvssEpoch uint64
	pvss      string
}

type churnResult struct {
	beacon Beacon
	err    error
}

type churnBenchmarkResult struct {
	label              string
	elapsed            time.Duration
	throughputPerSec   float64
	bandwidthKBPerSec  float64
	sentMessages       uint64
	recvMessages       uint64
	sentBytes          uint64
	recvBytes          uint64
	finalN             int
	finalF             int
	reconfigurationOps int
}

func runChurnBenchmarkCase(t *testing.T, label string, epochs int, reconfigTarget int, epochTimeout time.Duration, prefill time.Duration, minN int, maxN int, seed int64, initialN int, initialF int) churnBenchmarkResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(epochs)*2*time.Second+prefill)
	defer cancel()
	cluster := newChurnCluster(t, ctx, initialN, initialF)
	rng := rand.New(rand.NewSource(seed))
	nextJoin := initialN
	before := aggregateMetrics(cluster.transports())
	start := time.Now()
	if prefill > 0 {
		time.Sleep(prefill)
	}
	reconfigs := 0
	for epoch := 1; epoch <= epochs; epoch++ {
		if shouldRunReconfiguration(rng, epoch, epochs, reconfigs, reconfigTarget) {
			if cluster.randomChurn(t, ctx, rng, uint64(epoch), minN, maxN, &nextJoin) {
				reconfigs++
				cluster.assertMembershipBounds(t, minN, maxN)
			}
		}
		cluster.assertMembershipBounds(t, minN, maxN)
		cluster.runEpoch(t, ctx, uint64(epoch), epochTimeout)
		cluster.reconcileProtocolRemovals(t, uint64(epoch))
	}
	elapsed := time.Since(start)
	after := aggregateMetrics(cluster.transports())
	sentMessages := after.SentMessages - before.SentMessages
	recvMessages := after.RecvMessages - before.RecvMessages
	sentBytes := after.SentBytes - before.SentBytes
	recvBytes := after.RecvBytes - before.RecvBytes
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	result := churnBenchmarkResult{
		label:              label,
		elapsed:            elapsed,
		throughputPerSec:   float64(epochs) / seconds,
		bandwidthKBPerSec:  float64(sentBytes+recvBytes) / 1024 / seconds,
		sentMessages:       sentMessages,
		recvMessages:       recvMessages,
		sentBytes:          sentBytes,
		recvBytes:          recvBytes,
		finalN:             len(cluster.members()),
		finalF:             cluster.currentF(t),
		reconfigurationOps: reconfigs,
	}
	t.Logf("bench_result label=%s epochs=%d elapsed=%s throughput=%.4f/s bandwidth=%.2fKB/s sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB final_n=%d final_f=%d reconfig_ops=%d",
		result.label,
		epochs,
		result.elapsed,
		result.throughputPerSec,
		result.bandwidthKBPerSec,
		result.sentMessages,
		result.recvMessages,
		float64(result.sentBytes)/1024,
		float64(result.recvBytes)/1024,
		result.finalN,
		result.finalF,
		result.reconfigurationOps,
	)
	t.Logf("final metrics label=%s beacons=%d throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s final_n=%d final_f=%d reconfig_ops=%d",
		result.label,
		epochs,
		result.throughputPerSec*60,
		result.sentMessages,
		result.recvMessages,
		float64(result.sentBytes)/1024,
		float64(result.recvBytes)/1024,
		result.bandwidthKBPerSec,
		result.finalN,
		result.finalF,
		result.reconfigurationOps,
	)
	return result
}

func shouldRunReconfiguration(rng *rand.Rand, epoch int, epochs int, completed int, target int) bool {
	if target <= 0 || completed >= target || epochs <= 0 {
		return false
	}
	remainingEpochs := epochs - epoch + 1
	remainingEvents := target - completed
	if remainingEvents >= remainingEpochs {
		return true
	}
	return rng.Float64() < float64(remainingEvents)/float64(remainingEpochs)
}

func newChurnCluster(t *testing.T, parent context.Context, n int, f int) *churnCluster {
	t.Helper()
	ids := make([]p2p.NodeID, n)
	for i := range ids {
		ids[i] = p2p.NodeID(fmt.Sprintf("node%d", i))
	}
	pvss := os.Getenv("TYCHE_CHURN_PVSS")
	if pvss == "" {
		pvss = crypto.PVSSO1
	}
	pp, keys, err := crypto.SetupPVSS(pvss, "churn-config-0", f+1, ids)
	if err != nil {
		t.Fatal(err)
	}
	c := &churnCluster{
		net:     p2p.NewMemoryNetwork(),
		nodes:   make(map[p2p.NodeID]*Node, n),
		active:  make(map[p2p.NodeID]bool, n),
		stopped: make(map[p2p.NodeID]bool, n),
		cancels: make(map[p2p.NodeID]context.CancelFunc, n),
		pvss:    pvss,
	}
	blsPublic := defaultBLSPublic(ids)
	for _, id := range ids {
		scheme, err := crypto.NewPVSSScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(Config{ID: id, Members: ids, F: f, QueueLen: n + 64, PVSS: scheme, PVSSBackend: pvss, BLSPublic: blsPublic, Transport: c.net.NewTransport(id, 32768)})
		if err != nil {
			t.Fatal(err)
		}
		nodeCtx, cancel := context.WithCancel(parent)
		node.Start(nodeCtx)
		c.nodes[id] = node
		c.active[id] = true
		c.cancels[id] = cancel
	}
	return c
}

func (c *churnCluster) crashAndRemove(t *testing.T, id p2p.NodeID) {
	t.Helper()
	if !c.active[id] {
		return
	}
	c.active[id] = false
	c.cancels[id]()
	if err := c.nodes[id].Transport.Close(); err != nil {
		t.Fatal(err)
	}
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		node.removeMemberLocked(id)
		node.mu.Unlock()
	}
}

func (c *churnCluster) reconcileProtocolRemovals(t *testing.T, epoch uint64) {
	t.Helper()
	for _, id := range c.stoppedActiveIDs() {
		if !c.protocolRemovedByAnyActiveNode(id) {
			continue
		}
		beforeActive := c.activeIDs()
		c.closeProtocolRemovedNode(t, id)
		members := c.members()
		t.Logf("epoch=%d event=aba_deleted node=%s n_after=%d f_after=%d stopped=%v active_before=%v members_after=%v", epoch, id, len(members), c.currentF(t), c.stoppedActiveIDs(), beforeActive, members)
		c.active[id] = false
		delete(c.stopped, id)
		if cancel := c.cancels[id]; cancel != nil {
			cancel()
		}
		if node := c.nodes[id]; node != nil {
			if err := node.Transport.Close(); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("epoch=%d event=aba_delete_closed node=%s active_after=%v members_after=%v", epoch, id, c.activeIDs(), members)
	}
}

func (c *churnCluster) protocolRemovedByAnyActiveNode(id p2p.NodeID) bool {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		removed := !contains(node.State.Members, id)
		node.mu.Unlock()
		if removed {
			return true
		}
	}
	return false
}

func (c *churnCluster) closeProtocolRemovedNode(t *testing.T, id p2p.NodeID) {
	t.Helper()
	ref := c.protocolRemovedReference(id)
	if ref == nil {
		t.Fatalf("no certified removal state for %s", id)
	}
	for _, node := range c.activeNodes() {
		if node.ID == id {
			continue
		}
		if node != ref {
			copyRuntimeState(t, ref, node)
		}
		node.mu.Lock()
		delete(node.BLSPublic, string(id))
		node.installRemovalPVSSLocked()
		node.resetConfigurationCachesLocked()
		node.mu.Unlock()
	}
}

func (c *churnCluster) protocolRemovedReference(id p2p.NodeID) *Node {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		removed := !contains(node.State.Members, id)
		node.mu.Unlock()
		if removed {
			return node
		}
	}
	return nil
}

func (c *churnCluster) randomChurn(t *testing.T, parent context.Context, rng *rand.Rand, epoch uint64, minN int, maxN int, nextJoin *int) bool {
	t.Helper()
	n := len(c.members())
	pendingStop := len(c.stoppedActiveIDs()) > 0
	canDelete := n > minN && !pendingStop
	canJoin := n < maxN && !pendingStop
	if !canDelete && !canJoin {
		return false
	}
	deleteNode := canDelete && (!canJoin || rng.Intn(2) == 0)
	if deleteNode {
		ids := c.producingActiveIDs()
		victim := ids[rng.Intn(len(ids))]
		beforeMembers := c.members()
		beforeF := c.currentF(t)
		t.Logf("epoch=%d event=stop_produce node=%s n_before=%d f_before=%d active_before=%v members_before=%v", epoch, victim, len(beforeMembers), beforeF, c.activeIDs(), beforeMembers)
		c.stopProducer(victim)
		afterMembers := c.members()
		t.Logf("epoch=%d event=stopped_produce node=%s n_after=%d f_after=%d stopped=%v active_after=%v members_after=%v", epoch, victim, len(afterMembers), c.currentF(t), c.stoppedActiveIDs(), c.activeIDs(), afterMembers)
		return true
	}
	joiner := p2p.NodeID(fmt.Sprintf("node%d", *nextJoin))
	(*nextJoin)++
	beforeMembers := c.members()
	beforeF := c.currentF(t)
	t.Logf("epoch=%d event=join node=%s n_before=%d f_before=%d active_before=%v members_before=%v", epoch, joiner, len(beforeMembers), beforeF, c.activeIDs(), beforeMembers)
	joined := c.join(t, parent, joiner)
	afterMembers := c.members()
	if !joined {
		t.Logf("epoch=%d event=join_stale node=%s n_after=%d f_after=%d active_after=%v members_after=%v", epoch, joiner, len(afterMembers), c.currentF(t), c.activeIDs(), afterMembers)
		return true
	}
	t.Logf("epoch=%d event=joined node=%s n_after=%d f_after=%d active_after=%v members_after=%v", epoch, joiner, len(afterMembers), c.currentF(t), c.activeIDs(), afterMembers)
	return true
}

func (c *churnCluster) stopProducer(id p2p.NodeID) {
	if c.active[id] {
		c.stopped[id] = true
		c.nodes[id].SetProducing(false)
	}
}

func (c *churnCluster) assertMembershipBounds(t *testing.T, minN int, maxN int) {
	t.Helper()
	refMembers := c.members()
	n := len(refMembers)
	if n < minN || n > maxN {
		t.Fatalf("membership size out of bounds: n=%d min=%d max=%d members=%v active=%v", n, minN, maxN, refMembers, c.activeIDs())
	}
	f := c.currentF(t)
	if f >= n {
		t.Fatalf("invalid failure threshold: f=%d n=%d members=%v", f, n, refMembers)
	}
	if 3*f+1 > n {
		t.Fatalf("invalid BFT threshold: f=%d n=%d members=%v", f, n, refMembers)
	}
	active := c.activeIDs()
	if len(active) != n {
		t.Fatalf("active/member mismatch: active=%v members=%v", active, refMembers)
	}
	if !sameNodeIDs(active, refMembers) {
		t.Fatalf("active/member mismatch: active=%v members=%v", active, refMembers)
	}
	refVersion := c.currentConfigVersion(t)
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		nodeMembers := append([]p2p.NodeID(nil), node.State.Members...)
		nodeF := node.State.F
		nodeVersion := node.State.ConfigVersion
		node.mu.Unlock()
		if !sameNodeIDs(refMembers, nodeMembers) || nodeF != f {
			t.Fatalf("membership mismatch on %s: ref_members=%v ref_f=%d node_members=%v node_f=%d", node.ID, refMembers, f, nodeMembers, nodeF)
		}
		if nodeVersion != refVersion {
			t.Fatalf("config version mismatch on %s: ref=%d got=%d", node.ID, refVersion, nodeVersion)
		}
	}
}

func (c *churnCluster) currentF(t *testing.T) int {
	t.Helper()
	ref := c.reference(t)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.F
}

func (c *churnCluster) currentConfigVersion(t *testing.T) uint64 {
	t.Helper()
	ref := c.reference(t)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.ConfigVersion
}

func sameNodeIDs(a []p2p.NodeID, b []p2p.NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]p2p.NodeID(nil), a...)
	bb := append([]p2p.NodeID(nil), b...)
	sort.Slice(aa, func(i, j int) bool { return aa[i] < aa[j] })
	sort.Slice(bb, func(i, j int) bool { return bb[i] < bb[j] })
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

func (c *churnCluster) join(t *testing.T, parent context.Context, joiner p2p.NodeID) bool {
	t.Helper()
	ref := c.reference(t)
	currentMembers := c.members()
	targetMembers := append(append([]p2p.NodeID(nil), currentMembers...), joiner)
	sort.Slice(targetMembers, func(i, j int) bool { return targetMembers[i] < targetMembers[j] })
	ref.mu.Lock()
	version := ref.State.ConfigVersion
	activation := ref.State.Epoch + 1
	f := ref.State.F
	ref.mu.Unlock()
	targetF := (len(targetMembers) - 1) / 3

	c.pvssEpoch++
	pp, keys, err := crypto.SetupPVSS(c.pvss, fmt.Sprintf("churn-config-%d", c.pvssEpoch), targetF+1, targetMembers)
	if err != nil {
		t.Fatal(err)
	}
	joinerScheme, err := crypto.NewPVSSScheme(joiner, keys[joiner].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	commitment, _, err := joinerScheme.Share(joiner, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := JoinRequest{
		ConfigVersion:   version,
		ContextEpoch:    activation - 1,
		Joiner:          joiner,
		PublicKey:       string(joiner) + "-pk",
		BLSPublicKey:    defaultBLSPublicHex(joiner),
		CandidateParams: pp,
		Object:          Object{ConfigVersion: version + 1, Producer: joiner, Seq: 1, Commitment: commitment},
		FirstCoinEpoch:  activation - 1,
		ActivationEpoch: activation,
	}
	rho := JoinDigest(req)
	tau := TransitionIndex{ConfigVersion: version, Seq: 1}
	signers := c.activeIDs()
	need := 2*f + 1
	if len(signers) < need {
		t.Fatalf("not enough active signers for join: active=%v need=%d", signers, need)
	}
	cert := JoinCertificate{Request: req}
	for _, signer := range signers[:need] {
		cert.Cert1 = append(cert.Cert1, signedJoinAck(t, c.nodes[signer], tau, rho))
		cert.Cert2 = append(cert.Cert2, signedJoinCommit(t, c.nodes[signer], tau, rho, activation))
	}
	for _, node := range c.activeNodes() {
		node.RegisterPVSSKey(pp.Epoch(), keys[node.ID].Private)
		if err := node.InstallJoinCertificate(cert); err != nil {
			t.Fatal(err)
		}
	}
	if !contains(c.members(), joiner) {
		return false
	}
	c.installPVSS(t, pp, keys, targetMembers)
	c.addJoinerNode(t, parent, joiner, targetMembers, pp, keys)
	return true
}

func (c *churnCluster) installPVSS(t *testing.T, pp crypto.PVSSParams, keys map[p2p.NodeID]crypto.KeyPair, members []p2p.NodeID) {
	t.Helper()
	blsPublic := defaultBLSPublic(members)
	for _, node := range c.activeNodes() {
		scheme, err := crypto.NewPVSSScheme(node.ID, keys[node.ID].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		node.mu.Lock()
		node.PVSS = scheme
		node.BLSPublic = cloneBLSPublic(blsPublic)
		node.mu.Unlock()
	}
}

func (c *churnCluster) addJoinerNode(t *testing.T, parent context.Context, id p2p.NodeID, members []p2p.NodeID, pp crypto.PVSSParams, keys map[p2p.NodeID]crypto.KeyPair) {
	t.Helper()
	scheme, err := crypto.NewPVSSScheme(id, keys[id].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	ref := c.reference(t)
	ref.mu.Lock()
	f := ref.State.F
	ref.mu.Unlock()
	node, err := NewNode(Config{ID: id, Members: members, F: f, QueueLen: len(members) + 64, PVSS: scheme, PVSSBackend: c.pvss, BLSPublic: defaultBLSPublic(members), Transport: c.net.NewTransport(id, 32768)})
	if err != nil {
		t.Fatal(err)
	}
	copyRuntimeState(t, ref, node)
	nodeCtx, cancel := context.WithCancel(parent)
	node.Start(nodeCtx)
	c.nodes[id] = node
	c.active[id] = true
	c.cancels[id] = cancel
}

func (c *churnCluster) runEpoch(t *testing.T, parent context.Context, epoch uint64, timeout time.Duration) {
	t.Helper()
	c.refillCandidateLists()
	source, seq := nextSourceSeq(c.reference(t))
	removingStoppedSource := c.stopped[source] && c.isMarkedForRemovalAt(source, seq)
	sourceNode := c.nodes[source]
	if sourceNode == nil || !c.active[source] {
		t.Fatalf("selected inactive source %s at epoch %d active=%v members=%v", source, epoch, c.activeIDs(), c.members())
	}
	if c.stopped[source] && !c.isMarkedForRemoval(source) {
		c.applyABAFalse(t, parent, epoch, source, seq)
	}
	c.ensureStored(t, parent, sourceNode, source, seq, epoch)
	c.waitStoredCurrent(t, parent, source, seq)
	if !c.stopped[source] {
		c.ensureStored(t, parent, sourceNode, source, seq+1, epoch)
		c.waitStoredCurrent(t, parent, source, seq+1)
	}

	epochCtx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	active := c.activeNodes()
	required := active
	if removingStoppedSource {
		required = make([]*Node, 0, len(active)-1)
		for _, node := range active {
			if node.ID != source {
				required = append(required, node)
			}
		}
	}
	results := make(chan churnResult, len(required))
	for _, node := range required {
		go func(node *Node) {
			beacon, err := node.RunEpochAt(epochCtx, epoch)
			results <- churnResult{beacon: beacon, err: err}
		}(node)
	}
	var first Beacon
	received := 0
	for received < len(required) {
		select {
		case res := <-results:
			if res.err != nil {
				t.Fatalf("epoch %d failed: %v\n%s", epoch, res.err, dumpNodes(active))
			}
			if received == 0 {
				first = res.beacon
				received++
				continue
			}
			if !bytes.Equal(first.Random, res.beacon.Random) || first.Source != res.beacon.Source || first.Seq != res.beacon.Seq {
				t.Fatalf("epoch %d beacon mismatch: first=%+v got=%+v", epoch, first, res.beacon)
			}
			received++
		case <-time.After(10 * time.Millisecond):
			if removingStoppedSource && c.protocolRemovedByAnyActiveNode(source) {
				return
			}
		case <-epochCtx.Done():
			t.Fatalf("epoch %d timed out\n%s", epoch, dumpNodes(active))
		}
	}
}

func (c *churnCluster) isMarkedForRemoval(id p2p.NodeID) bool {
	ref := c.reference(nil)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.RmMark[id] != -1
}

func (c *churnCluster) isMarkedForRemovalAt(id p2p.NodeID, seq uint64) bool {
	ref := c.reference(nil)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return ref.State.RmMark[id] != -1 && uint64(ref.State.RmMark[id]) == seq
}

func (c *churnCluster) refillCandidateLists() {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		if len(node.State.SCL) == 0 {
			node.refillSCLLocked()
		}
		node.mu.Unlock()
	}
}

func (c *churnCluster) applyABAFalse(t *testing.T, ctx context.Context, epoch uint64, source p2p.NodeID, seq uint64) {
	t.Helper()
	instance := aba.EpochInstance(epoch, source)
	t.Logf("epoch=%d event=aba_false node=%s seq=%d stopped=%v active=%v members=%v", epoch, source, seq, c.stoppedActiveIDs(), c.activeIDs(), c.members())
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		if node.State.PendingABAs[instance] == nil {
			node.State.PendingABAs[instance] = &PendingABA{Instance: instance, Epoch: epoch, Source: source, Seq: seq}
		}
		node.mu.Unlock()
		_ = node.ABA.Propose(ctx, instance, false)
		node.handleABADecision(ctx, aba.Decision{Instance: instance, Value: false})
	}
}

func (c *churnCluster) ensureStored(t *testing.T, ctx context.Context, producer *Node, source p2p.NodeID, seq uint64, epoch uint64) {
	t.Helper()
	if c.allActiveStored(source, seq) {
		return
	}
	if c.copyStoredObjectToMissing(source, seq) && c.allActiveStored(source, seq) {
		return
	}
	producer.mu.Lock()
	version := producer.State.ConfigVersion
	if producer.State.ProducerSeq < seq {
		producer.State.ProducerSeq = seq
	}
	producer.mu.Unlock()
	if _, err := producer.produceSeq(ctx, seq, version); err != nil {
		t.Fatalf("produce source=%s seq=%d epoch=%d: %v", source, seq, epoch, err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.copyStoredObjectToMissing(source, seq) && c.allActiveStored(source, seq) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("object source=%s seq=%d epoch=%d was not stored on all active nodes", source, seq, epoch)
		}
	}
}

func (c *churnCluster) copyStoredObjectToMissing(source p2p.NodeID, seq uint64) bool {
	var obj Object
	found := false
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		candidate, ok := node.State.ComQ[source][seq]
		version := node.State.ConfigVersion
		node.mu.Unlock()
		if ok && candidate.ConfigVersion == version {
			obj = candidate
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		if node.State.ComQ[source] == nil {
			node.State.ComQ[source] = make(map[uint64]Object)
		}
		if _, ok := node.State.ComQ[source][seq]; !ok && obj.ConfigVersion == node.State.ConfigVersion {
			node.State.ComQ[source][seq] = obj
		}
		node.mu.Unlock()
	}
	return true
}

func (c *churnCluster) allActiveStored(source p2p.NodeID, seq uint64) bool {
	for _, node := range c.activeNodes() {
		node.mu.Lock()
		obj, ok := node.State.ComQ[source][seq]
		version := node.State.ConfigVersion
		node.mu.Unlock()
		if !ok || obj.ConfigVersion != version {
			return false
		}
	}
	return true
}

func (c *churnCluster) waitStoredCurrent(t *testing.T, ctx context.Context, source p2p.NodeID, seq uint64) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.allActiveStored(source, seq) {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for current stored object %s/%d", source, seq)
		}
	}
}

func (c *churnCluster) activeNodes() []*Node {
	ids := c.activeIDs()
	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, c.nodes[id])
	}
	return nodes
}

func (c *churnCluster) transports() []p2p.Transport {
	ids := make([]p2p.NodeID, 0, len(c.nodes))
	for id := range c.nodes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	transports := make([]p2p.Transport, 0, len(ids))
	for _, id := range ids {
		if node := c.nodes[id]; node != nil && node.Transport != nil {
			transports = append(transports, node.Transport)
		}
	}
	return transports
}

func (c *churnCluster) activeIDs() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.active))
	for id, active := range c.active {
		if active {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *churnCluster) producingActiveIDs() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.active))
	for id, active := range c.active {
		if active && !c.stopped[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *churnCluster) stoppedActiveIDs() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.stopped))
	for id, stopped := range c.stopped {
		if stopped && c.active[id] {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (c *churnCluster) members() []p2p.NodeID {
	ref := c.reference(nil)
	ref.mu.Lock()
	defer ref.mu.Unlock()
	return append([]p2p.NodeID(nil), ref.State.Members...)
}

func (c *churnCluster) reference(t *testing.T) *Node {
	for _, id := range c.activeIDs() {
		if node := c.nodes[id]; node != nil {
			return node
		}
	}
	if t != nil {
		t.Fatal("no active nodes")
	}
	panic("no active nodes")
}

func copyRuntimeState(t *testing.T, src *Node, dst *Node) {
	t.Helper()
	src.mu.Lock()
	defer src.mu.Unlock()
	dst.mu.Lock()
	defer dst.mu.Unlock()
	dst.State.ConfigVersion = src.State.ConfigVersion
	dst.State.Members = append([]p2p.NodeID(nil), src.State.Members...)
	dst.State.F = src.State.F
	dst.State.Epoch = src.State.Epoch
	dst.State.RPrev = append([]byte(nil), src.State.RPrev...)
	dst.State.SCL = append([]p2p.NodeID(nil), src.State.SCL...)
	dst.State.RSQ = append([]p2p.NodeID(nil), src.State.RSQ...)
	dst.State.Seqs = copySeqs(src.State.Seqs)
	dst.State.RmMark = copyRmMark(src.State.RmMark)
	dst.State.ComQ = copyComQ(src.State.ComQ)
	dst.State.QueueLen = src.State.QueueLen
	dst.State.ProducerSeq = dst.State.Seqs[dst.ID]
	dst.RBC.N, dst.RBC.F = len(dst.State.Members), dst.State.F
	dst.ABA.N, dst.ABA.F = len(dst.State.Members), dst.State.F
	for epoch, seed := range src.beaconSeeds {
		dst.beaconSeeds[epoch] = append([]byte(nil), seed...)
	}
}

func copySeqs(in map[p2p.NodeID]uint64) map[p2p.NodeID]uint64 {
	out := make(map[p2p.NodeID]uint64, len(in))
	for id, seq := range in {
		out[id] = seq
	}
	return out
}

func copyRmMark(in map[p2p.NodeID]int64) map[p2p.NodeID]int64 {
	out := make(map[p2p.NodeID]int64, len(in))
	for id, mark := range in {
		out[id] = mark
	}
	return out
}

func copyComQ(in map[p2p.NodeID]map[uint64]Object) map[p2p.NodeID]map[uint64]Object {
	out := make(map[p2p.NodeID]map[uint64]Object, len(in))
	for id, q := range in {
		out[id] = make(map[uint64]Object, len(q))
		for seq, obj := range q {
			out[id][seq] = obj
		}
	}
	return out
}

func defaultBLSPublic(ids []p2p.NodeID) map[string]kyber.Point {
	out := make(map[string]kyber.Point, len(ids))
	for _, id := range ids {
		kp := crypto.NewBLSKeyPairFromSeed(crypto.HashBytes([]byte("Tyche-v1/default-bls/private"), []byte(id)))
		out[string(id)] = kp.Public
	}
	return out
}

func cloneBLSPublic(in map[string]kyber.Point) map[string]kyber.Point {
	out := make(map[string]kyber.Point, len(in))
	for id, pub := range in {
		if pub != nil {
			out[id] = pub.Clone()
		}
	}
	return out
}

func defaultBLSPublicHex(id p2p.NodeID) string {
	kp := crypto.NewBLSKeyPairFromSeed(crypto.HashBytes([]byte("Tyche-v1/default-bls/private"), []byte(id)))
	return crypto.EncodeBLSPublicKey(kp.Public)
}

func signedJoinAck(t *testing.T, node *Node, tau TransitionIndex, rho string) JoinAck {
	t.Helper()
	sig, err := crypto.SignBLS(string(node.ID), node.BLS.Private, joinAckBytes(tau, rho))
	if err != nil {
		t.Fatal(err)
	}
	return JoinAck{Transition: tau, RequestDigest: rho, Signer: node.ID, Signature: sig}
}

func signedJoinCommit(t *testing.T, node *Node, tau TransitionIndex, rho string, activation uint64) JoinCommit {
	t.Helper()
	sig, err := crypto.SignBLS(string(node.ID), node.BLS.Private, joinCommitBytes(tau, rho, activation))
	if err != nil {
		t.Fatal(err)
	}
	return JoinCommit{Transition: tau, RequestDigest: rho, ActivationEpoch: activation, Signer: node.ID, Signature: sig}
}
