package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/Tyche/protocol/tyche"
	"github.com/scottocs/Tyche/utils/p2p"
)

type runStats struct {
	beacons atomic.Uint64
}

type finalMetricWindow struct {
	started bool
	start   time.Time
	metrics metricSnapshot
	perf    tyche.PerfSnapshot
	types   map[string]p2p.MessageTypeMetrics
	beacons uint64
}

type metricSnapshot struct {
	sentMessages  uint64
	sentBytes     uint64
	recvMessages  uint64
	recvBytes     uint64
	abaMessages   uint64
	abaBytes      uint64
	inboxLen      uint64
	inboxCap      uint64
	cryptoActive  int64
	cryptoQueued  int64
	cryptoWorkers int
}

const transportBuffer = 262144

func main() {
	n := flag.Int("n", 8, "number of local memory nodes")
	epochs := flag.Int("epochs", 1000, "number of beacon epochs")
	f := flag.Int("f", -1, "Byzantine fault threshold; defaults to (n-1)/3")
	transport := flag.String("transport", "memory", "transport type: memory or tcp")
	nodeID := flag.String("node", "", "node id for tcp mode, for example node0")
	peersRaw := flag.String("peers", "", "comma-separated tcp peers, for example node0=1.1.1.1:9000,node1=2.2.2.2:9000")
	listenAddr := flag.String("listen", "", "tcp listen address, for example 0.0.0.0:9000; defaults to listen_ip plus this node's peer port")
	listenIP := flag.String("listen-ip", "0.0.0.0", "tcp listen ip used when -listen is empty")
	queueLen := flag.Int("queue-len", 8, "per-source commitment queue length")
	producerMS := flag.Int("producer-ms", 50, "producer interval in milliseconds")
	prefillMS := flag.Int("prefill-ms", 3000, "producer prefill time in milliseconds")
	epochTimeoutMS := flag.Int("epoch-timeout-ms", 10000, "timeout per epoch in milliseconds")
	reportMS := flag.Int("report-ms", 5000, "periodic metrics interval in milliseconds")
	lingerMS := flag.Int("linger-ms", 0, "milliseconds to keep the node alive after final metrics before exiting")
	maxPool := flag.Int("max-pool", 4, "maximum concurrent cryptographic worker tasks per node")
	transportBufferFlag := flag.Int("transport-buffer", 0, "transport inbox buffer length; defaults to a size scaled by n")
	removalExpirationMS := flag.Int("removal-expiration-ms", 0, "epoch-control ABA false-input timeout in milliseconds; defaults to a size scaled by n")
	pvss := flag.String("pvss", "o1", "PVSS backend: o1 or scrape")
	reconfigEvents := flag.Int("reconfig-events", 0, "number of deterministic reconfiguration events")
	reconfigMinN := flag.Int("reconfig-min-n", 0, "minimum membership size for stop-producing reconfiguration events")
	reconfigMaxN := flag.Int("reconfig-max-n", 0, "maximum membership size for rejoin reconfiguration events")
	reconfigSeed := flag.Int64("reconfig-seed", 20260521, "seed for deterministic reconfiguration event schedule")
	reconfigCrashGraceMS := flag.Int("reconfig-crash-grace-ms", 2000, "milliseconds a reconfiguration victim waits after broadcasting its current object before exiting")
	flag.Parse()

	opts := runOptions{
		n: *n, epochs: *epochs, f: *f, transport: strings.ToLower(*transport),
		nodeID: p2p.NodeID(*nodeID), peersRaw: *peersRaw, listenAddr: *listenAddr, listenIP: *listenIP,
		queueLen: *queueLen, producerMS: *producerMS, prefillMS: *prefillMS,
		epochTimeoutMS: *epochTimeoutMS, reportMS: *reportMS, lingerMS: *lingerMS, maxPool: *maxPool,
		transportBuffer: *transportBufferFlag, removalExpirationMS: *removalExpirationMS,
		pvss:           strings.ToLower(*pvss),
		reconfigEvents: *reconfigEvents, reconfigMinN: *reconfigMinN, reconfigMaxN: *reconfigMaxN, reconfigSeed: *reconfigSeed,
		reconfigCrashGraceMS: *reconfigCrashGraceMS,
	}
	if err := run(opts); err != nil {
		log.Fatal(err)
	}
}

type runOptions struct {
	n                    int
	epochs               int
	f                    int
	transport            string
	nodeID               p2p.NodeID
	peersRaw             string
	listenAddr           string
	listenIP             string
	queueLen             int
	producerMS           int
	prefillMS            int
	epochTimeoutMS       int
	reportMS             int
	lingerMS             int
	maxPool              int
	transportBuffer      int
	removalExpirationMS  int
	pvss                 string
	reconfigEvents       int
	reconfigMinN         int
	reconfigMaxN         int
	reconfigSeed         int64
	reconfigCrashGraceMS int
}

func run(opts runOptions) error {
	if opts.transport != "memory" && opts.transport != "tcp" {
		return fmt.Errorf("unsupported transport %q", opts.transport)
	}
	if opts.pvss != "o1" && opts.pvss != "scrape" {
		return fmt.Errorf("unsupported PVSS backend %q", opts.pvss)
	}
	if opts.n <= 0 {
		return fmt.Errorf("-n must be positive")
	}
	if opts.epochs <= 0 {
		return fmt.Errorf("-epochs must be positive")
	}
	if opts.f < 0 {
		opts.f = (opts.n - 1) / 3
	}
	if 3*opts.f+1 > opts.n {
		return fmt.Errorf("invalid fault threshold: need n >= 3f+1, got n=%d f=%d", opts.n, opts.f)
	}
	if opts.queueLen <= 0 {
		opts.queueLen = 8
	}
	if opts.producerMS <= 0 {
		opts.producerMS = 250
	}
	if opts.prefillMS < 0 {
		opts.prefillMS = 0
	}
	if opts.epochTimeoutMS <= 0 {
		opts.epochTimeoutMS = 10000
	}
	if opts.reconfigMinN <= 0 {
		opts.reconfigMinN = opts.n - opts.f
	}
	if opts.reconfigMaxN <= 0 {
		opts.reconfigMaxN = opts.n + opts.f
	}
	if opts.reconfigMinN < 1 {
		opts.reconfigMinN = 1
	}
	if opts.reconfigMinN > opts.n {
		return fmt.Errorf("-reconfig-min-n must be <= -n: min=%d n=%d", opts.reconfigMinN, opts.n)
	}
	if opts.reconfigMaxN < opts.reconfigMinN {
		return fmt.Errorf("-reconfig-max-n must be >= -reconfig-min-n: max=%d min=%d", opts.reconfigMaxN, opts.reconfigMinN)
	}
	if opts.reconfigEvents < 0 {
		return fmt.Errorf("-reconfig-events must be non-negative")
	}
	if opts.reconfigCrashGraceMS < 0 {
		return fmt.Errorf("-reconfig-crash-grace-ms must be non-negative")
	}
	opts.transportBuffer = resolveTransportBuffer(opts)
	opts.removalExpirationMS = resolveRemovalExpirationMS(opts)
	lookaheadExpirationMS := resolveLookaheadExpirationMS(opts)
	if opts.transport == "tcp" {
		return runTCP(opts, lookaheadExpirationMS)
	}
	return runMemory(opts, lookaheadExpirationMS)
}

func runMemory(opts runOptions, lookaheadExpirationMS int) error {
	runCtx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.epochs+10)*time.Duration(opts.epochTimeoutMS)*time.Millisecond)
	defer cancel()

	ids, pp, keys, err := setupRuntime(opts.n, opts.f, opts.pvss)
	if err != nil {
		return err
	}

	net := p2p.NewMemoryNetwork()
	nodes := make([]*tyche.Node, 0, len(ids))
	for _, id := range ids {
		scheme, err := crypto.NewPVSSScheme(id, keys[id].Private, pp)
		if err != nil {
			return err
		}
		node, err := tyche.NewNode(tyche.Config{
			ID:                    id,
			Members:               ids,
			F:                     opts.f,
			QueueLen:              opts.queueLen,
			PVSS:                  scheme,
			PVSSBackend:           opts.pvss,
			CryptoWorkers:         opts.maxPool,
			RemovalExpiration:     time.Duration(opts.removalExpirationMS) * time.Millisecond,
			LookaheadExpiration:   time.Duration(lookaheadExpirationMS) * time.Millisecond,
			CurrentMissingRemoval: opts.reconfigEvents > 0,
			ExplicitRemovalOnly:   opts.reconfigEvents > 0,
			Transport:             net.NewTransport(id, opts.transportBuffer),
		})
		if err != nil {
			return err
		}
		node.Start(runCtx)
		node.StartProducer(runCtx, time.Duration(opts.producerMS)*time.Millisecond)
		nodes = append(nodes, node)
	}

	epochAttemptTimeout := tycheEpochAttemptTimeout(opts)
	fmt.Printf("config protocol=tyche-v1 transport=memory nodes=%d f=%d epochs=%d queue_len=%d producer_ms=%d epoch_timeout_ms=%d epoch_attempt_timeout_ms=%d report_ms=%d crypto_workers=%d transport_buffer=%d removal_expiration_ms=%d lookahead_expiration_ms=%d pvss=%s\n",
		opts.n, opts.f, opts.epochs, opts.queueLen, opts.producerMS, opts.epochTimeoutMS, int(epochAttemptTimeout/time.Millisecond), opts.reportMS, opts.maxPool, opts.transportBuffer, opts.removalExpirationMS, lookaheadExpirationMS, opts.pvss)

	stats := &runStats{}
	stopReport := startReporter(runCtx, nodes, stats, time.Duration(opts.reportMS)*time.Millisecond)
	defer stopReport()
	time.Sleep(time.Duration(opts.prefillMS) * time.Millisecond)
	var finalWindow finalMetricWindow
	reconfigSchedule := buildReconfigSchedule(ids, opts)
	stopped := make(map[p2p.NodeID]bool)
	reportedRemoved := make(map[p2p.NodeID]bool)
	localStops := 0

	for epoch := 1; epoch <= opts.epochs; epoch++ {
		if err := activatePendingReconfigurationJoins(runCtx, nodes, stopped, epoch); err != nil {
			return err
		}
		if event, ok := reconfigSchedule[epoch]; ok {
			stops, err := handleMemoryReconfigEvent(runCtx, nodes, event, stopped, opts, epochAttemptTimeout)
			if err != nil {
				return err
			}
			localStops += stops
		}
		activeNodes := currentMemberNodes(nodes)
		if len(activeNodes) == 0 {
			return fmt.Errorf("epoch %d: no active member nodes remain", epoch)
		}
		for _, node := range activeNodes {
			snapshot := node.DebugSnapshot()
			if stopped[snapshot.Source] {
				seq, applied, err := node.ForceReconfigurationRemoval(uint64(epoch), snapshot.Source)
				if err != nil {
					return fmt.Errorf("epoch %d: force reconfiguration removal for %s: %w", epoch, snapshot.Source, err)
				}
				if applied {
					fmt.Printf("reconfig_aba_false event=aba_false epoch=%d node=%s seq=%d removal_seq=%d observer=%s completed=%d config_version=%d\n",
						epoch, snapshot.Source, seq, seq, node.ID, snapshot.Completed, snapshot.ConfigVersion)
				}
			}
		}
		epochCtx, cancelEpoch := context.WithTimeout(runCtx, epochAttemptTimeout)
		results := make(chan result, len(activeNodes))
		for _, node := range activeNodes {
			go func(node *tyche.Node, epoch uint64) {
				b, err := node.RunEpochAt(epochCtx, epoch)
				results <- result{beacon: b, err: err}
			}(node, uint64(epoch))
		}

		var sample tyche.Beacon
		for i := 0; i < len(activeNodes); i++ {
			res := <-results
			if res.err != nil {
				cancelEpoch()
				return fmt.Errorf("epoch %d: %w", epoch, res.err)
			}
			if i == 0 {
				sample = res.beacon
			}
		}
		cancelEpoch()
		stats.beacons.Add(1)
		fmt.Printf("ts=%s epoch=%d source=%s seq=%d random=%x\n", logTimestamp(), sample.Epoch, sample.Source, sample.Seq, sample.Random[:8])
		finalWindow.recordBeacon(activeNodes)
		logReconfigRemovalProgress(activeNodes[0], stopped, reportedRemoved, epoch)
		for _, node := range nodes {
			drainJoinEvents(node, stopped, epoch)
		}
	}

	activeNodes := currentMemberNodes(nodes)
	if len(activeNodes) == 0 {
		activeNodes = nodes
	}
	stopReport()
	queueTotal, queueMax := collectQueue(activeNodes)
	finalWindow.print(activeNodes, queueTotal, queueMax)
	printReconfigFinal(activeNodes[0], len(reconfigSchedule), localStops, opts)
	lingerBeforeExit(runCtx, opts.lingerMS)
	return nil
}

func runTCP(opts runOptions, lookaheadExpirationMS int) error {
	if opts.nodeID == "" {
		return fmt.Errorf("tcp mode requires -node")
	}
	peers, err := parsePeers(opts.peersRaw)
	if err != nil {
		return err
	}
	if len(peers) != opts.n {
		return fmt.Errorf("-peers count must match -n: peers=%d n=%d", len(peers), opts.n)
	}
	if _, ok := peers[opts.nodeID]; !ok {
		return fmt.Errorf("-peers does not contain -node %s", opts.nodeID)
	}
	ids, pp, keys, err := setupRuntime(opts.n, opts.f, opts.pvss)
	if err != nil {
		return err
	}
	if !containsID(ids, opts.nodeID) {
		return fmt.Errorf("node id %s is outside generated node0..node%d set", opts.nodeID, opts.n-1)
	}
	listen := opts.listenAddr
	if listen == "" {
		_, port, err := net.SplitHostPort(peers[opts.nodeID])
		if err != nil {
			return fmt.Errorf("invalid self peer address %q: %w", peers[opts.nodeID], err)
		}
		listen = net.JoinHostPort(opts.listenIP, port)
	}

	runCtx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.epochs+10)*time.Duration(opts.epochTimeoutMS)*time.Millisecond)
	defer cancel()
	scheme, err := crypto.NewPVSSScheme(opts.nodeID, keys[opts.nodeID].Private, pp)
	if err != nil {
		return err
	}
	transport := p2p.NewTCPTransport(opts.nodeID, listen, peers, opts.transportBuffer)
	node, err := tyche.NewNode(tyche.Config{
		ID: opts.nodeID, Members: ids, F: opts.f, QueueLen: opts.queueLen, PVSS: scheme, PVSSBackend: opts.pvss, CryptoWorkers: opts.maxPool,
		RemovalExpiration: time.Duration(opts.removalExpirationMS) * time.Millisecond, LookaheadExpiration: time.Duration(lookaheadExpirationMS) * time.Millisecond, CurrentMissingRemoval: opts.reconfigEvents > 0, ExplicitRemovalOnly: opts.reconfigEvents > 0, Transport: transport,
	})
	if err != nil {
		return err
	}
	if err := transport.Start(runCtx); err != nil {
		return err
	}
	if err := waitForTCPPeers(runCtx, opts.nodeID, peers, 30*time.Second); err != nil {
		return err
	}
	fmt.Printf("node=%s tcp_peers_ready peers=%d\n", opts.nodeID, len(peers)-1)
	node.Start(runCtx)
	node.StartProducer(runCtx, time.Duration(opts.producerMS)*time.Millisecond)

	nodes := []*tyche.Node{node}
	epochAttemptTimeout := tycheEpochAttemptTimeout(opts)
	fmt.Printf("config protocol=tyche-v1 transport=tcp node=%s listen=%s nodes=%d f=%d epochs=%d queue_len=%d producer_ms=%d epoch_timeout_ms=%d epoch_attempt_timeout_ms=%d report_ms=%d crypto_workers=%d transport_buffer=%d removal_expiration_ms=%d lookahead_expiration_ms=%d pvss=%s peers=%v\n",
		opts.nodeID, listen, opts.n, opts.f, opts.epochs, opts.queueLen, opts.producerMS, opts.epochTimeoutMS, int(epochAttemptTimeout/time.Millisecond), opts.reportMS, opts.maxPool, opts.transportBuffer, opts.removalExpirationMS, lookaheadExpirationMS, opts.pvss, peers)
	stats := &runStats{}
	stopReport := startReporter(runCtx, nodes, stats, time.Duration(opts.reportMS)*time.Millisecond)
	defer stopReport()
	time.Sleep(time.Duration(opts.prefillMS) * time.Millisecond)
	startCount := 0
	if completed := node.CompletedEpoch(); completed > 0 {
		if completed >= uint64(opts.epochs) {
			startCount = opts.epochs
		} else {
			startCount = int(completed)
		}
		fmt.Printf("node=%s prefilled_epochs=%d counted=%d\n", opts.nodeID, completed, startCount)
	}
	var finalWindow finalMetricWindow
	reconfigSchedule := buildReconfigSchedule(ids, opts)
	stopped := make(map[p2p.NodeID]bool)
	reportedRemoved := make(map[p2p.NodeID]bool)
	localStops := 0
	var selfJoinCatchupTarget uint64

	for counted := startCount; counted < opts.epochs; counted++ {
		epoch := counted + 1
		event, hasEvent := reconfigSchedule[epoch]
		if err := node.ActivatePendingJoins(runCtx, uint64(epoch)); err != nil {
			return fmt.Errorf("node %s activating pending joins before epoch %d: %w", opts.nodeID, epoch, err)
		}
		drainJoinEvents(node, stopped, epoch)
		if !node.IsMember(opts.nodeID) {
			snapshot := node.DebugSnapshot()
			fmt.Printf("reconfig_self_removed epoch=%d node=%s completed=%d config_version=%d\n", epoch, opts.nodeID, snapshot.Completed, snapshot.ConfigVersion)
			urgentJoin := hasEvent && event.Action == reconfigJoin && event.Node == opts.nodeID
			catchupTarget := uint64(max(0, epoch-1))
			if selfJoinCatchupTarget > catchupTarget {
				catchupTarget = selfJoinCatchupTarget
				urgentJoin = true
			}
			waitTimeout := reconfigRemovedCatchupTimeout(epochAttemptTimeout, urgentJoin)
			if err := waitForCompletedEpoch(runCtx, node, catchupTarget, waitTimeout); err != nil {
				if urgentJoin {
					fmt.Printf("reconfig_removed_wait_timeout epoch=%d node=%s completed=%d config_version=%d target=%d err=%v\n",
						epoch, opts.nodeID, node.CompletedEpoch(), snapshot.ConfigVersion, catchupTarget, err)
				}
			} else if err := node.ActivatePendingJoins(runCtx, uint64(epoch)); err != nil {
				return fmt.Errorf("node %s activating pending joins after catchup for epoch %d: %w", opts.nodeID, epoch, err)
			}
		}
		if hasEvent {
			stoppedNow, joinActivation, err := handleReconfigEvent(runCtx, node, event, stopped, opts, epochAttemptTimeout)
			if err != nil {
				return err
			}
			if stoppedNow {
				localStops++
			}
			if joinActivation > 0 && event.Action == reconfigJoin && event.Node == opts.nodeID {
				selfJoinCatchupTarget = joinActivation - 1
			}
		}
		drainJoinEvents(node, stopped, epoch)
		if node.IsMember(opts.nodeID) {
			selfJoinCatchupTarget = 0
		}
		if !node.IsMember(opts.nodeID) {
			continue
		}
		catchupTarget := uint64(max(0, epoch-1))
		if node.CompletedEpoch() < catchupTarget {
			if err := catchUpRejoinedNode(runCtx, node, stopped, reportedRemoved, opts.nodeID, catchupTarget, epochAttemptTimeout); err != nil {
				return fmt.Errorf("node %s failed to catch up after rejoin before epoch %d: completed=%d target=%d: %w",
					opts.nodeID, epoch, node.CompletedEpoch(), catchupTarget, err)
			}
		}
		if err := forceStoppedSourceRemoval(node, stopped, opts.nodeID, uint64(epoch), "scheduled"); err != nil {
			return err
		}
		epochCtx, cancelEpoch := context.WithTimeout(runCtx, epochAttemptTimeout)
		targetEpoch := uint64(epoch)
		beacon, err := node.RunEpochAt(epochCtx, targetEpoch)
		cancelEpoch()
		if err != nil {
			return fmt.Errorf("epoch %d: %w", counted+1, err)
		}
		stats.beacons.Add(1)
		fmt.Printf("ts=%s node=%s epoch=%d source=%s seq=%d random=%x\n", logTimestamp(), opts.nodeID, beacon.Epoch, beacon.Source, beacon.Seq, beacon.Random[:8])
		finalWindow.recordBeacon(nodes)
		logReconfigRemovalProgress(node, stopped, reportedRemoved, epoch)
	}
	queueTotal, queueMax := collectQueue(nodes)
	stopReport()
	finalWindow.print(nodes, queueTotal, queueMax)
	printReconfigFinal(node, len(reconfigSchedule), localStops, opts)
	lingerBeforeExit(runCtx, opts.lingerMS)
	return nil
}

func lingerBeforeExit(ctx context.Context, lingerMS int) {
	if lingerMS <= 0 {
		return
	}
	fmt.Printf("linger_ms=%d\n", lingerMS)
	timer := time.NewTimer(time.Duration(lingerMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func reconfigEventLimit(opts runOptions) int {
	if opts.reconfigEvents <= 0 || opts.epochs <= 0 {
		return 0
	}
	maxEvents := opts.reconfigEvents
	if opts.epochs < maxEvents {
		maxEvents = opts.epochs
	}
	return maxEvents
}

type reconfigAction string

const (
	reconfigStop reconfigAction = "stop"
	reconfigJoin reconfigAction = "join"
)

type reconfigEvent struct {
	Epoch  int
	Action reconfigAction
	Node   p2p.NodeID
}

type pendingRejoinCandidate struct {
	id             p2p.NodeID
	availableEpoch int
}

func buildReconfigSchedule(ids []p2p.NodeID, opts runOptions) map[int]reconfigEvent {
	schedule := make(map[int]reconfigEvent)
	maxEvents := reconfigEventLimit(opts)
	if maxEvents == 0 {
		return schedule
	}
	rng := rand.New(rand.NewSource(opts.reconfigSeed))
	planningEpochs := opts.epochs - reconfigJoinModelDelay()
	if planningEpochs < 1 {
		planningEpochs = opts.epochs
	}
	members := make(map[p2p.NodeID]bool, len(ids))
	for _, id := range ids {
		members[id] = true
	}
	var removed []pendingRejoinCandidate
	nextEligibleEpoch := reconfigInitialQuietEpoch()
	for epoch := 1; epoch <= planningEpochs && len(schedule) < maxEvents; epoch++ {
		if epoch < nextEligibleEpoch {
			continue
		}
		if !shouldRunReconfiguration(rng, epoch, planningEpochs, len(schedule), maxEvents) {
			continue
		}
		canStop := len(members) > opts.reconfigMinN
		joinCandidates := availableRejoinCandidates(removed, epoch)
		canJoin := len(members) < opts.reconfigMaxN && len(joinCandidates) > 0
		if !canStop && !canJoin {
			continue
		}
		action := reconfigStop
		if canStop && canJoin {
			if rng.Intn(2) == 1 {
				action = reconfigJoin
			}
		} else if canJoin {
			action = reconfigJoin
		}
		switch action {
		case reconfigStop:
			candidates := make([]p2p.NodeID, 0, len(members))
			for _, id := range ids {
				if members[id] {
					candidates = append(candidates, id)
				}
			}
			if len(candidates) == 0 {
				continue
			}
			victim := candidates[rng.Intn(len(candidates))]
			delete(members, victim)
			removed = append(removed, pendingRejoinCandidate{id: victim, availableEpoch: epoch + reconfigJoinModelDelay()})
			schedule[epoch] = reconfigEvent{Epoch: epoch, Action: reconfigStop, Node: victim}
			nextEligibleEpoch = epoch + reconfigReconfigurationQuietEpochs()
		case reconfigJoin:
			joiner := joinCandidates[rng.Intn(len(joinCandidates))]
			members[joiner] = true
			removed = removeRejoinCandidate(removed, joiner)
			schedule[epoch] = reconfigEvent{Epoch: epoch, Action: reconfigJoin, Node: joiner}
			nextEligibleEpoch = epoch + reconfigReconfigurationQuietEpochs()
		}
	}
	return schedule
}

func availableRejoinCandidates(removed []pendingRejoinCandidate, epoch int) []p2p.NodeID {
	out := make([]p2p.NodeID, 0, len(removed))
	for _, candidate := range removed {
		if epoch >= candidate.availableEpoch {
			out = append(out, candidate.id)
		}
	}
	return out
}

func removeRejoinCandidate(removed []pendingRejoinCandidate, id p2p.NodeID) []pendingRejoinCandidate {
	out := removed[:0]
	for _, candidate := range removed {
		if candidate.id != id {
			out = append(out, candidate)
		}
	}
	return out
}

func reconfigJoinModelDelay() int {
	return 10
}

func reconfigReconfigurationQuietEpochs() int {
	return 20
}

func reconfigInitialQuietEpoch() int {
	return 20
}

func sortedNodeIDs(ids []p2p.NodeID) []p2p.NodeID {
	out := append([]p2p.NodeID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func normalizeNodeIDs(ids []p2p.NodeID) []p2p.NodeID {
	seen := make(map[p2p.NodeID]bool, len(ids))
	out := make([]p2p.NodeID, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func currentMemberSet(node *tyche.Node) map[p2p.NodeID]bool {
	members, _, _, _ := node.MembershipSnapshot()
	out := make(map[p2p.NodeID]bool, len(members))
	for _, id := range members {
		out[id] = true
	}
	return out
}

func stoppedMemberPending(node *tyche.Node, stopped map[p2p.NodeID]bool) bool {
	for id := range stopped {
		if node.IsMember(id) {
			return true
		}
	}
	return false
}

func currentMembersContain(node *tyche.Node, id p2p.NodeID) bool {
	return currentMemberSet(node)[id]
}

func ensureJoinKey(node *tyche.Node, joiner p2p.NodeID, eventEpoch int, opts runOptions) (tyche.JoinRequest, bool, error) {
	members, f, version, completed := node.MembershipSnapshot()
	if containsID(members, joiner) {
		return tyche.JoinRequest{}, false, nil
	}
	targetMembers := normalizeNodeIDs(append(members, joiner))
	targetF := (len(targetMembers) - 1) / 3
	pp, keys, err := crypto.SetupPVSS(opts.pvss, reconfigJoinPVSSEpoch(opts, eventEpoch, version, joiner, targetMembers), targetF+1, targetMembers)
	if err != nil {
		return tyche.JoinRequest{}, false, err
	}
	if key, ok := keys[node.ID]; ok {
		node.RegisterPVSSKey(pp.Epoch(), key.Private)
	}
	key, ok := keys[joiner]
	if !ok {
		return tyche.JoinRequest{}, false, fmt.Errorf("missing joiner pvss key for %s", joiner)
	}
	scheme, err := crypto.NewPVSSScheme(joiner, key.Private, pp)
	if err != nil {
		return tyche.JoinRequest{}, false, err
	}
	commitment, _, err := scheme.Share(joiner, 1, nil)
	if err != nil {
		return tyche.JoinRequest{}, false, err
	}
	req := tyche.JoinRequest{
		ConfigVersion:   version,
		ContextEpoch:    completed,
		Joiner:          joiner,
		PublicKey:       string(joiner) + "-pk",
		CandidateParams: pp,
		Object:          tyche.Object{ConfigVersion: version + 1, Producer: joiner, Seq: 1, Commitment: commitment},
		FirstCoinEpoch:  completed + 10,
		ActivationEpoch: completed + 30,
	}
	if f < 0 {
		return tyche.JoinRequest{}, false, fmt.Errorf("invalid current fault threshold %d", f)
	}
	return req, node.ID == reconfigJoinProposer(members), nil
}

func reconfigJoinProposer(members []p2p.NodeID) p2p.NodeID {
	if len(members) == 0 {
		return ""
	}
	members = sortedNodeIDs(members)
	return members[0]
}

func reconfigJoinPVSSEpoch(opts runOptions, eventEpoch int, version uint64, joiner p2p.NodeID, members []p2p.NodeID) string {
	return fmt.Sprintf("tyche-reconfig-seed-%d-event-%d-version-%d-join-%s-members-%s", opts.reconfigSeed, eventEpoch, version, joiner, join(stringsFromNodeIDs(members), "."))
}

func stringsFromNodeIDs(ids []p2p.NodeID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	sort.Strings(out)
	return out
}

func join(parts []string, sep string) string {
	return strings.Join(parts, sep)
}

func handleReconfigEvent(ctx context.Context, node *tyche.Node, event reconfigEvent, stopped map[p2p.NodeID]bool, opts runOptions, epochAttemptTimeout time.Duration) (bool, uint64, error) {
	switch event.Action {
	case reconfigStop:
		snapshot := node.DebugSnapshot()
		members, _, version, completed := node.MembershipSnapshot()
		if stoppedMemberPending(node, stopped) {
			fmt.Printf("reconfig_stop_deferred epoch=%d node=%s completed=%d config_version=%d reason=pending_removal\n",
				event.Epoch, event.Node, completed, version)
			return false, 0, nil
		}
		if len(members) <= opts.reconfigMinN {
			fmt.Printf("reconfig_stop_deferred epoch=%d node=%s completed=%d config_version=%d reason=min_n current_n=%d min_n=%d\n",
				event.Epoch, event.Node, completed, version, len(members), opts.reconfigMinN)
			return false, 0, nil
		}
		if !containsID(members, event.Node) {
			fmt.Printf("reconfig_stop_deferred epoch=%d node=%s completed=%d config_version=%d reason=not_member current_n=%d min_n=%d\n",
				event.Epoch, event.Node, completed, version, len(members), opts.reconfigMinN)
			return false, 0, nil
		}
		stopped[event.Node] = true
		fmt.Printf("reconfig_schedule epoch=%d action=stop_producing node=%s source=%s seq=%d completed=%d config_version=%d min_n=%d max_n=%d seed=%d\n",
			event.Epoch, event.Node, snapshot.Source, snapshot.Seq, snapshot.Completed, snapshot.ConfigVersion, opts.reconfigMinN, opts.reconfigMaxN, opts.reconfigSeed)
		if event.Node != node.ID {
			return false, 0, nil
		}
		ensureCtx, cancelEnsure := context.WithTimeout(ctx, epochAttemptTimeout)
		seq, err := node.EnsureCurrentObject(ensureCtx)
		cancelEnsure()
		if err != nil {
			return false, 0, fmt.Errorf("node %s failed to prepare current object before reconfiguration stop at epoch %d seq=%d: %w", node.ID, event.Epoch, seq, err)
		}
		node.SetProducing(false)
		fmt.Printf("reconfig_stop_producing epoch=%d node=%s seq=%d completed=%d config_version=%d\n",
			event.Epoch, event.Node, seq, node.CompletedEpoch(), snapshot.ConfigVersion)
		return true, 0, nil
	case reconfigJoin:
		if stoppedMemberPending(node, stopped) {
			snapshot := node.DebugSnapshot()
			fmt.Printf("reconfig_join_deferred epoch=%d node=%s completed=%d config_version=%d reason=pending_removal\n",
				event.Epoch, event.Node, snapshot.Completed, snapshot.ConfigVersion)
			return false, 0, nil
		}
		if currentMembersContain(node, event.Node) {
			snapshot := node.DebugSnapshot()
			fmt.Printf("reconfig_join_deferred epoch=%d node=%s completed=%d config_version=%d reason=already_member\n",
				event.Epoch, event.Node, snapshot.Completed, snapshot.ConfigVersion)
			return false, 0, nil
		}
		req, proposer, err := ensureJoinKey(node, event.Node, event.Epoch, opts)
		if err != nil {
			return false, 0, fmt.Errorf("prepare reconfiguration join for %s: %w", event.Node, err)
		}
		if proposer {
			members, f, version, completed := node.MembershipSnapshot()
			fmt.Printf("reconfig_joining event=joining_proposal epoch=%d node=%s completed=%d config_version=%d n_before=%d f_before=%d activation_epoch=%d members_before=%v\n",
				event.Epoch, event.Node, completed, version, len(members), f, req.ActivationEpoch, sortedNodeIDs(members))
			if err := node.ProposeJoin(ctx, req); err != nil {
				return false, 0, fmt.Errorf("propose reconfiguration join for %s: %w", event.Node, err)
			}
			return false, req.ActivationEpoch, nil
		}
		return false, 0, nil
	default:
		return false, 0, nil
	}
}

func handleMemoryReconfigEvent(ctx context.Context, nodes []*tyche.Node, event reconfigEvent, stopped map[p2p.NodeID]bool, opts runOptions, epochAttemptTimeout time.Duration) (int, error) {
	localStops := 0
	switch event.Action {
	case reconfigStop:
		refNodes := currentMemberNodes(nodes)
		if len(refNodes) == 0 {
			refNodes = nodes
		}
		ref := refNodes[0]
		members, _, version, completed := ref.MembershipSnapshot()
		if stoppedMemberPending(ref, stopped) {
			fmt.Printf("reconfig_stop_deferred epoch=%d node=%s completed=%d config_version=%d reason=pending_removal\n",
				event.Epoch, event.Node, completed, version)
			return 0, nil
		}
		if len(members) <= opts.reconfigMinN {
			fmt.Printf("reconfig_stop_deferred epoch=%d node=%s completed=%d config_version=%d reason=min_n current_n=%d min_n=%d\n",
				event.Epoch, event.Node, completed, version, len(members), opts.reconfigMinN)
			return 0, nil
		}
		if !containsID(members, event.Node) {
			fmt.Printf("reconfig_stop_deferred epoch=%d node=%s completed=%d config_version=%d reason=not_member current_n=%d min_n=%d\n",
				event.Epoch, event.Node, completed, version, len(members), opts.reconfigMinN)
			return 0, nil
		}
		for _, node := range nodes {
			stopped[event.Node] = true
			if node.ID != event.Node {
				continue
			}
			snapshot := node.DebugSnapshot()
			fmt.Printf("reconfig_schedule epoch=%d action=stop_producing node=%s source=%s seq=%d completed=%d config_version=%d min_n=%d max_n=%d seed=%d\n",
				event.Epoch, event.Node, snapshot.Source, snapshot.Seq, snapshot.Completed, snapshot.ConfigVersion, opts.reconfigMinN, opts.reconfigMaxN, opts.reconfigSeed)
			ensureCtx, cancelEnsure := context.WithTimeout(ctx, epochAttemptTimeout)
			seq, err := node.EnsureCurrentObject(ensureCtx)
			cancelEnsure()
			if err != nil {
				return 0, fmt.Errorf("node %s failed to prepare current object before reconfiguration stop at epoch %d seq=%d: %w", event.Node, event.Epoch, seq, err)
			}
			node.SetProducing(false)
			localStops++
			fmt.Printf("reconfig_stop_producing epoch=%d node=%s seq=%d\n", event.Epoch, event.Node, seq)
			return localStops, nil
		}
	case reconfigJoin:
		var proposerReq tyche.JoinRequest
		var proposer *tyche.Node
		for _, node := range nodes {
			if stoppedMemberPending(node, stopped) || currentMembersContain(node, event.Node) {
				continue
			}
			req, isProposer, err := ensureJoinKey(node, event.Node, event.Epoch, opts)
			if err != nil {
				return 0, fmt.Errorf("prepare reconfiguration join for %s: %w", event.Node, err)
			}
			if isProposer {
				members, f, version, completed := node.MembershipSnapshot()
				fmt.Printf("reconfig_joining event=joining_proposal epoch=%d node=%s observer=%s completed=%d config_version=%d n_before=%d f_before=%d activation_epoch=%d members_before=%v\n",
					event.Epoch, event.Node, node.ID, completed, version, len(members), f, req.ActivationEpoch, sortedNodeIDs(members))
				proposerReq = req
				proposer = node
			}
		}
		if proposer != nil {
			if err := proposer.ProposeJoin(ctx, proposerReq); err != nil {
				return 0, fmt.Errorf("propose reconfiguration join for %s: %w", event.Node, err)
			}
		}
	}
	return localStops, nil
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

func printReconfigFinal(node *tyche.Node, scheduled int, localStops int, opts runOptions) {
	if scheduled == 0 {
		return
	}
	members, f, version, completed := node.MembershipSnapshot()
	sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
	removed := opts.n - len(members)
	if removed < 0 {
		removed = 0
	}
	membershipChanges := int(version)
	fmt.Printf("reconfig_final scheduled_events=%d local_stop_events=%d membership_changes=%d removed=%d completed_epochs=%d final_n=%d final_f=%d config_version=%d min_n=%d seed=%d members=%v\n",
		scheduled,
		localStops,
		membershipChanges,
		removed,
		completed,
		len(members),
		f,
		version,
		opts.reconfigMinN,
		opts.reconfigSeed,
		members,
	)
}

func logReconfigRemovalProgress(node *tyche.Node, stopped map[p2p.NodeID]bool, reportedRemoved map[p2p.NodeID]bool, epoch int) {
	for id := range stopped {
		if node.IsMember(id) {
			continue
		}
		delete(stopped, id)
		if reportedRemoved[id] {
			continue
		}
		reportedRemoved[id] = true
		members, f, version, completed := node.MembershipSnapshot()
		sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
		fmt.Printf("reconfig_removed event=aba_deleted epoch=%d node=%s completed=%d config_version=%d final_n=%d final_f=%d members=%v\n",
			epoch, id, completed, version, len(members), f, members)
		fmt.Printf("reconfig_membership_change epoch=%d completed=%d config_version=%d final_n=%d final_f=%d members=%v\n",
			epoch, completed, version, len(members), f, members)
	}
}

func drainJoinEvents(node *tyche.Node, stopped map[p2p.NodeID]bool, epoch int) {
	for {
		select {
		case cert := <-node.Joins:
			delete(stopped, cert.Request.Joiner)
			if cert.Request.Joiner == node.ID {
				node.SetProducing(true)
			}
			members, f, version, completed := node.MembershipSnapshot()
			sort.Slice(members, func(i, j int) bool { return members[i] < members[j] })
			fmt.Printf("reconfig_joined event=joined epoch=%d node=%s observer=%s completed=%d config_version=%d final_n=%d final_f=%d members=%v\n",
				epoch, cert.Request.Joiner, node.ID, completed, version, len(members), f, members)
		default:
			return
		}
	}
}

func activatePendingReconfigurationJoins(ctx context.Context, nodes []*tyche.Node, stopped map[p2p.NodeID]bool, epoch int) error {
	for _, node := range nodes {
		if err := node.ActivatePendingJoins(ctx, uint64(epoch)); err != nil {
			return fmt.Errorf("node %s activating pending joins before epoch %d: %w", node.ID, epoch, err)
		}
		drainJoinEvents(node, stopped, epoch)
	}
	return nil
}

func catchUpRejoinedNode(ctx context.Context, node *tyche.Node, stopped map[p2p.NodeID]bool, reportedRemoved map[p2p.NodeID]bool, observer p2p.NodeID, target uint64, timeout time.Duration) error {
	node.ApplyPendingBeaconCertificatesUntil(target)
	if node.CompletedEpoch() >= target {
		return nil
	}
	catchupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for node.CompletedEpoch() < target {
		next := node.CompletedEpoch() + 1
		if err := forceStoppedSourceRemoval(node, stopped, observer, next, "catchup"); err != nil {
			return err
		}
		beacon, err := node.RunEpochAt(catchupCtx, next)
		if err != nil {
			return fmt.Errorf("catch up epoch %d: %w", next, err)
		}
		fmt.Printf("reconfig_catchup epoch=%d node=%s source=%s seq=%d completed=%d\n",
			beacon.Epoch, observer, beacon.Source, beacon.Seq, node.CompletedEpoch())
		logReconfigRemovalProgress(node, stopped, reportedRemoved, int(next))
	}
	return nil
}

func forceStoppedSourceRemoval(node *tyche.Node, stopped map[p2p.NodeID]bool, observer p2p.NodeID, epoch uint64, reason string) error {
	snapshot := node.DebugSnapshot()
	if snapshot.NextEpoch != epoch || snapshot.Source == "" || !stopped[snapshot.Source] {
		return nil
	}
	seq, applied, err := node.ForceReconfigurationRemoval(epoch, snapshot.Source)
	if err != nil {
		return fmt.Errorf("epoch %d: force reconfiguration removal for %s: %w", epoch, snapshot.Source, err)
	}
	if applied {
		fmt.Printf("reconfig_aba_false event=aba_false epoch=%d node=%s seq=%d removal_seq=%d observer=%s completed=%d config_version=%d reason=%s\n",
			epoch, snapshot.Source, seq, seq, observer, snapshot.Completed, snapshot.ConfigVersion, reason)
	}
	return nil
}

func waitForCompletedEpoch(ctx context.Context, node *tyche.Node, target uint64, timeout time.Duration) error {
	node.ApplyPendingBeaconCertificatesUntil(target)
	if node.CompletedEpoch() >= target {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		node.ApplyPendingBeaconCertificatesUntil(target)
		if node.CompletedEpoch() >= target {
			return nil
		}
		select {
		case <-ticker.C:
		case <-waitCtx.Done():
			return waitCtx.Err()
		}
	}
}

func reconfigRemovedCatchupTimeout(epochAttemptTimeout time.Duration, urgent bool) time.Duration {
	if urgent {
		return epochAttemptTimeout
	}
	poll := 200 * time.Millisecond
	if epochAttemptTimeout < poll {
		return epochAttemptTimeout
	}
	return poll
}

func tycheEpochAttemptTimeout(opts runOptions) time.Duration {
	outer := time.Duration(opts.epochTimeoutMS) * time.Millisecond
	raw := strings.TrimSpace(os.Getenv("TYCHE_EPOCH_ATTEMPT_MS"))
	if raw == "" {
		return outer
	}
	ms, err := strconv.Atoi(raw)
	if err != nil || ms <= 0 {
		return outer
	}
	attempt := time.Duration(ms) * time.Millisecond
	if attempt > outer {
		return outer
	}
	return attempt
}

func resolveTransportBuffer(opts runOptions) int {
	if opts.transportBuffer > 0 {
		return opts.transportBuffer
	}
	raw := strings.TrimSpace(os.Getenv("TYCHE_TRANSPORT_BUFFER"))
	if raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return value
		}
	}
	scaled := p2p.TCPBufferForPeers(opts.n)
	if scaled < transportBuffer {
		return transportBuffer
	}
	return scaled
}

func resolveRemovalExpirationMS(opts runOptions) int {
	if opts.removalExpirationMS > 0 {
		return opts.removalExpirationMS
	}
	raw := strings.TrimSpace(os.Getenv("TYCHE_REMOVAL_EXPIRATION_MS"))
	if raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return value
		}
	}
	// The lookahead object is delivered through RBC and SCRAPE verification.
	// At large n, the fixed 5s default can fire during startup even though the
	// next object is already in flight, forcing the epoch-control ABA down the
	// slow false-input path. Scale conservatively with n.
	return 5000 * max(1, (opts.n+31)/32)
}

func resolveLookaheadExpirationMS(opts runOptions) int {
	raw := strings.TrimSpace(os.Getenv("TYCHE_LOOKAHEAD_EXPIRATION_MS"))
	if raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 {
			return value
		}
	}
	if opts.reconfigEvents > 0 {
		return 10000
	}
	return opts.removalExpirationMS
}

func setupRuntime(n int, f int, pvss string) ([]p2p.NodeID, crypto.PVSSParams, map[p2p.NodeID]crypto.KeyPair, error) {
	ids := make([]p2p.NodeID, n)
	for i := range ids {
		ids[i] = p2p.NodeID(fmt.Sprintf("node%d", i))
	}
	epoch := fmt.Sprintf("tyche-runner-n%d-f%d", n, f)
	pp, keys, err := crypto.SetupPVSS(pvss, epoch, f+1, ids)
	return ids, pp, keys, err
}

func parsePeers(raw string) (map[p2p.NodeID]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("tcp mode requires -peers")
	}
	out := make(map[p2p.NodeID]string)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		id, addr, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(id) == "" || strings.TrimSpace(addr) == "" {
			return nil, fmt.Errorf("invalid peer %q, want node0=host:port", item)
		}
		addr = strings.TrimSpace(addr)
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("invalid peer address %q: %w", addr, err)
		}
		out[p2p.NodeID(strings.TrimSpace(id))] = addr
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tcp mode requires at least one peer")
	}
	return out, nil
}

func containsID(ids []p2p.NodeID, id p2p.NodeID) bool {
	for _, candidate := range ids {
		if candidate == id {
			return true
		}
	}
	return false
}

func waitForTCPPeers(ctx context.Context, self p2p.NodeID, peers map[p2p.NodeID]string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if allPeersReachable(ctx, self, peers) {
			return nil
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			return fmt.Errorf("timed out waiting for tcp peers")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func allPeersReachable(ctx context.Context, self p2p.NodeID, peers map[p2p.NodeID]string) bool {
	total := 0
	for id := range peers {
		if id == self {
			continue
		}
		total++
	}
	if total == 0 {
		return true
	}
	results := make(chan bool, total)
	for id, addr := range peers {
		if id == self {
			continue
		}
		go func(addr string) {
			dialCtx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
			if err == nil {
				_ = conn.Close()
			}
			results <- (err == nil)
		}(addr)
	}
	for i := 0; i < total; i++ {
		select {
		case ok := <-results:
			if !ok {
				return false
			}
		case <-ctx.Done():
			return false
		}
	}
	return true
}

type result struct {
	beacon tyche.Beacon
	err    error
}

func startReporter(ctx context.Context, nodes []*tyche.Node, stats *runStats, interval time.Duration) func() {
	done := make(chan struct{})
	var once sync.Once
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		last := collectMetrics(nodes)
		lastPerf := collectPerf(nodes)
		lastBeacon := stats.beacons.Load()
		lastAt := time.Now()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				current := collectMetrics(nodes)
				currentPerf := collectPerf(nodes)
				currentBeacon := stats.beacons.Load()
				queueTotal, queueMax := collectQueue(nodes)
				beaconDelta := currentBeacon - lastBeacon
				printMetricDelta("periodic", current.sub(last), currentPerf.Sub(lastPerf), queueTotal, queueMax, now.Sub(lastAt), beaconDelta)
				if beaconDelta == 0 {
					printDebugSnapshots(nodes)
				}
				last, lastAt = current, now
				lastPerf = currentPerf
				lastBeacon = currentBeacon
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

func collectMetrics(nodes []*tyche.Node) metricSnapshot {
	var out metricSnapshot
	for _, node := range nodes {
		m := node.Transport.Metrics()
		out.sentMessages += m.SentMessages
		out.sentBytes += m.SentBytes
		out.recvMessages += m.RecvMessages
		out.recvBytes += m.RecvBytes
		if typed, ok := node.Transport.(interface {
			MessageTypeMetrics() map[string]p2p.MessageTypeMetrics
		}); ok {
			for key, stats := range typed.MessageTypeMetrics() {
				if strings.HasPrefix(key, "aba/") {
					out.abaMessages += stats.SentMessages
					out.abaBytes += stats.SentBytes
				}
			}
		}
		if typed, ok := node.Transport.(interface {
			InboxStats() (int, int)
		}); ok {
			inboxLen, inboxCap := typed.InboxStats()
			out.inboxLen += uint64(inboxLen)
			out.inboxCap += uint64(inboxCap)
		}
		if node.Crypto != nil {
			stats := node.Crypto.Stats()
			out.cryptoActive += stats.Active
			out.cryptoQueued += stats.Queued
			out.cryptoWorkers += stats.Workers
		}
	}
	return out
}

func collectMessageTypeMetrics(nodes []*tyche.Node) map[string]p2p.MessageTypeMetrics {
	out := make(map[string]p2p.MessageTypeMetrics)
	for _, node := range nodes {
		typed, ok := node.Transport.(interface {
			MessageTypeMetrics() map[string]p2p.MessageTypeMetrics
		})
		if !ok {
			continue
		}
		for key, stats := range typed.MessageTypeMetrics() {
			current := out[key]
			current.SentMessages += stats.SentMessages
			current.SentBytes += stats.SentBytes
			current.RecvMessages += stats.RecvMessages
			current.RecvBytes += stats.RecvBytes
			out[key] = current
		}
	}
	return out
}

func collectQueue(nodes []*tyche.Node) (total int, max int) {
	for _, node := range nodes {
		t, m := node.QueueBacklog()
		total += t
		if m > max {
			max = m
		}
	}
	return total, max
}

func currentMemberNodes(nodes []*tyche.Node) []*tyche.Node {
	active := make([]*tyche.Node, 0, len(nodes))
	for _, node := range nodes {
		if node.IsMember(node.ID) {
			active = append(active, node)
		}
	}
	return active
}

func collectPerf(nodes []*tyche.Node) tyche.PerfSnapshot {
	var out tyche.PerfSnapshot
	for _, node := range nodes {
		if node.Perf != nil {
			out = out.Add(node.Perf.Snapshot())
		}
	}
	return out
}

func (w *finalMetricWindow) recordBeacon(nodes []*tyche.Node) {
	if !w.started {
		w.started = true
		w.start = time.Now()
		w.metrics = collectMetrics(nodes)
		w.perf = collectPerf(nodes)
		w.types = collectMessageTypeMetrics(nodes)
		return
	}
	w.beacons++
}

func (w *finalMetricWindow) print(nodes []*tyche.Node, queueTotal int, queueMax int) {
	if !w.started {
		printMetricDelta("final", metricSnapshot{}, tyche.PerfSnapshot{}, queueTotal, queueMax, 0, 0)
		return
	}
	printMetricDelta("final", collectMetrics(nodes).sub(w.metrics), collectPerf(nodes).Sub(w.perf), queueTotal, queueMax, time.Since(w.start), w.beacons)
	printMessageTypeMetricsDiff(collectMessageTypeMetrics(nodes), w.types)
}

func (m metricSnapshot) sub(prev metricSnapshot) metricSnapshot {
	return metricSnapshot{
		sentMessages:  m.sentMessages - prev.sentMessages,
		sentBytes:     m.sentBytes - prev.sentBytes,
		recvMessages:  m.recvMessages - prev.recvMessages,
		recvBytes:     m.recvBytes - prev.recvBytes,
		abaMessages:   m.abaMessages - prev.abaMessages,
		abaBytes:      m.abaBytes - prev.abaBytes,
		inboxLen:      m.inboxLen,
		inboxCap:      m.inboxCap,
		cryptoActive:  m.cryptoActive,
		cryptoQueued:  m.cryptoQueued,
		cryptoWorkers: m.cryptoWorkers,
	}
}

func printMetrics(label string, nodes []*tyche.Node, elapsed time.Duration, beacons uint64) {
	queueTotal, queueMax := collectQueue(nodes)
	printMetricDelta(label, collectMetrics(nodes), collectPerf(nodes), queueTotal, queueMax, elapsed, beacons)
	if label == "final" {
		printMessageTypeMetrics(nodes)
	}
}

func logTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func printMetricDelta(label string, delta metricSnapshot, perf tyche.PerfSnapshot, queueTotal int, queueMax int, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	abaPct := 0.0
	if delta.sentMessages > 0 {
		abaPct = float64(delta.abaMessages) * 100 / float64(delta.sentMessages)
	}
	fmt.Printf("%s metrics beacons=%d elapsed_s=%.3f throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s queue_total=%d queue_max=%d transport_inbox=%d transport_inbox_cap=%d crypto_active=%d crypto_queued=%d crypto_workers=%d aba_sent_msgs=%d aba_msg_pct=%.2f aba_sent=%.2fKB pvss_share_avg=%s pvss_verify_avg=%s pvss_prerecon_avg=%s pvss_recon_avg=%s rbc_avg=%s aba_avg=%s cert_sign_avg=%s cert_verify_avg=%s cert_agg_avg=%s\n",
		label,
		beacons,
		elapsed.Seconds(),
		float64(beacons)*60/seconds,
		delta.sentMessages,
		delta.recvMessages,
		float64(delta.sentBytes)/1024,
		float64(delta.recvBytes)/1024,
		float64(delta.sentBytes+delta.recvBytes)/1024/seconds,
		queueTotal,
		queueMax,
		delta.inboxLen,
		delta.inboxCap,
		delta.cryptoActive,
		delta.cryptoQueued,
		delta.cryptoWorkers,
		delta.abaMessages,
		abaPct,
		float64(delta.abaBytes)/1024,
		tyche.AvgDuration(perf.PVSSShareTotal, perf.PVSSShareCount),
		tyche.AvgDuration(perf.PVSSVerifyTotal, perf.PVSSVerifyCount),
		tyche.AvgDuration(perf.PVSSPreReconTotal, perf.PVSSPreReconCount),
		tyche.AvgDuration(perf.PVSSReconTotal, perf.PVSSReconCount),
		tyche.AvgDuration(perf.RBCHandleTotal, perf.RBCHandleCount),
		tyche.AvgDuration(perf.ABAHandleTotal, perf.ABAHandleCount),
		tyche.AvgDuration(perf.CertSignTotal, perf.CertSignCount),
		tyche.AvgDuration(perf.CertVerifyTotal, perf.CertVerifyCount),
		tyche.AvgDuration(perf.CertAggregateTotal, perf.CertAggregateCount),
	)
}

func printDebugSnapshots(nodes []*tyche.Node) {
	limit := len(nodes)
	if limit > 3 {
		limit = 3
	}
	for i := 0; i < limit; i++ {
		s := nodes[i].DebugSnapshot()
		fmt.Printf("stall_debug node=%s completed=%d next_epoch=%d source=%s seq=%d object=%t next_object=%t pending_abas=%d aba_input_sent=%t aba_input=%t aba_decided=%t aba_coin_wait=%t aba_round=%d aba_inputs=%d aba_input_true=%d aba_input_false=%d aba_finish=%d aba_bval_true=%d aba_bval_false=%d aba_bin_true=%t aba_bin_false=%t aba_aux=%d aba_conf=%d recon_sent=%t recon_done=%t recon_count=%d recon_need=%d echo_max=%d ready_max=%d certifying=%t certified=%t waiters=%d verified_cache=%d crypto_active=%d crypto_queued=%d crypto_workers=%d\n",
			s.Node,
			s.Completed,
			s.NextEpoch,
			s.Source,
			s.Seq,
			s.Object,
			s.NextObject,
			s.PendingABAs,
			s.ABAInputSent,
			s.ABAInput,
			s.ABADecided,
			s.ABACoinWait,
			s.ABARound,
			s.ABAInputs,
			s.ABAInputTrue,
			s.ABAInputFalse,
			s.ABAFinish,
			s.ABABValTrue,
			s.ABABValFalse,
			s.ABABinTrue,
			s.ABABinFalse,
			s.ABAAux,
			s.ABAConf,
			s.ReconSent,
			s.ReconDone,
			s.ReconCount,
			s.ReconNeed,
			s.EchoMax,
			s.ReadyMax,
			s.Certifying,
			s.Certified,
			s.Waiters,
			s.VerifiedCache,
			s.CryptoActive,
			s.CryptoQueued,
			s.CryptoWorkers,
		)
	}
}

func printMessageTypeMetrics(nodes []*tyche.Node) {
	types := collectMessageTypeMetrics(nodes)
	printMessageTypeMetricsDiff(types, nil)
}

func printMessageTypeMetricsDiff(types map[string]p2p.MessageTypeMetrics, prev map[string]p2p.MessageTypeMetrics) {
	if len(types) == 0 {
		return
	}
	if prev != nil {
		types = subtractMessageTypeMetrics(types, prev)
	}
	printMessageCategoryMetrics(types)
	keys := make([]string, 0, len(types))
	for key := range types {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stats := types[key]
		fmt.Printf("message_type type=%s sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB\n", key, stats.SentMessages, stats.RecvMessages, float64(stats.SentBytes)/1024, float64(stats.RecvBytes)/1024)
	}
}

func subtractMessageTypeMetrics(current, prev map[string]p2p.MessageTypeMetrics) map[string]p2p.MessageTypeMetrics {
	out := make(map[string]p2p.MessageTypeMetrics, len(current))
	for key, stats := range current {
		before := prev[key]
		out[key] = p2p.MessageTypeMetrics{
			SentMessages: stats.SentMessages - before.SentMessages,
			SentBytes:    stats.SentBytes - before.SentBytes,
			RecvMessages: stats.RecvMessages - before.RecvMessages,
			RecvBytes:    stats.RecvBytes - before.RecvBytes,
		}
	}
	return out
}

func printMessageCategoryMetrics(types map[string]p2p.MessageTypeMetrics) {
	categories := make(map[string]p2p.MessageTypeMetrics)
	for key, stats := range types {
		category := messageCategory(key)
		current := categories[category]
		current.SentMessages += stats.SentMessages
		current.SentBytes += stats.SentBytes
		current.RecvMessages += stats.RecvMessages
		current.RecvBytes += stats.RecvBytes
		categories[category] = current
	}
	keys := make([]string, 0, len(categories))
	for key := range categories {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stats := categories[key]
		fmt.Printf("message_category category=%s sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB\n", key, stats.SentMessages, stats.RecvMessages, float64(stats.SentBytes)/1024, float64(stats.RecvBytes)/1024)
	}
}

func messageCategory(key string) string {
	switch {
	case key == "rbc/VAL":
		return "producer_rbc_value"
	case strings.HasPrefix(key, "rbc/"):
		return "rbc_control"
	case key == "tyche/RECON":
		return "consumer_recon"
	case key == "tyche/RECON_ECHO":
		return "consumer_echo"
	case key == "tyche/RECON_READY":
		return "recon_ready"
	case key == "tyche/BEACON_CERT":
		return "beacon_cert"
	case strings.HasPrefix(key, "aba/"):
		return "aba"
	case strings.HasPrefix(key, "tyche/JOIN"):
		return "reconfig_join"
	case strings.HasPrefix(key, "tyche/"):
		return "tyche_other"
	default:
		return "other"
	}
}
