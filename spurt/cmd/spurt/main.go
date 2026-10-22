package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"Tyche/spurt/config"
	asig "Tyche/spurt/crypto"
	spurt "Tyche/spurt/protocol"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

const transportBuffer = 262144

type runtimeKeys struct {
	ids        []p2p.NodeID
	keys       map[p2p.NodeID]asig.KeyPair
	pubs       map[string]ed25519.PublicKey
	pvssKeys   map[p2p.NodeID]asig.PVSSKeyPair
	pvssPublic map[p2p.NodeID]kyber.Point
	seed       []byte
}

type runStats struct {
	beacons atomic.Uint64
}

type finalMetricWindow struct {
	started bool
	start   time.Time
	metrics metricSnapshot
	perf    spurt.PerfSnapshot
	beacons uint64
}

func main() {
	configPath := flag.String("config", "configs/local_8.json", "cluster configuration file")
	nodeID := flag.String("node", "", "node id for single-process TCP deployment; empty starts an in-memory local cluster")
	transport := flag.String("transport", "", "transport override: memory or tcp")
	duration := flag.String("duration", "", "optional run duration, e.g. 60s")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *transport != "" {
		cfg.Transport = strings.ToLower(*transport)
	}
	if *nodeID != "" {
		cfg.NodeID = p2p.NodeID(*nodeID)
	}
	if cfg.Transport != "memory" && !(cfg.Transport == "tcp" && cfg.AuthenticatedTCP) {
		log.Fatal("SPURT requires authenticated memory or mutual TLS TCP transport")
	}
	runDuration := parseDuration(*duration)

	if cfg.Transport == "tcp" && cfg.NodeID != "" {
		if err := runSingleNode(cfg, runDuration); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runLocalCluster(cfg, runDuration); err != nil {
		log.Fatal(err)
	}
}

func runLocalCluster(cfg config.Config, duration time.Duration) error {
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*spurt.Node, 0, len(rt.ids))
	for _, id := range rt.ids {
		node, err := newNode(cfg, rt, id, net.NewTransport(id, transportBuffer))
		if err != nil {
			return err
		}
		if err := node.Start(runCtx); err != nil {
			return err
		}
		nodes = append(nodes, node)
	}

	printConfig(cfg, len(rt.ids), "memory")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, nodes, stats)
	defer stopReport()
	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)
	var finalWindow, runWindow finalMetricWindow

	type localResult struct {
		node      int
		beacon    *spurt.Beacon
		err       error
		completed time.Time
	}
	results := make(chan localResult, len(nodes)*4)
	for index, node := range nodes {
		go func(index int, node *spurt.Node) {
			for count := uint64(0); count < uint64(cfg.Round); count++ {
				beacon, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
				select {
				case results <- localResult{index, beacon, err, time.Now()}:
				case <-runCtx.Done():
					return
				}
				if err != nil {
					return
				}
			}
		}(index, node)
	}
	pending := make(map[uint64]map[int]localResult)
	for epoch := uint64(0); epoch < uint64(cfg.Round); {
		select {
		case result := <-results:
			if result.err != nil {
				return result.err
			}
			if result.beacon == nil || result.beacon.Skipped {
				return fmt.Errorf("node %d returned invalid output", result.node)
			}
			e := result.beacon.Epoch
			if e < epoch {
				return fmt.Errorf("duplicate completed epoch %d", e)
			}
			if pending[e] == nil {
				pending[e] = make(map[int]localResult)
			}
			if _, duplicate := pending[e][result.node]; duplicate {
				return fmt.Errorf("duplicate node output")
			}
			pending[e][result.node] = result
		case <-runCtx.Done():
			return runCtx.Err()
		}
		for len(pending[epoch]) == len(nodes) {
			sample := pending[epoch][0].beacon
			completed := pending[epoch][0].completed
			for _, r := range pending[epoch] {
				if string(r.beacon.Random) != string(sample.Random) {
					return fmt.Errorf("epoch %d inconsistent beacon", epoch)
				}
				if r.completed.After(completed) {
					completed = r.completed
				}
			}
			stats.beacons.Add(1)
			fmt.Printf("ts=%s epoch=%d leader=%s digest=%s selected=%d random=%x\n", completed.UTC().Format(time.RFC3339Nano), sample.Epoch, nodes[0].State.Leader(sample.Epoch), sample.Digest, sample.Committeds, sample.Random[:8])
			runWindow.recordBeacon(nodes)
			if epoch >= uint64(cfg.WarmupOutputs) {
				finalWindow.recordBeacon(nodes)
			}
			delete(pending, epoch)
			epoch++
		}
	}

	cacheTotal, cacheMax := collectCachedCommitments(nodes)
	runWindow.printLabel("run", nodes, cacheTotal, cacheMax)
	finalWindow.print(nodes, cacheTotal, cacheMax)
	return nil
}

func runSingleNode(cfg config.Config, duration time.Duration) error {
	if cfg.NodeID == "" {
		return fmt.Errorf("tcp mode requires -node or node_id in config")
	}
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	peers := cfg.PeerMap()
	nodeTransport := p2p.NewTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), peers, p2p.TCPBufferForPeers(len(peers)))
	if cfg.AuthenticatedTCP {
		nodeTransport, err = p2p.NewAuthenticatedTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), peers, p2p.TCPBufferForPeers(len(peers)), rt.keys[cfg.NodeID].Private, rt.pubs)
		if err != nil {
			return err
		}
	}
	node, err := newNode(cfg, rt, cfg.NodeID, nodeTransport)
	if err != nil {
		return err
	}
	if err := nodeTransport.Start(runCtx); err != nil {
		return err
	}
	if err := waitForTCPPeers(runCtx, cfg.NodeID, cfg.PeerMap(), 30*time.Second); err != nil {
		return err
	}
	fmt.Printf("node=%s tcp_peers_ready peers=%d\n", cfg.NodeID, len(cfg.PeerMap())-1)
	node.StartProtocol(runCtx)
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, []*spurt.Node{node}, stats)
	defer stopReport()

	printConfig(cfg, 1, "tcp")
	count := uint64(0)
	runStart := time.Now()
	var finalWindow finalMetricWindow
	for {
		if duration > 0 && time.Since(runStart) >= duration {
			break
		}
		if count >= uint64(cfg.Round) {
			break
		}
		b, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
		if err != nil {
			return err
		}
		count++
		if b.Skipped {
			fmt.Printf("ts=%s node=%s epoch=%d leader=%s skipped stage=%s reason=%s random=%x diag=\"%s\"\n",
				logTimestamp(), node.ID, b.Epoch, node.State.Leader(b.Epoch), b.SkipStage, b.SkipReason, b.Random[:8], b.SkipDiag)
			continue
		}
		stats.beacons.Add(1)
		fmt.Printf("ts=%s node=%s epoch=%d leader=%s digest=%s random=%x\n",
			logTimestamp(), node.ID, b.Epoch, node.State.Leader(b.Epoch), b.Digest, b.Random)
		finalWindow.recordBeacon([]*spurt.Node{node})
	}
	nodes := []*spurt.Node{node}
	cacheTotal, cacheMax := collectCachedCommitments(nodes)
	finalWindow.print(nodes, cacheTotal, cacheMax)
	fmt.Printf("benchmark_complete outputs=%d\n", stats.beacons.Load())
	if cfg.LingerMS > 0 {
		time.Sleep(time.Duration(cfg.LingerMS) * time.Millisecond)
	}
	return nil
}

func prepareRuntime(cfg config.Config) (runtimeKeys, error) {
	ids := cfg.Members()
	if len(ids) == 0 {
		return runtimeKeys{}, fmt.Errorf("config has no cluster members")
	}
	keys, pubs, err := cfg.KeyPairs()
	if err != nil {
		return runtimeKeys{}, err
	}
	seed, err := cfg.SeedBytes()
	if err != nil {
		return runtimeKeys{}, err
	}
	pvssSeeds, err := cfg.NodeSeedBytes()
	if err != nil {
		return runtimeKeys{}, err
	}
	pvssKeys := make(map[p2p.NodeID]asig.PVSSKeyPair, len(ids))
	pvssPublic := make(map[p2p.NodeID]kyber.Point, len(ids))
	for _, id := range ids {
		pk := asig.PVSSKeyPairFromSeed(pvssSeeds[id])
		pvssKeys[id] = pk
		pvssPublic[id] = pk.Public
	}
	return runtimeKeys{
		ids: ids, keys: keys, pubs: pubs, pvssKeys: pvssKeys, pvssPublic: pvssPublic,
		seed: seed,
	}, nil
}

func newNode(cfg config.Config, rt runtimeKeys, id p2p.NodeID, transport p2p.Transport) (*spurt.Node, error) {
	pvssScheme, err := asig.NewPVSSScheme(id, cfg.F+1, rt.pvssKeys[id].Private, rt.pvssPublic)
	if err != nil {
		return nil, err
	}
	return spurt.NewNode(spurt.NodeConfig{
		ID: id, Members: rt.ids, F: cfg.F, Seed: rt.seed, Keys: rt.keys[id],
		Public:    rt.pubs,
		Transport: transport, PVSS: pvssScheme, CryptoWorkers: cfg.MaxPool, Lookahead: cfg.Lookahead,
	})
}

func runtimeContext(cfg config.Config, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration > 0 {
		return context.WithTimeout(context.Background(), duration)
	}
	if cfg.Round > 0 {
		return context.WithTimeout(context.Background(), time.Duration(cfg.Round+10)*time.Duration(cfg.EpochMS)*time.Millisecond)
	}
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

func parseDuration(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0
	}
	return d
}

func printConfig(cfg config.Config, nodes int, transport string) {
	fmt.Printf("protocol=%s transport=%s nodes=%d f=%d rounds=%d lookahead=%d epoch_ms=%d report_ms=%d crypto_workers=%d\n",
		spurt.Protocol, transport, nodes, cfg.F, cfg.Round, cfg.Lookahead, cfg.EpochMS, cfg.ReportMS, cfg.MaxPool)
	if transport == "tcp" {
		fmt.Printf("tcp node=%s listen=%s peers=%v\n", cfg.NodeID, cfg.ListenAddr(cfg.NodeID), cfg.PeerMap())
	}
}

func startReporter(ctx context.Context, cfg config.Config, nodes []*spurt.Node, stats *runStats) func() {
	done := make(chan struct{})
	interval := time.Duration(cfg.ReportMS) * time.Millisecond
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
				totalPending, maxPending := collectCachedCommitments(nodes)
				printMetricDelta("periodic", current.sub(last), currentPerf.Sub(lastPerf), totalPending, maxPending, now.Sub(lastAt), currentBeacon-lastBeacon)
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
	return func() { close(done) }
}

type metricSnapshot struct {
	sentMessages uint64
	sentBytes    uint64
	recvMessages uint64
	recvBytes    uint64
}

func collectMetrics(nodes []*spurt.Node) metricSnapshot {
	var out metricSnapshot
	for _, node := range nodes {
		m := node.Transport.Metrics()
		out.sentMessages += m.SentMessages
		out.sentBytes += m.SentBytes
		out.recvMessages += m.RecvMessages
		out.recvBytes += m.RecvBytes
	}
	return out
}

func collectPerf(nodes []*spurt.Node) spurt.PerfSnapshot {
	var out spurt.PerfSnapshot
	for _, node := range nodes {
		out = out.Add(node.PerfSnapshot())
	}
	return out
}

func collectCachedCommitments(nodes []*spurt.Node) (total int, max int) {
	for _, node := range nodes {
		if node == nil {
			continue
		}
		totalNode, maxNode := node.CachedCommitments()
		total += totalNode
		if maxNode > max {
			max = maxNode
		}
	}
	return total, max
}

func (w *finalMetricWindow) recordBeacon(nodes []*spurt.Node) {
	if !w.started {
		w.started = true
		w.start = time.Now()
		w.metrics = collectMetrics(nodes)
		w.perf = collectPerf(nodes)
		return
	}
	w.beacons++
}

func (w *finalMetricWindow) print(nodes []*spurt.Node, cacheTotal int, cacheMax int) {
	w.printLabel("final", nodes, cacheTotal, cacheMax)
}
func (w *finalMetricWindow) printLabel(label string, nodes []*spurt.Node, cacheTotal int, cacheMax int) {
	if !w.started {
		printMetricDelta(label, metricSnapshot{}, spurt.PerfSnapshot{}, cacheTotal, cacheMax, 0, 0)
		return
	}
	printMetricDelta(label, collectMetrics(nodes).sub(w.metrics), collectPerf(nodes).Sub(w.perf), cacheTotal, cacheMax, time.Since(w.start), w.beacons)
}

func (m metricSnapshot) sub(prev metricSnapshot) metricSnapshot {
	return metricSnapshot{
		sentMessages: m.sentMessages - prev.sentMessages,
		sentBytes:    m.sentBytes - prev.sentBytes,
		recvMessages: m.recvMessages - prev.recvMessages,
		recvBytes:    m.recvBytes - prev.recvBytes,
	}
}

func logTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func printMetricDelta(label string, delta metricSnapshot, perf spurt.PerfSnapshot, cacheTotal int, cacheMax int, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	fmt.Printf("%s metrics beacons=%d elapsed_s=%.3f throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent_bytes=%d recv_bytes=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s message_signs=%d message_verifies=%d message_sign_avg=%s message_verify_avg=%s cached_total=%d cached_max=%d pvss_share_avg=%s pvss_verify_avg=%s pvss_prerecon_avg=%s pvss_recon_avg=%s spurt_vote_avg=%s beacon_sign_avg=%s beacon_verify_avg=%s\n",
		label, beacons, elapsed.Seconds(), float64(beacons)*60/seconds,
		delta.sentMessages, delta.recvMessages, delta.sentBytes, delta.recvBytes, float64(delta.sentBytes)/1024,
		float64(delta.recvBytes)/1024, float64(delta.sentBytes+delta.recvBytes)/1024/seconds,
		perf.MessageSignCount, perf.MessageVerifyCount,
		spurt.AvgDuration(perf.MessageSignTotal, perf.MessageSignCount), spurt.AvgDuration(perf.MessageVerifyTotal, perf.MessageVerifyCount),
		cacheTotal, cacheMax,
		spurt.AvgDuration(perf.PVSSShareTotal, perf.PVSSShareCount), spurt.AvgDuration(perf.PVSSVerifyTotal, perf.PVSSVerifyCount),
		spurt.AvgDuration(perf.PVSSPreReconTotal, perf.PVSSPreReconCount), spurt.AvgDuration(perf.PVSSReconTotal, perf.PVSSReconCount),
		spurt.AvgDuration(perf.AgreementTotal, perf.AgreementCount),
		spurt.AvgDuration(perf.BeaconSignTotal, perf.BeaconSignCount),
		spurt.AvgDuration(perf.BeaconVerifyTotal, perf.BeaconVerifyCount),
	)
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
