package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	config "Tyche/grandline/config"
	asig "Tyche/grandline/crypto"
	grandline "Tyche/grandline/protocol"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type runtimeKeys struct {
	ids      []p2p.NodeID
	keys     map[p2p.NodeID]asig.KeyPair
	pubs     map[string]ed25519.PublicKey
	pvssKeys map[p2p.NodeID]asig.PVSSKeyPair
	pvssPub  map[p2p.NodeID]kyber.Point
	grand    asig.GRandResult
}

type runStats struct {
	beacons atomic.Uint64
}

type finalMetricWindow struct {
	started bool
	start   time.Time
	metrics metricSnapshot
	perf    grandline.PerfSnapshot
	beacons uint64
}

func main() {
	beaconMode := flag.String("beacon-mode", "", "beacon mode: standard (default, online commitments) or reference (fixed commitments); both omit outer signatures")
	setupFile := flag.String("setup-file", "", "common precomputed GRand setup snapshot")
	writeSetup := flag.String("write-setup", "", "write a fresh benchmark setup snapshot and exit")
	configPath := flag.String("config", "configs/local_8.json", "cluster configuration file")
	nodeID := flag.String("node", "", "node id for single-process TCP deployment; empty starts an in-memory cluster")
	transport := flag.String("transport", "", "override transport: memory or tcp")
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
	if *beaconMode != "" {
		cfg.BeaconMode = *beaconMode
	}
	if cfg.BeaconMode == "signed" {
		cfg.BeaconMode = "standard"
	}
	if cfg.BeaconMode != "standard" && cfg.BeaconMode != "reference" {
		log.Fatal("beacon-mode must be standard or reference")
	}
	if cfg.Transport != "memory" && cfg.Transport != "tcp" {
		log.Fatal("transport must be memory or tcp (mutual TLS)")
	}
	runDuration := parseDuration(*duration)

	if *setupFile != "" {
		cfg.SetupFile = *setupFile
	}
	if *writeSetup != "" {
		cfg.Transport = "memory"
		cfg.NodeID = ""
		cfg.SetupFile = ""
		rt, err := prepareRuntime(cfg)
		if err != nil {
			log.Fatal(err)
		}
		raw, err := json.Marshal(rt.grand)
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(*writeSetup, raw, 0600); err != nil {
			log.Fatal(err)
		}
		return
	}
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

	netw := p2p.NewMemoryNetwork()
	nodes := make([]*grandline.Node, 0, len(rt.ids))
	for _, id := range rt.ids {
		node, err := newNode(cfg, rt, id, netw.NewTransport(id, 4096))
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
	runStart := time.Now()
	var finalWindow, runWindow finalMetricWindow

	limit := uint64(cfg.Round)
	if duration > 0 {
		limit = ^uint64(0)
	}
	type localResult struct {
		node      int
		beacon    *grandline.Beacon
		err       error
		completed time.Time
	}
	results := make(chan localResult, len(nodes)*4)
	for index, node := range nodes {
		go func(index int, node *grandline.Node) {
			for count := uint64(0); count < limit; count++ {
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
	for epoch := uint64(0); epoch < limit; {
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
			fmt.Printf("ts=%s epoch=%d msg_hash=%s shares=%d signature=%s random=%x\n", completed.UTC().Format(time.RFC3339Nano), sample.Epoch, sample.Commit, sample.Shares, sample.SigHex[:16], sample.Random[:8])
			runWindow.recordBeacon(nodes)
			if epoch >= uint64(cfg.WarmupOutputs) {
				finalWindow.recordBeacon(nodes)
			}
			delete(pending, epoch)
			epoch++
			if duration > 0 && time.Since(runStart) >= duration {
				epoch = limit
				break
			}
		}
	}

	runWindow.printLabel("run", nodes)
	finalWindow.print(nodes)
	return nil
}

func runSingleNode(cfg config.Config, duration time.Duration) error {
	if cfg.NodeID == "" {
		return fmt.Errorf("tcp mode requires -node")
	}
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	peers := cfg.PeerMap()
	keys, pubs, err := cfg.KeyPairs()
	if err != nil {
		return err
	}
	transport, err := p2p.NewAuthenticatedTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), peers, p2p.TCPBufferForPeers(len(peers)), keys[cfg.NodeID].Private, pubs)
	if err != nil {
		return err
	}
	probe, err := p2p.OpenBenchmark(string(cfg.NodeID), transport, uint64(cfg.Round))
	if err != nil {
		return err
	}
	defer probe.Close()
	if err := transport.Start(runCtx); err != nil {
		return err
	}
	fmt.Printf("node=%s preparing grand setup nodes=%d f=%d threshold=%d\n", cfg.NodeID, len(cfg.Members()), cfg.F, cfg.F+1)
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	fmt.Printf("node=%s grand setup ready\n", cfg.NodeID)
	node, err := newNode(cfg, rt, cfg.NodeID, transport)
	if err != nil {
		return err
	}
	if err := waitForTCPPeers(runCtx, cfg.NodeID, cfg.PeerMap(), 30*time.Second); err != nil {
		return err
	}
	fmt.Printf("node=%s tcp_peers_ready peers=%d\n", cfg.NodeID, len(cfg.PeerMap())-1)
	node.StartProtocol(runCtx)

	printConfig(cfg, 1, "tcp")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, []*grandline.Node{node}, stats)
	defer stopReport()

	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)
	count := uint64(0)
	nodes := []*grandline.Node{node}
	runStart := time.Now()
	var finalWindow finalMetricWindow
	for {
		if duration > 0 && time.Since(runStart) >= duration {
			break
		}
		if uint64(cfg.Round) > 0 && count >= uint64(cfg.Round) {
			break
		}
		b, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
		if err != nil {
			return err
		}
		if b != nil && b.Skipped {
			fmt.Printf("ts=%s node=%s epoch=%d skipped stage=%s reason=%s random=%x diag=\"%s\"\n", logTimestamp(), node.ID, b.Epoch, b.SkipStage, b.SkipReason, b.Random[:8], b.SkipDiag)
			count++
			continue
		}
		count++
		stats.beacons.Add(1)
		if b != nil {
			fmt.Printf("ts=%s node=%s epoch=%d msg_hash=%s shares=%d signature=%s random=%x\n",
				logTimestamp(), node.ID, b.Epoch, b.Commit, b.Shares, b.SigHex[:16], b.Random)
		}
		finalWindow.recordBeacon(nodes)
		if err := probe.Output(count, func() any { return collectPerf(nodes) }); err != nil {
			return err
		}
	}
	finalWindow.print(nodes)
	if err := probe.Finish(runCtx); err != nil {
		return err
	}
	if probe != nil {
		cancel()
	}
	fmt.Printf("benchmark_complete outputs=%d\n", stats.beacons.Load())
	if err := probe.Complete(); err != nil {
		return err
	}
	if cfg.LingerMS > 0 {
		time.Sleep(time.Duration(cfg.LingerMS) * time.Millisecond)
	}
	return nil
}

func prepareRuntime(cfg config.Config) (runtimeKeys, error) {
	if cfg.Transport != "memory" && cfg.Transport != "tcp" {
		return runtimeKeys{}, fmt.Errorf("transport must be memory or tcp (mutual TLS)")
	}
	ids := cfg.Members()
	if len(ids) == 0 {
		return runtimeKeys{}, fmt.Errorf("config has no cluster members")
	}
	keys, pubs, err := cfg.KeyPairs()
	if err != nil {
		return runtimeKeys{}, err
	}
	nodeSeeds, err := cfg.NodeSeedBytes()
	if err != nil {
		return runtimeKeys{}, err
	}
	pvssKeys := make(map[p2p.NodeID]asig.PVSSKeyPair, len(ids))
	pvssPub := make(map[p2p.NodeID]kyber.Point, len(ids))
	for _, id := range ids {
		pk := asig.PVSSKeyPairFromSeed(nodeSeeds[id])
		pvssKeys[id] = pk
		pvssPub[id] = pk.Public
	}
	signingPublic := make(map[p2p.NodeID]ed25519.PublicKey, len(ids))
	for _, id := range ids {
		signingPublic[id] = pubs[string(id)]
	}
	pvssSchemes := make(map[p2p.NodeID]*asig.PVSSPairingFreeScheme, len(ids))
	for _, id := range ids {
		scheme, err := asig.NewPVSSScheme(id, cfg.F+1, pvssKeys[id].Private, pvssPub, asig.PVSSSigningKeys{Private: keys[id].Private, Public: signingPublic})
		if err != nil {
			return runtimeKeys{}, err
		}
		pvssSchemes[id] = scheme
	}
	var grandResult asig.GRandResult
	if cfg.SetupFile != "" {
		raw, err := os.ReadFile(cfg.SetupFile)
		if err != nil {
			return runtimeKeys{}, err
		}
		if err := json.Unmarshal(raw, &grandResult); err != nil {
			return runtimeKeys{}, err
		}
		if err := asig.ValidateGRandSetup(grandResult, ids, pvssSchemes, cfg.F+1); err != nil {
			return runtimeKeys{}, err
		}
	} else {
		if cfg.Transport == "tcp" && cfg.NodeID != "" {
			return runtimeKeys{}, fmt.Errorf("independent nodes require a common -setup-file; generate one once with -write-setup for this benchmark")
		}
		var err error
		grandResult, err = asig.SetupGRandFromAPVSS(ids, pvssSchemes, cfg.F+1)
		if err != nil {
			return runtimeKeys{}, err
		}
	}
	if cfg.BeaconMode == "reference" {
		if cfg.Transport != "memory" {
			return runtimeKeys{}, fmt.Errorf("reference mode requires authenticated memory transport")
		}
		if cfg.SetupFile == "" {
			if err := asig.PrepareReferenceCommitments(&grandResult, ids); err != nil {
				return runtimeKeys{}, err
			}
		} else if err := asig.ValidateReferenceCommitments(grandResult, ids); err != nil {
			return runtimeKeys{}, err
		}
	}
	return runtimeKeys{
		ids: ids, keys: keys, pubs: pubs, pvssKeys: pvssKeys, pvssPub: pvssPub, grand: grandResult,
	}, nil
}

func newNode(cfg config.Config, rt runtimeKeys, id p2p.NodeID, transport p2p.Transport) (*grandline.Node, error) {
	pvssScheme, err := asig.NewPVSSScheme(id, cfg.F+1, rt.pvssKeys[id].Private, rt.pvssPub, pvssSigningKeys(rt, id))
	if err != nil {
		return nil, err
	}
	nodeCfg := grandline.NodeConfig{
		BeaconMode: cfg.BeaconMode,
		ID:         id, Members: rt.ids, F: cfg.F,
		Transport: transport, PVSS: pvssScheme,
		GRand: rt.grand.ShareFor(id), CryptoWorkers: cfg.MaxPool,
	}
	if cfg.BeaconMode == "reference" {
		if rt.grand.Reference == nil {
			return nil, fmt.Errorf("reference setup missing")
		}
		nodeCfg.ReferenceCommitments = rt.grand.Reference.Commitments
		nodeCfg.ReferenceAlpha = rt.grand.Reference.Alphas[id]
	}
	return grandline.NewNode(nodeCfg)
}

func runtimeContext(cfg config.Config, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration > 0 {
		return context.WithTimeout(context.Background(), duration)
	}
	if cfg.Round > 0 {
		return context.WithTimeout(context.Background(), time.Duration(cfg.Round+3)*time.Duration(cfg.EpochMS)*time.Millisecond)
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
	protocol := grandline.Protocol
	if cfg.BeaconMode == "reference" {
		protocol = grandline.ReferenceProtocol
	}
	fmt.Printf("protocol=%s beacon_mode=%s transport=%s nodes=%d f=%d rounds=%d epoch_ms=%d report_ms=%d crypto_workers=%d\n",
		protocol, cfg.BeaconMode, transport, nodes, cfg.F, cfg.Round, cfg.EpochMS, cfg.ReportMS, cfg.MaxPool)
	if transport == "tcp" {
		fmt.Printf("tcp node=%s listen=%s peers=%v\n", cfg.NodeID, cfg.ListenAddr(cfg.NodeID), cfg.PeerMap())
	}
}

func startReporter(ctx context.Context, cfg config.Config, nodes []*grandline.Node, stats *runStats) func() {
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
				printMetricDelta("periodic", current.sub(last), currentPerf.Sub(lastPerf), now.Sub(lastAt), currentBeacon-lastBeacon)
				last, lastAt = current, now
				lastPerf = currentPerf
				lastBeacon = currentBeacon
			case <-ctx.Done():
				return
			case <-done:
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

func collectMetrics(nodes []*grandline.Node) metricSnapshot {
	var out metricSnapshot
	for _, n := range nodes {
		m := n.Transport.Metrics()
		out.sentMessages += m.SentMessages
		out.sentBytes += m.SentBytes
		out.recvMessages += m.RecvMessages
		out.recvBytes += m.RecvBytes
	}
	return out
}

func collectPerf(nodes []*grandline.Node) grandline.PerfSnapshot {
	var out grandline.PerfSnapshot
	for _, n := range nodes {
		out = out.Add(n.PerfSnapshot())
	}
	return out
}

func (w *finalMetricWindow) recordBeacon(nodes []*grandline.Node) {
	if !w.started {
		w.started = true
		w.start = time.Now()
		w.metrics = collectMetrics(nodes)
		w.perf = collectPerf(nodes)
		return
	}
	w.beacons++
}

func (w *finalMetricWindow) print(nodes []*grandline.Node) {
	w.printLabel("final", nodes)
}
func (w *finalMetricWindow) printLabel(label string, nodes []*grandline.Node) {
	if !w.started {
		printMetricDelta(label, metricSnapshot{}, grandline.PerfSnapshot{}, 0, 0)
		return
	}
	printMetricDelta(label, collectMetrics(nodes).sub(w.metrics), collectPerf(nodes).Sub(w.perf), time.Since(w.start), w.beacons)
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

func printMetricDelta(label string, delta metricSnapshot, perf grandline.PerfSnapshot, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	fmt.Printf("%s metrics beacons=%d elapsed_s=%.3f throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent_bytes=%d recv_bytes=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s message_signs=%d message_verifies=%d message_sign_avg=%s message_verify_avg=%s queue_total=%d queue_max=%d sign_avg=%s verify_avg=%s recover_avg=%s pvss_share_avg=%s pvss_verify_avg=%s\n",
		label,
		beacons,
		elapsed.Seconds(),
		float64(beacons)*60/seconds,
		delta.sentMessages, delta.recvMessages, delta.sentBytes, delta.recvBytes,
		float64(delta.sentBytes)/1024,
		float64(delta.recvBytes)/1024,
		float64(delta.sentBytes+delta.recvBytes)/1024/seconds,
		perf.MessageSignCount, perf.MessageVerifyCount,
		grandline.AvgDuration(perf.MessageSignTotal, perf.MessageSignCount), grandline.AvgDuration(perf.MessageVerifyTotal, perf.MessageVerifyCount),
		0, 0, // Legacy queue log fields remain zero.
		grandline.AvgDuration(perf.SignTotal, perf.SignCount),
		grandline.AvgDuration(perf.VerifyTotal, perf.VerifyCount),
		grandline.AvgDuration(perf.RecoverTotal, perf.RecoverCount),
		grandline.AvgDuration(perf.PVSSShareTotal, perf.PVSSShareCount),
		grandline.AvgDuration(perf.PVSSVerifyTotal, perf.PVSSVerifyCount))
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

func pvssSigningKeys(rt runtimeKeys, id p2p.NodeID) asig.PVSSSigningKeys {
	public := make(map[p2p.NodeID]ed25519.PublicKey, len(rt.ids))
	for _, member := range rt.ids {
		public[member] = rt.pubs[string(member)]
	}
	return asig.PVSSSigningKeys{Private: rt.keys[id].Private, Public: public}
}
