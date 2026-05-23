package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	asig "github.com/scottocs/Tyche/asyrand/crypto"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/scottocs/Tyche/asyrand/config"
	asyrand "github.com/scottocs/Tyche/asyrand/protocol"
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type runtimeKeys struct {
	ids        []p2p.NodeID
	keys       map[p2p.NodeID]asig.KeyPair
	pubs       map[string]ed25519.PublicKey
	pvssKeys   map[p2p.NodeID]asig.PVSSKeyPair
	pvssPublic map[p2p.NodeID]kyber.Point
	blsKeys    map[p2p.NodeID]asig.BLSKeyPair
	blsPublic  map[string]kyber.Point
	seed       []byte
}

type runStats struct {
	beacons atomic.Uint64
}

func main() {
	configPath := flag.String("config", "", "cluster configuration file")
	nodeID := flag.String("node", "", "node id for single-process TCP deployment; empty starts an in-memory local cluster")
	transport := flag.String("transport", "", "transport override: memory or tcp")
	duration := flag.Duration("duration", 0, "optional run duration, for example 5m")
	flag.Parse()

	if *configPath == "" {
		log.Fatal("-config is required")
	}
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
	if cfg.Transport == "tcp" && cfg.NodeID != "" {
		if err := runSingleNode(cfg, *duration); err != nil {
			log.Fatal(err)
		}
		return
	}
	if err := runLocalCluster(cfg, *duration); err != nil {
		log.Fatal(err)
	}
}

func runLocalCluster(cfg config.Config, duration time.Duration) error {
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	started := time.Now()
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*asyrand.Node, 0, len(rt.ids))
	for _, id := range rt.ids {
		node, err := newNode(cfg, rt, id, net.NewTransport(id, 4096))
		if err != nil {
			return err
		}
		if err := node.Start(runCtx); err != nil {
			return err
		}
		node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)
		nodes = append(nodes, node)
	}

	printConfig(cfg, len(rt.ids), "memory")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, nodes, stats)
	defer stopReport()
	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)

	for epoch := 0; epoch < cfg.Round; epoch++ {
		type result struct {
			beacon   *asyrand.Beacon
			consumed bool
			err      error
		}
		results := make(chan result, len(nodes))
		for _, node := range nodes {
			go func(node *asyrand.Node) {
				beacon, consumed, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
				results <- result{beacon: beacon, consumed: consumed, err: err}
			}(node)
		}
		var sample *asyrand.Beacon
		consumedCount := 0
		for range nodes {
			res := <-results
			if res.err != nil {
				return res.err
			}
			if res.consumed {
				consumedCount++
			}
			if sample == nil {
				sample = res.beacon
			}
		}
		if sample == nil {
			fmt.Printf("epoch=%d removed source and retried source candidate list\n", epoch)
			continue
		}
		stats.beacons.Add(1)
		fmt.Printf("epoch=%d source=%s consumed=%d/%d commit=%s random=%x\n", sample.Epoch, sample.Source, consumedCount, len(nodes), sample.CommitID, sample.Random[:8])
	}
	printMetrics("final", nodes, time.Since(started), stats.beacons.Load())
	return nil
}

func runSingleNode(cfg config.Config, duration time.Duration) error {
	if cfg.NodeID == "" {
		return fmt.Errorf("tcp mode requires -node or node_id in config")
	}
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	started := time.Now()
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	transport := p2p.NewTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), cfg.PeerMap(), 4096)
	node, err := newNode(cfg, rt, cfg.NodeID, transport)
	if err != nil {
		return err
	}
	if err := transport.Start(runCtx); err != nil {
		return err
	}
	if err := waitForTCPPeers(runCtx, cfg.NodeID, cfg.PeerMap(), 30*time.Second); err != nil {
		return err
	}
	fmt.Printf("node=%s tcp_peers_ready peers=%d\n", cfg.NodeID, len(cfg.PeerMap())-1)
	node.StartProtocol(runCtx)
	node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)
	nodes := []*asyrand.Node{node}
	printConfig(cfg, len(rt.ids), "tcp")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, nodes, stats)
	defer stopReport()
	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)

	for produced := 0; produced < cfg.Round; {
		beacon, consumed, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
		if err != nil {
			return err
		}
		if beacon == nil {
			fmt.Printf("node=%s removed source and retried source candidate list\n", node.ID)
			continue
		}
		produced++
		stats.beacons.Add(1)
		fmt.Printf("node=%s epoch=%d source=%s consumed=%t commit=%s random=%x\n", node.ID, beacon.Epoch, beacon.Source, consumed, beacon.CommitID, beacon.Random[:8])
	}
	printMetrics("final", nodes, time.Since(started), stats.beacons.Load())
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
	nodeSeeds, err := cfg.NodeSeedBytes()
	if err != nil {
		return runtimeKeys{}, err
	}
	pvssKeys := make(map[p2p.NodeID]asig.PVSSKeyPair, len(ids))
	pvssPublic := make(map[p2p.NodeID]kyber.Point, len(ids))
	blsKeys := make(map[p2p.NodeID]asig.BLSKeyPair, len(ids))
	blsPublic := make(map[string]kyber.Point, len(ids))
	for _, id := range ids {
		pvssKeys[id] = asig.PVSSKeyPairFromSeed(nodeSeeds[id])
		pvssPublic[id] = pvssKeys[id].Public
		blsKeys[id] = asig.NewBLSKeyPairFromSeed(nodeSeeds[id])
		blsPublic[string(id)] = blsKeys[id].Public
	}
	seed, err := cfg.SeedBytes()
	if err != nil {
		return runtimeKeys{}, err
	}
	return runtimeKeys{
		ids: ids, keys: keys, pubs: pubs, pvssKeys: pvssKeys,
		pvssPublic: pvssPublic, blsKeys: blsKeys, blsPublic: blsPublic, seed: seed,
	}, nil
}

func newNode(cfg config.Config, rt runtimeKeys, id p2p.NodeID, transport p2p.Transport) (*asyrand.Node, error) {
	pvssScheme, err := asig.NewScheme(id, cfg.F+1, rt.pvssKeys[id].Private, rt.pvssPublic)
	if err != nil {
		return nil, err
	}
	return asyrand.NewNode(asyrand.NodeConfig{
		ID: id, Members: rt.ids, F: cfg.F, QueueLen: cfg.QueueLen, Seed: rt.seed, Keys: rt.keys[id],
		Public: rt.pubs, BLS: rt.blsKeys[id], BLSPublic: rt.blsPublic,
		Transport: transport, PVSS: pvssScheme, CryptoWorkers: cfg.MaxPool,
	})
}

func runtimeContext(cfg config.Config, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration > 0 {
		return context.WithTimeout(context.Background(), duration)
	}
	return context.WithTimeout(context.Background(), time.Duration(cfg.Round+10)*time.Duration(cfg.EpochMS)*time.Millisecond)
}

func printConfig(cfg config.Config, nodes int, transport string) {
	fmt.Printf("config protocol=%s transport=%s nodes=%d f=%d rounds=%d queue_len=%d producer_ms=%d epoch_ms=%d report_ms=%d crypto_workers=%d\n",
		cfg.Protocol, transport, nodes, cfg.F, cfg.Round, cfg.QueueLen, cfg.ProducerMS, cfg.EpochMS, cfg.ReportMS, cfg.MaxPool)
	if transport == "tcp" {
		fmt.Printf("tcp node=%s listen=%s peers=%v\n", cfg.NodeID, cfg.ListenAddr(cfg.NodeID), cfg.PeerMap())
	}
}

func startReporter(ctx context.Context, cfg config.Config, nodes []*asyrand.Node, stats *runStats) func() {
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
				totalPending, maxPending := collectQueue(nodes)
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

func collectMetrics(nodes []*asyrand.Node) metricSnapshot {
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

func collectPerf(nodes []*asyrand.Node) asyrand.PerfSnapshot {
	var out asyrand.PerfSnapshot
	for _, node := range nodes {
		out = out.Add(node.PerfSnapshot())
	}
	return out
}

func collectQueue(nodes []*asyrand.Node) (total int, max int) {
	for _, node := range nodes {
		if node == nil || node.State == nil {
			continue
		}
		qTotal, qMax := node.State.QueueBacklog()
		total += qTotal
		if qMax > max {
			max = qMax
		}
	}
	return total, max
}

func (m metricSnapshot) sub(prev metricSnapshot) metricSnapshot {
	return metricSnapshot{
		sentMessages: m.sentMessages - prev.sentMessages,
		sentBytes:    m.sentBytes - prev.sentBytes,
		recvMessages: m.recvMessages - prev.recvMessages,
		recvBytes:    m.recvBytes - prev.recvBytes,
	}
}

func printMetrics(label string, nodes []*asyrand.Node, elapsed time.Duration, beacons uint64) {
	queueTotal, queueMax := collectQueue(nodes)
	printMetricDelta(label, collectMetrics(nodes), collectPerf(nodes), queueTotal, queueMax, elapsed, beacons)
}

func printMetricDelta(label string, delta metricSnapshot, perf asyrand.PerfSnapshot, queueTotal int, queueMax int, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	fmt.Printf("%s metrics beacons=%d throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s queue_total=%d queue_max=%d pvss_share_avg=%s pvss_verify_avg=%s pvss_prerecon_avg=%s pvss_recon_avg=%s rbc_avg=%s bls_sign_avg=%s bls_verify_avg=%s bls_agg_avg=%s\n",
		label, beacons, float64(beacons)*60/seconds,
		delta.sentMessages, delta.recvMessages, float64(delta.sentBytes)/1024,
		float64(delta.recvBytes)/1024, float64(delta.sentBytes+delta.recvBytes)/1024/seconds,
		queueTotal, queueMax,
		asyrand.AvgDuration(perf.PVSSShareTotal, perf.PVSSShareCount), asyrand.AvgDuration(perf.PVSSVerifyTotal, perf.PVSSVerifyCount),
		asyrand.AvgDuration(perf.PVSSPreReconTotal, perf.PVSSPreReconCount), asyrand.AvgDuration(perf.PVSSReconTotal, perf.PVSSReconCount),
		asyrand.AvgDuration(perf.RBCHandleTotal, perf.RBCHandleCount),
		asyrand.AvgDuration(perf.BLSSignTotal, perf.BLSSignCount),
		asyrand.AvgDuration(perf.BLSVerifyTotal, perf.BLSVerifyCount), asyrand.AvgDuration(perf.BLSAggregateTotal, perf.BLSAggregateCount))
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
