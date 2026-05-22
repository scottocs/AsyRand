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

	"github.com/scottocs/Tyche/spurt/config"
	asig "github.com/scottocs/Tyche/spurt/crypto"
	spurt "github.com/scottocs/Tyche/spurt/protocol"
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

const transportBuffer = 262144

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
	start := time.Now()
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
		node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)
		nodes = append(nodes, node)
	}

	printConfig(cfg, len(rt.ids), "memory")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, nodes, stats)
	defer stopReport()
	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)

	for epoch := uint64(0); epoch < uint64(cfg.Round); epoch++ {
		result := make(chan *spurt.Beacon, len(nodes))
		errCh := make(chan error, len(nodes))
		for _, node := range nodes {
			go func(n *spurt.Node) {
				b, err := n.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
				if err != nil {
					errCh <- err
					result <- nil
					return
				}
				result <- b
				errCh <- nil
			}(node)
		}
		var sample *spurt.Beacon
		for i := 0; i < len(nodes); i++ {
			b := <-result
			if err := <-errCh; err != nil {
				return err
			}
			if sample == nil {
				sample = b
			}
		}
		if sample == nil {
			return fmt.Errorf("epoch %d produced no beacon", epoch)
		}
		stats.beacons.Add(1)
		fmt.Printf("epoch=%d leader=%s digest=%s selected=%d random=%x\n",
			sample.Epoch, nodes[0].State.Leader(sample.Epoch), sample.Digest, sample.Committeds, sample.Random[:8])
	}
	printMetrics("final", nodes, time.Since(start), stats.beacons.Load())
	return nil
}

func runSingleNode(cfg config.Config, duration time.Duration) error {
	if cfg.NodeID == "" {
		return fmt.Errorf("tcp mode requires -node or node_id in config")
	}
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	start := time.Now()
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	nodeTransport := p2p.NewTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), cfg.PeerMap(), 4096)
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
	node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, []*spurt.Node{node}, stats)
	defer stopReport()

	printConfig(cfg, 1, "tcp")
	count := uint64(0)
	for {
		if duration > 0 && time.Since(start) >= duration {
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
		stats.beacons.Add(1)
		fmt.Printf("node=%s epoch=%d leader=%s digest=%s random=%x\n",
			node.ID, b.Epoch, node.State.Leader(b.Epoch), b.Digest, b.Random[:8])
	}
	printMetrics("final", []*spurt.Node{node}, time.Since(start), stats.beacons.Load())
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
	blsKeys := make(map[p2p.NodeID]asig.BLSKeyPair, len(ids))
	blsPublic := make(map[string]kyber.Point, len(ids))
	for _, id := range ids {
		pk := asig.PVSSKeyPairFromSeed(pvssSeeds[id])
		pvssKeys[id] = pk
		pvssPublic[id] = pk.Public
		bk := asig.NewBLSKeyPairFromSeed(pvssSeeds[id])
		blsKeys[id] = bk
		blsPublic[string(id)] = bk.Public
	}
	return runtimeKeys{
		ids: ids, keys: keys, pubs: pubs, pvssKeys: pvssKeys, pvssPublic: pvssPublic,
		blsKeys: blsKeys, blsPublic: blsPublic, seed: seed,
	}, nil
}

func newNode(cfg config.Config, rt runtimeKeys, id p2p.NodeID, transport p2p.Transport) (*spurt.Node, error) {
	pvssScheme, err := asig.NewPVSSScheme(id, cfg.F+1, rt.pvssKeys[id].Private, rt.pvssPublic)
	if err != nil {
		return nil, err
	}
	return spurt.NewNode(spurt.NodeConfig{
		ID: id, Members: rt.ids, F: cfg.F, QueueLen: cfg.QueueLen, Seed: rt.seed, Keys: rt.keys[id],
		Public: rt.pubs, BLS: rt.blsKeys[id], BLSPublic: rt.blsPublic,
		Transport: transport, PVSS: pvssScheme,
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
	fmt.Printf("protocol=%s transport=%s nodes=%d f=%d rounds=%d queue_len=%d producer_ms=%d epoch_ms=%d report_ms=%d\n",
		cfg.Protocol, transport, nodes, cfg.F, cfg.Round, cfg.QueueLen, cfg.ProducerMS, cfg.EpochMS, cfg.ReportMS)
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

func collectQueue(nodes []*spurt.Node) (total int, max int) {
	for _, node := range nodes {
		if node == nil || node.State == nil {
			continue
		}
		totalNode, maxNode := node.State.QueueBacklog()
		total += totalNode
		if maxNode > max {
			max = maxNode
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

func printMetrics(label string, nodes []*spurt.Node, elapsed time.Duration, beacons uint64) {
	queueTotal, queueMax := collectQueue(nodes)
	printMetricDelta(label, collectMetrics(nodes), collectPerf(nodes), queueTotal, queueMax, elapsed, beacons)
}

func printMetricDelta(label string, delta metricSnapshot, perf spurt.PerfSnapshot, queueTotal int, queueMax int, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	fmt.Printf("%s metrics beacons=%d throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s queue_total=%d queue_max=%d pvss_share_avg=%s pvss_verify_avg=%s pvss_prerecon_avg=%s pvss_recon_avg=%s spurt_vote_avg=%s bls_verify_avg=%s bls_agg_avg=%s\n",
		label, beacons, float64(beacons)*60/seconds,
		delta.sentMessages, delta.recvMessages, float64(delta.sentBytes)/1024,
		float64(delta.recvBytes)/1024, float64(delta.sentBytes+delta.recvBytes)/1024/seconds,
		queueTotal, queueMax,
		spurt.AvgDuration(perf.PVSSShareTotal, perf.PVSSShareCount), spurt.AvgDuration(perf.PVSSVerifyTotal, perf.PVSSVerifyCount),
		spurt.AvgDuration(perf.PVSSPreReconTotal, perf.PVSSPreReconCount), spurt.AvgDuration(perf.PVSSReconTotal, perf.PVSSReconCount),
		spurt.AvgDuration(perf.AgreementTotal, perf.AgreementCount),
		spurt.AvgDuration(perf.BLSVerifyTotal, perf.BLSVerifyCount), spurt.AvgDuration(perf.BLSAggregateTotal, perf.BLSAggregateCount),
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
