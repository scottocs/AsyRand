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

	config "github.com/scottocs/asyrand/grandline/internal"
	asig "github.com/scottocs/asyrand/grandline/internal/crypto"
	"github.com/scottocs/asyrand/grandline/internal/dkg"
	"github.com/scottocs/asyrand/grandline/internal/grandline"
	"github.com/scottocs/asyrand/grandline/internal/p2p"
	"github.com/scottocs/asyrand/grandline/internal/pvss"
	"go.dedis.ch/kyber/v3"
)

type runtimeKeys struct {
	ids      []p2p.NodeID
	keys     map[p2p.NodeID]asig.KeyPair
	pubs     map[string]ed25519.PublicKey
	pvssKeys map[p2p.NodeID]pvss.KeyPair
	pvssPub  map[p2p.NodeID]kyber.Point
	seed     []byte
	dkg      dkg.Result
}

type runStats struct {
	beacons atomic.Uint64
}

func main() {
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
		node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)
		nodes = append(nodes, node)
	}

	printConfig(cfg, len(rt.ids), "memory")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, nodes, stats)
	defer stopReport()
	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)

	limit := uint64(cfg.Round)
	if duration > 0 {
		limit = ^uint64(0)
	}
	for epoch := uint64(0); epoch < limit; epoch++ {
		results := make(chan *grandline.Beacon, len(nodes))
		for _, node := range nodes {
			go func(node *grandline.Node) {
				b, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
				if err != nil {
					log.Printf("node %s epoch %d: %v", node.ID, epoch, err)
					results <- nil
					return
				}
				results <- b
			}(node)
		}

		var sample *grandline.Beacon
		for i := 0; i < len(nodes); i++ {
			b := <-results
			if b == nil {
				return fmt.Errorf("epoch %d failed to complete", epoch)
			}
			if sample == nil {
				sample = b
			}
		}
		stats.beacons.Add(1)
		if sample != nil {
			fmt.Printf("epoch=%d msg_hash=%s shares=%d signature=%s random=%x\n",
				sample.Epoch, sample.Commit, sample.Shares, sample.SigHex[:16], sample.Random[:8])
		}
		if duration > 0 && time.Since(start) >= duration {
			break
		}
	}
	printMetrics("final", nodes, time.Since(start), stats.beacons.Load())
	return nil
}

func runSingleNode(cfg config.Config, duration time.Duration) error {
	if cfg.NodeID == "" {
		return fmt.Errorf("tcp mode requires -node")
	}
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	start := time.Now()
	rt, err := prepareRuntime(cfg)
	if err != nil {
		return err
	}
	transport := p2p.NewTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), cfg.PeerMap(), 4096)
	node, err := newNode(cfg, rt, cfg.NodeID, transport)
	if err != nil {
		return err
	}
	if err := node.Start(runCtx); err != nil {
		return err
	}
	if err := waitForTCPPeers(runCtx, cfg.NodeID, cfg.PeerMap(), time.Duration(cfg.EpochMS)*time.Millisecond); err != nil {
		return err
	}
	node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)

	printConfig(cfg, 1, "tcp")
	stats := &runStats{}
	stopReport := startReporter(runCtx, cfg, []*grandline.Node{node}, stats)
	defer stopReport()

	time.Sleep(time.Duration(cfg.PrefillMS) * time.Millisecond)
	count := uint64(0)
	for {
		if duration > 0 && time.Since(start) >= duration {
			break
		}
		if uint64(cfg.Round) > 0 && count >= uint64(cfg.Round) {
			break
		}
		_, err := node.RunEpoch(runCtx, time.Duration(cfg.EpochMS)*time.Millisecond)
		if err != nil {
			return err
		}
		count++
		stats.beacons.Add(1)
	}
	printMetrics("final", []*grandline.Node{node}, time.Since(start), stats.beacons.Load())
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
	dkgResult, err := dkg.SetupFromSeed(ids, seed, cfg.F+1)
	if err != nil {
		return runtimeKeys{}, err
	}
	nodeSeeds, err := cfg.NodeSeedBytes()
	if err != nil {
		return runtimeKeys{}, err
	}
	pvssKeys := make(map[p2p.NodeID]pvss.KeyPair, len(ids))
	pvssPub := make(map[p2p.NodeID]kyber.Point, len(ids))
	for _, id := range ids {
		pk := pvss.KeyPairFromSeed(nodeSeeds[id])
		pvssKeys[id] = pk
		pvssPub[id] = pk.Public
	}
	return runtimeKeys{
		ids: ids, keys: keys, pubs: pubs, pvssKeys: pvssKeys, pvssPub: pvssPub, seed: seed, dkg: dkgResult,
	}, nil
}

func newNode(cfg config.Config, rt runtimeKeys, id p2p.NodeID, transport p2p.Transport) (*grandline.Node, error) {
	pvssScheme, err := pvss.NewScheme(id, cfg.F+1, rt.pvssKeys[id].Private, rt.pvssPub)
	if err != nil {
		return nil, err
	}
	return grandline.NewNode(grandline.NodeConfig{
		ID: id, Members: rt.ids, F: cfg.F, QueueLen: cfg.QueueLen, Seed: rt.seed, Keys: rt.keys[id],
		Public: rt.pubs, Transport: transport, PVSS: pvssScheme,
		CoinShare: rt.dkg.Shares[id], CoinPublic: rt.dkg.Public,
	})
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
	fmt.Printf("protocol=%s transport=%s nodes=%d f=%d rounds=%d queue_len=%d producer_ms=%d epoch_ms=%d report_ms=%d\n",
		cfg.Protocol, transport, nodes, cfg.F, cfg.Round, cfg.QueueLen, cfg.ProducerMS, cfg.EpochMS, cfg.ReportMS)
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
				totalPending, maxPending := collectQueue(nodes)
				printMetricDelta("periodic", current.sub(last), currentPerf.Sub(lastPerf), totalPending, maxPending, now.Sub(lastAt), currentBeacon-lastBeacon)
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

func collectQueue(nodes []*grandline.Node) (total int, max int) {
	for _, n := range nodes {
		if n == nil || n.State == nil {
			continue
		}
		t, m := n.State.QueueBacklog()
		total += t
		if m > max {
			max = m
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

func printMetrics(label string, nodes []*grandline.Node, elapsed time.Duration, beacons uint64) {
	queueTotal, queueMax := collectQueue(nodes)
	printMetricDelta(label, collectMetrics(nodes), collectPerf(nodes), queueTotal, queueMax, elapsed, beacons)
}

func printMetricDelta(label string, delta metricSnapshot, perf grandline.PerfSnapshot, queueTotal int, queueMax int, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	fmt.Printf("%s metrics beacons=%d throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s queue_total=%d queue_max=%d sign_avg=%s verify_avg=%s recover_avg=%s pvss_share_avg=%s pvss_verify_avg=%s\n",
		label,
		beacons,
		float64(beacons)*60/seconds,
		delta.sentMessages, delta.recvMessages,
		float64(delta.sentBytes)/1024,
		float64(delta.recvBytes)/1024,
		float64(delta.sentBytes+delta.recvBytes)/1024/seconds,
		queueTotal, queueMax,
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
	for id, addr := range peers {
		if id == self {
			continue
		}
		dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		cancel()
		if err != nil {
			return false
		}
		_ = conn.Close()
	}
	return true
}
