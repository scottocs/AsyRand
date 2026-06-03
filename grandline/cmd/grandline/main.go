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

	config "github.com/scottocs/Tyche/grandline/config"
	asig "github.com/scottocs/Tyche/grandline/crypto"
	grandline "github.com/scottocs/Tyche/grandline/protocol"
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type runtimeKeys struct {
	ids      []p2p.NodeID
	keys     map[p2p.NodeID]asig.KeyPair
	pubs     map[string]ed25519.PublicKey
	pvssKeys map[p2p.NodeID]asig.PVSSKeyPair
	pvssPub  map[p2p.NodeID]kyber.Point
	seed     []byte
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
	runStart := time.Now()
	var finalWindow finalMetricWindow

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
			} else if sample.Epoch != b.Epoch || string(sample.Random) != string(b.Random) || sample.Skipped != b.Skipped {
				return fmt.Errorf("epoch %d inconsistent beacon: sample_epoch=%d sample_skipped=%t got_epoch=%d got_skipped=%t",
					epoch, sample.Epoch, sample.Skipped, b.Epoch, b.Skipped)
			}
		}
		if sample != nil && sample.Skipped {
			fmt.Printf("ts=%s epoch=%d skipped stage=%s reason=%s random=%x diag=\"%s\"\n", logTimestamp(), sample.Epoch, sample.SkipStage, sample.SkipReason, sample.Random[:8], sample.SkipDiag)
			continue
		}
		stats.beacons.Add(1)
		if sample != nil {
			fmt.Printf("ts=%s epoch=%d msg_hash=%s shares=%d signature=%s random=%x\n",
				logTimestamp(), sample.Epoch, sample.Commit, sample.Shares, sample.SigHex[:16], sample.Random[:8])
		}
		finalWindow.recordBeacon(nodes)
		if duration > 0 && time.Since(runStart) >= duration {
			break
		}
	}
	queueTotal, queueMax := collectQueue(nodes)
	finalWindow.print(nodes, queueTotal, queueMax)
	return nil
}

func runSingleNode(cfg config.Config, duration time.Duration) error {
	if cfg.NodeID == "" {
		return fmt.Errorf("tcp mode requires -node")
	}
	runCtx, cancel := runtimeContext(cfg, duration)
	defer cancel()
	peers := cfg.PeerMap()
	transport := p2p.NewTCPTransport(cfg.NodeID, cfg.ListenAddr(cfg.NodeID), peers, p2p.TCPBufferForPeers(len(peers)))
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
	node.StartProducer(runCtx, time.Duration(cfg.ProducerMS)*time.Millisecond)

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
				logTimestamp(), node.ID, b.Epoch, b.Commit, b.Shares, b.SigHex[:16], b.Random[:8])
		}
		finalWindow.recordBeacon(nodes)
	}
	queueTotal, queueMax := collectQueue(nodes)
	finalWindow.print(nodes, queueTotal, queueMax)
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
	pvssSchemes := make(map[p2p.NodeID]*asig.PVSSPairingFreeScheme, len(ids))
	for _, id := range ids {
		scheme, err := asig.NewPVSSScheme(id, cfg.F+1, pvssKeys[id].Private, pvssPub)
		if err != nil {
			return runtimeKeys{}, err
		}
		pvssSchemes[id] = scheme
	}
	grandResult, err := asig.SetupGRandFromAPVSS(ids, pvssSchemes, cfg.F+1)
	if err != nil {
		return runtimeKeys{}, err
	}
	return runtimeKeys{
		ids: ids, keys: keys, pubs: pubs, pvssKeys: pvssKeys, pvssPub: pvssPub, seed: seed, grand: grandResult,
	}, nil
}

func newNode(cfg config.Config, rt runtimeKeys, id p2p.NodeID, transport p2p.Transport) (*grandline.Node, error) {
	pvssScheme, err := asig.NewPVSSScheme(id, cfg.F+1, rt.pvssKeys[id].Private, rt.pvssPub)
	if err != nil {
		return nil, err
	}
	return grandline.NewNode(grandline.NodeConfig{
		ID: id, Members: rt.ids, F: cfg.F, QueueLen: cfg.QueueLen, Seed: rt.seed, Keys: rt.keys[id],
		Public: rt.pubs, Transport: transport, PVSS: pvssScheme,
		GRand: rt.grand.ShareFor(id), CryptoWorkers: cfg.MaxPool,
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
	fmt.Printf("protocol=%s transport=%s nodes=%d f=%d rounds=%d queue_len=%d producer_ms=unused epoch_ms=%d report_ms=%d crypto_workers=%d\n",
		cfg.Protocol, transport, nodes, cfg.F, cfg.Round, cfg.QueueLen, cfg.EpochMS, cfg.ReportMS, cfg.MaxPool)
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

func (w *finalMetricWindow) print(nodes []*grandline.Node, queueTotal int, queueMax int) {
	if !w.started {
		printMetricDelta("final", metricSnapshot{}, grandline.PerfSnapshot{}, queueTotal, queueMax, 0, 0)
		return
	}
	printMetricDelta("final", collectMetrics(nodes).sub(w.metrics), collectPerf(nodes).Sub(w.perf), queueTotal, queueMax, time.Since(w.start), w.beacons)
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

func logTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func printMetricDelta(label string, delta metricSnapshot, perf grandline.PerfSnapshot, queueTotal int, queueMax int, elapsed time.Duration, beacons uint64) {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	fmt.Printf("%s metrics beacons=%d elapsed_s=%.3f throughput=%.2fbeacon/min sent_msgs=%d recv_msgs=%d sent=%.2fKB recv=%.2fKB bandwidth=%.2fKB/s queue_total=%d queue_max=%d sign_avg=%s verify_avg=%s recover_avg=%s pvss_share_avg=%s pvss_verify_avg=%s\n",
		label,
		beacons,
		elapsed.Seconds(),
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
