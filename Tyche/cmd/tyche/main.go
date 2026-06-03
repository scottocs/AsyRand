package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
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
	producerMS := flag.Int("producer-ms", 150, "producer interval in milliseconds")
	prefillMS := flag.Int("prefill-ms", 3000, "producer prefill time in milliseconds")
	epochTimeoutMS := flag.Int("epoch-timeout-ms", 10000, "timeout per epoch in milliseconds")
	reportMS := flag.Int("report-ms", 5000, "periodic metrics interval in milliseconds")
	maxPool := flag.Int("max-pool", 4, "maximum concurrent cryptographic worker tasks per node")
	transportBufferFlag := flag.Int("transport-buffer", 0, "transport inbox buffer length; defaults to a size scaled by n")
	removalExpirationMS := flag.Int("removal-expiration-ms", 0, "epoch-control ABA false-input timeout in milliseconds; defaults to a size scaled by n")
	pvss := flag.String("pvss", "o1", "PVSS backend: o1 or scrape")
	flag.Parse()

	opts := runOptions{
		n: *n, epochs: *epochs, f: *f, transport: strings.ToLower(*transport),
		nodeID: p2p.NodeID(*nodeID), peersRaw: *peersRaw, listenAddr: *listenAddr, listenIP: *listenIP,
		queueLen: *queueLen, producerMS: *producerMS, prefillMS: *prefillMS,
		epochTimeoutMS: *epochTimeoutMS, reportMS: *reportMS, maxPool: *maxPool,
		transportBuffer: *transportBufferFlag, removalExpirationMS: *removalExpirationMS,
		pvss: strings.ToLower(*pvss),
	}
	if err := run(opts); err != nil {
		log.Fatal(err)
	}
}

type runOptions struct {
	n                   int
	epochs              int
	f                   int
	transport           string
	nodeID              p2p.NodeID
	peersRaw            string
	listenAddr          string
	listenIP            string
	queueLen            int
	producerMS          int
	prefillMS           int
	epochTimeoutMS      int
	reportMS            int
	maxPool             int
	transportBuffer     int
	removalExpirationMS int
	pvss                string
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
	opts.transportBuffer = resolveTransportBuffer(opts)
	opts.removalExpirationMS = resolveRemovalExpirationMS(opts)
	if opts.transport == "tcp" {
		return runTCP(opts)
	}
	return runMemory(opts)
}

func runMemory(opts runOptions) error {
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
			ID:                id,
			Members:           ids,
			F:                 opts.f,
			QueueLen:          opts.queueLen,
			PVSS:              scheme,
			PVSSBackend:       opts.pvss,
			CryptoWorkers:     opts.maxPool,
			RemovalExpiration: time.Duration(opts.removalExpirationMS) * time.Millisecond,
			Transport:         net.NewTransport(id, opts.transportBuffer),
		})
		if err != nil {
			return err
		}
		node.Start(runCtx)
		node.StartProducer(runCtx, time.Duration(opts.producerMS)*time.Millisecond)
		nodes = append(nodes, node)
	}

	epochAttemptTimeout := tycheEpochAttemptTimeout(opts)
	fmt.Printf("config protocol=tyche-v1 transport=memory nodes=%d f=%d epochs=%d queue_len=%d producer_ms=%d epoch_timeout_ms=%d epoch_attempt_timeout_ms=%d report_ms=%d crypto_workers=%d transport_buffer=%d removal_expiration_ms=%d pvss=%s\n",
		opts.n, opts.f, opts.epochs, opts.queueLen, opts.producerMS, opts.epochTimeoutMS, int(epochAttemptTimeout/time.Millisecond), opts.reportMS, opts.maxPool, opts.transportBuffer, opts.removalExpirationMS, opts.pvss)

	stats := &runStats{}
	stopReport := startReporter(runCtx, nodes, stats, time.Duration(opts.reportMS)*time.Millisecond)
	defer stopReport()
	time.Sleep(time.Duration(opts.prefillMS) * time.Millisecond)
	var finalWindow finalMetricWindow

	for epoch := 1; epoch <= opts.epochs; epoch++ {
		epochCtx, cancelEpoch := context.WithTimeout(runCtx, epochAttemptTimeout)
		results := make(chan result, len(nodes))
		for _, node := range nodes {
			go func(node *tyche.Node, epoch uint64) {
				b, err := node.RunEpochAt(epochCtx, epoch)
				results <- result{beacon: b, err: err}
			}(node, uint64(epoch))
		}

		var sample tyche.Beacon
		for i := 0; i < len(nodes); i++ {
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
		finalWindow.recordBeacon(nodes)
	}

	queueTotal, queueMax := collectQueue(nodes)
	finalWindow.print(nodes, queueTotal, queueMax)
	printMessageTypeMetrics(nodes)
	return nil
}

func runTCP(opts runOptions) error {
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
		RemovalExpiration: time.Duration(opts.removalExpirationMS) * time.Millisecond, Transport: transport,
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
	fmt.Printf("config protocol=tyche-v1 transport=tcp node=%s listen=%s nodes=%d f=%d epochs=%d queue_len=%d producer_ms=%d epoch_timeout_ms=%d epoch_attempt_timeout_ms=%d report_ms=%d crypto_workers=%d transport_buffer=%d removal_expiration_ms=%d pvss=%s peers=%v\n",
		opts.nodeID, listen, opts.n, opts.f, opts.epochs, opts.queueLen, opts.producerMS, opts.epochTimeoutMS, int(epochAttemptTimeout/time.Millisecond), opts.reportMS, opts.maxPool, opts.transportBuffer, opts.removalExpirationMS, opts.pvss, peers)
	stats := &runStats{}
	stopReport := startReporter(runCtx, nodes, stats, time.Duration(opts.reportMS)*time.Millisecond)
	defer stopReport()
	time.Sleep(time.Duration(opts.prefillMS) * time.Millisecond)
	if completed := node.CompletedEpoch(); completed > 0 {
		fmt.Printf("node=%s prefilled_epochs=%d counted=0\n", opts.nodeID, completed)
	}
	var finalWindow finalMetricWindow

	for counted := 0; counted < opts.epochs; counted++ {
		epochCtx, cancelEpoch := context.WithTimeout(runCtx, epochAttemptTimeout)
		targetEpoch := uint64(counted + 1)
		beacon, err := node.RunEpochAt(epochCtx, targetEpoch)
		cancelEpoch()
		if err != nil {
			return fmt.Errorf("epoch %d: %w", counted+1, err)
		}
		stats.beacons.Add(1)
		fmt.Printf("ts=%s node=%s epoch=%d source=%s seq=%d random=%x\n", logTimestamp(), opts.nodeID, beacon.Epoch, beacon.Source, beacon.Seq, beacon.Random[:8])
		finalWindow.recordBeacon(nodes)
	}
	queueTotal, queueMax := collectQueue(nodes)
	finalWindow.print(nodes, queueTotal, queueMax)
	printMessageTypeMetrics(nodes)
	return nil
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
	return func() { close(done) }
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
	if len(types) == 0 {
		return
	}
	keys := make([]string, 0, len(types))
	for key := range types {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		stats := types[key]
		fmt.Printf("message_type type=%s sent_msgs=%d sent=%.2fKB\n", key, stats.SentMessages, float64(stats.SentBytes)/1024)
	}
}
