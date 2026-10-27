// Command asyrand runs the paper protocol over the existing memory/TCP layout.
package main

import (
	"Tyche/asyrand/config"
	asyrand "Tyche/asyrand/protocol"
	"Tyche/asyrand/protocol/aba"
	"Tyche/utils/p2p"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	path := flag.String("config", "configs/local_8.json", "deployment JSON")
	id := flag.String("node", "", "single TCP node; empty runs the local committee")
	transport := flag.String("transport", "", "memory or tcp override")
	duration := flag.Duration("duration", 0, "abort the run after this duration")
	history := flag.String("history", "", "write publicly verifiable history JSON")
	flag.Parse()
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if *id != "" {
		cfg.NodeID = p2p.NodeID(*id)
		cfg.Transport = "tcp"
	}
	if err = cfg.Validate(); err == nil {
		err = run(cfg, *duration, *history)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "asyrand:", err)
		os.Exit(1)
	}
}
func run(cfg config.Config, duration time.Duration, historyPath string) error {
	ctx, signalCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer signalCancel()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if duration > 0 {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, duration)
		defer stop()
	}
	ids := cfg.Members()
	if cfg.NodeID != "" {
		ids = []p2p.NodeID{cfg.NodeID}
	}
	network := p2p.NewMemoryNetwork()
	nodes := make([]*asyrand.Node, 0, len(ids))
	transports := make([]p2p.Transport, 0, len(ids))
	peers := cfg.PeerMap()
	for _, id := range ids {
		var t p2p.Transport
		if cfg.Transport == "tcp" {
			if cfg.AuthenticatedTCP {
				keys, pubs, err := cfg.KeyPairs()
				if err != nil {
					return err
				}
				t, err = p2p.NewAuthenticatedTCPTransport(id, cfg.ListenAddr(id), peers, cfg.TransportBuffer, keys[id].Private, pubs)
				if err != nil {
					return err
				}
			} else {
				t = p2p.NewTCPTransport(id, cfg.ListenAddr(id), peers, cfg.TransportBuffer)
			}
		} else {
			t = network.NewTransport(id, cfg.TransportBuffer)
		}
		node, err := asyrand.New(cfg, id, t)
		if err != nil {
			return err
		}
		nodes = append(nodes, node)
		transports = append(transports, t)
	}
	var probe *p2p.BenchmarkProbe
	if cfg.NodeID != "" {
		var err error
		probe, err = p2p.OpenBenchmark(string(cfg.NodeID), transports[0], uint64(cfg.Round+cfg.Warmup))
		if err != nil {
			return err
		}
	}
	defer probe.Close()
	defer func() {
		cancel()
		for _, n := range nodes {
			n.Stop()
		}
		for _, t := range transports {
			t.Close()
		}
	}()
	for _, n := range nodes {
		if err := n.Start(ctx); err != nil {
			return err
		}
	}
	var completed atomic.Uint64
	if cfg.ReportMS > 0 {
		go func() {
			ticker := time.NewTicker(time.Duration(cfg.ReportMS) * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					sent, recv, messages := metrics(nodes)
					fmt.Printf("progress completed=%d sent_msgs=%d sent_bytes=%d recv_bytes=%d\n", completed.Load(), messages, sent, recv)
				}
			}
		}()
	}
	fmt.Printf("config protocol=asyrand n=%d f=%d q=%d t=%d W=%d parallel=%t transport=%s session=%s\n", len(cfg.Members()), cfg.F, cfg.Quorum(), cfg.Threshold(), cfg.ProductionWindow, cfg.ParallelConsumption, cfg.Transport, cfg.SessionID)
	select {
	case <-time.After(time.Duration(cfg.PrefillMS) * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}
	for _, n := range nodes {
		n.Begin()
	}
	var first, runFirst time.Time
	var before, runBefore trafficSnapshot
	measured := 0
	for epoch := uint64(1); epoch <= uint64(cfg.Round+cfg.Warmup); epoch++ {
		wait, c := context.WithTimeout(ctx, time.Duration(cfg.EpochMS)*time.Millisecond)
		var sample asyrand.Entry
		for i, n := range nodes {
			e, err := n.WaitBeacon(wait, epoch)
			if err != nil {
				c()
				return fmt.Errorf("epoch %d node %s: %w (watchdog abort; no skipped beacon)", epoch, n.ID, err)
			}
			if i == 0 {
				sample = e
			} else if e.Record.Hash() != sample.Record.Hash() {
				c()
				return fmt.Errorf("inconsistent certified epoch %d", epoch)
			}
		}
		c()
		completed.Store(epoch)
		fmt.Printf("ts=%s epoch=%d column=%d source=%s digest=%s random=%s\n", time.Now().UTC().Format(time.RFC3339Nano), epoch, sample.Record.Column, sample.Record.Source, sample.Record.Hash(), sample.Record.Random)
		if runFirst.IsZero() {
			runFirst = time.Now()
			runBefore = snapshotTraffic(nodes)
		}
		if epoch <= uint64(cfg.Warmup) {
			continue
		}
		if first.IsZero() {
			if cfg.Warmup == 0 {
				first, before = runFirst, runBefore
			} else {
				first = time.Now()
				before = snapshotTraffic(nodes)
			}
		} else {
			measured++
		}
		if err := probe.Output(epoch, func() any { return nodes[0].BenchmarkStats() }); err != nil {
			return err
		}
	}
	elapsed := time.Since(first).Seconds()
	runElapsed := time.Since(runFirst).Seconds()
	after := snapshotTraffic(nodes)
	printTraffic("final", measured, elapsed, before, after)
	printTraffic("run", cfg.Round+cfg.Warmup-1, runElapsed, runBefore, after)
	if err := probe.Finish(ctx); err != nil {
		return err
	}
	if cfg.NodeID == "" || probe != nil {
		cancel()
		for _, n := range nodes {
			n.Stop()
		}
	}
	h := nodes[0].Export(uint64(cfg.Round + cfg.Warmup))
	if err := asyrand.VerifyHistory(nodes[0].Public, h); err != nil {
		return fmt.Errorf("public verification: %w", err)
	}
	fmt.Printf("verification valid_epochs=%d columns=%d\n", len(h.Entries), len(h.Columns)+1)
	instances := make(map[p2p.NodeID][]asyrand.ABAInstanceStats, len(nodes))
	for _, node := range nodes {
		instances[node.ID] = node.ABAStatistics()
	}
	instanceJSON, _ := json.Marshal(instances)
	fmt.Printf("final aba_instances %s\n", instanceJSON)
	if historyPath != "" {
		b, err := json.MarshalIndent(h, "", "  ")
		if err != nil {
			return err
		}
		if err = os.WriteFile(historyPath, b, 0600); err != nil {
			return err
		}
	}
	if cfg.NodeID != "" {
		fmt.Printf("benchmark_complete outputs=%d\n", cfg.Round+cfg.Warmup)
		if err := probe.Complete(); err != nil {
			return err
		}
		if probe != nil {
			time.Sleep(time.Duration(cfg.LingerMS) * time.Millisecond)
			return nil
		}
		select {
		case <-time.After(time.Duration(cfg.LingerMS) * time.Millisecond):
		case <-ctx.Done():
		}
	}
	return nil
}

type trafficSnapshot struct {
	sent, recv, messages uint64
	types                map[string]p2p.MessageTypeMetrics
}

func snapshotTraffic(nodes []*asyrand.Node) trafficSnapshot {
	types, complete := messageMetrics(nodes)
	if !complete {
		sent, recv, messages := metrics(nodes)
		return trafficSnapshot{sent, recv, messages, types}
	}
	// Derive all counters from the same frozen type snapshots. Reading separate
	// aggregate atomics while senders run can otherwise disagree with the split.
	var sent, recv, messages uint64
	for _, m := range types {
		sent += m.SentBytes
		recv += m.RecvBytes
		messages += m.SentMessages
	}
	return trafficSnapshot{sent, recv, messages, types}
}

func printTraffic(label string, beacons int, elapsed float64, before, after trafficSnapshot) {
	sent, recv, messages := after.sent-before.sent, after.recv-before.recv, after.messages-before.messages
	rps := 0.0
	if elapsed > 0 {
		rps = float64(beacons) / elapsed
	}
	fmt.Printf("%s metrics beacons=%d elapsed_s=%.6f throughput=%.2fbeacon/min beacon_s=%.6f sent_msgs=%d sent=%.2fKB recv=%.2fKB sent_bytes=%d recv_bytes=%d\n", label, beacons, elapsed, rps*60, rps, messages, float64(sent)/1024, float64(recv)/1024, sent, recv)
	types := make(map[string]p2p.MessageTypeMetrics, len(after.types))
	var core, cert, recovery, total uint64
	for name, m := range after.types {
		old := before.types[name]
		m.SentMessages -= old.SentMessages
		m.SentBytes -= old.SentBytes
		m.RecvMessages -= old.RecvMessages
		m.RecvBytes -= old.RecvBytes
		types[name] = m
		total += m.SentBytes
		if strings.HasPrefix(name, aba.Protocol+"/") {
			switch strings.TrimPrefix(name, aba.Protocol+"/") {
			case aba.PRE, aba.VOTE, aba.MAIN, aba.FINAL:
				core += m.SentBytes
			case aba.DECISION, aba.REQUEST, aba.RESPONSE:
				cert += m.SentBytes
			}
		} else if name == asyrand.Protocol+"/SYNC" || name == asyrand.Protocol+"/REPLAY" {
			recovery += m.SentBytes
		}
	}
	typeJSON, _ := json.Marshal(types)
	fmt.Printf("%s message_metrics %s\n", label, typeJSON)
	percent := 0.0
	if total > 0 {
		percent = 100 * float64(core+cert+recovery) / float64(total)
	}
	fmt.Printf("%s aba_metrics core_bytes=%d certificate_bytes=%d recovery_bytes=%d aba_bytes=%d type_total_bytes=%d aba_sent_pct=%.6f\n", label, core, cert, recovery, core+cert+recovery, total, percent)
}
func metrics(nodes []*asyrand.Node) (sent, recv, msg uint64) {
	for _, n := range nodes {
		m := n.Transport.Metrics()
		sent += m.SentBytes
		recv += m.RecvBytes
		msg += m.SentMessages
	}
	return
}

func messageMetrics(nodes []*asyrand.Node) (map[string]p2p.MessageTypeMetrics, bool) {
	out := make(map[string]p2p.MessageTypeMetrics)
	complete := true
	for _, node := range nodes {
		if tr, ok := node.Transport.(interface {
			MessageTypeMetrics() map[string]p2p.MessageTypeMetrics
		}); ok {
			for name, m := range tr.MessageTypeMetrics() {
				x := out[name]
				x.SentMessages += m.SentMessages
				x.SentBytes += m.SentBytes
				x.RecvMessages += m.RecvMessages
				x.RecvBytes += m.RecvBytes
				out[name] = x
			}
		} else {
			complete = false
		}
	}
	return out, complete
}
