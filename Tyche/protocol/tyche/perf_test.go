package tyche

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/scottocs/Tyche/Tyche/crypto"
	"github.com/scottocs/Tyche/Tyche/protocol/aba"
	"github.com/scottocs/Tyche/utils/p2p"
)

func TestBeacon8Nodes100EpochsPerformance(t *testing.T) {
	if os.Getenv("TYCHE_BEACON_PERF") != "1" {
		t.Skip("set TYCHE_BEACON_PERF=1 to run the 8-node/100-epoch beacon performance test")
	}
	epochs := envInt("TYCHE_BEACON_EPOCHS", 100)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	ids := make([]p2p.NodeID, 8)
	for i := range ids {
		ids[i] = p2p.NodeID(fmt.Sprintf("n%d", i))
	}
	pp, keys, err := crypto.Setup("perf-8x100", 3, ids)
	if err != nil {
		t.Fatal(err)
	}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Node, 0, len(ids))
	transports := make([]p2p.Transport, 0, len(ids))
	for _, id := range ids {
		s, err := crypto.NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		transport := net.NewTransport(id, 16384)
		node, err := NewNode(Config{ID: id, Members: ids, F: 2, QueueLen: 2, PVSS: s, Transport: transport})
		if err != nil {
			t.Fatal(err)
		}
		node.Start(ctx)
		nodes = append(nodes, node)
		transports = append(transports, transport)
	}
	for _, node := range nodes {
		node.StartProducer(ctx, 20*time.Millisecond)
	}
	waitQueuesAtLeast(t, ctx, nodes, 1)

	before := aggregateMetrics(transports)
	start := time.Now()
	for e := 0; e < epochs; e++ {
		source, seq := nextSourceSeq(nodes[0])
		waitStored(t, ctx, nodes, source, seq)

		results := make(chan Beacon, len(nodes))
		errs := make(chan error, len(nodes))
		for _, node := range nodes {
			go func(node *Node) {
				b, err := node.RunEpochAt(ctx, uint64(e+1))
				if err != nil {
					errs <- err
					return
				}
				results <- b
			}(node)
		}
		var first Beacon
		epochTimer := time.NewTimer(10 * time.Second)
		for i := 0; i < len(nodes); i++ {
			select {
			case err := <-errs:
				epochTimer.Stop()
				t.Fatalf("run epoch %d: %v", e+1, err)
			case b := <-results:
				if i == 0 {
					first = b
				} else if string(first.Random) != string(b.Random) || first.Source != b.Source || first.Seq != b.Seq {
					epochTimer.Stop()
					t.Fatalf("epoch %d mismatch: first=%+v got=%+v", e+1, first, b)
				}
			case <-epochTimer.C:
				t.Fatalf("epoch %d exceeded 10s without all beacon outputs\n%s", e+1, dumpNodes(nodes))
			case <-ctx.Done():
				epochTimer.Stop()
				t.Fatalf("timed out at epoch %d: %v", e+1, ctx.Err())
			}
		}
		epochTimer.Stop()
		if (e+1)%10 == 0 {
			t.Logf("completed %d/%d epochs in %s", e+1, epochs, time.Since(start))
		}
	}
	elapsed := time.Since(start)
	after := aggregateMetrics(transports)
	sentMessages := after.SentMessages - before.SentMessages
	sentBytes := after.SentBytes - before.SentBytes
	t.Logf("tyche beacon perf: nodes=%d epochs=%d elapsed=%s throughput=%.2f epochs/s sent_messages=%d sent_bytes=%d bandwidth=%.2f MiB/s bytes_per_epoch=%.2f KiB",
		len(nodes), epochs, elapsed, float64(epochs)/elapsed.Seconds(), sentMessages, sentBytes,
		float64(sentBytes)/(1024*1024)/elapsed.Seconds(), float64(sentBytes)/float64(epochs)/1024)
}

func aggregateMetrics(transports []p2p.Transport) p2p.Metrics {
	var out p2p.Metrics
	for _, transport := range transports {
		m := transport.Metrics()
		out.SentMessages += m.SentMessages
		out.SentBytes += m.SentBytes
		out.RecvMessages += m.RecvMessages
		out.RecvBytes += m.RecvBytes
	}
	return out
}

func waitQueuesAtLeast(t *testing.T, ctx context.Context, nodes []*Node, depth int) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		ok := true
		for _, observer := range nodes {
			observer.mu.Lock()
			for _, producer := range nodes {
				if len(observer.State.ComQ[producer.ID]) < depth {
					ok = false
					break
				}
			}
			observer.mu.Unlock()
			if !ok {
				break
			}
		}
		if ok {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("timed out waiting for producer queues to reach depth %d", depth)
		}
	}
}

func nextSourceSeq(n *Node) (p2p.NodeID, uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	idx := beaconIndex(n.State.RPrev, len(n.State.SCL))
	source := n.State.SCL[idx]
	return source, n.State.Seqs[source] + 1
}

func dumpNodes(nodes []*Node) string {
	out := ""
	for _, n := range nodes {
		n.mu.Lock()
		queueDepths := make(map[p2p.NodeID]int, len(n.State.ComQ))
		queueSeqs := make(map[p2p.NodeID][]uint64, len(n.State.ComQ))
		for id, q := range n.State.ComQ {
			queueDepths[id] = len(q)
			for seq := range q {
				queueSeqs[id] = append(queueSeqs[id], seq)
			}
		}
		reconCounts := make(map[string]int, len(n.recon))
		for key, shares := range n.recon {
			reconCounts[key] = len(shares)
		}
		echoCounts := make(map[string]int, len(n.echoes))
		for key, byRandom := range n.echoes {
			for random, senders := range byRandom {
				echoCounts[key+"/"+random] = len(senders)
			}
		}
		readyCounts := make(map[string]int, len(n.readies))
		for key, byRandom := range n.readies {
			for random, senders := range byRandom {
				readyCounts[key+"/"+random] = len(senders)
			}
		}
		abaStatuses := make(map[string]aba.Status, len(n.State.PendingABAs))
		for inst := range n.State.PendingABAs {
			abaStatuses[inst] = n.ABA.Status(inst)
		}
		out += fmt.Sprintf("node=%s epoch=%d scl=%v rsq=%v seqs=%v queues=%v queue_seqs=%v pending=%v aba=%v recon=%v recon_done=%v echoes=%v readies=%v seeds=%d verified=%d\n",
			n.ID, n.State.Epoch, n.State.SCL, n.State.RSQ, n.State.Seqs, queueDepths, queueSeqs, n.State.PendingABAs, abaStatuses,
			reconCounts, n.reconDone, echoCounts, readyCounts, len(n.beaconSeeds), len(n.verified))
		n.mu.Unlock()
	}
	return out
}

func envInt(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
