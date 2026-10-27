package asyrand

import (
	"Tyche/asyrand/config"
	"Tyche/asyrand/crypto"
	"Tyche/asyrand/protocol/aba"
	"Tyche/asyrand/protocol/rbc"
	"Tyche/utils/p2p"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testConfig(n int, parallel bool) config.Config {
	c := config.Config{Name: "test", Protocol: "asyrand-v2", Transport: "memory", F: (n - 1) / 3, Round: 12, EpochMS: 30000, MaxPool: 2, ProductionWindow: 2, TransportBuffer: 8192, SendRetryMS: 10, RecoveryMS: 1000, ABAFutureRounds: 4, HistoryBatch: 4, SessionID: fmt.Sprintf("test-%d-%t", n, parallel), ParallelConsumption: parallel, ClusterIndex: make(map[p2p.NodeID]int), NodeSeeds: make(map[p2p.NodeID]string)}
	for i := 0; i < n; i++ {
		id := p2p.NodeID(fmt.Sprintf("node%d", i))
		c.ClusterIndex[id] = i
		seed := make([]byte, ed25519.SeedSize)
		seed[0] = byte(i + 1)
		c.NodeSeeds[id] = hex.EncodeToString(seed)
	}
	return c
}
func testCluster(t *testing.T, n int, parallel bool, silent int) ([]*Node, context.Context) {
	t.Helper()
	return testConfiguredCluster(t, testConfig(n, parallel), silent)
}
func testConfiguredCluster(t *testing.T, cfg config.Config, silent int) ([]*Node, context.Context) {
	t.Helper()
	n := len(cfg.ClusterIndex)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	net := p2p.NewMemoryNetwork()
	var nodes []*Node
	var transports []p2p.Transport
	for _, id := range cfg.Members() {
		tr := net.NewTransport(id, cfg.TransportBuffer)
		transports = append(transports, tr)
		node, err := New(cfg, id, tr)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
	}
	t.Cleanup(func() {
		cancel()
		for _, node := range nodes {
			node.Stop()
		}
		for _, tr := range transports {
			tr.Close()
		}
	})
	nodes = nodes[:n-silent]
	for _, node := range nodes {
		if err := node.Start(ctx); err != nil {
			t.Fatal(err)
		}
		node.Begin()
	}
	return nodes, ctx
}
func TestProtocolAndPublicHistory(t *testing.T) {
	for _, n := range []int{4, 8} {
		for _, parallel := range []bool{false, true} {
			t.Run(fmt.Sprintf("n%d-parallel%t", n, parallel), func(t *testing.T) {
				nodes, ctx := testCluster(t, n, parallel, 0)
				outputs := uint64(2*n + 1)
				for e := uint64(1); e <= outputs; e++ {
					hash := ""
					for _, node := range nodes {
						entry, err := node.WaitBeacon(ctx, e)
						if err != nil {
							t.Fatalf("epoch %d: %v", e, err)
						}
						if hash != "" && entry.Record.Hash() != hash {
							t.Fatal("agreement failure")
						}
						hash = entry.Record.Hash()
					}
				}
				h := nodes[0].Export(outputs)
				for _, object := range h.Genesis.Objects {
					if object.Transcript.Version != "AsyRand-v1/ALBATROSS-DDH/edwards25519" || len(object.Transcript.Proof.Coefficients) != nodes[0].Config.Threshold() {
						t.Fatal("protocol did not use ALBATROSS PVSS")
					}
				}
				if err := VerifyHistory(nodes[0].Public, h); err != nil {
					t.Fatal(err)
				}
				for _, mutate := range []func(*History){func(x *History) { x.Entries[0].Record.Random = string(make([]byte, 64)) }, func(x *History) { x.Entries[0].Record.NextColumnHash = "bad" }, func(x *History) { x.Entries[0].Shares = append(x.Entries[0].Shares, x.Entries[0].Shares[0]) }, func(x *History) { x.Genesis.Objects[0].Delivery.Signatures[0].Signature = "00" }, func(x *History) { x.Genesis.Record.Accepted[0].Hash = "bad" }, func(x *History) { x.Entries[0].Shares = x.Entries[0].Shares[:1] },
					func(x *History) { x.Entries[0].Shares[1] = x.Entries[0].Shares[0] },
					func(x *History) { x.Entries[0].Shares[0].Proof.R = "00" },
					func(x *History) { x.Entries[0].Shares[0].Proof.A = "" },
					func(x *History) { x.Entries[0].Shares[0].Proof.B = "" },
					func(x *History) { x.Entries[0].Shares[0].Holder = "unknown" }} {
					bad := clone(h)
					mutate(&bad)
					if VerifyHistory(nodes[0].Public, bad) == nil {
						t.Fatal("accepted tampered public history")
					}
				}
				// Every record references its preceding BEACON, including a boundary.
				previous := genesis(nodes[0].Public, h.Genesis).PreviousHash
				for _, e := range h.Entries {
					if e.Record.PreviousHash != previous {
						t.Fatal("column advancement inserted an extra history hash")
					}
					previous = e.Record.Hash()
				}
				// The first f records in parallel mode uniformly omit next-column hashes.
				used := make(map[uint64]int)
				for _, e := range h.Entries {
					pos := used[e.Record.Column]
					used[e.Record.Column]++
					expected := !parallel || pos >= nodes[0].Config.F
					if (e.Record.NextColumnHash != "") != expected {
						t.Fatal("incorrect look-ahead barrier")
					}
				}
			})
		}
	}
}
func TestSilentFaultsRequireCompleteObjectDecisions(t *testing.T) {
	for _, n := range []int{4, 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			nodes, ctx := testCluster(t, n, false, (n-1)/3)
			for e := uint64(1); e <= uint64(n+2); e++ {
				for _, node := range nodes {
					if _, err := node.WaitBeacon(ctx, e); err != nil {
						t.Fatalf("epoch %d: %v", e, err)
					}
				}
			}
			h := nodes[0].Export(uint64(n + 2))
			if err := VerifyHistory(nodes[0].Public, h); err != nil {
				t.Fatal(err)
			}
			if h.Genesis.Record.Whole != aba.Zero || len(h.Genesis.Decisions) != n || len(h.Genesis.Record.Accepted) != n-nodes[0].Config.F {
				t.Fatal("missing certified rejection or quorum")
			}
		})
	}
}

func TestParallelSilentFaultsWithAggressiveRecovery(t *testing.T) {
	for _, n := range []int{4, 8} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			cfg := testConfig(n, true)
			cfg.RecoveryMS = 100
			nodes, ctx := testConfiguredCluster(t, cfg, cfg.F)
			outputs := uint64(n + 2)
			for epoch := uint64(1); epoch <= outputs; epoch++ {
				previous := ""
				for _, node := range nodes {
					e, err := node.WaitBeacon(ctx, epoch)
					if err != nil {
						t.Fatalf("epoch=%d node=%s: %v", epoch, node.ID, err)
					}
					if previous != "" && previous != e.Record.Hash() {
						t.Fatal("parallel fault agreement failure")
					}
					previous = e.Record.Hash()
				}
			}
			h := nodes[0].Export(outputs)
			if err := VerifyHistory(nodes[0].Public, h); err != nil {
				t.Fatal(err)
			}
			for _, col := range append([]Column{h.Genesis}, h.Columns...) {
				if col.Record.Whole != aba.Zero || len(col.Decisions) != n || len(col.Record.Accepted) != cfg.Quorum() {
					t.Fatal("parallel fault path lacks complete decisions or accepted quorum")
				}
			}
			positions := make(map[uint64]int)
			for _, entry := range h.Entries {
				position := positions[entry.Record.Column]
				positions[entry.Record.Column]++
				if (entry.Record.NextColumnHash != "") != (position >= cfg.F) {
					t.Fatal("parallel fault path bypassed the position-dependent successor barrier")
				}
			}
		})
	}
}

func TestLateMemberPullsCertifiedHistory(t *testing.T) {
	cfg := testConfig(4, false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	net := p2p.NewMemoryNetwork()
	var nodes []*Node
	var trs []p2p.Transport
	for _, id := range cfg.Members() {
		tr := net.NewTransport(id, 8192)
		node, err := New(cfg, id, tr)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
		trs = append(trs, tr)
	}
	defer func() {
		cancel()
		for _, n := range nodes {
			n.Stop()
		}
		for _, tr := range trs {
			tr.Close()
		}
	}()
	for _, n := range nodes[:3] {
		if err := n.Start(ctx); err != nil {
			t.Fatal(err)
		}
		n.Begin()
	}
	for _, n := range nodes[:3] {
		if _, err := n.WaitBeacon(ctx, 6); err != nil {
			t.Fatal(err)
		}
	}
	if err := nodes[3].Start(ctx); err != nil {
		t.Fatal(err)
	}
	nodes[3].Begin()
	e, err := nodes[3].WaitBeacon(ctx, 6)
	if err != nil {
		t.Fatal(err)
	}
	first, err := nodes[0].WaitBeacon(ctx, 6)
	if err != nil || first.Record.Hash() != e.Record.Hash() {
		t.Fatal("late receiver history diverged")
	}
	if err := VerifyHistory(nodes[3].Public, nodes[3].Export(6)); err != nil {
		t.Fatal(err)
	}
}
func TestFutureABACoreAdmissionDoesNotAllocateRounds(t *testing.T) {
	nodes, ctx := testCluster(t, 4, false, 0)
	for _, n := range nodes {
		if _, err := n.WaitBeacon(ctx, 1); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan bool, 1)
	nodes[0].post(func() {
		a := nodes[0].instances[columnID(2)]
		before := a.Status()
		fake, _ := p2p.NewMessage(aba.Protocol, aba.PRE, columnID(2), nodes[1].ID, nodes[0].ID, aba.CoreMessage{CommitteeID: a.Verifier().CommitteeID(), Round: 1000000, Value: aba.Zero, SigHex: "00"})
		nodes[0].routeABA(fake)
		after := a.Status()
		done <- before.Round == after.Round
	})
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("future ABA packet advanced state")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestTCPDeployment(t *testing.T) {
	cfg := testConfig(4, false)
	cfg.Transport = "tcp"
	cfg.ListenIP = "127.0.0.1"
	cfg.Peers = nil
	peers := map[p2p.NodeID]string{}
	for _, id := range cfg.Members() {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		peers[id] = listener.Addr().String()
		cfg.Peers = append(cfg.Peers, config.Peer{ID: id, Addr: peers[id]})
		listener.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	var nodes []*Node
	var transports []p2p.Transport
	defer func() {
		cancel()
		for _, n := range nodes {
			n.Stop()
		}
		for _, tr := range transports {
			tr.Close()
		}
	}()
	for _, id := range cfg.Members() {
		tr := p2p.NewTCPTransport(id, cfg.ListenAddr(id), peers, 8192)
		node, err := New(cfg, id, tr)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
		transports = append(transports, tr)
	}
	for _, n := range nodes {
		if err := n.Start(ctx); err != nil {
			t.Fatal(err)
		}
		n.Begin()
	}
	for epoch := uint64(1); epoch <= 9; epoch++ {
		hash := ""
		for _, n := range nodes {
			e, err := n.WaitBeacon(ctx, epoch)
			if err != nil {
				t.Fatal(err)
			}
			if hash != "" && hash != e.Record.Hash() {
				t.Fatal("TCP disagreement")
			}
			hash = e.Record.Hash()
		}
	}
	if err := VerifyHistory(nodes[0].Public, nodes[0].Export(9)); err != nil {
		t.Fatal(err)
	}
}

// The laggard receives witnesses but no ordinary peer RECON packets. It must
// still release its own RECON exactly once for each recovered state before
// installing that state, and must never introduce an output-vote phase.
type recoveryTransport struct {
	p2p.Transport
	inbox    chan p2p.Message
	mu       sync.Mutex
	released map[uint64]int
	votes    int
}

func (t *recoveryTransport) Inbox() <-chan p2p.Message { return t.inbox }
func (t *recoveryTransport) Start(ctx context.Context) error {
	if err := t.Transport.Start(ctx); err != nil {
		return err
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-t.Transport.Inbox():
				if !ok {
					return
				}
				if m.Protocol == Protocol && m.Type == "RECON" && m.From != t.ID() {
					continue
				}
				select {
				case t.inbox <- m:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return nil
}
func (t *recoveryTransport) Send(ctx context.Context, to p2p.NodeID, m p2p.Message) error {
	if m.Protocol == Protocol && to == t.ID() {
		t.mu.Lock()
		if m.Type == "VOTE" {
			t.votes++
		}
		if m.Type == "RECON" {
			env, _ := p2p.DecodePayload[envelope](m)
			var p reconPacket
			json.Unmarshal(env.Body, &p)
			t.released[p.Header.Epoch]++
		}
		t.mu.Unlock()
	}
	return t.Transport.Send(ctx, to, m)
}
func TestRecoveredWitnessReleasesOwnShare(t *testing.T) {
	cfg := testConfig(4, false)
	cfg.RecoveryMS = 100
	net := p2p.NewMemoryNetwork()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	var nodes []*Node
	var trs []p2p.Transport
	var lag *recoveryTransport
	for i, id := range cfg.Members() {
		var tr p2p.Transport = net.NewTransport(id, 8192)
		if i == 3 {
			lag = &recoveryTransport{Transport: tr, inbox: make(chan p2p.Message, 8192), released: make(map[uint64]int)}
			tr = lag
		}
		node, err := New(cfg, id, tr)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
		trs = append(trs, tr)
	}
	defer func() {
		cancel()
		for _, n := range nodes {
			n.Stop()
		}
		for _, tr := range trs {
			tr.Close()
		}
	}()
	for _, n := range nodes {
		if err := n.Start(ctx); err != nil {
			t.Fatal(err)
		}
		n.Begin()
	}
	if _, err := nodes[3].WaitBeacon(ctx, 8); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHistory(nodes[3].Public, nodes[3].Export(8)); err != nil {
		t.Fatal(err)
	}
	// Senders are asynchronous: wait for queued loopback emissions to drain.
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		lag.mu.Lock()
		complete := true
		for e := uint64(1); e <= 8; e++ {
			if lag.released[e] != 1 {
				complete = false
			}
		}
		votes := lag.votes
		lag.mu.Unlock()
		if votes != 0 {
			t.Fatal("unexpected beacon output vote")
		}
		if complete {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("missing or repeated recovery RECON")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestStoppedABAHelperDoesNotPullFutureRounds(t *testing.T) {
	cfg := testConfig(4, false)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	keys, _, _ := cfg.KeyPairs()
	instances := map[p2p.NodeID]*aba.Instance{}
	var queue []p2p.Message
	for _, id := range cfg.Members() {
		a, err := aba.New(aba.Config{PublicConfig: node.Public.ABA(), ID: id, Instance: columnID(1), Private: keys[id].Private})
		if err != nil {
			t.Fatal(err)
		}
		instances[id] = a
		out, err := a.Propose(aba.Zero)
		if err != nil {
			t.Fatal(err)
		}
		queue = append(queue, out...)
	}
	for steps := 0; len(queue) > 0; steps++ {
		if steps > 10000 {
			t.Fatal("ABA help did not stop")
		}
		m := queue[0]
		queue = queue[1:]
		for _, id := range cfg.Members() {
			if m.To != "" && m.To != id {
				continue
			}
			out, err := instances[id].Handle(m)
			if err != nil {
				t.Fatal(err)
			}
			queue = append(queue, out...)
		}
	}
	a := instances[node.ID]
	if !a.Status().Stopped {
		t.Fatal("unanimous ABA helper failed to stop")
	}
	node.instances[columnID(1)] = a
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	round := a.Status().Round + 1000
	from := p2p.NodeID("node1")
	statement := encode(struct {
		Domain, CommitteeID, Instance string
		Sender                        p2p.NodeID
		Round                         uint64
		Phase                         string
		Value                         aba.Value
	}{aba.Protocol + "/core", a.Verifier().CommitteeID(), columnID(1), from, round, aba.PRE, aba.Zero})
	m, _ := p2p.NewMessage(aba.Protocol, aba.PRE, columnID(1), from, node.ID, aba.CoreMessage{CommitteeID: a.Verifier().CommitteeID(), Round: round, Value: aba.Zero, SigHex: hex.EncodeToString(crypto.Sign(keys[from].Private, statement))})
	if !a.VerifyCoreMessage(m) {
		t.Fatal("test did not produce authenticated future packet")
	}
	node.routeABA(m)
	for _, s := range node.senders {
		if len(s.queue) != 0 {
			t.Fatal("stopped ABA requested a future round, permitting a recovery loop")
		}
	}
}

func TestABACertificatePullIsDeferredToRecovery(t *testing.T) {
	cfg := testConfig(4, false)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	node.ensureColumn(1)
	node.ensureObject(1, "node1")
	for _, s := range node.senders {
		if len(s.queue) != 0 {
			t.Fatal("new ABA eagerly requested a full certificate")
		}
	}
	// Even an instance with no proposal must still be able to recover a result.
	node.lastInstall = time.Now().Add(-2 * time.Duration(cfg.RecoveryMS) * time.Millisecond)
	node.recover()
	found := map[string]int{}
	for _, s := range node.senders {
		for _, m := range s.queue {
			if m.Protocol == aba.Protocol && m.Type == aba.REQUEST {
				found[m.Instance]++
			}
		}
	}
	if found[columnID(1)] != 1 || found[objectID(1, "node1")] != 1 {
		t.Fatal("recovery must request unresolved certificates once, independently of proposal")
	}
}

func TestSYNCDoesNotAmplifyCertificateRequests(t *testing.T) {
	cfg := testConfig(4, true)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	a := node.ensureColumn(1).whole
	node.propose(a, aba.One)
	for _, s := range node.senders {
		s.queue = nil
	}
	keys, _, _ := cfg.KeyPairs()
	from := p2p.NodeID("node1")
	body := json.RawMessage(encode(request{Instance: columnID(1), Round: 0}))
	env := envelope{node.Public.Context, body, hex.EncodeToString(ed25519.Sign(keys[from].Private, envelopeStatement(node.Public.Context, "SYNC", from, body)))}
	m, _ := p2p.NewMessage(Protocol, "SYNC", node.Public.Context, from, node.ID, env)
	node.handleBeacon(m)
	for id, s := range node.senders {
		if id == from {
			if len(s.queue) != 1 || s.queue[0].Type != "REPLAY" {
				t.Fatal("SYNC did not serve the requested core archive")
			}
		} else if len(s.queue) != 0 {
			t.Fatal("one SYNC generated another membership certificate query")
		}
	}
}

func TestRecoveryBackoffResetsAfterOutputProgress(t *testing.T) {
	cfg := testConfig(4, true)
	cfg.RecoveryMS = 100
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	base := 100 * time.Millisecond
	now := time.Now()
	node.lastInstall = now.Add(-2 * base)
	for _, step := range []struct {
		offset time.Duration
		calls  uint64
	}{{0, 1}, {base / 2, 1}, {base, 2}, {2 * base, 2}, {3 * base, 3}} {
		node.recoverAt(now.Add(step.offset))
		if node.Perf.Recoveries.Load() != step.calls {
			t.Fatal("recovery retries did not back off within an unchanged epoch")
		}
	}
	node.state = &consumptionState{Epoch: 2, Column: 1}
	node.lastInstall = now.Add(3 * base)
	node.recoverAt(now.Add(4 * base))
	if node.Perf.Recoveries.Load() != 4 || !node.nextRecovery.Equal(now.Add(5*base)) {
		t.Fatal("output progress did not reset recovery to the configured interval")
	}
}

func TestABAStatisticsDistinguishesCreationAndProposal(t *testing.T) {
	cfg := testConfig(4, true)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	whole := node.ensureColumn(1).whole
	node.ensureObject(1, "node1")
	stats := node.ABAStatistics()
	if len(stats) != 2 || stats[0].Instance != columnID(1) || stats[0].Proposed || stats[1].Proposed {
		t.Fatal("created instances were counted as running proposals")
	}
	node.propose(whole, aba.One)
	stats = node.ABAStatistics()
	if !stats[0].Proposed || stats[0].Certified || stats[1].Proposed {
		t.Fatal("statistics did not distinguish input submission from certification")
	}
	stats[0].Instance = "mutated"
	if node.ABAStatistics()[0].Instance != columnID(1) {
		t.Fatal("statistics exposed mutable instance identifiers")
	}
}

func TestABAStatisticsDuringLiveProtocol(t *testing.T) {
	nodes, ctx := testCluster(t, 4, true, 0)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 256; i++ {
			for _, node := range nodes {
				node.ABAStatistics()
			}
		}
	}()
	for _, node := range nodes {
		if _, err := node.WaitBeacon(ctx, 12); err != nil {
			t.Fatal(err)
		}
		if len(node.ABAStatistics()) == 0 {
			t.Fatal("no ABA instances reported after outputs")
		}
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestFutureShareDoesNotPullHistoryDuringNativeReconstruction(t *testing.T) {
	cfg := testConfig(4, false)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	node.state = &consumptionState{Epoch: 1, Column: 1}
	node.recon = &pendingRecon{}
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	keys, _, _ := cfg.KeyPairs()
	from := p2p.NodeID("node1")
	body := json.RawMessage(encode(reconPacket{Header: reconHeader{Epoch: 2}}))
	env := envelope{node.Public.Context, body, hex.EncodeToString(ed25519.Sign(keys[from].Private, envelopeStatement(node.Public.Context, "RECON", from, body)))}
	m, _ := p2p.NewMessage(Protocol, "RECON", node.Public.Context, from, node.ID, env)
	node.handleBeacon(m)
	for _, s := range node.senders {
		if len(s.queue) != 0 {
			t.Fatal("native reconstruction pulled redundant history on scheduling skew")
		}
	}
	if len(node.earlyShares[2]) != 1 {
		t.Fatal("optimization discarded the future share")
	}
	// Missing column prerequisites can still trigger an immediate passive pull.
	node.recon = nil
	node.handleBeacon(m)
	queued := node.senders[from].queue
	if len(queued) != 1 || queued[0].Type != "HISTORY" {
		t.Fatal("missing prerequisites did not trigger immediate history recovery")
	}
	node.recon = &pendingRecon{}
	node.lastInstall = time.Now().Add(-2 * time.Duration(cfg.RecoveryMS) * time.Millisecond)
	node.recover()
	found := false
	for _, out := range node.senders[from].queue[1:] {
		found = found || out.Type == "HISTORY"
	}
	if !found {
		t.Fatal("a stalled native reconstruction lost periodic history recovery")
	}
}

func TestCachedColumnEvidenceAndConflict(t *testing.T) {
	nodes, ctx := testCluster(t, 4, false, 0)
	if _, err := nodes[0].WaitBeacon(ctx, 3); err != nil {
		t.Fatal(err)
	}
	h := nodes[0].Export(3)
	v, err := NewVerifier(nodes[0].Public)
	if err != nil {
		t.Fatal(err)
	}
	if err = v.Initialize(h.Genesis); err != nil {
		t.Fatal(err)
	}
	redundant := clone(h.Genesis)
	redundant.Whole.Signatures = nil
	redundant.Objects = nil
	if err = v.AddColumn(redundant); err != nil {
		t.Fatal("did not reuse previously verified column evidence", err)
	}
	conflict := clone(h.Genesis)
	conflict.Record.Accepted[0].Hash = "changed"
	if v.AddColumn(conflict) == nil {
		t.Fatal("cached verification accepted a conflicting description")
	}
	for _, c := range h.Columns {
		if err := v.AddColumn(c); err != nil {
			t.Fatal(err)
		}
	}
	if err = v.CheckEntry(h.Entries[0]); err != nil {
		t.Fatal("redundant evidence overwrote the trusted cache", err)
	}
}

func TestEarlyNextColumnABAIsBufferedUntilLocalStart(t *testing.T) {
	cfg := testConfig(4, false)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	keys, _, _ := cfg.KeyPairs()
	av, err := aba.NewVerifier(node.Public.ABA())
	if err != nil {
		t.Fatal(err)
	}
	// Three peers have moved into column two and start its successor while this
	// receiver is still closing column one. The packet must survive that gap.
	for _, from := range cfg.Members()[1:] {
		statement := encode(struct {
			Domain, CommitteeID, Instance string
			Sender                        p2p.NodeID
			Round                         uint64
			Phase                         string
			Value                         aba.Value
		}{aba.Protocol + "/core", av.CommitteeID(), columnID(3), from, 0, aba.PRE, aba.One})
		m, _ := p2p.NewMessage(aba.Protocol, aba.PRE, columnID(3), from, node.ID, aba.CoreMessage{CommitteeID: av.CommitteeID(), Round: 0, Value: aba.One, SigHex: hex.EncodeToString(crypto.Sign(keys[from].Private, statement))})
		node.routeABA(m)
	}
	a := node.instances[columnID(3)]
	if a == nil || a.Status().Proposed {
		t.Fatal("early future-column traffic was discarded or bypassed the input guard")
	}
	out, err := a.Propose(aba.One)
	if err != nil {
		t.Fatal(err)
	}
	voted := false
	for _, m := range out {
		if m.Type == aba.VOTE {
			voted = true
		}
	}
	if !voted {
		t.Fatal("local ABA start lost its buffered PRE quorum")
	}
	before := len(node.instances)
	m, _ := p2p.NewMessage(aba.Protocol, aba.PRE, columnID(4), "node1", node.ID, aba.CoreMessage{Round: 0})
	node.routeABA(m)
	if len(node.instances) != before {
		t.Fatal("allocated an instance beyond the production window")
	}
}

func TestProducerWindowAdvancesOnlyWithConsumptionColumn(t *testing.T) {
	cfg := testConfig(4, false)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	columns := map[uint64]Column{}
	for c := uint64(1); c <= 2; c++ {
		col := Column{Record: ColumnRecord{Column: c}}
		for _, id := range node.Public.Members {
			col.Record.Accepted = append(col.Record.Accepted, Accepted{Source: id, Hash: "object"})
		}
		columns[c] = col
	}
	state := genesis(node.Public, columns[1])
	node.state = &state
	node.verifier.state = node.state
	node.nextSeq = 3
	// Its own consumed position cannot enable position W+1 midway through a column.
	record := BeaconRecord{Type: "BEACON", Epoch: state.Epoch, PreviousHash: state.PreviousHash, Column: 1, Source: node.ID, Random: "first"}
	if err := state.install(node.Public, record, columns); err != nil {
		t.Fatal(err)
	}
	node.produce()
	if node.producing || len(node.jobs) != 0 || node.nextSeq != 3 {
		t.Fatal("producer replenished its window before column advancement")
	}
	for state.Column == 1 {
		record := BeaconRecord{Type: "BEACON", Epoch: state.Epoch, PreviousHash: state.PreviousHash, Column: 1, Source: state.Remaining[0], Random: "next"}
		if err := state.install(node.Public, record, columns); err != nil {
			t.Fatal(err)
		}
		if state.PreviousHash != record.Hash() {
			t.Fatal("advancement inserted a CLOSE hash")
		}
	}
	node.produce()
	if state.Column != 2 || !node.producing || len(node.validationJobs) != 1 || len(node.jobs) != 0 || node.nextSeq != 4 {
		t.Fatal("shared column did not replenish exactly the next producer position")
	}
}
func TestColumnAdvanceFailureLeavesStateUnchanged(t *testing.T) {
	setup := PublicSetup{F: 1, Context: "test"}
	col := Column{Record: ColumnRecord{Column: 1, Accepted: []Accepted{{Source: "node0"}}}}
	state := genesis(setup, col)
	before := string(encode(state))
	record := BeaconRecord{Type: "BEACON", Epoch: 1, Column: 1, Source: "node0", PreviousHash: state.PreviousHash, Random: "next"}
	if state.install(setup, record, map[uint64]Column{1: col}) == nil {
		t.Fatal("advanced without successor")
	}
	if string(encode(state)) != before {
		t.Fatal("failed installation changed state")
	}
}
func TestPVSSCacheCannotRebindRBCPosition(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(fmt.Sprint(pending), func(t *testing.T) {
			cfg := testConfig(4, false)
			net := p2p.NewMemoryNetwork()
			node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
			if err != nil {
				t.Fatal(err)
			}
			node.ctx = context.Background()
			for _, id := range cfg.Members() {
				node.senders[id] = &sender{wake: make(chan struct{}, 1)}
			}
			keys, _, _ := cfg.KeyPairs()
			seeds, _ := cfg.NodeSeedBytes()
			dealer := p2p.NodeID("node1")
			kp := crypto.PVSSKeyPairFromSeed(seeds[dealer])
			scheme, err := crypto.NewALBATROSSPVSSScheme(dealer, cfg.Threshold(), kp.Private, node.Public.PVSS)
			if err != nil {
				t.Fatal(err)
			}
			object, _, err := scheme.Share(dealer, 1, node.Public.Members)
			if err != nil {
				t.Fatal(err)
			}
			value := encode(object)
			hash := rbc.Hash(value)
			packet := func(from p2p.NodeID, seq uint64) p2p.Message {
				b := rbc.New(rbc.Config{ID: from, F: cfg.F, Members: node.Public.Members, Context: node.Public.Context, Private: keys[from].Private, Public: node.Public.Signing})
				return b.Broadcast(seq, value)[0]
			}
			if pending {
				node.handleRBC(packet(dealer, 1))
				node.handleRBC(packet("node2", 1))
				if len(node.validationJobs) != 1 || len(node.jobs) != 0 {
					t.Fatal("did not deduplicate in-flight PVSS check")
				}
				(<-node.validationJobs)()
				(<-node.events)()
			} else {
				node.verifier.objects[hash] = verifiedPVSS{dealer: dealer, seq: 1}
				node.handleRBC(packet("node2", 1))
				node.handleRBC(packet(dealer, 2))
			}
			if node.Perf.Invalid.Load() == 0 {
				t.Fatal("accepted rebinding of cached or in-flight PVSS object")
			}
			for _, s := range node.senders {
				for _, m := range s.queue {
					p, _ := p2p.DecodePayload[rbc.Packet](m)
					if m.Type == "ECHO" && (p.Dealer != dealer || p.Seq != 1) {
						t.Fatal("echoed cached object under a different RBC position")
					}
				}
			}
			if !pending {
				for _, s := range node.senders {
					if len(s.queue) != 0 {
						t.Fatal("rebound object generated protocol messages")
					}
				}
			}
		})
	}
}

func TestRecoveryQueueCoalescesOnlyIdenticalPendingPackets(t *testing.T) {
	var total atomic.Int64
	s := &sender{wake: make(chan struct{}, 1), total: &total}
	m, _ := p2p.NewMessage(rbc.Protocol, "REPLY", "node1/1", "node1", "node0", map[string]string{"value": "one"})
	s.push(m)
	s.push(m)
	other := m
	other.Payload = []byte(`{"value":"two"}`)
	s.push(other)
	if len(s.queue) != 2 {
		t.Fatal("duplicate recovery copied payload or distinct evidence was lost")
	}
	if got, ok := s.pop(); !ok || string(got.Payload) != string(m.Payload) {
		t.Fatal("queue ordering changed")
	}
	s.push(m) // A retry after transmission must remain possible.
	if len(s.queue) != 2 {
		t.Fatal("coalescing suppressed a later retry")
	}
	for {
		if _, ok := s.pop(); !ok {
			break
		}
	}
	if total.Load() != 0 {
		t.Fatal("queue byte accounting did not drain")
	}
	native := m
	native.Type = "ECHO"
	s.push(native)
	s.push(native)
	if len(s.queue) != 2 {
		t.Fatal("native protocol messages were discarded")
	}
}

func shareCheckFixture(t *testing.T) (*Node, []reconPacket) {
	t.Helper()
	cfg := testConfig(7, true)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	object, _, err := node.pvss.Share(node.ID, 1, node.Public.Members)
	if err != nil {
		t.Fatal(err)
	}
	h := reconHeader{Epoch: 1, Previous: "previous", Column: 1, Source: node.ID, ObjectHash: rbc.Hash(encode(object))}
	node.state = &consumptionState{Epoch: 1, Column: 1, PreviousHash: h.Previous}
	node.recon = &pendingRecon{header: h, object: Object{Transcript: object}, shares: make(map[p2p.NodeID]crypto.PVSSDecryptedShare), verifying: make(map[p2p.NodeID]bool), candidates: make(map[p2p.NodeID]reconPacket), done: make(chan struct{})}
	node.recon.prepared, _ = node.pvss.Prepare(object)
	seeds, _ := cfg.NodeSeedBytes()
	var packets []reconPacket
	for _, id := range cfg.Members() {
		kp := crypto.PVSSKeyPairFromSeed(seeds[id])
		scheme, err := crypto.NewALBATROSSPVSSScheme(id, cfg.Threshold(), kp.Private, node.Public.PVSS)
		if err != nil {
			t.Fatal(err)
		}
		sh, err := scheme.PreReconTrusted(object, id)
		if err != nil {
			t.Fatal(err)
		}
		packets = append(packets, reconPacket{h, sh})
	}
	return node, packets
}

func TestThresholdShareChecksRefillAfterInvalidCandidate(t *testing.T) {
	node, packets := shareCheckFixture(t)
	node.recon.shares[node.ID] = packets[0].Share
	packets[1].Share.Proof.R = "invalid"
	for _, p := range packets[1:] {
		node.acceptShare(p.Share.Holder, p)
	}
	if len(node.urgentJobs) != node.Config.Threshold()-1 {
		t.Fatal("scheduled surplus share checks")
	}
	for len(node.urgentJobs) > 0 {
		(<-node.urgentJobs)()
		if len(node.urgentEvents) > 0 {
			(<-node.urgentEvents)()
		} else if len(node.events) > 0 {
			(<-node.events)()
		}
	}
	if len(node.recon.shares) != node.Config.Threshold() || node.Perf.Invalid.Load() != 1 {
		t.Fatal("invalid candidate prevented a valid threshold subset")
	}
	for _, sh := range node.recon.shares {
		if !node.pvss.VerifyShare(node.recon.object.Transcript, sh) {
			t.Fatal("accepted an unchecked share")
		}
	}
	if len(node.recon.candidates) == 0 {
		t.Fatal("surplus candidates were needlessly consumed")
	}
}

func TestPendingOwnShareReservesOneCheckSlot(t *testing.T) {
	node, packets := shareCheckFixture(t)
	node.recon.releasePending = true
	for _, p := range packets[1:] {
		node.acceptShare(p.Share.Holder, p)
	}
	if len(node.urgentJobs) != node.Config.Threshold()-1 {
		t.Fatal("did not reserve the pending local share")
	}
	node.recon.shares[node.ID] = packets[0].Share
	node.recon.released = true
	node.checkShares()
	if len(node.urgentJobs) != node.Config.Threshold()-1 {
		t.Fatal("local share installation scheduled a surplus check")
	}
}

func TestStaleQueuedShareChecksSkipCryptography(t *testing.T) {
	node, packets := shareCheckFixture(t)
	for _, p := range packets[1:] {
		node.acceptShare(p.Share.Holder, p)
	}
	before := node.checks.Stats().Executions
	close(node.recon.done)
	for len(node.urgentJobs) > 0 {
		(<-node.urgentJobs)()
	}
	if node.checks.Stats().Executions != before || len(node.events) != 0 {
		t.Fatal("obsolete epoch still performed cryptography")
	}
}

func TestProducerBackpressurePreservesSuccessorProduction(t *testing.T) {
	cfg := testConfig(7, true)
	cfg.ProductionWindow = 4
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	node.outgoingBytes.Store(17 << 20)
	node.nextSeq = 3
	node.produce()
	if node.producing || len(node.jobs) != 0 {
		t.Fatal("congestion did not backpressure speculation")
	}
	node.nextSeq = 2
	node.produce()
	if !node.producing || len(node.validationJobs) != 1 || len(node.jobs) != 0 {
		t.Fatal("congestion blocked the required successor")
	}
}

func TestAdaptiveProductionBoundsAndCriticalProgress(t *testing.T) {
	cfg := testConfig(7, true)
	cfg.ProductionWindow = 8
	cfg.AdaptiveProduction = true
	cfg.ProductionWindowMin = 2
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	node.ready[7] = map[p2p.NodeID]Object{"node1": {}}
	now := time.Now()
	node.outgoingBytes.Store(9 << 20)
	for i := 0; i < 8; i++ {
		node.reviewProduction(now.Add(time.Duration(i) * 250 * time.Millisecond))
	}
	if node.production.active != 8 || node.Config.ProductionWindow != 8 || len(node.ready[7]) != 1 {
		t.Fatal("startup filling shrank the horizon or discarded evidence")
	}
	// A busy worker with no queued work is not spare capacity.
	node.production.active = 3
	node.cryptoActive.Store(int64(cfg.MaxPool))
	node.outgoingBytes.Store(0)
	for i := 8; i < 16; i++ {
		node.reviewProduction(now.Add(time.Duration(i) * 250 * time.Millisecond))
	}
	if node.production.active != 3 {
		t.Fatal("busy workers mistaken for an empty execution pipeline")
	}
	node.cryptoActive.Store(0)
	node.outgoingBytes.Store(0)
	// Excess complete inventory permits a cautious decrease without requiring
	// a large outbound queue. Accepted evidence and peer horizons stay intact.
	for c := uint64(3); c <= 10; c++ {
		node.columns[c] = Column{Record: ColumnRecord{Column: c, Whole: aba.One}}
	}
	for i := 16; i < 28; i++ {
		node.state = &consumptionState{Column: 3 + uint64((i-16)/4)}
		node.reviewProduction(now.Add(time.Duration(i) * 250 * time.Millisecond))
	}
	if node.production.active != 2 || node.Perf.ProductionShrinks.Load() != 1 {
		t.Fatal("safe reserve did not permit bounded shrinking", node.production)
	}
	node.state = nil
	node.nextSeq = 2
	node.produce()
	if !node.producing || len(node.validationJobs) != 1 {
		t.Fatal("adaptive congestion blocked the required successor")
	}
	node.outgoingBytes.Store(0)
	// The queued successor is required work, not unused worker capacity.
	<-node.validationJobs
	for i := 28; i < 44; i++ {
		node.reviewProduction(now.Add(time.Duration(i) * 250 * time.Millisecond))
	}
	if node.production.active != 8 || node.Perf.ProductionShrinks.Load() != 1 || node.Perf.ProductionGrows.Load() != 6 {
		t.Fatal("adaptive bounds/hysteresis failed", node.production)
	}
}

func TestAdaptiveFallbackRestoresLookaheadWithoutChangingDecision(t *testing.T) {
	cfg := testConfig(7, true)
	cfg.ProductionWindow, cfg.ProductionWindowMin, cfg.AdaptiveProduction = 8, 2, true
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.production.active = 2
	node.state = &consumptionState{Column: 3}
	node.columns[3] = Column{Record: ColumnRecord{Column: 3, Whole: aba.Zero}}
	node.reviewProduction(time.Now())
	if node.production.active != 3 || node.columns[3].Record.Whole != aba.Zero || node.Config.ProductionWindow != 8 {
		t.Fatal("fallback feedback changed evidence or failed to restore lookahead")
	}
}

func TestReadyAuthenticationCompletesBeforeActorAdmission(t *testing.T) {
	cfg := testConfig(4, true)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx, node.cancel = context.WithCancel(context.Background())
	defer func() { node.cancel(); node.wg.Wait() }()
	keys, _, _ := cfg.KeyPairs()
	p := rbc.Packet{Context: node.Public.Context, Dealer: "node2", Seq: 1, Hash: rbc.Hash([]byte("value"))}
	statement := encode(struct {
		Domain, Context, Type string
		From, Dealer          p2p.NodeID
		Seq                   uint64
		Hash                  string
	}{rbc.Protocol, p.Context, "READY", "node1", p.Dealer, p.Seq, p.Hash})
	p.Signature = hex.EncodeToString(ed25519.Sign(keys["node1"].Private, statement))
	valid, _ := p2p.NewMessage(rbc.Protocol, "READY", rbc.Key(p.Dealer, p.Seq), "node1", node.ID, p)
	node.authStarted.Store(true)
	node.handleRBC(valid)
	if len(node.authJobs) != 1 || node.checks.Stats().Executions != 0 {
		t.Fatal("actor synchronously performed queued READY cryptography")
	}
	node.wg.Add(1)
	go node.authenticateReady()
	runCompletion := func() {
		t.Helper()
		select {
		case f := <-node.events:
			f()
		case <-time.After(5 * time.Second):
			t.Fatal("authentication completion missing")
		}
	}
	runCompletion()
	if node.Perf.Invalid.Load() != 0 || node.checks.Stats().Executions != 1 {
		t.Fatal("valid signature did not authenticate exactly once")
	}
	p.Hash = rbc.Hash([]byte("tampered value"))
	bad, _ := p2p.NewMessage(rbc.Protocol, "READY", rbc.Key(p.Dealer, p.Seq), "node1", node.ID, p)
	node.handleRBC(bad)
	runCompletion()
	if node.Perf.Invalid.Load() != 1 || len(node.ready) != 0 || len(node.columns) != 0 {
		t.Fatal("unverified READY changed protocol evidence")
	}
}

func TestAdaptiveWindowPublicHistoryAndSilentFaults(t *testing.T) {
	for _, silent := range []int{0, 1} {
		t.Run(fmt.Sprint(silent), func(t *testing.T) {
			cfg := testConfig(4, true)
			cfg.ProductionWindow = 8
			cfg.AdaptiveProduction = true
			cfg.ProductionWindowMin = 2
			nodes, ctx := testConfiguredCluster(t, cfg, silent)
			for epoch := uint64(1); epoch <= 9; epoch++ {
				var hash string
				for _, node := range nodes {
					e, err := node.WaitBeacon(ctx, epoch)
					if err != nil {
						t.Fatal(err)
					}
					if hash != "" && e.Record.Hash() != hash {
						t.Fatal("adaptive agreement failure")
					}
					hash = e.Record.Hash()
				}
			}
			for _, node := range nodes {
				if err := VerifyHistory(node.Public, node.Export(9)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestHistoryReplyOmitsOnlyRequesterRetainedColumns(t *testing.T) {
	cfg := testConfig(7, true)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	node.senders["node1"] = &sender{wake: make(chan struct{}, 1)}
	node.history[1] = Entry{Record: BeaconRecord{Epoch: 1, Column: 1}}
	node.columns[1] = Column{Record: ColumnRecord{Column: 1}}
	node.columns[2] = Column{Record: ColumnRecord{Column: 2}}
	keys, _, _ := cfg.KeyPairs()
	for through := uint64(0); through <= 2; through++ {
		body := json.RawMessage(encode(request{Epoch: 1, HaveThroughColumn: through}))
		from := p2p.NodeID("node1")
		env := envelope{node.Public.Context, body, hex.EncodeToString(ed25519.Sign(keys[from].Private, envelopeStatement(node.Public.Context, "HISTORY", from, body)))}
		m, _ := p2p.NewMessage(Protocol, "HISTORY", node.Public.Context, from, node.ID, env)
		node.handleBeacon(m)
		reply, ok := node.senders[from].pop()
		if !ok {
			t.Fatal("history request was not answered")
		}
		packet, _ := p2p.DecodePayload[envelope](reply)
		var resp response
		if json.Unmarshal(packet.Body, &resp) != nil || len(resp.Entries) != 1 || len(resp.Columns) != 2-int(through) {
			t.Fatal("column omission lost entries or required evidence")
		}
		for _, col := range resp.Columns {
			if col.Record.Column <= through {
				t.Fatal("resent retained column")
			}
		}
	}
}

func TestPeriodicHistoryRecoveryRotatesAcrossMembership(t *testing.T) {
	cfg := testConfig(7, true)
	net := p2p.NewMemoryNetwork()
	node, err := New(cfg, "node0", net.NewTransport("node0", 8192))
	if err != nil {
		t.Fatal(err)
	}
	node.ctx = context.Background()
	for _, id := range cfg.Members() {
		node.senders[id] = &sender{wake: make(chan struct{}, 1)}
	}
	now := time.Now()
	node.lastInstall = now.Add(-time.Minute)
	seen := map[p2p.NodeID]bool{}
	for attempt := 0; attempt < len(cfg.Members())-1; attempt++ {
		node.recoverAt(now.Add(time.Duration(attempt) * 10 * time.Second))
		count := 0
		for peer, s := range node.senders {
			for {
				m, ok := s.pop()
				if !ok {
					break
				}
				if m.Protocol == Protocol && m.Type == "HISTORY" {
					count++
					seen[peer] = true
					if peer == node.ID {
						t.Fatal("history recovery queried self")
					}
				}
			}
		}
		if count != 1 {
			t.Fatal("periodic recovery solicited duplicate full histories")
		}
	}
	if len(seen) != len(cfg.Members())-1 {
		t.Fatal("history recovery cannot pass silent peers")
	}
}

type consumptionTap struct {
	p2p.Transport
	owner            *Node
	wrongPredecessor atomic.Uint64
	released         atomic.Uint64
}

func (tap *consumptionTap) Send(ctx context.Context, to p2p.NodeID, message p2p.Message) error {
	if message.Protocol == Protocol && message.Type == "RECON" {
		var envelope envelope
		var packet reconPacket
		if json.Unmarshal(message.Payload, &envelope) != nil || json.Unmarshal(envelope.Body, &packet) != nil {
			tap.wrongPredecessor.Add(1)
		} else if packet.Header.Epoch > 1 {
			tap.owner.mu.RLock()
			previous, ok := tap.owner.history[packet.Header.Epoch-1]
			tap.owner.mu.RUnlock()
			if !ok || previous.Record.Hash() != packet.Header.Previous {
				tap.wrongPredecessor.Add(1)
			}
		}
		tap.released.Add(1)
		// Allow real slack between online release and peer arrival, without
		// delaying the actor. This exercises the private precompute path.
		time.Sleep(2 * time.Millisecond)
	}
	return tap.Transport.Send(ctx, to, message)
}

func TestConsumptionPrefetchKeepsReleaseBindingAndPublicHistory(t *testing.T) {
	t.Setenv("TYCHE_ASY_PREDECRYPT", "1")
	cfg := testConfig(4, true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	network := p2p.NewMemoryNetwork()
	var nodes []*Node
	var taps []*consumptionTap
	for _, id := range cfg.Members() {
		tap := &consumptionTap{Transport: network.NewTransport(id, cfg.TransportBuffer)}
		node, err := New(cfg, id, tap)
		if err != nil {
			t.Fatal(err)
		}
		tap.owner = node
		nodes = append(nodes, node)
		taps = append(taps, tap)
	}
	t.Cleanup(func() {
		cancel()
		for _, n := range nodes {
			n.Stop()
		}
		for _, tap := range taps {
			tap.Close()
		}
	})
	for _, n := range nodes {
		if err := n.Start(ctx); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)
	for _, tap := range taps {
		if tap.released.Load() != 0 {
			t.Fatal("released before Begin")
		}
	}
	for _, n := range nodes {
		n.Begin()
	}
	const outputs = 17
	for e := uint64(1); e <= outputs; e++ {
		var hash string
		for _, n := range nodes {
			entry, err := n.WaitBeacon(ctx, e)
			if err != nil {
				t.Fatal(err)
			}
			if hash != "" && entry.Record.Hash() != hash {
				t.Fatal("agreement failure")
			}
			hash = entry.Record.Hash()
		}
	}
	var hits uint64
	for i, n := range nodes {
		if taps[i].wrongPredecessor.Load() != 0 {
			t.Fatal("released share before its predecessor was installed")
		}
		hits += n.Perf.PrefetchHits.Load()
		if err := VerifyHistory(n.Public, n.Export(outputs)); err != nil {
			t.Fatal(err)
		}
	}
	if hits == 0 {
		t.Fatal("did not exercise completed private-share cache")
	}
}

func TestConsumerPriorityDrainsCompletionsBeforeBackgroundWithoutStarvingIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	node := &Node{ctx: ctx, consumerPriority: true, Transport: p2p.NewMemoryNetwork().NewTransport("node0", 8), events: make(chan func(), 8), urgentEvents: make(chan func(), 8)}
	var order []string
	for i := 0; i < 4; i++ {
		node.post(func() { order = append(order, "background") })
	}
	node.postUrgent(func() { order = append(order, "consumer") })
	if !node.drainReady() || len(order) != 5 || order[0] != "consumer" {
		t.Fatal("priority or background progress lost", order)
	}
	node.consumerPriority = false
	node.postUrgent(func() {})
	if len(node.events) != 1 || len(node.urgentEvents) != 0 {
		t.Fatal("disabled option changed original callback routing")
	}
}
