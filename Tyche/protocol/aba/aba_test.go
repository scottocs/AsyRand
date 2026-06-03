package aba

import (
	"context"
	"testing"
	"time"

	"github.com/scottocs/Tyche/utils/p2p"
)

func TestOptimisticPathDecidesTrue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	nodes, _ := newTestAgreements(ctx, t)
	instance := EpochInstance(1, "n0")
	for _, node := range nodes {
		if err := node.Propose(ctx, instance, true); err != nil {
			t.Fatal(err)
		}
	}
	for _, node := range nodes {
		select {
		case d := <-node.Decisions:
			if d.Instance != instance || !d.Value || !d.FastPath {
				t.Fatalf("unexpected decision: %+v", d)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for optimistic decision")
		}
	}
}

func TestPessimisticPathUsesExternalCoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	nodes, _ := newTestAgreements(ctx, t)
	instance := EpochInstance(2, "n1")
	for _, node := range nodes {
		if err := node.Propose(ctx, instance, false); err != nil {
			t.Fatal(err)
		}
	}

	seen := 0
	for seen < len(nodes) {
		for _, node := range nodes {
			select {
			case req := <-node.CoinRequests:
				if req.Instance != instance || req.Round != 0 {
					t.Fatalf("bad coin request: %+v", req)
				}
				node.FeedCoin(ctx, req.Instance, req.Round, false)
				seen++
			default:
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
			t.Fatal("timed out waiting for coin requests")
		}
	}

	for _, node := range nodes {
		select {
		case d := <-node.Decisions:
			if d.Instance != instance || d.Value || d.FastPath {
				t.Fatalf("unexpected decision: %+v", d)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for pessimistic decision")
		}
	}
}

func TestPruneDropsDecidedStateAndIgnoresLateMessages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	a := New("n0", 4, 1, nil)
	instance := EpochInstance(7, "n1")
	st := a.get(instance)
	st.decided = true
	st.decision = false

	a.Prune(instance)
	if a.state[instance] != nil {
		t.Fatal("pruned ABA state was retained")
	}
	status := a.Status(instance)
	if !status.Decided || status.Value {
		t.Fatalf("bad pruned status: %+v", status)
	}

	msg, err := p2p.NewMessage(Protocol, "INPUT", instance, "n1", "n0", InputMessage{Value: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Handle(ctx, msg); err != nil {
		t.Fatal(err)
	}
	if a.state[instance] != nil {
		t.Fatal("late message recreated pruned ABA state")
	}
}

func TestProcessPendingAuxSendsConfOnce(t *testing.T) {
	a := New("n0", 4, 1, nil)
	st := a.get(EpochInstance(8, "n0"))
	a.ensureRound(st, 0)
	st.bin[0][true] = true
	st.auxPending[0]["n0"] = true
	st.auxPending[0]["n1"] = true
	st.auxPending[0]["n2"] = true

	send, values := a.processPendingAuxLocked(st, 0)
	if !send || len(values) != 1 || !values[0] {
		t.Fatalf("expected one true CONF trigger, send=%v values=%v", send, values)
	}
	send, values = a.processPendingAuxLocked(st, 0)
	if send || values != nil {
		t.Fatalf("CONF trigger repeated, send=%v values=%v", send, values)
	}
}

func TestBValSendsAuxOncePerRound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	net := p2p.NewMemoryNetwork()
	transport := net.NewTransport("n0", 64)
	a := New("n0", 4, 1, transport)
	instance := EpochInstance(9, "n0")

	a.handleBVal(ctx, instance, "n0", 0, true)
	a.handleBVal(ctx, instance, "n1", 0, true)
	a.handleBVal(ctx, instance, "n2", 0, true)
	a.handleBVal(ctx, instance, "n3", 0, true)

	stats := transport.MessageTypeMetrics()["aba/AUX"]
	if stats.SentMessages != 1 {
		t.Fatalf("AUX broadcast count = %d, want 1", stats.SentMessages)
	}
}

func newTestAgreements(ctx context.Context, t *testing.T) ([]*Agreement, []p2p.Transport) {
	t.Helper()
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Agreement, 0, len(ids))
	transports := make([]p2p.Transport, 0, len(ids))
	for _, id := range ids {
		transport := net.NewTransport(id, 256)
		node := New(id, len(ids), 1, transport)
		nodes = append(nodes, node)
		transports = append(transports, transport)
		go func(node *Agreement, transport p2p.Transport) {
			for {
				select {
				case msg := <-transport.Inbox():
					_ = node.Handle(ctx, msg)
				case <-ctx.Done():
					return
				}
			}
		}(node, transport)
	}
	return nodes, transports
}
