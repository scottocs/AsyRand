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
