package aba

import (
	"context"
	"testing"
	"time"

	asig "github.com/scottocs/asyrand/asyrand/internal/crypto"
	"github.com/scottocs/asyrand/asyrand/internal/dkg"
	"github.com/scottocs/asyrand/asyrand/internal/p2p"
)

func TestOptimisticPathDecidesTrue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	net := p2p.NewMemoryNetwork()
	seeds := make(map[p2p.NodeID][]byte)
	for _, id := range ids {
		seeds[id] = asig.HashBytes([]byte(id))
	}
	dkgResult, err := dkg.RunPedersen(ids, seeds, 2)
	if err != nil {
		t.Fatal(err)
	}

	agreements := make([]*Agreement, 0, len(ids))
	for _, id := range ids {
		transport := net.NewTransport(id, 128)
		coin := asig.NewThresholdCoin(string(id), dkgResult.Shares[id], dkgResult.Public, 2, len(ids))
		agreement := New(id, len(ids), 1, transport, coin)
		agreements = append(agreements, agreement)
		go func(agreement *Agreement, transport p2p.Transport) {
			for {
				select {
				case msg := <-transport.Inbox():
					_ = agreement.Handle(ctx, msg)
				case <-ctx.Done():
					return
				}
			}
		}(agreement, transport)
	}

	instance := EpochInstance(0, "n0")
	for _, agreement := range agreements {
		if err := agreement.Propose(ctx, instance, true); err != nil {
			t.Fatal(err)
		}
	}

	for _, agreement := range agreements {
		select {
		case decision := <-agreement.Decisions:
			if decision.Instance != instance || !decision.Value || !decision.FastPath {
				t.Fatalf("unexpected decision: %+v", decision)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for ABA decision")
		}
	}
}

func TestPessimisticPathDecidesFalse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	net := p2p.NewMemoryNetwork()
	dkgResult, err := dkg.SetupFromSeed(ids, asig.HashBytes([]byte("aba-false")), 2)
	if err != nil {
		t.Fatal(err)
	}

	agreements := make([]*Agreement, 0, len(ids))
	for _, id := range ids {
		transport := net.NewTransport(id, 128)
		coin := asig.NewThresholdCoin(string(id), dkgResult.Shares[id], dkgResult.Public, 2, len(ids))
		agreement := New(id, len(ids), 1, transport, coin)
		agreements = append(agreements, agreement)
		go func(agreement *Agreement, transport p2p.Transport) {
			for {
				select {
				case msg := <-transport.Inbox():
					_ = agreement.Handle(ctx, msg)
				case <-ctx.Done():
					return
				}
			}
		}(agreement, transport)
	}

	instance := EpochInstance(1, "n0")
	for _, agreement := range agreements {
		if err := agreement.Propose(ctx, instance, false); err != nil {
			t.Fatal(err)
		}
	}

	for _, agreement := range agreements {
		select {
		case decision := <-agreement.Decisions:
			if decision.Instance != instance || decision.Value || decision.FastPath {
				t.Fatalf("unexpected decision: %+v", decision)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for pessimistic ABA decision")
		}
	}
}
