package aba

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	tychecrypto "Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
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

	deadline := time.After(time.Second)
	for {
		stats := transport.MessageTypeMetrics()["aba/AUX"]
		if stats.SentMessages == 1 {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("AUX broadcast count = %d, want 1", stats.SentMessages)
		case <-time.After(time.Millisecond):
		}
	}
}

func TestAuthenticatedABARejectsForgedAndCrossConfigInput(t *testing.T) {
	ctx := context.Background()
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	private := make(map[p2p.NodeID]ed25519.PrivateKey)
	public := make(map[string]ed25519.PublicKey)
	for _, id := range ids {
		key, err := tychecrypto.GenerateIdentityKeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		private[id], public[string(id)] = key.Private, key.Public
	}
	a, err := NewAuthenticated("n0", 4, "control", ids, 1, p2p.NewMemoryNetwork().NewTransport("n0", 32), private["n0"], public)
	if err != nil {
		t.Fatal(err)
	}
	instance := EpochInstanceFor(4, 1, "n2", 1)
	body := InputMessage{Value: true}
	body.Signature, err = tychecrypto.SignTranscript("n1", private["n1"], a.payloadTranscript("INPUT", instance, body))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p2p.NewMessage(Protocol, "INPUT", instance, "n1", "n0", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Handle(ctx, msg); err != nil {
		t.Fatal(err)
	}
	if got := a.Status(instance).Inputs; got != 1 {
		t.Fatalf("valid authenticated input count=%d", got)
	}

	replayedInstance := EpochInstanceFor(5, 1, "n2", 1)
	replay, err := p2p.NewMessage(Protocol, "INPUT", replayedInstance, "n1", "n0", body)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Handle(ctx, replay); err != nil {
		t.Fatal(err)
	}
	if got := a.Status(replayedInstance).Inputs; got != 0 {
		t.Fatalf("cross-configuration replay counted: %d", got)
	}

	forged := body
	forged.Value = false
	forgedMsg, err := p2p.NewMessage(Protocol, "INPUT", instance, "n1", "n0", forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Handle(ctx, forgedMsg); err != nil {
		t.Fatal(err)
	}
	status := a.Status(instance)
	if status.InputFalse != 0 || status.Inputs != 1 {
		t.Fatalf("tampered payload counted: %+v", status)
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
