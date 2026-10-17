package grandline

import (
	"encoding/hex"
	"testing"

	asig "Tyche/grandline/crypto"
	"Tyche/utils/p2p"
	"Tyche/utils/pairing"
	"Tyche/utils/verification"
)

func TestUnsignedShareRequiresAuthenticatedDeliveryBeforeBuffering(t *testing.T) {
	n := &Node{checks: verification.New(), ID: "n0",
		GRand:  asig.GRandShare{PublicShares: map[p2p.NodeID]string{"n1": "known-public-share"}},
		rounds: make(map[string]*roundState), pendingShares: make(map[string][]shareMessage), Perf: &PerfMetrics{}}
	msg, _ := p2p.NewMessage(Protocol, "SHARE", roundKey(7), "n1", "", shareMessage{Epoch: 7, Share: asig.BeaconShare{Epoch: 7, Signer: "n1"}})
	n.dispatchMessage(msg)
	if len(n.pendingShares) != 0 {
		t.Fatal("unauthenticated share reached handler")
	}
	net := p2p.NewMemoryNetwork()
	a, b := net.NewTransport("n1", 1), net.NewTransport("n0", 1)
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(<-b.Inbox())
	if len(n.pendingShares[roundKey(7)]) != 1 {
		t.Fatal("authenticated unsigned packet rejected")
	}
	msg.Instance = roundKey(8)
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(<-b.Inbox())
	if len(n.pendingShares[roundKey(7)]) != 1 {
		t.Fatal("mismatched epoch reached handler")
	}
	if n.PerfSnapshot().MessageVerifyCount != 0 {
		t.Fatal("ordinary message triggered signature verification")
	}
}

func TestOnlineCommitmentRequiresAuthenticatedSender(t *testing.T) {
	g := pairing.NewSuite()
	x := g.G1().Scalar().SetInt64(139)
	pk, _ := g.G2().Point().Mul(x, nil).MarshalBinary()
	sk, _ := g.G1().Point().Mul(x, nil).MarshalBinary()
	cm, _, err := asig.NewBeaconCommitment("n1", hex.EncodeToString(sk))
	if err != nil {
		t.Fatal(err)
	}
	n := &Node{checks: verification.New(), ID: "n0", GRand: asig.GRandShare{PublicShares: map[p2p.NodeID]string{"n1": hex.EncodeToString(pk)}}, rounds: map[string]*roundState{}, commitments: map[p2p.NodeID]*asig.VerifiedBeaconCommitment{}}
	msg, err := p2p.NewMessage(Protocol, "COMMIT", "commitment", "n1", "n0", cm)
	if err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(msg)
	if len(n.commitments) != 0 {
		t.Fatal("unauthenticated commitment accepted")
	}
	net := p2p.NewMemoryNetwork()
	a, b := net.NewTransport("n1", 2), net.NewTransport("n0", 2)
	attacker := net.NewTransport("n2", 2)
	if err := attacker.Send(t.Context(), "n0", msg); err == nil {
		t.Fatal("another endpoint impersonated commitment sender")
	}
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(<-b.Inbox())
	if len(n.commitments) != 1 {
		t.Fatal("authenticated commitment rejected")
	}
	cm.CM1 = "invalid"
	bad, _ := p2p.NewMessage(Protocol, "COMMIT", "commitment", "n1", "n0", cm)
	before := n.commitments["n1"]
	if err := a.Send(t.Context(), "n0", bad); err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(<-b.Inbox())
	if n.commitments["n1"] != before {
		t.Fatal("invalid native commitment replaced fixed commitment")
	}
}
