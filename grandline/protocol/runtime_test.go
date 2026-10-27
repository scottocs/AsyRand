package grandline

import (
	asig "Tyche/grandline/crypto"
	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"Tyche/utils/pairing"
	"Tyche/utils/verification"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestParallelAdmissionReservesLocalShare(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	n := &Node{ID: "n0", ctx: ctx, State: NewState([]p2p.NodeID{"n0", "n1", "n2", "n3"}, 1), Crypto: cryptoexec.New(2), commitments: map[p2p.NodeID]*asig.VerifiedBeaconCommitment{}}
	st := &roundState{shares: map[p2p.NodeID]*asig.VerifiedBeaconShare{}, localPending: true}
	entered, release := make(chan struct{}, 2), make(chan struct{})
	for i := 0; i < 2; i++ {
		n.Crypto.Go(ctx, func() { entered <- struct{}{}; <-release })
	}
	<-entered
	<-entered
	for _, id := range []p2p.NodeID{"n1", "n2", "n3"} {
		n.commitments[id] = new(asig.VerifiedBeaconCommitment)
		n.recordShare(st, shareMessage{Share: asig.BeaconShare{Signer: id, Sigma1: "candidate", Sigma2: "candidate"}})
	}
	n.roundMu.Lock()
	if len(st.verifying) != 1 || len(st.candidateOrder) != 2 {
		t.Error("excess parallel checks", len(st.verifying), len(st.candidateOrder))
	}
	n.roundMu.Unlock()
	cancel()
	close(release)
}

func TestInvalidCandidateDoesNotDisplaceHonestShare(t *testing.T) {
	g := pairing.NewSuite()
	x := g.G1().Scalar().SetInt64(139)
	pk, _ := g.G2().Point().Mul(x, nil).MarshalBinary()
	sk, _ := g.G1().Point().Mul(x, nil).MarshalBinary()
	cm, a, err := asig.NewBeaconCommitment("n1", hex.EncodeToString(sk))
	if err != nil {
		t.Fatal(err)
	}
	checked, ok := asig.DecodeAndVerifyBeaconCommitment(hex.EncodeToString(pk), cm)
	if !ok {
		t.Fatal("invalid commitment")
	}
	signer, err := asig.NewBeaconSigner("n1", hex.EncodeToString(sk), a, checked)
	if err != nil {
		t.Fatal(err)
	}
	e := asig.NewBeaconEpoch(7, []byte("candidate-test"))
	wire, _, err := signer.Share(e)
	if err != nil {
		t.Fatal(err)
	}
	st := &roundState{epoch: 7, crypto: e, shares: map[p2p.NodeID]*asig.VerifiedBeaconShare{}}
	n := &Node{checks: verification.New(), Crypto: cryptoexec.New(1), State: NewState([]p2p.NodeID{"n0", "n1", "n2", "n3"}, 1), commitments: map[p2p.NodeID]*asig.VerifiedBeaconCommitment{"n1": checked}}
	entered, release, drained := make(chan struct{}), make(chan struct{}), make(chan struct{})
	n.Crypto.Go(t.Context(), func() { close(entered); <-release })
	<-entered
	bad := wire
	bad.Sigma1 = "invalid"
	n.recordShare(st, shareMessage{Epoch: 7, Share: bad})
	n.recordShare(st, shareMessage{Epoch: 7, Share: wire})
	n.recordShare(st, shareMessage{Epoch: 7, Share: wire})
	n.Crypto.Go(t.Context(), func() { close(drained) })
	close(release)
	select {
	case <-drained:
	case <-time.After(10 * time.Second):
		t.Fatal("verification stalled")
	}
	n.roundMu.Lock()
	defer n.roundMu.Unlock()
	if st.shares["n1"] == nil || len(st.verifying) != 0 || len(st.candidates["n1"]) != 0 {
		t.Fatal("honest candidate lost behind invalid candidate")
	}
}

func TestReferenceIngressRequiresTransportAuthentication(t *testing.T) {
	n := &Node{reference: true, checks: verification.New(), ID: "n0", GRand: asig.GRandShare{PublicShares: map[p2p.NodeID]string{"n1": "known"}}, rounds: map[string]*roundState{}, pendingShares: map[string][]shareMessage{}, commitments: map[p2p.NodeID]*asig.VerifiedBeaconCommitment{}, Perf: &PerfMetrics{}}
	msg, _ := p2p.NewMessage(ReferenceProtocol, "SHARE", roundKey(7), "n1", "", shareMessage{Epoch: 7, Share: asig.BeaconShare{Epoch: 7, Signer: "n1"}})
	n.dispatchMessage(msg)
	if len(n.pendingShares) != 0 {
		t.Fatal("unauthenticated share buffered")
	}
	net := p2p.NewMemoryNetwork()
	a, b := net.NewTransport("n1", 2), net.NewTransport("n0", 2)
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(<-b.Inbox())
	if len(n.pendingShares[roundKey(7)]) != 1 || n.PerfSnapshot().MessageVerifyCount != 0 {
		t.Fatal("authenticated share rejected or outer signature verified")
	}
	forged := msg
	forged.From = "n2"
	if err := a.Send(t.Context(), "n0", forged); err == nil {
		t.Fatal("forged identity delivered")
	}
	msg.Type = "COMMIT"
	if err := a.Send(t.Context(), "n0", msg); err != nil {
		t.Fatal(err)
	}
	n.dispatchMessage(<-b.Inbox())
	if len(n.commitments) != 0 {
		t.Fatal("online commitment accepted in fixed setup mode")
	}
}

type unauthenticatedTransport struct{ p2p.Transport }

func (unauthenticatedTransport) AuthenticatedDelivery() bool { return false }
func TestNodeRejectsUnauthenticatedTransport(t *testing.T) {
	for _, mode := range []string{"standard", "reference"} {
		if _, err := NewNode(NodeConfig{ID: "n0", BeaconMode: mode, Transport: unauthenticatedTransport{}}); err == nil || !strings.Contains(err.Error(), "authenticated delivery") {
			t.Fatal("node accepted unauthenticated transport", mode)
		}
	}
}
