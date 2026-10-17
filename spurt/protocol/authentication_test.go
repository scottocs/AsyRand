package spurt

import (
	asig "Tyche/spurt/crypto"
	"Tyche/utils/p2p"
	"encoding/hex"
	"strings"
	"testing"
)

type unauthenticatedTransport struct{ p2p.Transport }

func (unauthenticatedTransport) AuthenticatedDelivery() bool { return false }

func TestNodeRequiresAuthenticatedDelivery(t *testing.T) {
	if _, err := NewNode(NodeConfig{ID: "n0", Transport: unauthenticatedTransport{}}); err == nil || !strings.Contains(err.Error(), "authenticated delivery") {
		t.Fatal("missing transport authentication gate", err)
	}
}

func TestAuthenticatedBeaconStillNeedsNativeSignature(t *testing.T) {
	n, es, keys := beaconTestNode(t)
	net := p2p.NewMemoryNetwork()
	a, b := net.NewTransport("n1", 4), net.NewTransport("n0", 4)
	random := []byte("signed native beacon")
	rh := randomHash(random)
	body := BeaconMessage{Epoch: 0, Leader: "n0", Digest: es.digest, Random: random, RandomHash: rh, Signature: asig.SignatureShare{Signer: "n1", SigHex: hex.EncodeToString(make([]byte, 64))}}
	deliver := func(body BeaconMessage) {
		t.Helper()
		msg, err := p2p.NewMessage(Protocol, "BEACON", epochInstance(0), "n1", "n0", body)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.Send(t.Context(), "n0", msg); err != nil {
			t.Fatal(err)
		}
		n.dispatchSpurt(<-b.Inbox())
	}
	deliver(body)
	if len(es.beaconVotes[es.digest+"/"+rh]) != 0 || es.random != nil {
		t.Fatal("authenticated packet bypassed native signature")
	}
	body.Signature.SigHex = hex.EncodeToString(asig.Sign(keys["n1"].Private, beaconVoteBytes(0, es.digest, rh)))
	deliver(body)
	if len(es.beaconVotes[es.digest+"/"+rh]) != 1 {
		t.Fatal("valid native signature rejected")
	}
	before := n.PerfSnapshot().BeaconVerifyCount
	deliver(body)
	if n.PerfSnapshot().BeaconVerifyCount != before {
		t.Fatal("native signature verified twice")
	}
	if p := n.PerfSnapshot(); p.MessageSignCount != 0 || p.MessageVerifyCount != 0 {
		t.Fatal("outer signature path remains")
	}
}
