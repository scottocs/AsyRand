package aba

import (
	asig "Tyche/asyrand/crypto"
	"Tyche/utils/p2p"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestUnsignedCoreRequiresAuthenticatedDelivery(t *testing.T) {
	ids := []p2p.NodeID{"a", "b", "c", "d"}
	keys := make(map[p2p.NodeID]asig.KeyPair)
	pub := make(map[string]ed25519.PublicKey)
	for _, id := range ids {
		k, err := asig.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = k
		pub[string(id)] = k.Public
	}
	public := PublicConfig{SetupID: strings.Repeat("a", 64), Members: ids, F: 1, Public: pub}
	a, err := New(Config{PublicConfig: public, ID: "a", Instance: "col/1", Private: keys["a"].Private, Authenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(Config{PublicConfig: public, ID: "b", Instance: "col/1", Private: keys["b"].Private, Authenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	messages, err := a.Propose(One)
	if err != nil {
		t.Fatal(err)
	}
	var core p2p.Message
	for _, m := range messages {
		if m.Type == PRE {
			core = m
			break
		}
	}
	body, err := p2p.DecodePayload[CoreMessage](core)
	if err != nil || body.SigHex != "" {
		t.Fatal("core still signed", err)
	}
	if _, err := b.Handle(core); err == nil {
		t.Fatal("unsigned untrusted core accepted")
	}
	network := p2p.NewMemoryNetwork()
	sender, receiver := network.NewTransport("a", 4), network.NewTransport("b", 4)
	if err := sender.Send(context.Background(), "b", core); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Handle(<-receiver.Inbox()); err != nil {
		t.Fatal("authenticated core rejected", err)
	}
}
