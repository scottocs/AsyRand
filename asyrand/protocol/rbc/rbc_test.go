package rbc

import (
	"Tyche/utils/p2p"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
)

func broadcasters() []*Broadcaster {
	members := []p2p.NodeID{"a", "b", "c", "d"}
	pub := map[string]ed25519.PublicKey{}
	priv := map[p2p.NodeID]ed25519.PrivateKey{}
	for i, id := range members {
		seed := make([]byte, 32)
		seed[0] = byte(i + 1)
		priv[id] = ed25519.NewKeyFromSeed(seed)
		pub[string(id)] = priv[id].Public().(ed25519.PublicKey)
	}
	var out []*Broadcaster
	for _, id := range members {
		out = append(out, New(Config{ID: id, F: 1, Members: members, Context: Hash([]byte("test")), Private: priv[id], Public: pub}))
	}
	return out
}
func TestDeliveryProofAndMissingPayloadRecovery(t *testing.T) {
	bs := broadcasters()
	queue := bs[0].Broadcast(1, []byte("value"))
	delivered := map[p2p.NodeID]Delivery{}
	steps := 0
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		steps++
		if steps > 10000 {
			t.Fatal("message loop")
		}
		for _, b := range bs {
			if m.To != "" && m.To != b.cfg.ID {
				continue
			}
			if m.Type == "VAL" && b.cfg.ID == "d" {
				continue
			}
			p, ok := Authenticate(b.cfg.Context, b.cfg.Public, m)
			if !ok {
				t.Fatal("authentication failed")
			}
			out, del := b.Handle(m, p)
			queue = append(queue, out...)
			for _, d := range del {
				if _, ok := delivered[b.cfg.ID]; ok {
					t.Fatal("duplicate delivery")
				}
				delivered[b.cfg.ID] = d
			}
		}
	}
	if len(delivered) != 4 {
		t.Fatalf("missing payload recovery failed: %d deliveries", len(delivered))
	}
	for _, d := range delivered {
		if string(d.Value) != "value" || !VerifyCertificate(bs[0].cfg.Context, bs[0].cfg.Public, 1, d.Certificate) {
			t.Fatal("bad delivery certificate")
		}
		bad := d.Certificate
		bad.Signatures = append([]Signature(nil), bad.Signatures...)
		bad.Signatures[0].Signature = hex.EncodeToString(make([]byte, 64))
		if VerifyCertificate(bs[0].cfg.Context, bs[0].cfg.Public, 1, bad) {
			t.Fatal("accepted forged READY certificate")
		}
	}
}
func TestDealerEquivocationCannotCauseTwoLocalEchoes(t *testing.T) {
	bs := broadcasters()
	b := bs[1]
	first := bs[0].Broadcast(1, []byte("first"))[0]
	second := bs[0].Broadcast(1, []byte("second"))[0]
	for i, m := range []p2p.Message{first, second} {
		p, _ := Authenticate(b.cfg.Context, b.cfg.Public, m)
		out, _ := b.Handle(m, p)
		if i == 0 && len(out) != 1 {
			t.Fatal("missing first ECHO")
		}
		if i == 1 && len(out) != 0 {
			t.Fatal("echoed equivocating dealer")
		}
	}
	// Equivocations and arbitrary pull requests cannot grow the hash-state table.
	for i := 0; i < 100; i++ {
		p := Packet{Context: b.cfg.Context, Dealer: "a", Seq: 1, Hash: Hash([]byte{byte(i)})}
		m := bs[0].message("REQUEST", "b", p)
		packet, _ := Authenticate(b.cfg.Context, b.cfg.Public, m)
		b.Handle(m, packet)
	}
	if len(b.states[Key("a", 1)].values) != 1 {
		t.Fatal("unsolicited requests allocated hash states")
	}
}
