package rbc

import (
	"Tyche/utils/p2p"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"
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

func TestPendingValidationDoesNotRequestOrEchoUnverifiedPayload(t *testing.T) {
	bs := broadcasters()
	b := bs[3]
	m := bs[0].Broadcast(1, []byte("pending value"))[0]
	p, _ := Authenticate(b.cfg.Context, b.cfg.Public, m)
	b.PayloadPending(p, true)
	for _, holder := range bs[:3] {
		ready := holder.message("READY", "", pVote(p))
		packet, ok := Authenticate(b.cfg.Context, b.cfg.Public, ready)
		if !ok {
			t.Fatal("invalid test READY")
		}
		out, delivered := b.Handle(ready, packet)
		for _, sent := range out {
			if sent.Type == "REQUEST" || sent.Type == "ECHO" {
				t.Fatal("pending validation caused retrieval or premature ECHO")
			}
		}
		if len(delivered) != 0 {
			t.Fatal("delivered unverified payload")
		}
	}
	if out := b.RetryPayloads(time.Now().Add(time.Hour)); len(out) != 0 {
		t.Fatal("retried locally pending validation")
	}
	_, delivered := b.Handle(m, p) // Caller has now completed payload validation.
	if len(delivered) != 1 {
		t.Fatal("validated payload did not complete delivery")
	}
	if out := b.PayloadPending(p, false); len(out) != 0 {
		t.Fatal("retrieved an already accepted payload")
	}
}

func TestMissingPayloadRotatesPastSilentHolderAndStopsAfterDelivery(t *testing.T) {
	bs := broadcasters()
	b := bs[3]
	m := bs[0].Broadcast(1, []byte("value"))[0]
	p, _ := Authenticate(b.cfg.Context, b.cfg.Public, m)
	b.PayloadPending(p, true)
	for _, holder := range bs[:3] {
		ready := holder.message("READY", "", pVote(p))
		packet, _ := Authenticate(b.cfg.Context, b.cfg.Public, ready)
		b.Handle(ready, packet)
	}
	out := b.PayloadPending(p, false) // Failed local validation must not suppress recovery forever.
	if len(out) != 1 || out[0].To == "" {
		t.Fatal("retrieval should contact one holder")
	}
	seen := map[p2p.NodeID]bool{out[0].To: true}
	if retry := b.RetryPayloads(time.Now()); len(retry) != 0 {
		t.Fatal("retried before backoff")
	}
	for i := 1; i <= len(bs)+1; i++ {
		retry := b.RetryPayloads(time.Now().Add(time.Duration(i) * 2 * time.Second))
		if len(retry) != 1 || retry[0].To == "" || retry[0].To == b.cfg.ID {
			t.Fatal("invalid targeted retry")
		}
		seen[retry[0].To] = true
	}
	if len(seen) != len(bs)-1 {
		t.Fatal("silent first holder prevented membership fallback")
	}
	reply := bs[0].message("REPLY", b.cfg.ID, Packet{Dealer: p.Dealer, Seq: p.Seq, Hash: p.Hash, Value: p.Value})
	packet, _ := Authenticate(b.cfg.Context, b.cfg.Public, reply)
	_, delivered := b.Handle(reply, packet)
	if len(delivered) != 1 {
		t.Fatal("valid retrieved value was not delivered")
	}
	if retry := b.RetryPayloads(time.Now().Add(time.Hour)); len(retry) != 0 {
		t.Fatal("retrieval continued after delivery")
	}
}

func TestFailedPendingValuesDoNotRetainUnverifiedHashStates(t *testing.T) {
	b := broadcasters()[3]
	for i := 0; i < 1000; i++ {
		p := Packet{Dealer: "a", Seq: 1, Hash: Hash([]byte{byte(i), byte(i >> 8)})}
		b.PayloadPending(p, true)
		b.PayloadPending(p, false)
	}
	if len(b.states) != 0 || len(b.pending) != 0 || len(b.missing) != 0 {
		t.Fatal("failed validation retained unbounded RBC states")
	}
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
