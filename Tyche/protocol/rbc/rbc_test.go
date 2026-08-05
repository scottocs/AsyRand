package rbc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	tychecrypto "Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

func TestRBCBroadcastDeliversSameValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	net := p2p.NewMemoryNetwork()
	nodes := make([]*Broadcaster, 0, len(ids))
	for _, id := range ids {
		transport := net.NewTransport(id, 256)
		b := New(id, len(ids), 1, transport)
		nodes = append(nodes, b)
		go func(b *Broadcaster, transport p2p.Transport) {
			for {
				select {
				case msg := <-transport.Inbox():
					_ = b.Handle(ctx, msg)
				case <-ctx.Done():
					return
				}
			}
		}(b, transport)
	}

	value := []byte("tyche-rbc-value")
	if err := nodes[0].Broadcast(ctx, 1, value); err != nil {
		t.Fatal(err)
	}
	for _, b := range nodes {
		select {
		case d := <-b.Deliveries:
			if d.Dealer != "n0" || d.Seq != 1 || !bytes.Equal(d.Value, value) || d.Hash != Digest(value) {
				t.Fatalf("bad delivery: %+v", d)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for RBC delivery")
		}
	}
}

func TestRBCInitialCarriesValue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	net := p2p.NewMemoryNetwork()
	transport0 := net.NewTransport("n0", 8)
	transport1 := net.NewTransport("n1", 8)
	b := New("n0", 2, 0, transport0)

	value := []byte("large-rbc-payload")
	if err := b.Broadcast(ctx, 7, value); err != nil {
		t.Fatal(err)
	}

	var msg p2p.Message
	select {
	case msg = <-transport1.Inbox():
	case <-ctx.Done():
		t.Fatal("timed out waiting for initial message")
	}
	if msg.Type != "VAL" {
		t.Fatalf("unexpected message type: %s", msg.Type)
	}
	val, err := p2p.DecodePayload[ValueMessage](msg)
	if err != nil {
		t.Fatal(err)
	}
	if val.Hash != Digest(value) {
		t.Fatalf("bad hash: %s", val.Hash)
	}
	if !bytes.Equal(val.Value, value) {
		t.Fatalf("bad initial value: %+v", val)
	}
}

func TestRBCValAfterReadyQuorumDelivers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	net := p2p.NewMemoryNetwork()
	transport := net.NewTransport("n0", 16)
	b := New("n0", 4, 1, transport)

	value := []byte("late-val-rbc-value")
	hash := Digest(value)
	for _, from := range []p2p.NodeID{"n1", "n2", "n3"} {
		msg, err := p2p.NewMessage(Protocol, "READY", Instance("dealer", 9, hash), from, "n0", VoteMessage{Hash: hash})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Handle(ctx, msg); err != nil {
			t.Fatal(err)
		}
	}

	select {
	case d := <-b.Deliveries:
		t.Fatalf("delivered without VAL: %+v", d)
	default:
	}

	val, err := p2p.NewMessage(Protocol, "VAL", Instance("dealer", 9, hash), "dealer", "n0", ValueMessage{Value: value, Hash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Handle(ctx, val); err != nil {
		t.Fatal(err)
	}

	select {
	case d := <-b.Deliveries:
		if d.Dealer != "dealer" || d.Seq != 9 || !bytes.Equal(d.Value, value) || d.Hash != hash {
			t.Fatalf("bad delivery: %+v", d)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for delivery after VAL")
	}
}

func TestPruneThroughKeepsFutureInstances(t *testing.T) {
	b := New("n0", 4, 1, nil)
	oldHash := Digest([]byte("old"))
	futureHash := Digest([]byte("future"))
	old := Instance("dealer", 3, oldHash)
	future := Instance("dealer", 4, futureHash)

	b.values[old] = ValueMessage{Value: []byte("old"), Hash: oldHash}
	b.echoes[old] = map[p2p.NodeID]bool{"n1": true}
	b.readies[old] = map[p2p.NodeID]bool{"n2": true}
	b.echoSent[old] = true
	b.readySent[old] = true
	b.delivered[old] = true

	b.values[future] = ValueMessage{Value: []byte("future"), Hash: futureHash}
	b.echoes[future] = map[p2p.NodeID]bool{"n1": true}
	b.readies[future] = map[p2p.NodeID]bool{"n2": true}
	b.echoSent[future] = true
	b.readySent[future] = true
	b.delivered[future] = true

	b.PruneThrough(map[p2p.NodeID]uint64{"dealer": 3})
	if b.values[old].Value != nil || b.echoes[old] != nil || b.readies[old] != nil || b.echoSent[old] || b.readySent[old] || b.delivered[old] {
		t.Fatal("old RBC instance was retained")
	}
	if b.values[future].Value == nil || b.echoes[future] == nil || b.readies[future] == nil || !b.echoSent[future] || !b.readySent[future] || !b.delivered[future] {
		t.Fatal("future RBC instance was pruned")
	}
}

func TestAuthenticatedDeliveryCertificateBindsExactVoterSet(t *testing.T) {
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
	b, err := NewAuthenticated("n0", 7, "pvss", ids, 1, p2p.NewMemoryNetwork().NewTransport("n0", 8), private["n0"], public)
	if err != nil {
		t.Fatal(err)
	}
	instance := InstanceFor(7, "pvss", "n1", 9)
	hash := Digest([]byte("value"))
	cert := DeliveryCertificate{ConfigVersion: 7, Purpose: "pvss", Instance: instance, Hash: hash}
	var votes []tychecrypto.SignedVote
	for _, id := range ids[:3] {
		vote, err := tychecrypto.SignTranscript(string(id), private[id], b.transcript("READY", instance, hash))
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	cert.ReadyCertificate, err = tychecrypto.BuildSignedQuorumCertificate(
		votes,
		public,
		b.quorum(),
		b.transcript("READY", instance, hash),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyDeliveryCertificate(cert); err != nil {
		t.Fatal(err)
	}
	tampered := cert
	tampered.Hash = Digest([]byte("other"))
	if err := b.VerifyDeliveryCertificate(tampered); err == nil {
		t.Fatal("certificate replayed for a different value")
	}
	mismatch := cert
	mismatch.ReadyCertificate.SignerBitmap = append([]byte(nil), cert.ReadyCertificate.SignerBitmap...)
	mismatch.ReadyCertificate.SignerBitmap[0] &^= 1 << 2
	mismatch.ReadyCertificate.SignerBitmap[0] |= 1 << 3
	if err := b.VerifyDeliveryCertificate(mismatch); err == nil {
		t.Fatal("signatures were accepted for a different READY bitmap")
	}
}

func TestAuthenticatedRBCRejectsEquivocatingSecondVAL(t *testing.T) {
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
	b, err := NewAuthenticated("n0", 3, "pvss", ids, 1, p2p.NewMemoryNetwork().NewTransport("n0", 32), private["n0"], public)
	if err != nil {
		t.Fatal(err)
	}
	instance := InstanceFor(3, "pvss", "n1", 1)
	send := func(value []byte) {
		body := ValueMessage{Value: value, Hash: Digest(value)}
		body.Signature, err = tychecrypto.SignTranscript("n1", private["n1"], b.transcript("VAL", instance, body.Hash))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := p2p.NewMessage(Protocol, "VAL", instance, "n1", "n0", body)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Handle(ctx, msg); err != nil {
			t.Fatal(err)
		}
	}
	send([]byte("first"))
	send([]byte("second"))
	if got := b.values[instance]; !bytes.Equal(got.Value, []byte("first")) {
		t.Fatalf("equivocation replaced fixed RBC value: %q", got.Value)
	}
}
