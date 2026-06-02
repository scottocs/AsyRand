package rbc

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/scottocs/Tyche/utils/p2p"
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
		t.Fatalf("initial message did not carry raw value: %q", val.Value)
	}
}
