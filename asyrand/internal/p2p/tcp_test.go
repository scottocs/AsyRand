package p2p

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTCPTransportSendAndMetrics(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrA := freeAddr(t)
	addrB := freeAddr(t)
	peers := map[NodeID]string{"node0": addrA, "node1": addrB}
	a := NewTCPTransport("node0", "127.0.0.1"+addrPort(addrA), peers, 8)
	b := NewTCPTransport("node1", "127.0.0.1"+addrPort(addrB), peers, 8)
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	msg, err := NewMessage("test", "PING", "inst", "node0", "node1", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, "node1", msg); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-b.Inbox():
		if got.From != "node0" || got.To != "node1" || got.Type != "PING" {
			t.Fatalf("unexpected message: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for tcp message")
	}
	if a.Metrics().SentBytes == 0 || b.Metrics().RecvBytes == 0 {
		t.Fatal("tcp metrics were not updated")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func addrPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return ":" + port
}
