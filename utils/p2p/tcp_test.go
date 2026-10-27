package p2p

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

type frameRecordingConn struct {
	net.Conn
	bytes.Buffer
	limit, writes int
}

func (c *frameRecordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *frameRecordingConn) Read(p []byte) (int, error)       { return c.Buffer.Read(p) }
func (c *frameRecordingConn) Write(p []byte) (int, error) {
	c.writes++
	if c.limit > 0 && len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.Buffer.Write(p)
}

func TestTCPFrameSingleWriteAndPartialWriteRecovery(t *testing.T) {
	for _, limit := range []int{0, 3} {
		conn := &frameRecordingConn{limit: limit}
		transport := NewTCPTransport("node0", "", nil, 8)
		transport.conns["node1"] = &tcpPeerConn{conn: conn}
		for _, payload := range [][]byte{[]byte(`{"payload":"first"}`), []byte("second frame")} {
			conn.Reset()
			conn.writes = 0
			if err := transport.sendOnce(context.Background(), "node1", "", payload); err != nil {
				t.Fatal(err)
			}
			wire := conn.Bytes()
			if len(wire) != 4+len(payload) || binary.BigEndian.Uint32(wire[:4]) != uint32(len(payload)) || !bytes.Equal(wire[4:], payload) {
				t.Fatal("TCP frame changed or a partial write lost bytes")
			}
			if limit == 0 && conn.writes != 1 {
				t.Fatal("header and body used separate writes")
			}
		}
	}
}

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

func TestTCPTransportBroadcastIgnoresUnreachablePeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrA := freeAddr(t)
	addrB := freeAddr(t)
	missing := freeAddr(t)
	peers := map[NodeID]string{"node0": addrA, "node1": addrB, "node2": missing}
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

	msg, err := NewMessage("test", "PING", "inst", "node0", "", map[string]string{"hello": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Broadcast(ctx, msg); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-b.Inbox():
		if got.From != "node0" || got.To != "node1" || got.Type != "PING" {
			t.Fatalf("unexpected message: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for tcp broadcast")
	}
}

func TestTCPTransportSelfSendDoesNotBlockWhenInboxFull(t *testing.T) {
	transport := NewTCPTransport("node0", "127.0.0.1:0", map[NodeID]string{"node0": "127.0.0.1:0"}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	msg, err := NewMessage("test", "PING", "i", "node0", "node0", map[string]string{"ok": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Send(ctx, "node0", msg); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := transport.Send(ctx, "node0", msg); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("self send blocked with full inbox: %s", elapsed)
	}
	<-transport.Inbox()
	select {
	case <-transport.Inbox():
	case <-ctx.Done():
		t.Fatal("timed out waiting for deferred self message")
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

func TestMutualTLSBindsSenderAndPinsDestination(t *testing.T) {
	pubA, privA, _ := ed25519.GenerateKey(rand.Reader)
	pubB, privB, _ := ed25519.GenerateKey(rand.Reader)
	pubs := map[string]ed25519.PublicKey{"a": pubA, "b": pubB}
	peers := map[NodeID]string{"a": freeAddr(t), "b": freeAddr(t)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := NewAuthenticatedTCPTransport("a", peers["a"], peers, 8, privA, pubs)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAuthenticatedTCPTransport("b", peers["b"], peers, 8, privB, pubs)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := b.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	msg, _ := NewMessage("test", "PING", "i", "a", "b", nil)
	if err := a.Send(ctx, "b", msg); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-b.Inbox():
		if !got.Authenticated() || got.From != "a" {
			t.Fatal("message not bound to TLS sender")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	msg.From = "b"
	if err := a.Send(ctx, "b", msg); err == nil {
		t.Fatal("accepted forged sender")
	}
	// B's valid certificate cannot impersonate A at a misrouted destination.
	msg.From = "a"
	a.peers["a"] = peers["b"]
	if err := a.sendOnce(ctx, "a", peers["b"], []byte("{}")); err == nil {
		t.Fatal("accepted wrong destination identity")
	}
	if _, err := NewAuthenticatedTCPTransport("a", peers["a"], peers, 8, privB, pubs); err == nil {
		t.Fatal("accepted wrong local key")
	}
	network := a.NetworkMessageTypeMetrics()["test/PING"]
	if network.SentMessages != 1 || b.NetworkMessageTypeMetrics()["test/PING"].RecvMessages != 1 {
		t.Fatal("network counters lost remote delivery")
	}
	if err := a.Send(ctx, "a", msg); err != nil {
		t.Fatal(err)
	}
	if a.NetworkMessageTypeMetrics()["test/PING"] != network {
		t.Fatal("network counters include local self-delivery")
	}
}
