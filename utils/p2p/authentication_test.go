package p2p

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMemoryAuthenticationCannotBeForgedOrForwarded(t *testing.T) {
	n := NewMemoryNetwork()
	a, b := n.NewTransport("a", 4), n.NewTransport("b", 4)
	msg, _ := NewMessage("test", "value", "instance", "b", "", "body")
	if err := a.Send(context.Background(), "b", msg); err == nil {
		t.Fatal("forged identity accepted")
	}
	msg.From = "a"
	if err := a.Send(context.Background(), "b", msg); err != nil {
		t.Fatal(err)
	}
	msg.Payload[0] = 'x'
	got := <-b.Inbox()
	if !got.Authenticated() || !json.Valid(got.Payload) {
		t.Fatal("missing authentication or mutable delivered payload")
	}
	raw, _ := json.Marshal(got)
	var decoded Message
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Authenticated() {
		t.Fatal("authentication leaked into a wire encoding")
	}
	decoded.From = "b"
	if _, ok := got.AuthenticateReplay(decoded); ok {
		t.Fatal("third-party replay inherited authentication")
	}
	decoded.From = "a"
	if replay, ok := got.AuthenticateReplay(decoded); !ok || !replay.Authenticated() {
		t.Fatal("original sender replay lost authentication")
	}
}
