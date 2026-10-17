package p2p

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignedMessagesBindOriginProtocolAndBody(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := NewMessage("baseline", "PREPARE", "epoch-7", "n0", "", map[string]int{"value": 1})
	signed, err := SignMessage(plain, private)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenSignedMessage(signed, public)
	if err != nil || string(opened.Payload) != string(plain.Payload) {
		t.Fatal("honest multicast rejected", err)
	}
	if _, err := OpenSignedMessage(plain, public); err == nil {
		t.Fatal("unsigned packet accepted")
	}
	for _, change := range []func(*Message){
		func(m *Message) { m.From = "n1" },
		func(m *Message) { m.Protocol = "other" },
		func(m *Message) { m.Type = "COMMIT" },
		func(m *Message) { m.Instance = "epoch-8" },
		func(m *Message) {
			m.Payload = append([]byte(nil), signed.Payload...)
			for i, b := range m.Payload {
				if b == '1' {
					m.Payload[i] = '2'
					break
				}
			}
		},
	} {
		packet := signed
		change(&packet)
		if _, err := OpenSignedMessage(packet, public); err == nil {
			t.Fatal("tampered packet accepted")
		}
	}
	// A channel-authenticated unsigned packet must still fail this signature API.
	net := NewMemoryNetwork()
	a, b := net.NewTransport("n0", 1), net.NewTransport("n1", 1)
	if err := a.Send(t.Context(), "n1", plain); err != nil {
		t.Fatal(err)
	}
	packet := <-b.Inbox()
	if !packet.Authenticated() {
		t.Fatal("test requires authenticated delivery")
	}
	if _, err := OpenSignedMessage(packet, public); err == nil {
		t.Fatal("channel authentication bypassed signature")
	}
}
