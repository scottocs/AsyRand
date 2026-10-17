package p2p

import (
	"Tyche/utils/verification"
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

// SignedPayload carries a transferable sender signature. Channel authentication
// is deliberately not a substitute for it in the two signed-message baselines.
type SignedPayload struct {
	Body      json.RawMessage `json:"body"`
	Signature []byte          `json:"signature"`
}

func messageStatement(msg Message, body json.RawMessage) []byte {
	// Recipient and send time are transport metadata: one signed multicast may
	// be delivered to every member, and its signature can be forwarded as evidence.
	raw, _ := json.Marshal(struct {
		Domain, Protocol, Type, Instance string
		From                             NodeID
		Body                             json.RawMessage
	}{"Tyche/signed-message/v1", msg.Protocol, msg.Type, msg.Instance, msg.From, body})
	return raw
}

func SignMessage(msg Message, private ed25519.PrivateKey) (Message, error) {
	if len(private) != ed25519.PrivateKeySize || msg.From == "" || !json.Valid(msg.Payload) {
		return Message{}, errors.New("invalid message signing input")
	}
	body := append(json.RawMessage(nil), msg.Payload...)
	raw, err := json.Marshal(SignedPayload{body, ed25519.Sign(private, messageStatement(msg, body))})
	if err != nil {
		return Message{}, err
	}
	msg.Payload = raw
	return msg, nil
}

// OpenSignedMessage verifies before exposing the body to any protocol handler.
func OpenSignedMessage(msg Message, public ed25519.PublicKey, caches ...*verification.Cache) (Message, error) {
	opened, _, err := OpenSignedMessageOnce(msg, public, verification.Optional(caches...))
	return opened, err
}

// OpenSignedMessageOnce reports actual cryptographic work separately from a
// successful cache lookup. Decoding and all message-binding checks still run.
func OpenSignedMessageOnce(msg Message, public ed25519.PublicKey, cache *verification.Cache) (Message, bool, error) {
	var packet SignedPayload
	if len(public) != ed25519.PublicKeySize || json.Unmarshal(msg.Payload, &packet) != nil ||
		!json.Valid(packet.Body) {
		return Message{}, false, errors.New("invalid message signature")
	}
	valid, executed := cache.Ed25519Once(public, messageStatement(msg, packet.Body), packet.Signature)
	if !valid {
		return Message{}, executed, errors.New("invalid message signature")
	}
	msg.Payload = append(json.RawMessage(nil), packet.Body...)
	return msg, executed, nil
}
