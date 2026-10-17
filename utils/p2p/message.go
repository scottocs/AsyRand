package p2p

import (
	"encoding/json"
	"time"
)

type NodeID string

type Message struct {
	Protocol string          `json:"protocol"`
	Type     string          `json:"type"`
	Instance string          `json:"instance"`
	From     NodeID          `json:"from"`
	To       NodeID          `json:"to,omitempty"`
	Payload  json.RawMessage `json:"payload"`
	SentAt   time.Time       `json:"sent_at"`
	// Set only by a transport that binds the sender identity. Never serialized.
	authenticated bool
}

func (m Message) Authenticated() bool { return m.authenticated }

// AuthenticateReplay preserves origin authentication only for messages replayed
// by their original sender over an authenticated channel, never by a third party.
func (m Message) AuthenticateReplay(original Message) (Message, bool) {
	if !m.authenticated || original.From != m.From {
		return Message{}, false
	}
	original.authenticated = true
	return original, true
}

func NewMessage(protocol, typ, instance string, from, to NodeID, payload any) (Message, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{
		Protocol: protocol,
		Type:     typ,
		Instance: instance,
		From:     from,
		To:       to,
		Payload:  raw,
		SentAt:   time.Now().UTC(),
	}, nil
}

func DecodePayload[T any](msg Message) (T, error) {
	var out T
	err := json.Unmarshal(msg.Payload, &out)
	return out, err
}
