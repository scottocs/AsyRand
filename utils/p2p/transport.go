package p2p

import "context"

type Metrics struct {
	SentMessages uint64
	SentBytes    uint64
	RecvMessages uint64
	RecvBytes    uint64
}

type MessageTypeMetrics struct {
	SentMessages uint64
	SentBytes    uint64
	RecvMessages uint64
	RecvBytes    uint64
}

type Transport interface {
	ID() NodeID
	Inbox() <-chan Message
	Start(context.Context) error
	Send(context.Context, NodeID, Message) error
	Broadcast(context.Context, Message) error
	Metrics() Metrics
	Close() error
}
