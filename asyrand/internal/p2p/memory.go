package p2p

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
)

type MemoryNetwork struct {
	mu    sync.RWMutex
	peers map[NodeID]*MemoryTransport
}

func NewMemoryNetwork() *MemoryNetwork {
	return &MemoryNetwork{peers: make(map[NodeID]*MemoryTransport)}
}

func (n *MemoryNetwork) NewTransport(id NodeID, buffer int) *MemoryTransport {
	n.mu.Lock()
	defer n.mu.Unlock()
	t := &MemoryTransport{id: id, net: n, inbox: make(chan Message, buffer)}
	n.peers[id] = t
	return t
}

type MemoryTransport struct {
	id           NodeID
	net          *MemoryNetwork
	inbox        chan Message
	closed       bool
	mu           sync.RWMutex
	sentMessages atomic.Uint64
	sentBytes    atomic.Uint64
	recvMessages atomic.Uint64
	recvBytes    atomic.Uint64
}

func (t *MemoryTransport) ID() NodeID                  { return t.id }
func (t *MemoryTransport) Inbox() <-chan Message       { return t.inbox }
func (t *MemoryTransport) Start(context.Context) error { return nil }

func (t *MemoryTransport) Send(ctx context.Context, to NodeID, msg Message) error {
	t.net.mu.RLock()
	peer := t.net.peers[to]
	t.net.mu.RUnlock()
	if peer == nil {
		return errors.New("unknown peer: " + string(to))
	}
	peer.mu.RLock()
	closed := peer.closed
	peer.mu.RUnlock()
	if closed {
		return errors.New("peer closed: " + string(to))
	}
	msg.To = to
	size := messageSize(msg)
	select {
	case peer.inbox <- msg:
		t.sentMessages.Add(1)
		t.sentBytes.Add(uint64(size))
		peer.recvMessages.Add(1)
		peer.recvBytes.Add(uint64(size))
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *MemoryTransport) Broadcast(ctx context.Context, msg Message) error {
	t.net.mu.RLock()
	ids := make([]NodeID, 0, len(t.net.peers))
	for id := range t.net.peers {
		ids = append(ids, id)
	}
	t.net.mu.RUnlock()
	for _, id := range ids {
		if err := t.Send(ctx, id, msg); err != nil {
			return err
		}
	}
	return nil
}

func (t *MemoryTransport) Metrics() Metrics {
	return Metrics{
		SentMessages: t.sentMessages.Load(),
		SentBytes:    t.sentBytes.Load(),
		RecvMessages: t.recvMessages.Load(),
		RecvBytes:    t.recvBytes.Load(),
	}
}

func (t *MemoryTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.inbox)
	}
	return nil
}

func messageSize(msg Message) int {
	data, err := json.Marshal(msg)
	if err != nil {
		return 0
	}
	return len(data)
}
