package asyrand

import (
	"Tyche/asyrand/protocol/aba"
	"Tyche/asyrand/protocol/rbc"
	"Tyche/utils/p2p"
	"crypto/sha256"
	"sync"
	"sync/atomic"
)

type sendKey struct {
	protocol, typ, instance string
	from, to                p2p.NodeID
	payload                 [sha256.Size]byte
}

// Only identical recovery packets waiting for the same peer are coalesced.
// Once popped, a later retry is admitted again. Native protocol messages and
// distinct evidence are never discarded to satisfy a queue budget.
func recoveryKey(m p2p.Message) (sendKey, bool) {
	coalesce := m.Protocol == rbc.Protocol && (m.Type == "REQUEST" || m.Type == "REPLY") ||
		m.Protocol == Protocol && (m.Type == "REPLY" || m.Type == "SYNC" || m.Type == "REPLAY") ||
		m.Protocol == aba.Protocol && (m.Type == aba.REQUEST || m.Type == aba.RESPONSE)
	if !coalesce {
		return sendKey{}, false
	}
	return sendKey{m.Protocol, m.Type, m.Instance, m.From, m.To, sha256.Sum256(m.Payload)}, true
}

func messageQueueBytes(m p2p.Message) int64 {
	return int64(len(m.Payload) + len(m.Protocol) + len(m.Type) + len(m.Instance) + len(m.From) + len(m.To) + 128)
}

type sender struct {
	mu     sync.Mutex
	queue  []p2p.Message
	queued map[sendKey]bool
	total  *atomic.Int64
	wake   chan struct{}
}

func (s *sender) push(m p2p.Message) {
	key, coalesce := recoveryKey(m)
	s.mu.Lock()
	if coalesce {
		if s.queued == nil {
			s.queued = make(map[sendKey]bool)
		}
		if s.queued[key] {
			s.mu.Unlock()
			return
		}
		s.queued[key] = true
	}
	s.queue = append(s.queue, m)
	if s.total != nil {
		s.total.Add(messageQueueBytes(m))
	}
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *sender) pop() (p2p.Message, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		return p2p.Message{}, false
	}
	m := s.queue[0]
	s.queue[0] = p2p.Message{}
	s.queue = s.queue[1:]
	if key, coalesce := recoveryKey(m); coalesce {
		delete(s.queued, key)
	}
	if s.total != nil {
		s.total.Add(-messageQueueBytes(m))
	}
	return m, true
}
