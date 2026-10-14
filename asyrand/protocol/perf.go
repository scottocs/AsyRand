package asyrand

import (
	"Tyche/asyrand/protocol/aba"
	"sort"
	"sync/atomic"
)

type Perf struct {
	Invalid     atomic.Uint64
	Recoveries  atomic.Uint64
	ShareCount  atomic.Uint64
	VerifyCount atomic.Uint64
	ReconCount  atomic.Uint64
}

// ABAInstanceStats reports one local copy of a logical instance. Consumers of
// these snapshots must union Instance across nodes to count committee-wide
// instances. Creation is different from proposal, native decision and adoption.
type ABAInstanceStats struct {
	Instance        string `json:"instance"`
	Proposed        bool   `json:"proposed"`
	InternalDecided bool   `json:"internal_decided"`
	Certified       bool   `json:"certified"`
	Stopped         bool   `json:"stopped"`
	Round           uint64 `json:"round"`
}

func (n *Node) ABAStatistics() []ABAInstanceStats {
	n.mu.RLock()
	instances := make(map[string]*aba.Instance, len(n.instances))
	for id, instance := range n.instances {
		instances[id] = instance
	}
	n.mu.RUnlock()
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	stats := make([]ABAInstanceStats, 0, len(ids))
	for _, id := range ids {
		s := instances[id].Status()
		stats = append(stats, ABAInstanceStats{id, s.Proposed, s.InternalDecided, s.Certified, s.Stopped, s.Round})
	}
	return stats
}
