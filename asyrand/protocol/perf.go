package asyrand

import (
	"Tyche/asyrand/protocol/aba"
	"sort"
	"sync/atomic"
)

type Perf struct {
	Invalid             atomic.Uint64
	Recoveries          atomic.Uint64
	ShareCount          atomic.Uint64
	VerifyCount         atomic.Uint64
	ReconCount          atomic.Uint64
	PreReconCount       atomic.Uint64
	ShareCheckCount     atomic.Uint64
	ActorEvents         atomic.Uint64
	DriveCalls          atomic.Uint64
	ProductionWindow    atomic.Uint64
	ProductionMinimum   atomic.Uint64
	ProductionMaximum   atomic.Uint64
	ProductionGrows     atomic.Uint64
	ProductionShrinks   atomic.Uint64
	ProductionPaused    atomic.Uint64
	ProductionDeficit   atomic.Uint64
	ProductionReserve   atomic.Uint64
	PrefetchDecryptions atomic.Uint64
	PrefetchHits        atomic.Uint64
	PrefetchJoins       atomic.Uint64
}

func (n *Node) BenchmarkStats() map[string]any {
	return map[string]any{"consumer_priority_enabled": n.consumerPriority, "consumption_prefetch_enabled": n.prefetchEnabled, "prefetch_decryptions": n.Perf.PrefetchDecryptions.Load(), "prefetch_hits": n.Perf.PrefetchHits.Load(), "prefetch_joins": n.Perf.PrefetchJoins.Load(), "pvss": n.pvss.WorkStats(), "sharing": n.Perf.ShareCount.Load(), "object_verifications": n.Perf.VerifyCount.Load(),
		"local_decryptions": n.Perf.PreReconCount.Load(), "share_verifications": n.Perf.ShareCheckCount.Load(), "reconstructions": n.Perf.ReconCount.Load(),
		"invalid": n.Perf.Invalid.Load(), "recoveries": n.Perf.Recoveries.Load(), "actor_events": n.Perf.ActorEvents.Load(), "drive_calls": n.Perf.DriveCalls.Load(),
		"queued_bytes": n.outgoingBytes.Load(), "crypto_queue": len(n.jobs), "urgent_queue": len(n.urgentJobs), "validation_queue": len(n.validationJobs),
		"crypto_active": n.cryptoActive.Load(), "ready_auth_queue": len(n.authJobs), "production_ready_reserve": n.Perf.ProductionReserve.Load(),
		"production_window": n.Perf.ProductionWindow.Load(), "production_minimum": n.Perf.ProductionMinimum.Load(), "production_maximum": n.Perf.ProductionMaximum.Load(), "production_window_grows": n.Perf.ProductionGrows.Load(), "production_window_shrinks": n.Perf.ProductionShrinks.Load(),
		"production_paused": n.Perf.ProductionPaused.Load(), "production_deficit_ticks": n.Perf.ProductionDeficit.Load()}
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
