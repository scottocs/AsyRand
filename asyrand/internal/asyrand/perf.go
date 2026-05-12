package asyrand

import (
	"sync/atomic"
	"time"
)

type PerfMetrics struct {
	pvssShareNs    atomic.Int64
	pvssShareCount atomic.Uint64

	pvssVerifyNs    atomic.Int64
	pvssVerifyCount atomic.Uint64

	pvssPreReconNs    atomic.Int64
	pvssPreReconCount atomic.Uint64

	pvssReconNs    atomic.Int64
	pvssReconCount atomic.Uint64

	rbcHandleNs    atomic.Int64
	rbcHandleCount atomic.Uint64

	abaHandleNs    atomic.Int64
	abaHandleCount atomic.Uint64

	blsVerifyNs    atomic.Int64
	blsVerifyCount atomic.Uint64

	blsAggregateNs    atomic.Int64
	blsAggregateCount atomic.Uint64
}

type PerfSnapshot struct {
	PVSSShareCount    uint64
	PVSSShareTotal    time.Duration
	PVSSVerifyCount   uint64
	PVSSVerifyTotal   time.Duration
	PVSSPreReconCount uint64
	PVSSPreReconTotal time.Duration
	PVSSReconCount    uint64
	PVSSReconTotal    time.Duration
	RBCHandleCount    uint64
	RBCHandleTotal    time.Duration
	ABAHandleCount    uint64
	ABAHandleTotal    time.Duration
	BLSVerifyCount    uint64
	BLSVerifyTotal    time.Duration
	BLSAggregateCount uint64
	BLSAggregateTotal time.Duration
}

func (p *PerfMetrics) addShare(d time.Duration) {
	p.pvssShareNs.Add(d.Nanoseconds())
	p.pvssShareCount.Add(1)
}

func (p *PerfMetrics) addVerify(d time.Duration) {
	p.pvssVerifyNs.Add(d.Nanoseconds())
	p.pvssVerifyCount.Add(1)
}

func (p *PerfMetrics) addPreRecon(d time.Duration) {
	p.pvssPreReconNs.Add(d.Nanoseconds())
	p.pvssPreReconCount.Add(1)
}

func (p *PerfMetrics) addRecon(d time.Duration) {
	p.pvssReconNs.Add(d.Nanoseconds())
	p.pvssReconCount.Add(1)
}

func (p *PerfMetrics) addRBCHandle(d time.Duration) {
	p.rbcHandleNs.Add(d.Nanoseconds())
	p.rbcHandleCount.Add(1)
}

func (p *PerfMetrics) addABAHandle(d time.Duration) {
	p.abaHandleNs.Add(d.Nanoseconds())
	p.abaHandleCount.Add(1)
}

func (p *PerfMetrics) addBLSVerify(d time.Duration) {
	p.blsVerifyNs.Add(d.Nanoseconds())
	p.blsVerifyCount.Add(1)
}

func (p *PerfMetrics) addBLSAggregate(d time.Duration) {
	p.blsAggregateNs.Add(d.Nanoseconds())
	p.blsAggregateCount.Add(1)
}

func (p *PerfMetrics) Snapshot() PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:    p.pvssShareCount.Load(),
		PVSSShareTotal:    time.Duration(p.pvssShareNs.Load()),
		PVSSVerifyCount:   p.pvssVerifyCount.Load(),
		PVSSVerifyTotal:   time.Duration(p.pvssVerifyNs.Load()),
		PVSSPreReconCount: p.pvssPreReconCount.Load(),
		PVSSPreReconTotal: time.Duration(p.pvssPreReconNs.Load()),
		PVSSReconCount:    p.pvssReconCount.Load(),
		PVSSReconTotal:    time.Duration(p.pvssReconNs.Load()),
		RBCHandleCount:    p.rbcHandleCount.Load(),
		RBCHandleTotal:    time.Duration(p.rbcHandleNs.Load()),
		ABAHandleCount:    p.abaHandleCount.Load(),
		ABAHandleTotal:    time.Duration(p.abaHandleNs.Load()),
		BLSVerifyCount:    p.blsVerifyCount.Load(),
		BLSVerifyTotal:    time.Duration(p.blsVerifyNs.Load()),
		BLSAggregateCount: p.blsAggregateCount.Load(),
		BLSAggregateTotal: time.Duration(p.blsAggregateNs.Load()),
	}
}

func (s PerfSnapshot) Add(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:    s.PVSSShareCount + o.PVSSShareCount,
		PVSSShareTotal:    s.PVSSShareTotal + o.PVSSShareTotal,
		PVSSVerifyCount:   s.PVSSVerifyCount + o.PVSSVerifyCount,
		PVSSVerifyTotal:   s.PVSSVerifyTotal + o.PVSSVerifyTotal,
		PVSSPreReconCount: s.PVSSPreReconCount + o.PVSSPreReconCount,
		PVSSPreReconTotal: s.PVSSPreReconTotal + o.PVSSPreReconTotal,
		PVSSReconCount:    s.PVSSReconCount + o.PVSSReconCount,
		PVSSReconTotal:    s.PVSSReconTotal + o.PVSSReconTotal,
		RBCHandleCount:    s.RBCHandleCount + o.RBCHandleCount,
		RBCHandleTotal:    s.RBCHandleTotal + o.RBCHandleTotal,
		ABAHandleCount:    s.ABAHandleCount + o.ABAHandleCount,
		ABAHandleTotal:    s.ABAHandleTotal + o.ABAHandleTotal,
		BLSVerifyCount:    s.BLSVerifyCount + o.BLSVerifyCount,
		BLSVerifyTotal:    s.BLSVerifyTotal + o.BLSVerifyTotal,
		BLSAggregateCount: s.BLSAggregateCount + o.BLSAggregateCount,
		BLSAggregateTotal: s.BLSAggregateTotal + o.BLSAggregateTotal,
	}
}

func (s PerfSnapshot) Sub(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:    s.PVSSShareCount - o.PVSSShareCount,
		PVSSShareTotal:    s.PVSSShareTotal - o.PVSSShareTotal,
		PVSSVerifyCount:   s.PVSSVerifyCount - o.PVSSVerifyCount,
		PVSSVerifyTotal:   s.PVSSVerifyTotal - o.PVSSVerifyTotal,
		PVSSPreReconCount: s.PVSSPreReconCount - o.PVSSPreReconCount,
		PVSSPreReconTotal: s.PVSSPreReconTotal - o.PVSSPreReconTotal,
		PVSSReconCount:    s.PVSSReconCount - o.PVSSReconCount,
		PVSSReconTotal:    s.PVSSReconTotal - o.PVSSReconTotal,
		RBCHandleCount:    s.RBCHandleCount - o.RBCHandleCount,
		RBCHandleTotal:    s.RBCHandleTotal - o.RBCHandleTotal,
		ABAHandleCount:    s.ABAHandleCount - o.ABAHandleCount,
		ABAHandleTotal:    s.ABAHandleTotal - o.ABAHandleTotal,
		BLSVerifyCount:    s.BLSVerifyCount - o.BLSVerifyCount,
		BLSVerifyTotal:    s.BLSVerifyTotal - o.BLSVerifyTotal,
		BLSAggregateCount: s.BLSAggregateCount - o.BLSAggregateCount,
		BLSAggregateTotal: s.BLSAggregateTotal - o.BLSAggregateTotal,
	}
}

func AvgDuration(total time.Duration, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return time.Duration(int64(total) / int64(count))
}
