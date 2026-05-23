package tyche

import (
	"sync/atomic"
	"time"
)

type PerfMetrics struct {
	pvssShareNs     atomic.Int64
	pvssShareCount  atomic.Uint64
	pvssVerifyNs    atomic.Int64
	pvssVerifyCount atomic.Uint64
	pvssPreReconNs  atomic.Int64
	pvssPreReconCnt atomic.Uint64
	pvssReconNs     atomic.Int64
	pvssReconCount  atomic.Uint64
	rbcHandleNs     atomic.Int64
	rbcHandleCount  atomic.Uint64
	abaHandleNs     atomic.Int64
	abaHandleCount  atomic.Uint64
	blsSignNs       atomic.Int64
	blsSignCount    atomic.Uint64
	blsVerifyNs     atomic.Int64
	blsVerifyCount  atomic.Uint64
	blsAggregateNs  atomic.Int64
	blsAggregateCnt atomic.Uint64
}

type PerfSnapshot struct {
	PVSSShareTotal    time.Duration
	PVSSShareCount    uint64
	PVSSVerifyTotal   time.Duration
	PVSSVerifyCount   uint64
	PVSSPreReconTotal time.Duration
	PVSSPreReconCount uint64
	PVSSReconTotal    time.Duration
	PVSSReconCount    uint64
	RBCHandleTotal    time.Duration
	RBCHandleCount    uint64
	ABAHandleTotal    time.Duration
	ABAHandleCount    uint64
	BLSSignTotal      time.Duration
	BLSSignCount      uint64
	BLSVerifyTotal    time.Duration
	BLSVerifyCount    uint64
	BLSAggregateTotal time.Duration
	BLSAggregateCount uint64
}

func (p *PerfMetrics) addPVSSShare(d time.Duration) {
	p.pvssShareNs.Add(d.Nanoseconds())
	p.pvssShareCount.Add(1)
}

func (p *PerfMetrics) addPVSSVerify(d time.Duration) {
	p.pvssVerifyNs.Add(d.Nanoseconds())
	p.pvssVerifyCount.Add(1)
}

func (p *PerfMetrics) addPVSSPreRecon(d time.Duration) {
	p.pvssPreReconNs.Add(d.Nanoseconds())
	p.pvssPreReconCnt.Add(1)
}

func (p *PerfMetrics) addPVSSRecon(d time.Duration) {
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

func (p *PerfMetrics) addBLSSign(d time.Duration) {
	p.blsSignNs.Add(d.Nanoseconds())
	p.blsSignCount.Add(1)
}

func (p *PerfMetrics) addBLSVerify(d time.Duration) {
	p.blsVerifyNs.Add(d.Nanoseconds())
	p.blsVerifyCount.Add(1)
}

func (p *PerfMetrics) addBLSAggregate(d time.Duration) {
	p.blsAggregateNs.Add(d.Nanoseconds())
	p.blsAggregateCnt.Add(1)
}

func (p *PerfMetrics) Snapshot() PerfSnapshot {
	if p == nil {
		return PerfSnapshot{}
	}
	return PerfSnapshot{
		PVSSShareTotal:    time.Duration(p.pvssShareNs.Load()),
		PVSSShareCount:    p.pvssShareCount.Load(),
		PVSSVerifyTotal:   time.Duration(p.pvssVerifyNs.Load()),
		PVSSVerifyCount:   p.pvssVerifyCount.Load(),
		PVSSPreReconTotal: time.Duration(p.pvssPreReconNs.Load()),
		PVSSPreReconCount: p.pvssPreReconCnt.Load(),
		PVSSReconTotal:    time.Duration(p.pvssReconNs.Load()),
		PVSSReconCount:    p.pvssReconCount.Load(),
		RBCHandleTotal:    time.Duration(p.rbcHandleNs.Load()),
		RBCHandleCount:    p.rbcHandleCount.Load(),
		ABAHandleTotal:    time.Duration(p.abaHandleNs.Load()),
		ABAHandleCount:    p.abaHandleCount.Load(),
		BLSSignTotal:      time.Duration(p.blsSignNs.Load()),
		BLSSignCount:      p.blsSignCount.Load(),
		BLSVerifyTotal:    time.Duration(p.blsVerifyNs.Load()),
		BLSVerifyCount:    p.blsVerifyCount.Load(),
		BLSAggregateTotal: time.Duration(p.blsAggregateNs.Load()),
		BLSAggregateCount: p.blsAggregateCnt.Load(),
	}
}

func (s PerfSnapshot) Add(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareTotal:    s.PVSSShareTotal + o.PVSSShareTotal,
		PVSSShareCount:    s.PVSSShareCount + o.PVSSShareCount,
		PVSSVerifyTotal:   s.PVSSVerifyTotal + o.PVSSVerifyTotal,
		PVSSVerifyCount:   s.PVSSVerifyCount + o.PVSSVerifyCount,
		PVSSPreReconTotal: s.PVSSPreReconTotal + o.PVSSPreReconTotal,
		PVSSPreReconCount: s.PVSSPreReconCount + o.PVSSPreReconCount,
		PVSSReconTotal:    s.PVSSReconTotal + o.PVSSReconTotal,
		PVSSReconCount:    s.PVSSReconCount + o.PVSSReconCount,
		RBCHandleTotal:    s.RBCHandleTotal + o.RBCHandleTotal,
		RBCHandleCount:    s.RBCHandleCount + o.RBCHandleCount,
		ABAHandleTotal:    s.ABAHandleTotal + o.ABAHandleTotal,
		ABAHandleCount:    s.ABAHandleCount + o.ABAHandleCount,
		BLSSignTotal:      s.BLSSignTotal + o.BLSSignTotal,
		BLSSignCount:      s.BLSSignCount + o.BLSSignCount,
		BLSVerifyTotal:    s.BLSVerifyTotal + o.BLSVerifyTotal,
		BLSVerifyCount:    s.BLSVerifyCount + o.BLSVerifyCount,
		BLSAggregateTotal: s.BLSAggregateTotal + o.BLSAggregateTotal,
		BLSAggregateCount: s.BLSAggregateCount + o.BLSAggregateCount,
	}
}

func (s PerfSnapshot) Sub(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareTotal:    s.PVSSShareTotal - o.PVSSShareTotal,
		PVSSShareCount:    s.PVSSShareCount - o.PVSSShareCount,
		PVSSVerifyTotal:   s.PVSSVerifyTotal - o.PVSSVerifyTotal,
		PVSSVerifyCount:   s.PVSSVerifyCount - o.PVSSVerifyCount,
		PVSSPreReconTotal: s.PVSSPreReconTotal - o.PVSSPreReconTotal,
		PVSSPreReconCount: s.PVSSPreReconCount - o.PVSSPreReconCount,
		PVSSReconTotal:    s.PVSSReconTotal - o.PVSSReconTotal,
		PVSSReconCount:    s.PVSSReconCount - o.PVSSReconCount,
		RBCHandleTotal:    s.RBCHandleTotal - o.RBCHandleTotal,
		RBCHandleCount:    s.RBCHandleCount - o.RBCHandleCount,
		ABAHandleTotal:    s.ABAHandleTotal - o.ABAHandleTotal,
		ABAHandleCount:    s.ABAHandleCount - o.ABAHandleCount,
		BLSSignTotal:      s.BLSSignTotal - o.BLSSignTotal,
		BLSSignCount:      s.BLSSignCount - o.BLSSignCount,
		BLSVerifyTotal:    s.BLSVerifyTotal - o.BLSVerifyTotal,
		BLSVerifyCount:    s.BLSVerifyCount - o.BLSVerifyCount,
		BLSAggregateTotal: s.BLSAggregateTotal - o.BLSAggregateTotal,
		BLSAggregateCount: s.BLSAggregateCount - o.BLSAggregateCount,
	}
}

func AvgDuration(total time.Duration, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}
