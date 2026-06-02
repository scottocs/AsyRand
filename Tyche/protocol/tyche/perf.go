package tyche

import (
	"sync/atomic"
	"time"
)

type PerfMetrics struct {
	pvssShareNs      atomic.Int64
	pvssShareCount   atomic.Uint64
	pvssVerifyNs     atomic.Int64
	pvssVerifyCount  atomic.Uint64
	pvssPreReconNs   atomic.Int64
	pvssPreReconCnt  atomic.Uint64
	pvssReconNs      atomic.Int64
	pvssReconCount   atomic.Uint64
	rbcHandleNs      atomic.Int64
	rbcHandleCount   atomic.Uint64
	abaHandleNs      atomic.Int64
	abaHandleCount   atomic.Uint64
	certSignNs       atomic.Int64
	certSignCount    atomic.Uint64
	certVerifyNs     atomic.Int64
	certVerifyCount  atomic.Uint64
	certAggregateNs  atomic.Int64
	certAggregateCnt atomic.Uint64
}

type PerfSnapshot struct {
	PVSSShareTotal     time.Duration
	PVSSShareCount     uint64
	PVSSVerifyTotal    time.Duration
	PVSSVerifyCount    uint64
	PVSSPreReconTotal  time.Duration
	PVSSPreReconCount  uint64
	PVSSReconTotal     time.Duration
	PVSSReconCount     uint64
	RBCHandleTotal     time.Duration
	RBCHandleCount     uint64
	ABAHandleTotal     time.Duration
	ABAHandleCount     uint64
	CertSignTotal      time.Duration
	CertSignCount      uint64
	CertVerifyTotal    time.Duration
	CertVerifyCount    uint64
	CertAggregateTotal time.Duration
	CertAggregateCount uint64
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

func (p *PerfMetrics) addCertSign(d time.Duration) {
	p.certSignNs.Add(d.Nanoseconds())
	p.certSignCount.Add(1)
}

func (p *PerfMetrics) addCertVerify(d time.Duration) {
	p.certVerifyNs.Add(d.Nanoseconds())
	p.certVerifyCount.Add(1)
}

func (p *PerfMetrics) addCertAggregate(d time.Duration) {
	p.certAggregateNs.Add(d.Nanoseconds())
	p.certAggregateCnt.Add(1)
}

func (p *PerfMetrics) Snapshot() PerfSnapshot {
	if p == nil {
		return PerfSnapshot{}
	}
	return PerfSnapshot{
		PVSSShareTotal:     time.Duration(p.pvssShareNs.Load()),
		PVSSShareCount:     p.pvssShareCount.Load(),
		PVSSVerifyTotal:    time.Duration(p.pvssVerifyNs.Load()),
		PVSSVerifyCount:    p.pvssVerifyCount.Load(),
		PVSSPreReconTotal:  time.Duration(p.pvssPreReconNs.Load()),
		PVSSPreReconCount:  p.pvssPreReconCnt.Load(),
		PVSSReconTotal:     time.Duration(p.pvssReconNs.Load()),
		PVSSReconCount:     p.pvssReconCount.Load(),
		RBCHandleTotal:     time.Duration(p.rbcHandleNs.Load()),
		RBCHandleCount:     p.rbcHandleCount.Load(),
		ABAHandleTotal:     time.Duration(p.abaHandleNs.Load()),
		ABAHandleCount:     p.abaHandleCount.Load(),
		CertSignTotal:      time.Duration(p.certSignNs.Load()),
		CertSignCount:      p.certSignCount.Load(),
		CertVerifyTotal:    time.Duration(p.certVerifyNs.Load()),
		CertVerifyCount:    p.certVerifyCount.Load(),
		CertAggregateTotal: time.Duration(p.certAggregateNs.Load()),
		CertAggregateCount: p.certAggregateCnt.Load(),
	}
}

func (s PerfSnapshot) Add(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareTotal:     s.PVSSShareTotal + o.PVSSShareTotal,
		PVSSShareCount:     s.PVSSShareCount + o.PVSSShareCount,
		PVSSVerifyTotal:    s.PVSSVerifyTotal + o.PVSSVerifyTotal,
		PVSSVerifyCount:    s.PVSSVerifyCount + o.PVSSVerifyCount,
		PVSSPreReconTotal:  s.PVSSPreReconTotal + o.PVSSPreReconTotal,
		PVSSPreReconCount:  s.PVSSPreReconCount + o.PVSSPreReconCount,
		PVSSReconTotal:     s.PVSSReconTotal + o.PVSSReconTotal,
		PVSSReconCount:     s.PVSSReconCount + o.PVSSReconCount,
		RBCHandleTotal:     s.RBCHandleTotal + o.RBCHandleTotal,
		RBCHandleCount:     s.RBCHandleCount + o.RBCHandleCount,
		ABAHandleTotal:     s.ABAHandleTotal + o.ABAHandleTotal,
		ABAHandleCount:     s.ABAHandleCount + o.ABAHandleCount,
		CertSignTotal:      s.CertSignTotal + o.CertSignTotal,
		CertSignCount:      s.CertSignCount + o.CertSignCount,
		CertVerifyTotal:    s.CertVerifyTotal + o.CertVerifyTotal,
		CertVerifyCount:    s.CertVerifyCount + o.CertVerifyCount,
		CertAggregateTotal: s.CertAggregateTotal + o.CertAggregateTotal,
		CertAggregateCount: s.CertAggregateCount + o.CertAggregateCount,
	}
}

func (s PerfSnapshot) Sub(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareTotal:     s.PVSSShareTotal - o.PVSSShareTotal,
		PVSSShareCount:     s.PVSSShareCount - o.PVSSShareCount,
		PVSSVerifyTotal:    s.PVSSVerifyTotal - o.PVSSVerifyTotal,
		PVSSVerifyCount:    s.PVSSVerifyCount - o.PVSSVerifyCount,
		PVSSPreReconTotal:  s.PVSSPreReconTotal - o.PVSSPreReconTotal,
		PVSSPreReconCount:  s.PVSSPreReconCount - o.PVSSPreReconCount,
		PVSSReconTotal:     s.PVSSReconTotal - o.PVSSReconTotal,
		PVSSReconCount:     s.PVSSReconCount - o.PVSSReconCount,
		RBCHandleTotal:     s.RBCHandleTotal - o.RBCHandleTotal,
		RBCHandleCount:     s.RBCHandleCount - o.RBCHandleCount,
		ABAHandleTotal:     s.ABAHandleTotal - o.ABAHandleTotal,
		ABAHandleCount:     s.ABAHandleCount - o.ABAHandleCount,
		CertSignTotal:      s.CertSignTotal - o.CertSignTotal,
		CertSignCount:      s.CertSignCount - o.CertSignCount,
		CertVerifyTotal:    s.CertVerifyTotal - o.CertVerifyTotal,
		CertVerifyCount:    s.CertVerifyCount - o.CertVerifyCount,
		CertAggregateTotal: s.CertAggregateTotal - o.CertAggregateTotal,
		CertAggregateCount: s.CertAggregateCount - o.CertAggregateCount,
	}
}

func AvgDuration(total time.Duration, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return total / time.Duration(count)
}
