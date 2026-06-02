package protocol

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

	certSignNs    atomic.Int64
	certSignCount atomic.Uint64

	certVerifyNs    atomic.Int64
	certVerifyCount atomic.Uint64

	certAggregateNs    atomic.Int64
	certAggregateCount atomic.Uint64
}

type PerfSnapshot struct {
	PVSSShareCount     uint64
	PVSSShareTotal     time.Duration
	PVSSVerifyCount    uint64
	PVSSVerifyTotal    time.Duration
	PVSSPreReconCount  uint64
	PVSSPreReconTotal  time.Duration
	PVSSReconCount     uint64
	PVSSReconTotal     time.Duration
	RBCHandleCount     uint64
	RBCHandleTotal     time.Duration
	CertSignCount      uint64
	CertSignTotal      time.Duration
	CertVerifyCount    uint64
	CertVerifyTotal    time.Duration
	CertAggregateCount uint64
	CertAggregateTotal time.Duration
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
	p.certAggregateCount.Add(1)
}

func (p *PerfMetrics) Snapshot() PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:     p.pvssShareCount.Load(),
		PVSSShareTotal:     time.Duration(p.pvssShareNs.Load()),
		PVSSVerifyCount:    p.pvssVerifyCount.Load(),
		PVSSVerifyTotal:    time.Duration(p.pvssVerifyNs.Load()),
		PVSSPreReconCount:  p.pvssPreReconCount.Load(),
		PVSSPreReconTotal:  time.Duration(p.pvssPreReconNs.Load()),
		PVSSReconCount:     p.pvssReconCount.Load(),
		PVSSReconTotal:     time.Duration(p.pvssReconNs.Load()),
		RBCHandleCount:     p.rbcHandleCount.Load(),
		RBCHandleTotal:     time.Duration(p.rbcHandleNs.Load()),
		CertSignCount:      p.certSignCount.Load(),
		CertSignTotal:      time.Duration(p.certSignNs.Load()),
		CertVerifyCount:    p.certVerifyCount.Load(),
		CertVerifyTotal:    time.Duration(p.certVerifyNs.Load()),
		CertAggregateCount: p.certAggregateCount.Load(),
		CertAggregateTotal: time.Duration(p.certAggregateNs.Load()),
	}
}

func (s PerfSnapshot) Add(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:     s.PVSSShareCount + o.PVSSShareCount,
		PVSSShareTotal:     s.PVSSShareTotal + o.PVSSShareTotal,
		PVSSVerifyCount:    s.PVSSVerifyCount + o.PVSSVerifyCount,
		PVSSVerifyTotal:    s.PVSSVerifyTotal + o.PVSSVerifyTotal,
		PVSSPreReconCount:  s.PVSSPreReconCount + o.PVSSPreReconCount,
		PVSSPreReconTotal:  s.PVSSPreReconTotal + o.PVSSPreReconTotal,
		PVSSReconCount:     s.PVSSReconCount + o.PVSSReconCount,
		PVSSReconTotal:     s.PVSSReconTotal + o.PVSSReconTotal,
		RBCHandleCount:     s.RBCHandleCount + o.RBCHandleCount,
		RBCHandleTotal:     s.RBCHandleTotal + o.RBCHandleTotal,
		CertSignCount:      s.CertSignCount + o.CertSignCount,
		CertSignTotal:      s.CertSignTotal + o.CertSignTotal,
		CertVerifyCount:    s.CertVerifyCount + o.CertVerifyCount,
		CertVerifyTotal:    s.CertVerifyTotal + o.CertVerifyTotal,
		CertAggregateCount: s.CertAggregateCount + o.CertAggregateCount,
		CertAggregateTotal: s.CertAggregateTotal + o.CertAggregateTotal,
	}
}

func (s PerfSnapshot) Sub(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:     s.PVSSShareCount - o.PVSSShareCount,
		PVSSShareTotal:     s.PVSSShareTotal - o.PVSSShareTotal,
		PVSSVerifyCount:    s.PVSSVerifyCount - o.PVSSVerifyCount,
		PVSSVerifyTotal:    s.PVSSVerifyTotal - o.PVSSVerifyTotal,
		PVSSPreReconCount:  s.PVSSPreReconCount - o.PVSSPreReconCount,
		PVSSPreReconTotal:  s.PVSSPreReconTotal - o.PVSSPreReconTotal,
		PVSSReconCount:     s.PVSSReconCount - o.PVSSReconCount,
		PVSSReconTotal:     s.PVSSReconTotal - o.PVSSReconTotal,
		RBCHandleCount:     s.RBCHandleCount - o.RBCHandleCount,
		RBCHandleTotal:     s.RBCHandleTotal - o.RBCHandleTotal,
		CertSignCount:      s.CertSignCount - o.CertSignCount,
		CertSignTotal:      s.CertSignTotal - o.CertSignTotal,
		CertVerifyCount:    s.CertVerifyCount - o.CertVerifyCount,
		CertVerifyTotal:    s.CertVerifyTotal - o.CertVerifyTotal,
		CertAggregateCount: s.CertAggregateCount - o.CertAggregateCount,
		CertAggregateTotal: s.CertAggregateTotal - o.CertAggregateTotal,
	}
}

func AvgDuration(total time.Duration, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return time.Duration(int64(total) / int64(count))
}
