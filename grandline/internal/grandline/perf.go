package grandline

import (
	"sync/atomic"
	"time"
)

type PerfMetrics struct {
	pvssShareNs    atomic.Int64
	pvssShareCount atomic.Uint64

	pvssVerifyNs    atomic.Int64
	pvssVerifyCount atomic.Uint64

	shareSignNs    atomic.Int64
	shareSignCount atomic.Uint64

	shareVerifyNs    atomic.Int64
	shareVerifyCount atomic.Uint64

	shareRecoverNs    atomic.Int64
	shareRecoverCount atomic.Uint64
}

type PerfSnapshot struct {
	PVSSShareCount  uint64
	PVSSShareTotal  time.Duration
	PVSSVerifyCount uint64
	PVSSVerifyTotal time.Duration
	SignCount       uint64
	SignTotal       time.Duration
	VerifyCount     uint64
	VerifyTotal     time.Duration
	RecoverCount    uint64
	RecoverTotal    time.Duration
}

func (p *PerfMetrics) addPvssShare(d time.Duration) {
	p.pvssShareNs.Add(d.Nanoseconds())
	p.pvssShareCount.Add(1)
}

func (p *PerfMetrics) addPvssVerify(d time.Duration) {
	p.pvssVerifyNs.Add(d.Nanoseconds())
	p.pvssVerifyCount.Add(1)
}

func (p *PerfMetrics) addSign(d time.Duration) {
	p.shareSignNs.Add(d.Nanoseconds())
	p.shareSignCount.Add(1)
}

func (p *PerfMetrics) addVerify(d time.Duration) {
	p.shareVerifyNs.Add(d.Nanoseconds())
	p.shareVerifyCount.Add(1)
}

func (p *PerfMetrics) addRecover(d time.Duration) {
	p.shareRecoverNs.Add(d.Nanoseconds())
	p.shareRecoverCount.Add(1)
}

func (p *PerfMetrics) Snapshot() PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:  p.pvssShareCount.Load(),
		PVSSShareTotal:  time.Duration(p.pvssShareNs.Load()),
		PVSSVerifyCount: p.pvssVerifyCount.Load(),
		PVSSVerifyTotal: time.Duration(p.pvssVerifyNs.Load()),
		SignCount:       p.shareSignCount.Load(),
		SignTotal:       time.Duration(p.shareSignNs.Load()),
		VerifyCount:     p.shareVerifyCount.Load(),
		VerifyTotal:     time.Duration(p.shareVerifyNs.Load()),
		RecoverCount:    p.shareRecoverCount.Load(),
		RecoverTotal:    time.Duration(p.shareRecoverNs.Load()),
	}
}

func (s PerfSnapshot) Add(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:  s.PVSSShareCount + o.PVSSShareCount,
		PVSSShareTotal:  s.PVSSShareTotal + o.PVSSShareTotal,
		PVSSVerifyCount: s.PVSSVerifyCount + o.PVSSVerifyCount,
		PVSSVerifyTotal: s.PVSSVerifyTotal + o.PVSSVerifyTotal,
		SignCount:       s.SignCount + o.SignCount,
		SignTotal:       s.SignTotal + o.SignTotal,
		VerifyCount:     s.VerifyCount + o.VerifyCount,
		VerifyTotal:     s.VerifyTotal + o.VerifyTotal,
		RecoverCount:    s.RecoverCount + o.RecoverCount,
		RecoverTotal:    s.RecoverTotal + o.RecoverTotal,
	}
}

func (s PerfSnapshot) Sub(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSShareCount:  s.PVSSShareCount - o.PVSSShareCount,
		PVSSShareTotal:  s.PVSSShareTotal - o.PVSSShareTotal,
		PVSSVerifyCount: s.PVSSVerifyCount - o.PVSSVerifyCount,
		PVSSVerifyTotal: s.PVSSVerifyTotal - o.PVSSVerifyTotal,
		SignCount:       s.SignCount - o.SignCount,
		SignTotal:       s.SignTotal - o.SignTotal,
		VerifyCount:     s.VerifyCount - o.VerifyCount,
		VerifyTotal:     s.VerifyTotal - o.VerifyTotal,
		RecoverCount:    s.RecoverCount - o.RecoverCount,
		RecoverTotal:    s.RecoverTotal - o.RecoverTotal,
	}
}

func AvgDuration(total time.Duration, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return time.Duration(int64(total) / int64(count))
}

func (n *Node) PerfSnapshot() PerfSnapshot {
	if n.Perf == nil {
		return PerfSnapshot{}
	}
	return n.Perf.Snapshot()
}
