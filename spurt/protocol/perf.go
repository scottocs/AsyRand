package spurt

import (
	"sync/atomic"
	"time"
)

type PerfMetrics struct {
	pvssInputVerifyCount atomic.Uint64
	pvssReconVerifyCount atomic.Uint64
	pvssShareNs          atomic.Int64
	pvssShareCount       atomic.Uint64

	pvssVerifyNs    atomic.Int64
	pvssVerifyCount atomic.Uint64

	pvssPreReconNs    atomic.Int64
	pvssPreReconCount atomic.Uint64

	pvssReconNs    atomic.Int64
	pvssReconCount atomic.Uint64

	agreementNs    atomic.Int64
	agreementCount atomic.Uint64

	beaconSignNs    atomic.Int64
	beaconSignCount atomic.Uint64

	beaconVerifyNs    atomic.Int64
	beaconVerifyCount atomic.Uint64
}

type PerfSnapshot struct {
	PVSSInputVerifyCount uint64
	PVSSReconVerifyCount uint64
	// Legacy output fields remain zero: ordinary messages have no outer signatures.
	MessageSignCount   uint64
	MessageSignTotal   time.Duration
	MessageVerifyCount uint64
	MessageVerifyTotal time.Duration
	PVSSShareCount     uint64
	PVSSShareTotal     time.Duration
	PVSSVerifyCount    uint64
	PVSSVerifyTotal    time.Duration
	PVSSPreReconCount  uint64
	PVSSPreReconTotal  time.Duration
	PVSSReconCount     uint64
	PVSSReconTotal     time.Duration
	AgreementCount     uint64
	AgreementTotal     time.Duration
	BeaconSignCount    uint64
	BeaconSignTotal    time.Duration
	BeaconVerifyCount  uint64
	BeaconVerifyTotal  time.Duration
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

func (p *PerfMetrics) addAgreement(d time.Duration) {
	p.agreementNs.Add(d.Nanoseconds())
	p.agreementCount.Add(1)
}

func (p *PerfMetrics) addBeaconSign(d time.Duration) {
	p.beaconSignNs.Add(d.Nanoseconds())
	p.beaconSignCount.Add(1)
}

func (p *PerfMetrics) addBeaconVerify(d time.Duration) {
	p.beaconVerifyNs.Add(d.Nanoseconds())
	p.beaconVerifyCount.Add(1)
}

func (p *PerfMetrics) Snapshot() PerfSnapshot {
	return PerfSnapshot{
		PVSSInputVerifyCount: p.pvssInputVerifyCount.Load(),
		PVSSReconVerifyCount: p.pvssReconVerifyCount.Load(),
		PVSSShareCount:       p.pvssShareCount.Load(),
		PVSSShareTotal:       time.Duration(p.pvssShareNs.Load()),
		PVSSVerifyCount:      p.pvssVerifyCount.Load(),
		PVSSVerifyTotal:      time.Duration(p.pvssVerifyNs.Load()),
		PVSSPreReconCount:    p.pvssPreReconCount.Load(),
		PVSSPreReconTotal:    time.Duration(p.pvssPreReconNs.Load()),
		PVSSReconCount:       p.pvssReconCount.Load(),
		PVSSReconTotal:       time.Duration(p.pvssReconNs.Load()),
		AgreementCount:       p.agreementCount.Load(),
		AgreementTotal:       time.Duration(p.agreementNs.Load()),
		BeaconSignCount:      p.beaconSignCount.Load(),
		BeaconSignTotal:      time.Duration(p.beaconSignNs.Load()),
		BeaconVerifyCount:    p.beaconVerifyCount.Load(),
		BeaconVerifyTotal:    time.Duration(p.beaconVerifyNs.Load()),
	}
}

func (s PerfSnapshot) Add(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSInputVerifyCount: s.PVSSInputVerifyCount + o.PVSSInputVerifyCount,
		PVSSReconVerifyCount: s.PVSSReconVerifyCount + o.PVSSReconVerifyCount,
		MessageSignCount:     s.MessageSignCount + o.MessageSignCount, MessageSignTotal: s.MessageSignTotal + o.MessageSignTotal,
		MessageVerifyCount: s.MessageVerifyCount + o.MessageVerifyCount, MessageVerifyTotal: s.MessageVerifyTotal + o.MessageVerifyTotal,
		PVSSShareCount:    s.PVSSShareCount + o.PVSSShareCount,
		PVSSShareTotal:    s.PVSSShareTotal + o.PVSSShareTotal,
		PVSSVerifyCount:   s.PVSSVerifyCount + o.PVSSVerifyCount,
		PVSSVerifyTotal:   s.PVSSVerifyTotal + o.PVSSVerifyTotal,
		PVSSPreReconCount: s.PVSSPreReconCount + o.PVSSPreReconCount,
		PVSSPreReconTotal: s.PVSSPreReconTotal + o.PVSSPreReconTotal,
		PVSSReconCount:    s.PVSSReconCount + o.PVSSReconCount,
		PVSSReconTotal:    s.PVSSReconTotal + o.PVSSReconTotal,
		AgreementCount:    s.AgreementCount + o.AgreementCount,
		AgreementTotal:    s.AgreementTotal + o.AgreementTotal,
		BeaconSignCount:   s.BeaconSignCount + o.BeaconSignCount,
		BeaconSignTotal:   s.BeaconSignTotal + o.BeaconSignTotal,
		BeaconVerifyCount: s.BeaconVerifyCount + o.BeaconVerifyCount,
		BeaconVerifyTotal: s.BeaconVerifyTotal + o.BeaconVerifyTotal,
	}
}

func (s PerfSnapshot) Sub(o PerfSnapshot) PerfSnapshot {
	return PerfSnapshot{
		PVSSInputVerifyCount: s.PVSSInputVerifyCount - o.PVSSInputVerifyCount,
		PVSSReconVerifyCount: s.PVSSReconVerifyCount - o.PVSSReconVerifyCount,
		MessageSignCount:     s.MessageSignCount - o.MessageSignCount, MessageSignTotal: s.MessageSignTotal - o.MessageSignTotal,
		MessageVerifyCount: s.MessageVerifyCount - o.MessageVerifyCount, MessageVerifyTotal: s.MessageVerifyTotal - o.MessageVerifyTotal,
		PVSSShareCount:    s.PVSSShareCount - o.PVSSShareCount,
		PVSSShareTotal:    s.PVSSShareTotal - o.PVSSShareTotal,
		PVSSVerifyCount:   s.PVSSVerifyCount - o.PVSSVerifyCount,
		PVSSVerifyTotal:   s.PVSSVerifyTotal - o.PVSSVerifyTotal,
		PVSSPreReconCount: s.PVSSPreReconCount - o.PVSSPreReconCount,
		PVSSPreReconTotal: s.PVSSPreReconTotal - o.PVSSPreReconTotal,
		PVSSReconCount:    s.PVSSReconCount - o.PVSSReconCount,
		PVSSReconTotal:    s.PVSSReconTotal - o.PVSSReconTotal,
		AgreementCount:    s.AgreementCount - o.AgreementCount,
		AgreementTotal:    s.AgreementTotal - o.AgreementTotal,
		BeaconSignCount:   s.BeaconSignCount - o.BeaconSignCount,
		BeaconSignTotal:   s.BeaconSignTotal - o.BeaconSignTotal,
		BeaconVerifyCount: s.BeaconVerifyCount - o.BeaconVerifyCount,
		BeaconVerifyTotal: s.BeaconVerifyTotal - o.BeaconVerifyTotal,
	}
}

func AvgDuration(total time.Duration, count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	return time.Duration(int64(total) / int64(count))
}
