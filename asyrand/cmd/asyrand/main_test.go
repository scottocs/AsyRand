package main

import (
	"testing"

	asyrand "Tyche/asyrand/protocol"
	"Tyche/utils/p2p"
)

type splitMetricsTransport struct {
	p2p.Transport
	types map[string]p2p.MessageTypeMetrics
}

func (t splitMetricsTransport) Metrics() p2p.Metrics {
	// A concurrent send can make aggregate atomics newer than type snapshots.
	return p2p.Metrics{SentMessages: 99, SentBytes: 99999, RecvBytes: 99999}
}

func (t splitMetricsTransport) MessageTypeMetrics() map[string]p2p.MessageTypeMetrics {
	return t.types
}

func TestTrafficSnapshotTotalsMatchFrozenMessageTypes(t *testing.T) {
	tr := splitMetricsTransport{types: map[string]p2p.MessageTypeMetrics{
		"asyrand/rbc/v1/VAL":      {SentMessages: 2, SentBytes: 200, RecvBytes: 150},
		"asyrand/beacon/v2/RECON": {SentMessages: 3, SentBytes: 300, RecvBytes: 250},
	}}
	s := snapshotTraffic([]*asyrand.Node{{Transport: tr}})
	if s.sent != 500 || s.recv != 400 || s.messages != 5 {
		t.Fatalf("snapshot combines incompatible counter times: %+v", s)
	}
	tr.types["asyrand/rbc/v1/VAL"] = p2p.MessageTypeMetrics{SentBytes: 1000}
	if s.types["asyrand/rbc/v1/VAL"].SentBytes != 200 {
		t.Fatal("snapshot changed after collection")
	}
}
