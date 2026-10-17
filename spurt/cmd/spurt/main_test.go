package main

import (
	config "Tyche/spurt/config"
	"testing"
)

func TestIndependentNodeLoopsCompleteMatchingBeacons(t *testing.T) {
	cfg, err := config.Load("../../configs/local_8.json")
	if err != nil {
		t.Fatal(err)
	}
	for id, index := range cfg.ClusterIndex {
		if index >= 4 {
			delete(cfg.ClusterIndex, id)
			delete(cfg.ClusterIPs, id)
			delete(cfg.PeerP2PPort, id)
			delete(cfg.NodeSeeds, id)
		}
	}
	cfg.F = 1
	cfg.Round = 6
	cfg.PrefillMS = 1
	cfg.EpochMS = 15000
	cfg.ReportMS = 0
	cfg.MaxPool = 4
	cfg.Transport = "memory"
	if err := runLocalCluster(cfg, 0); err != nil {
		t.Fatal(err)
	}
}
