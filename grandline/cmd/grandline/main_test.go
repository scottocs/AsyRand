package main

import (
	config "Tyche/grandline/config"
	"encoding/json"
	"os"
	"path/filepath"
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
	for _, mode := range []string{"standard", "reference"} {
		t.Run(mode, func(t *testing.T) {
			cfg.BeaconMode = mode
			if err := runLocalCluster(cfg, 0); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReferenceSetupSnapshotAndTransportRestriction(t *testing.T) {
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
	cfg.Transport = "memory"
	cfg.BeaconMode = "reference"
	rt, err := prepareRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetupFile = filepath.Join(t.TempDir(), "setup.json")
	raw, err := json.Marshal(rt.grand)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.SetupFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	again, err := prepareRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range rt.ids {
		if again.grand.Reference.Commitments[id] != rt.grand.Reference.Commitments[id] {
			t.Fatal("fixed commitments regenerated")
		}
	}
	cfg.Transport = "tcp"
	if _, err := prepareRuntime(cfg); err == nil {
		t.Fatal("reference mode accepted unauthenticated transport")
	}
}

func TestCommonSetupSnapshotIsValidated(t *testing.T) {
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
	cfg.Transport = "memory"
	runtime, err := prepareRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetupFile = filepath.Join(t.TempDir(), "setup.json")
	raw, err := json.Marshal(runtime.grand)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.SetupFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	again, err := prepareRuntime(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if again.grand.PublicKey != runtime.grand.PublicKey {
		t.Fatal("setup snapshot changed keys")
	}
	runtime.grand.SecretShares[runtime.ids[0]] = runtime.grand.SecretShares[runtime.ids[1]]
	raw, _ = json.Marshal(runtime.grand)
	if err := os.WriteFile(cfg.SetupFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareRuntime(cfg); err == nil {
		t.Fatal("tampered setup accepted")
	}
}
