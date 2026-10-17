package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sort"

	asig "Tyche/grandline/crypto"
	"Tyche/utils/p2p"
)

type Peer struct {
	ID   p2p.NodeID `json:"id"`
	Addr string     `json:"addr"`
}

type Config struct {
	BeaconMode    string                `json:"beacon_mode,omitempty"`
	WarmupOutputs int                   `json:"warmup_outputs"`
	SetupFile     string                `json:"setup_file,omitempty"`
	Name          p2p.NodeID            `json:"name"`
	Protocol      string                `json:"protocol"`
	Transport     string                `json:"transport"`
	F             int                   `json:"f"`
	Round         int                   `json:"round"`
	ListenIP      string                `json:"listen_ip"`
	PrefillMS     int                   `json:"prefill_ms"`
	EpochMS       int                   `json:"epoch_timeout_ms"`
	ReportMS      int                   `json:"report_interval_ms"`
	LingerMS      int                   `json:"linger_ms"`
	BatchSize     int                   `json:"batch_size"`
	MaxPool       int                   `json:"max_pool"`
	LogLevel      int                   `json:"log_level"`
	ClusterIndex  map[p2p.NodeID]int    `json:"cluster_index"`
	ClusterIPs    map[p2p.NodeID]string `json:"cluster_ips"`
	PeerP2PPort   map[p2p.NodeID]int    `json:"peers_p2p_port"`
	NodeSeeds     map[p2p.NodeID]string `json:"node_key_seed"`

	NodeID p2p.NodeID `json:"node_id"`
	Peers  []Peer     `json:"peers"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Round == 0 {
		cfg.Round = 1
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "grandline"
	}
	if cfg.BeaconMode == "" || cfg.BeaconMode == "signed" {
		cfg.BeaconMode = "standard"
	}
	if cfg.BeaconMode != "standard" && cfg.BeaconMode != "reference" {
		return Config{}, errors.New("beacon_mode must be standard or reference")
	}
	if cfg.Transport == "" {
		cfg.Transport = "memory"
	}
	if cfg.ListenIP == "" {
		cfg.ListenIP = "0.0.0.0"
	}
	if cfg.PrefillMS == 0 {
		cfg.PrefillMS = 1000
	}
	if cfg.EpochMS == 0 {
		cfg.EpochMS = 5000
	}
	if cfg.ReportMS == 0 {
		cfg.ReportMS = 5000
	}
	if cfg.MaxPool == 0 {
		cfg.MaxPool = 4
	}
	if cfg.LingerMS == 0 {
		cfg.LingerMS = 15000
	}
	if cfg.F < 0 {
		cfg.F = (len(cfg.ClusterIndex) - 1) / 3
	}
	return cfg, nil
}

func (c Config) Members() []p2p.NodeID {
	ids := make([]p2p.NodeID, 0, len(c.ClusterIndex))
	for id := range c.ClusterIndex {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return c.ClusterIndex[ids[i]] < c.ClusterIndex[ids[j]] })
	return ids
}

func (c Config) PeerMap() map[p2p.NodeID]string {
	if len(c.Peers) > 0 {
		out := make(map[p2p.NodeID]string, len(c.Peers))
		for _, peer := range c.Peers {
			out[peer.ID] = peer.Addr
		}
		return out
	}
	out := make(map[p2p.NodeID]string, len(c.ClusterIPs))
	for id, ip := range c.ClusterIPs {
		out[id] = ip
		if port, ok := c.PeerP2PPort[id]; ok {
			out[id] = ip + ":" + itoa(port)
		}
	}
	return out
}

func (c Config) ListenAddr(id p2p.NodeID) string {
	if len(c.Peers) > 0 {
		for _, peer := range c.Peers {
			if peer.ID == id {
				_, port, err := net.SplitHostPort(peer.Addr)
				if err == nil {
					return net.JoinHostPort(c.ListenIP, port)
				}
				return peer.Addr
			}
		}
	}
	port := c.PeerP2PPort[id]
	return c.ListenIP + ":" + itoa(port)
}

func (c Config) KeyPairs() (map[p2p.NodeID]asig.KeyPair, map[string]ed25519.PublicKey, error) {
	keys := make(map[p2p.NodeID]asig.KeyPair, len(c.NodeSeeds))
	pubs := make(map[string]ed25519.PublicKey, len(c.NodeSeeds))
	for _, id := range c.Members() {
		seedHex, ok := c.NodeSeeds[id]
		if !ok {
			return nil, nil, errors.New("missing key seed for " + string(id))
		}
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			return nil, nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, nil, errors.New("ed25519 seed must be 32 bytes for " + string(id))
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		keys[id] = asig.KeyPair{Public: pub, Private: priv}
		pubs[string(id)] = pub
	}
	return keys, pubs, nil
}

func (c Config) NodeSeedBytes() (map[p2p.NodeID][]byte, error) {
	out := make(map[p2p.NodeID][]byte, len(c.NodeSeeds))
	for _, id := range c.Members() {
		seedHex, ok := c.NodeSeeds[id]
		if !ok {
			return nil, errors.New("missing key seed for " + string(id))
		}
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			return nil, err
		}
		out[id] = seed
	}
	return out, nil
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	n := v
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
