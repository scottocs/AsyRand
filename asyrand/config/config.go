package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"

	asig "Tyche/asyrand/crypto"
	"Tyche/utils/p2p"
)

type Peer struct {
	ID   p2p.NodeID `json:"id"`
	Addr string     `json:"addr"`
}

type Config struct {
	AuthenticatedTCP bool       `json:"authenticated_tcp"`
	Name             p2p.NodeID `json:"name"`
	Protocol         string     `json:"protocol"`
	Transport        string     `json:"transport"`
	F                int        `json:"f"`
	Round            int        `json:"round"`
	ListenIP         string     `json:"listen_ip"`
	PrefillMS        int        `json:"prefill_ms"`
	EpochMS          int        `json:"epoch_timeout_ms"`
	ReportMS         int        `json:"report_interval_ms"`
	LingerMS         int        `json:"linger_ms"`
	// The quorum, reconstruction threshold and RSQ capacity follow n and f.
	ProductionWindow    int                   `json:"production_window"`
	AdaptiveProduction  bool                  `json:"adaptive_production_window"`
	ProductionWindowMin int                   `json:"production_window_min"`
	ParallelConsumption bool                  `json:"parallel_consumption"`
	SessionID           string                `json:"session_id"`
	TransportBuffer     int                   `json:"transport_buffer"`
	SendRetryMS         int                   `json:"send_retry_ms"`
	RecoveryMS          int                   `json:"recovery_interval_ms"`
	ABAFutureRounds     uint64                `json:"aba_future_round_window"`
	HistoryBatch        int                   `json:"history_batch_size"`
	Warmup              int                   `json:"warmup_outputs"`
	MaxPool             int                   `json:"max_pool"`
	LogLevel            int                   `json:"log_level"`
	ClusterIndex        map[p2p.NodeID]int    `json:"cluster_index"`
	ClusterIPs          map[p2p.NodeID]string `json:"cluster_ips"`
	PeerP2PPort         map[p2p.NodeID]int    `json:"peers_p2p_port"`
	NodeSeeds           map[p2p.NodeID]string `json:"node_key_seed"`

	NodeID p2p.NodeID `json:"node_id"`
	Peers  []Peer     `json:"peers"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	// Initialize before unmarshalling so an omitted flag defaults to parallel,
	// while an explicit false still selects the standard consumption protocol.
	cfg := Config{ParallelConsumption: true}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Round == 0 {
		cfg.Round = 1
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "asyrand-v2"
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
	if cfg.ProductionWindow == 0 {
		cfg.ProductionWindow = 8
	}
	if cfg.ProductionWindowMin == 0 {
		cfg.ProductionWindowMin = 2
	}
	if cfg.F < 0 {
		cfg.F = (len(cfg.ClusterIndex) - 1) / 3
	}
	if cfg.SessionID == "" {
		cfg.SessionID = string(cfg.Name)
	}
	if cfg.TransportBuffer == 0 {
		cfg.TransportBuffer = 16384
	}
	if cfg.SendRetryMS == 0 {
		cfg.SendRetryMS = 100
	}
	if cfg.RecoveryMS == 0 {
		cfg.RecoveryMS = 1000
	}
	if cfg.ABAFutureRounds == 0 {
		cfg.ABAFutureRounds = 8
	}
	if cfg.HistoryBatch == 0 {
		cfg.HistoryBatch = 8
	}
	return cfg, cfg.Validate()
}

func (c Config) Validate() error {
	if c.AdaptiveProduction && (c.ProductionWindowMin < 2 || c.ProductionWindowMin > c.ProductionWindow) {
		return errors.New("adaptive production requires 2 <= minimum <= configured window")
	}
	n := len(c.ClusterIndex)
	if n == 0 || c.F < 0 || 3*c.F >= n {
		return errors.New("AsyRand requires n > 3f >= 0")
	}
	if c.Protocol != "asyrand-v2" || (c.Transport != "memory" && c.Transport != "tcp") {
		return errors.New("invalid AsyRand protocol or transport")
	}
	if c.ProductionWindow < 2 || c.MaxPool < 1 || c.TransportBuffer < 1 || c.SendRetryMS < 1 || c.RecoveryMS < 1 || c.ABAFutureRounds < 1 || c.ABAFutureRounds > 256 || c.HistoryBatch < 1 || c.HistoryBatch > 64 || c.Round < 1 || c.EpochMS < 1 || c.Warmup < 0 || c.SessionID == "" {
		return errors.New("invalid window, worker, recovery or run parameter")
	}
	seen := make(map[int]bool)
	for id, index := range c.ClusterIndex {
		if id == "" || index < 0 || index >= n || seen[index] {
			return fmt.Errorf("invalid committee index for %s", id)
		}
		seen[index] = true
	}
	_, _, err := c.KeyPairs()
	return err
}

func (c Config) Quorum() int      { return len(c.ClusterIndex) - c.F }
func (c Config) Threshold() int   { return c.F + 1 }
func (c Config) RSQCapacity() int { return c.F + 1 }

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
	seenSeeds := make(map[string]bool)
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
		canonical := hex.EncodeToString(seed)
		if seenSeeds[canonical] {
			return nil, nil, errors.New("duplicate signing/shareholder seed")
		}
		seenSeeds[canonical] = true
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
