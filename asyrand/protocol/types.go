package asyrand

import (
	"Tyche/asyrand/config"
	"Tyche/asyrand/crypto"
	"Tyche/asyrand/protocol/aba"
	"Tyche/asyrand/protocol/rbc"
	"Tyche/utils/p2p"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.dedis.ch/kyber/v3"
	"sort"
)

// v2 binds the shared-column Consumer and its BEACON-only history chain.
const Protocol = "asyrand/beacon/v2"

type PublicSetup struct {
	Members  []p2p.NodeID
	F        int
	Parallel bool
	Session  string
	Signing  map[string]ed25519.PublicKey
	PVSS     map[p2p.NodeID]kyber.Point
	Context  string
}

func Setup(cfg config.Config) (PublicSetup, error) {
	if err := cfg.Validate(); err != nil {
		return PublicSetup{}, err
	}
	_, pub, err := cfg.KeyPairs()
	if err != nil {
		return PublicSetup{}, err
	}
	s := PublicSetup{Members: cfg.Members(), F: cfg.F, Parallel: cfg.ParallelConsumption, Session: cfg.SessionID, Signing: pub, PVSS: make(map[p2p.NodeID]kyber.Point)}
	sort.Slice(s.Members, func(i, j int) bool { return s.Members[i] < s.Members[j] })
	seeds, err := cfg.NodeSeedBytes()
	if err != nil {
		return s, err
	}
	for _, id := range s.Members {
		s.PVSS[id] = crypto.PVSSKeyPairFromSeed(seeds[id]).Public
	}
	pv, err := crypto.NewALBATROSSPVSSVerifier(s.F+1, s.PVSS)
	if err != nil {
		return s, err
	}
	s.Context = digest("setup", struct {
		Version, Session, PVSS string
		F                      int
		Parallel               bool
		Members                []p2p.NodeID
		Keys                   map[string]ed25519.PublicKey
	}{Protocol, s.Session, pv.SetupID(), s.F, s.Parallel, s.Members, s.Signing})
	return s, nil
}
func (s PublicSetup) ABA() aba.PublicConfig {
	return aba.PublicConfig{SetupID: s.Context, Members: s.Members, F: s.F, Public: s.Signing}
}
func columnID(c uint64) string                { return fmt.Sprintf("col/%d", c) }
func objectID(c uint64, id p2p.NodeID) string { return fmt.Sprintf("obj/%d/%s", c, id) }
func encode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
func digest(domain string, v any) string {
	h := sha256.Sum256(encode(struct {
		Domain string
		Value  any
	}{Protocol + "/" + domain, v}))
	return hex.EncodeToString(h[:])
}
func clone[T any](v T) T {
	var x T
	if err := json.Unmarshal(encode(v), &x); err != nil {
		panic(err)
	}
	return x
}

type Object struct {
	Transcript crypto.PVSSCommitment `json:"transcript"`
	Delivery   rbc.Certificate       `json:"delivery"`
}
type ObjectDecision struct {
	Source p2p.NodeID `json:"source"`
	Bit    aba.Value  `json:"bit"`
}
type Accepted struct {
	Source p2p.NodeID `json:"source"`
	Hash   string     `json:"hash"`
}
type ColumnRecord struct {
	Column    uint64           `json:"column"`
	Whole     aba.Value        `json:"whole"`
	Decisions []ObjectDecision `json:"decisions"`
	Accepted  []Accepted       `json:"accepted"`
}
type Column struct {
	Record    ColumnRecord      `json:"record"`
	Whole     aba.Certificate   `json:"whole_certificate"`
	Decisions []aba.Certificate `json:"decision_certificates,omitempty"`
	Objects   []Object          `json:"objects"`
}

func (c Column) Hash() string { return digest("column", c.Record) }

type BeaconRecord struct {
	Type              string     `json:"type"`
	Epoch             uint64     `json:"epoch"`
	PreviousHash      string     `json:"previous_hash"`
	Column            uint64     `json:"column"`
	Source            p2p.NodeID `json:"source"`
	ObjectHash        string     `json:"object_hash"`
	CurrentColumnHash string     `json:"current_column_hash"`
	NextColumnHash    string     `json:"next_column_hash"`
	Random            string     `json:"random"`
}

func (r BeaconRecord) Hash() string { return digest("history", r) }

type Entry struct {
	Record BeaconRecord                `json:"record"`
	Shares []crypto.PVSSDecryptedShare `json:"shares"`
}
type History struct {
	Genesis Column   `json:"genesis"`
	Columns []Column `json:"columns"`
	Entries []Entry  `json:"entries"`
}

func randomValue(e uint64, prev string, z []byte) string {
	return digest("beacon", struct {
		Epoch    uint64
		Previous string
		Z        string
	}{e, prev, hex.EncodeToString(z)})
}
