package grandline

import (
	"Tyche/utils/p2p"
	"sort"
	"sync"
)

type Beacon struct {
	Epoch      uint64     `json:"epoch"`
	Source     p2p.NodeID `json:"source"`
	Random     []byte     `json:"random"`
	Commit     string     `json:"commit"`
	SigHex     string     `json:"signature"`
	Shares     int        `json:"shares"`
	Skipped    bool       `json:"skipped,omitempty"`
	SkipStage  string     `json:"skip_stage,omitempty"`
	SkipReason string     `json:"skip_reason,omitempty"`
	SkipDiag   string     `json:"skip_diag,omitempty"`
}

type State struct {
	mu      sync.RWMutex
	N       int
	F       int
	Epoch   uint64
	Members []p2p.NodeID
}

func NewState(members []p2p.NodeID, f int) *State {
	cp := append([]p2p.NodeID(nil), members...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return &State{N: len(cp), F: f, Members: cp}
}

func (s *State) CurrentEpoch() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Epoch
}

func (s *State) Threshold() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.F + 1
}

func (s *State) MembersSnapshot() []p2p.NodeID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]p2p.NodeID(nil), s.Members...)
}

func (s *State) Advance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Epoch++
}
