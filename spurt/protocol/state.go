package spurt

import (
	"encoding/binary"
	"sort"
	"sync"

	asig "tyche.local/Tyche/spurt/crypto"
	"tyche.local/Tyche/utils/p2p"
)

type CommitmentRef struct {
	Dealer p2p.NodeID `json:"dealer"`
	Seq    uint64     `json:"seq"`
}

type Beacon struct {
	Epoch      uint64                     `json:"epoch"`
	Random     []byte                     `json:"random"`
	Digest     string                     `json:"digest"`
	Selected   []CommitmentRef            `json:"selected"`
	Signature  asig.BLSAggregateSignature `json:"signature"`
	Committeds int                        `json:"committeds"`
	Skipped    bool                       `json:"skipped,omitempty"`
	SkipStage  string                     `json:"skip_stage,omitempty"`
	SkipReason string                     `json:"skip_reason,omitempty"`
	SkipDiag   string                     `json:"skip_diag,omitempty"`
}

type State struct {
	mu sync.RWMutex

	N     int
	F     int
	Epoch uint64
	RPrev []byte
	Seed  []byte

	Members     []p2p.NodeID
	MemberIndex map[p2p.NodeID]int
}

func NewState(members []p2p.NodeID, f int, seed []byte) *State {
	cp := append([]p2p.NodeID(nil), members...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	seedCopy := append([]byte(nil), seed...)
	if len(seedCopy) == 0 {
		seedCopy = asig.HashBytes([]byte("Spurt-v1-genesis"))
	}
	st := &State{
		N:           len(cp),
		F:           f,
		RPrev:       epochSeed(seedCopy, 0),
		Seed:        seedCopy,
		Members:     cp,
		MemberIndex: make(map[p2p.NodeID]int, len(cp)),
	}
	for i, id := range cp {
		st.MemberIndex[id] = i
	}
	return st
}

func (s *State) CurrentEpoch() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Epoch
}

func (s *State) RPrevBytes() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return epochSeed(s.Seed, s.Epoch)
}

func (s *State) Threshold() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.F + 1
}

func (s *State) MembersSnapshot() []p2p.NodeID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]p2p.NodeID, len(s.Members))
	copy(out, s.Members)
	return out
}

func (s *State) Leader(epoch uint64) p2p.NodeID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.Members) == 0 {
		return ""
	}
	return s.Members[int(epoch)%len(s.Members)]
}

func (s *State) IsMember(id p2p.NodeID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.MemberIndex[id]
	return ok
}

func (s *State) Advance(random []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RPrev = append([]byte(nil), random...)
	s.Epoch++
}

func (s *State) Skip(reason string) (uint64, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	epoch := s.Epoch
	random := asig.HashBytes([]byte("Spurt-v1/skip"), epochSeed(s.Seed, epoch), encodeEpoch(epoch), []byte(reason))
	s.RPrev = append([]byte(nil), random...)
	s.Epoch++
	return epoch, append([]byte(nil), random...)
}

func encodeEpoch(e uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, e)
	return b
}

func epochSeed(seed []byte, epoch uint64) []byte {
	return asig.HashBytes([]byte("Spurt-v1/epoch"), seed, encodeEpoch(epoch))
}
