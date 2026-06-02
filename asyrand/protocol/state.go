package protocol

import (
	"encoding/binary"
	"errors"
	asig "github.com/scottocs/Tyche/asyrand/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
	"sort"
	"sync"
)

type Beacon struct {
	Epoch       uint64                 `json:"epoch"`
	Source      p2p.NodeID             `json:"source"`
	Random      []byte                 `json:"random"`
	CommitID    string                 `json:"commit_id"`
	Certificate asig.QuorumCertificate `json:"certificate"`
	Shares      []asig.DecryptedShare  `json:"shares"`
	Skipped     bool                   `json:"skipped,omitempty"`
	SkipStage   string                 `json:"skip_stage,omitempty"`
	SkipReason  string                 `json:"skip_reason,omitempty"`
	SkipDiag    string                 `json:"skip_diag,omitempty"`
}

type State struct {
	mu sync.RWMutex

	N        int
	F        int
	QueueLen int
	Epoch    uint64
	RPrev    []byte
	Seed     []byte

	Members          []p2p.NodeID
	MemberIndex      map[p2p.NodeID]int
	RecentSources    []p2p.NodeID
	SourceCandidates []p2p.NodeID
	// ComQ is indexed by member position, then commitment sequence: ComQ[i][seq].
	ComQ    []map[uint64]asig.Commitment
	HeadSeq []uint64
	Removed map[p2p.NodeID]bool
}

func NewState(members []p2p.NodeID, f, queueLen int, seed []byte) *State {
	cp := append([]p2p.NodeID(nil), members...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	seedCopy := append([]byte(nil), seed...)
	if len(seedCopy) == 0 {
		seedCopy = asig.HashBytes([]byte("AsyRand-v1-genesis"))
	}
	st := &State{
		N: len(cp), F: f, QueueLen: queueLen, RPrev: epochSeed(seedCopy, 0), Seed: seedCopy,
		Members: cp, MemberIndex: make(map[p2p.NodeID]int, len(cp)), SourceCandidates: append([]p2p.NodeID(nil), cp...),
		ComQ: make([]map[uint64]asig.Commitment, len(cp)), HeadSeq: make([]uint64, len(cp)),
		Removed: make(map[p2p.NodeID]bool, len(cp)),
	}
	for i, member := range cp {
		st.MemberIndex[member] = i
		st.ComQ[i] = make(map[uint64]asig.Commitment)
		st.HeadSeq[i] = 1
	}
	return st
}

func (s *State) Source() (p2p.NodeID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.SourceCandidates) == 0 {
		return "", errors.New("source candidate list is empty")
	}
	idx := 0
	selector := epochSeed(s.Seed, s.Epoch)
	if len(selector) >= 8 {
		idx = int(binary.BigEndian.Uint64(selector[:8]) % uint64(len(s.SourceCandidates)))
	} else if len(selector) > 0 {
		idx = int(selector[0]) % len(s.SourceCandidates)
	}
	return s.SourceCandidates[idx], nil
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

func (s *State) Enqueue(c asig.Commitment) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indexLocked(c.Dealer)
	if !ok || s.Removed[c.Dealer] || c.Seq == 0 {
		return false
	}
	if s.hasCommitmentLocked(c) {
		return false
	}
	if c.Seq < s.HeadSeq[idx] {
		return false
	}
	s.ComQ[idx][c.Seq] = c
	return true
}

func (s *State) HasCommitment(id p2p.NodeID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return false
	}
	_, ok = s.ComQ[idx][s.HeadSeq[idx]]
	return ok
}

func (s *State) PopCommitment(id p2p.NodeID) (asig.Commitment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return asig.Commitment{}, false
	}
	head := s.HeadSeq[idx]
	c, ok := s.ComQ[idx][head]
	if !ok {
		return asig.Commitment{}, false
	}
	delete(s.ComQ[idx], head)
	s.HeadSeq[idx] = head + 1
	return c, true
}

func (s *State) AdvanceHeadToNextCommitment(id p2p.NodeID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return false
	}
	head := s.HeadSeq[idx]
	if _, ok := s.ComQ[idx][head]; ok {
		return false
	}
	var next uint64
	for seq := range s.ComQ[idx] {
		if seq > head && (next == 0 || seq < next) {
			next = seq
		}
	}
	if next == 0 {
		return false
	}
	s.HeadSeq[idx] = next
	return true
}

func (s *State) PeekCommitment(id p2p.NodeID) (asig.Commitment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return asig.Commitment{}, false
	}
	c, ok := s.ComQ[idx][s.HeadSeq[idx]]
	return c, ok
}

func (s *State) RemoveSource(id p2p.NodeID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Removed[id] = true
	if idx, ok := s.indexLocked(id); ok {
		s.ComQ[idx] = make(map[uint64]asig.Commitment)
		s.HeadSeq[idx] = 1
	}
	s.N = s.activeCountLocked()
	s.rebuildSourceCandidateListLocked()
}

func (s *State) Advance(random []byte) {
	s.AdvanceForSource(random, "")
}

func (s *State) AdvanceForSource(random []byte, source p2p.NodeID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RPrev = append([]byte(nil), random...)
	s.Epoch++
	if source != "" && !s.Removed[source] {
		s.RecentSources = append(s.RecentSources, source)
		if len(s.RecentSources) > s.F {
			s.RecentSources = s.RecentSources[len(s.RecentSources)-s.F:]
		}
		s.rebuildSourceCandidateListLocked()
	}
}

func (s *State) Skip(source p2p.NodeID, reason string) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	random := asig.HashBytes([]byte("AsyRand-v1/skip"), epochSeed(s.Seed, s.Epoch), encodeUint64(s.Epoch), []byte(source), []byte(reason))
	s.RPrev = append([]byte(nil), random...)
	s.Epoch++
	if source != "" && !s.Removed[source] {
		s.RecentSources = append(s.RecentSources, source)
		if len(s.RecentSources) > s.F {
			s.RecentSources = s.RecentSources[len(s.RecentSources)-s.F:]
		}
		s.rebuildSourceCandidateListLocked()
	}
	return append([]byte(nil), random...)
}

func (s *State) QueueLength(id p2p.NodeID) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return 0
	}
	return len(s.ComQ[idx])
}

func (s *State) HasCommitmentSeq(id p2p.NodeID, seq uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return false
	}
	_, ok = s.ComQ[idx][seq]
	return ok
}

func (s *State) ConsumedSeq(id p2p.NodeID) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok {
		return 0
	}
	if s.HeadSeq[idx] == 0 {
		return 0
	}
	return s.HeadSeq[idx] - 1
}

func (s *State) QueueHasSpace(id p2p.NodeID, pending int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.QueueLen <= 0 {
		return true
	}
	idx, ok := s.indexLocked(id)
	if !ok || s.Removed[id] {
		return false
	}
	return len(s.ComQ[idx])+pending < s.QueueLen
}

func (s *State) QueueBacklog() (total int, max int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i, member := range s.Members {
		if s.Removed[member] {
			continue
		}
		pending := len(s.ComQ[i])
		total += pending
		if pending > max {
			max = pending
		}
	}
	return total, max
}

func (s *State) indexLocked(id p2p.NodeID) (int, bool) {
	idx, ok := s.MemberIndex[id]
	return idx, ok
}

func (s *State) hasCommitmentLocked(c asig.Commitment) bool {
	idx, ok := s.indexLocked(c.Dealer)
	if !ok {
		return false
	}
	if _, ok := s.ComQ[idx][c.Seq]; ok {
		return true
	}
	for _, existing := range s.ComQ[idx] {
		if existing.SecretID == c.SecretID {
			return true
		}
	}
	return false
}

func (s *State) rebuildSourceCandidateListLocked() {
	blocked := make(map[p2p.NodeID]bool, len(s.RecentSources))
	for _, source := range s.RecentSources {
		blocked[source] = true
	}
	s.SourceCandidates = s.SourceCandidates[:0]
	for _, member := range s.Members {
		if !s.Removed[member] && !blocked[member] {
			s.SourceCandidates = append(s.SourceCandidates, member)
		}
	}
	if len(s.SourceCandidates) == 0 {
		for _, member := range s.Members {
			if !s.Removed[member] {
				s.SourceCandidates = append(s.SourceCandidates, member)
			}
		}
		s.RecentSources = nil
	}
}

func (s *State) activeCountLocked() int {
	count := 0
	for _, member := range s.Members {
		if !s.Removed[member] {
			count++
		}
	}
	return count
}

func encodeUint64(v uint64) []byte {
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, v)
	return out
}

func epochSeed(seed []byte, epoch uint64) []byte {
	return asig.HashBytes([]byte("AsyRand-v1/epoch"), seed, encodeUint64(epoch))
}
