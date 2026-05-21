package spurt

import (
	"encoding/binary"
	"errors"
	"sort"
	"sync"

	asig "github.com/scottocs/Tyche/spurt/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
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
}

type State struct {
	mu sync.RWMutex

	N        int
	F        int
	QueueLen int
	Epoch    uint64
	RPrev    []byte

	Members     []p2p.NodeID
	MemberIndex map[p2p.NodeID]int

	// ComQ[i][seq] caches commitments by producer index i and commitment sequence.
	ComQ    []map[uint64]asig.PVSSCommitment
	HeadSeq []uint64
}

func NewState(members []p2p.NodeID, f, queueLen int, seed []byte) *State {
	cp := append([]p2p.NodeID(nil), members...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	rprev := append([]byte(nil), seed...)
	if len(rprev) == 0 {
		rprev = asig.HashBytes([]byte("Spurt-v1-genesis"))
	}
	st := &State{
		N:           len(cp),
		F:           f,
		QueueLen:    queueLen,
		RPrev:       rprev,
		Members:     cp,
		MemberIndex: make(map[p2p.NodeID]int, len(cp)),
		ComQ:        make([]map[uint64]asig.PVSSCommitment, len(cp)),
		HeadSeq:     make([]uint64, len(cp)),
	}
	for i, id := range cp {
		st.MemberIndex[id] = i
		st.ComQ[i] = make(map[uint64]asig.PVSSCommitment)
		st.HeadSeq[i] = 1
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
	return append([]byte(nil), s.RPrev...)
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

func (s *State) Enqueue(c asig.PVSSCommitment) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indexLocked(c.Dealer)
	if !ok || c.Seq == 0 {
		return false
	}
	if c.Seq < s.HeadSeq[idx] {
		return false
	}
	if s.hasCommitmentLocked(c) {
		return false
	}
	s.ComQ[idx][c.Seq] = c
	if _, ok := s.ComQ[idx][s.HeadSeq[idx]]; !ok {
		s.HeadSeq[idx] = c.Seq
	}
	return true
}

func (s *State) Commitment(id p2p.NodeID, seq uint64) (asig.PVSSCommitment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok {
		return asig.PVSSCommitment{}, false
	}
	c, ok := s.ComQ[idx][seq]
	return c, ok
}

func (s *State) Head(id p2p.NodeID) (asig.PVSSCommitment, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok {
		return asig.PVSSCommitment{}, false
	}
	c, ok := s.ComQ[idx][s.HeadSeq[idx]]
	return c, ok
}

func (s *State) AllHeads() []CommitmentRef {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CommitmentRef, 0, s.N)
	for i, id := range s.Members {
		_, ok := s.ComQ[i][s.HeadSeq[i]]
		if !ok {
			continue
		}
		out = append(out, CommitmentRef{Dealer: id, Seq: s.HeadSeq[i]})
	}
	return out
}

func (s *State) Heads() map[p2p.NodeID]asig.PVSSCommitment {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[p2p.NodeID]asig.PVSSCommitment, len(s.Members))
	for i, id := range s.Members {
		if c, ok := s.ComQ[i][s.HeadSeq[i]]; ok {
			out[id] = c
		}
	}
	return out
}

func (s *State) PopHead(id p2p.NodeID, seq uint64) (asig.PVSSCommitment, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx, ok := s.indexLocked(id)
	if !ok {
		return asig.PVSSCommitment{}, false
	}
	if s.HeadSeq[idx] != seq {
		return asig.PVSSCommitment{}, false
	}
	c, ok := s.ComQ[idx][s.HeadSeq[idx]]
	if !ok {
		return asig.PVSSCommitment{}, false
	}
	delete(s.ComQ[idx], s.HeadSeq[idx])
	s.HeadSeq[idx]++
	return c, true
}

func (s *State) PopAll(refs []CommitmentRef) {
	for _, ref := range refs {
		_, _ = s.PopHead(ref.Dealer, ref.Seq)
	}
}

func (s *State) QueueLength(id p2p.NodeID) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.indexLocked(id)
	if !ok {
		return 0
	}
	return len(s.ComQ[idx])
}

func (s *State) QueueHasSpace(id p2p.NodeID, pending int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.QueueLen <= 0 {
		return true
	}
	idx, ok := s.indexLocked(id)
	if !ok {
		return false
	}
	return len(s.ComQ[idx])+pending < s.QueueLen
}

func (s *State) QueueBacklog() (total int, max int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, q := range s.ComQ {
		total += len(q)
		if len(q) > max {
			max = len(q)
		}
	}
	return total, max
}

func (s *State) ValidateHeadSet(refs []CommitmentRef) ([]asig.PVSSCommitment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unique := make(map[p2p.NodeID]struct{}, len(refs))
	out := make([]asig.PVSSCommitment, 0, len(refs))
	for _, ref := range refs {
		if ref.Dealer == "" || ref.Seq == 0 {
			return nil, errors.New("invalid commitment reference")
		}
		idx, ok := s.indexLocked(ref.Dealer)
		if !ok {
			return nil, errors.New("unknown dealer: " + string(ref.Dealer))
		}
		if _, exists := unique[ref.Dealer]; exists {
			return nil, errors.New("duplicate dealer")
		}
		unique[ref.Dealer] = struct{}{}
		c, ok := s.ComQ[idx][ref.Seq]
		if !ok {
			return nil, errors.New("missing commitment")
		}
		// The selected commitment must stay at the head for this epoch to avoid reusing stale values.
		if c.Seq != s.HeadSeq[idx] {
			return nil, errors.New("stale commitment reference")
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *State) indexLocked(id p2p.NodeID) (int, bool) {
	idx, ok := s.MemberIndex[id]
	return idx, ok
}

func (s *State) hasCommitmentLocked(c asig.PVSSCommitment) bool {
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

func encodeEpoch(e uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, e)
	return b
}
