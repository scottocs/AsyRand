package tyche

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"Tyche/Tyche/protocol/aba"
	"Tyche/utils/p2p"
)

// PersistentState contains the safety-critical state that must survive a
// process restart. Configuration material and private PVSS keys are deployment
// inputs and are deliberately not copied into this record.
type PersistentState struct {
	Schedule          SchedulingState         `json:"schedule"`
	Certificate       *BeaconQC               `json:"certificate,omitempty"`
	HistoryAnchor     SchedulingState         `json:"history_anchor"`
	BeaconHistory     []BeaconHistoryLink     `json:"beacon_history,omitempty"`
	SignedBeaconSlots map[string]string       `json:"signed_beacon_slots"`
	ProducerSeq       uint64                  `json:"producer_seq"`
	ABADecisions      map[string]aba.Decision `json:"aba_decisions,omitempty"`
}

// StateStore provides atomic BEACON-vote reservation and snapshot replacement.
type StateStore interface {
	Load() (PersistentState, bool, error)
	ReserveBeaconVote(slot, voteHash string) error
	Save(PersistentState) error
}

type MemoryStateStore struct {
	mu      sync.Mutex
	present bool
	state   PersistentState
}

func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{}
}

func (s *MemoryStateStore) Load() (PersistentState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return clonePersistentState(s.state), s.present, nil
}

func (s *MemoryStateStore) ReserveBeaconVote(slot, voteHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := reserveVote(&s.state, slot, voteHash); err != nil {
		return err
	}
	s.present = true
	return nil
}

func (s *MemoryStateStore) Save(state PersistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mergeVoteReservations(&state, s.state.SignedBeaconSlots); err != nil {
		return err
	}
	s.state = clonePersistentState(state)
	s.present = true
	return nil
}

// FileStateStore writes one JSON record using fsync + atomic rename. The
// containing directory must be on the same filesystem as the target.
type FileStateStore struct {
	mu   sync.Mutex
	path string
}

func NewFileStateStore(path string) (*FileStateStore, error) {
	if path == "" {
		return nil, errors.New("state store path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileStateStore{path: path}, nil
}

func (s *FileStateStore) Load() (PersistentState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *FileStateStore) ReserveBeaconVote(slot, voteHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, _, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := reserveVote(&state, slot, voteHash); err != nil {
		return err
	}
	return s.writeLocked(state)
}

func (s *FileStateStore) Save(state PersistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, _, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := mergeVoteReservations(&state, current.SignedBeaconSlots); err != nil {
		return err
	}
	return s.writeLocked(state)
}

func (s *FileStateStore) loadLocked() (PersistentState, bool, error) {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return PersistentState{}, false, nil
	}
	if err != nil {
		return PersistentState{}, false, err
	}
	var state PersistentState
	if err := json.Unmarshal(raw, &state); err != nil {
		return PersistentState{}, false, fmt.Errorf("decode Tyche state store: %w", err)
	}
	return state, true, nil
}

func (s *FileStateStore) writeLocked(state PersistentState) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".tyche-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}

func reserveVote(state *PersistentState, slot, voteHash string) error {
	if slot == "" || voteHash == "" {
		return errors.New("BEACON vote reservation requires a slot and vote hash")
	}
	if state.SignedBeaconSlots == nil {
		state.SignedBeaconSlots = make(map[string]string)
	}
	if existing := state.SignedBeaconSlots[slot]; existing != "" && existing != voteHash {
		return fmt.Errorf("persistent double-sign prevention: %s is reserved for %s", slot, existing)
	}
	state.SignedBeaconSlots[slot] = voteHash
	return nil
}

func mergeVoteReservations(state *PersistentState, reservations map[string]string) error {
	if state.SignedBeaconSlots == nil {
		state.SignedBeaconSlots = make(map[string]string)
	}
	for slot, voteHash := range reservations {
		if existing := state.SignedBeaconSlots[slot]; existing != "" && existing != voteHash {
			return fmt.Errorf("conflicting persistent vote reservation for slot %s", slot)
		}
		state.SignedBeaconSlots[slot] = voteHash
	}
	return nil
}

func clonePersistentState(in PersistentState) PersistentState {
	out := in
	out.Schedule = CloneSchedulingState(in.Schedule)
	out.HistoryAnchor = CloneSchedulingState(in.HistoryAnchor)
	out.BeaconHistory = append([]BeaconHistoryLink(nil), in.BeaconHistory...)
	if in.Certificate != nil {
		qc := *in.Certificate
		out.Certificate = &qc
	}
	out.SignedBeaconSlots = make(map[string]string, len(in.SignedBeaconSlots))
	for slot, voteHash := range in.SignedBeaconSlots {
		out.SignedBeaconSlots[slot] = voteHash
	}
	out.ABADecisions = cloneABADecisions(in.ABADecisions)
	return out
}

func (n *Node) persistentStateLocked() PersistentState {
	state := PersistentState{
		Schedule:          CloneSchedulingState(n.Schedule),
		HistoryAnchor:     CloneSchedulingState(n.HistoryAnchor),
		BeaconHistory:     append([]BeaconHistoryLink(nil), n.BeaconHistory...),
		SignedBeaconSlots: make(map[string]string),
		ProducerSeq:       n.State.ProducerSeq,
		ABADecisions:      cloneABADecisions(n.State.ABADecisions),
	}
	if n.LatestBeaconQC != nil {
		qc := *n.LatestBeaconQC
		state.Certificate = &qc
	}
	return clonePersistentState(state)
}

func (n *Node) persistLocked() error {
	if n.Store == nil {
		return errors.New("Tyche state store is not configured")
	}
	return n.Store.Save(n.persistentStateLocked())
}

func (n *Node) restorePersistentState() error {
	state, present, err := n.Store.Load()
	if err != nil || !present {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if state.ProducerSeq > n.State.ProducerSeq {
		n.State.ProducerSeq = state.ProducerSeq
	}
	if state.Schedule.ConfigDigest == "" {
		return nil
	}
	configuration := n.Configuration
	if configuration.Version != state.Schedule.ConfigVersion || configuration.Digest() != state.Schedule.ConfigDigest {
		return fmt.Errorf("persisted state does not match the fixed configuration (%s)", state.Schedule.ConfigDigest)
	}
	if !sameMembers(state.Schedule.Members, configuration.Members) {
		return errors.New("persisted scheduling state membership does not match configured setup")
	}
	n.Schedule = CloneSchedulingState(state.Schedule)
	if state.HistoryAnchor.ConfigDigest != "" {
		n.HistoryAnchor = CloneSchedulingState(state.HistoryAnchor)
	}
	n.BeaconHistory = append([]BeaconHistoryLink(nil), state.BeaconHistory...)
	if state.Certificate != nil {
		qc := *state.Certificate
		n.LatestBeaconQC = &qc
	}
	n.State.ConfigVersion = state.Schedule.ConfigVersion
	n.State.F = state.Schedule.F
	n.State.Epoch = state.Schedule.Epoch
	n.State.RPrev = append([]byte(nil), state.Schedule.Random...)
	n.State.Members = append([]p2p.NodeID(nil), state.Schedule.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), state.Schedule.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), state.Schedule.RSQ...)
	n.State.Seqs = cloneSeqMap(state.Schedule.Seqs)
	n.State.ABADecisions = cloneABADecisions(state.ABADecisions)
	n.State.ProducerSeq = maxUint64(n.State.ProducerSeq, state.ProducerSeq)
	return nil
}

func cloneABADecisions(in map[string]aba.Decision) map[string]aba.Decision {
	out := make(map[string]aba.Decision, len(in))
	for instance, decision := range in {
		out[instance] = decision
	}
	return out
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
