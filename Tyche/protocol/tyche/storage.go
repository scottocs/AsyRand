package tyche

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

// PersistentState contains the safety-critical state that must survive a
// process restart. Configuration material and private PVSS keys are deployment
// inputs and are deliberately not copied into this record.
type PersistentState struct {
	Certified      CertifiedState                  `json:"certified"`
	Certificate    *StateQC                        `json:"certificate,omitempty"`
	HistoryAnchor  CertifiedState                  `json:"history_anchor"`
	StateHistory   []StateCertificateMessage       `json:"state_history,omitempty"`
	SignedParents  map[string]string               `json:"signed_parents"`
	ProducerSeq    uint64                          `json:"producer_seq"`
	Retirement     map[string]RetirementObligation `json:"retirement"`
	ErasedVersions map[uint64]bool                 `json:"erased_versions"`
}

// StateStore provides atomic vote reservation and snapshot replacement.
// ReserveStateVote must be durable before the corresponding signature is sent.
type StateStore interface {
	Load() (PersistentState, bool, error)
	ReserveStateVote(parentHash, childHash string) error
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

func (s *MemoryStateStore) ReserveStateVote(parentHash, childHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := reserveVote(&s.state, parentHash, childHash); err != nil {
		return err
	}
	s.present = true
	return nil
}

func (s *MemoryStateStore) Save(state PersistentState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mergeVoteReservations(&state, s.state.SignedParents); err != nil {
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

func (s *FileStateStore) ReserveStateVote(parentHash, childHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, _, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := reserveVote(&state, parentHash, childHash); err != nil {
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
	if err := mergeVoteReservations(&state, current.SignedParents); err != nil {
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

func reserveVote(state *PersistentState, parentHash, childHash string) error {
	if parentHash == "" || childHash == "" {
		return errors.New("state vote reservation requires parent and child hashes")
	}
	if state.SignedParents == nil {
		state.SignedParents = make(map[string]string)
	}
	if existing := state.SignedParents[parentHash]; existing != "" && existing != childHash {
		return fmt.Errorf("persistent double-sign prevention: parent %s is reserved for %s", parentHash, existing)
	}
	state.SignedParents[parentHash] = childHash
	return nil
}

func mergeVoteReservations(state *PersistentState, reservations map[string]string) error {
	if state.SignedParents == nil {
		state.SignedParents = make(map[string]string)
	}
	for parent, child := range reservations {
		if existing := state.SignedParents[parent]; existing != "" && existing != child {
			return fmt.Errorf("conflicting persistent vote reservation for parent %s", parent)
		}
		state.SignedParents[parent] = child
	}
	return nil
}

func clonePersistentState(in PersistentState) PersistentState {
	out := in
	out.Certified = CloneCertifiedState(in.Certified)
	out.HistoryAnchor = CloneCertifiedState(in.HistoryAnchor)
	out.StateHistory = append([]StateCertificateMessage(nil), in.StateHistory...)
	if in.Certificate != nil {
		qc := *in.Certificate
		out.Certificate = &qc
	}
	out.SignedParents = make(map[string]string, len(in.SignedParents))
	for parent, child := range in.SignedParents {
		out.SignedParents[parent] = child
	}
	out.Retirement = make(map[string]RetirementObligation, len(in.Retirement))
	for key, obligation := range in.Retirement {
		copyObligation := obligation
		copyObligation.Secret = append([]byte(nil), obligation.Secret...)
		copyObligation.Shares = make(map[p2p.NodeID]crypto.DecryptedShare, len(obligation.Shares))
		for holder, share := range obligation.Shares {
			copyObligation.Shares[holder] = share
		}
		out.Retirement[key] = copyObligation
	}
	out.ErasedVersions = make(map[uint64]bool, len(in.ErasedVersions))
	for version, erased := range in.ErasedVersions {
		out.ErasedVersions[version] = erased
	}
	return out
}

func (n *Node) persistentStateLocked() PersistentState {
	state := PersistentState{
		Certified:      CloneCertifiedState(n.Certified),
		HistoryAnchor:  CloneCertifiedState(n.HistoryAnchor),
		StateHistory:   append([]StateCertificateMessage(nil), n.StateHistory...),
		SignedParents:  make(map[string]string, len(n.signedParents)),
		ProducerSeq:    n.State.ProducerSeq,
		Retirement:     make(map[string]RetirementObligation, len(n.Retirement)),
		ErasedVersions: make(map[uint64]bool),
	}
	if n.StateCertificate != nil {
		qc := *n.StateCertificate
		state.Certificate = &qc
	}
	for parent, child := range n.signedParents {
		state.SignedParents[parent] = child
	}
	for key, obligation := range n.Retirement {
		if obligation != nil {
			state.Retirement[key] = *obligation
		}
	}
	for version, pvssContext := range n.PVSSContexts {
		if pvssContext != nil && pvssContext.Status == PVSSErased {
			state.ErasedVersions[version] = true
		}
	}
	return clonePersistentState(state)
}

func (n *Node) persistLocked() error {
	if n.Store == nil {
		return errors.New("Tyche state store is not configured")
	}
	return n.Store.Save(n.persistentStateLocked())
}

func (n *Node) persistCertifiedLocked(child CertifiedState, qc StateQC) error {
	state := n.persistentStateLocked()
	state.Certified = CloneCertifiedState(child)
	qcCopy := qc
	state.Certificate = &qcCopy
	return n.Store.Save(state)
}

func (n *Node) restorePersistentState() error {
	state, present, err := n.Store.Load()
	if err != nil || !present {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for parent, child := range state.SignedParents {
		n.signedParents[parent] = child
	}
	if state.ProducerSeq > n.State.ProducerSeq {
		n.State.ProducerSeq = state.ProducerSeq
	}
	if state.Certified.ConfigDigest == "" {
		return nil
	}
	setup, exists := n.ConfigurationSetups[state.Certified.ConfigVersion]
	if !exists || setup.Configuration.Digest() != state.Certified.ConfigDigest {
		return fmt.Errorf("persisted state needs exact configuration setup %d (%s)", state.Certified.ConfigVersion, state.Certified.ConfigDigest)
	}
	if !sameMembers(state.Certified.Members, setup.Configuration.Members) {
		return errors.New("persisted certified state membership does not match configured setup")
	}
	n.Certified = CloneCertifiedState(state.Certified)
	if state.HistoryAnchor.ConfigDigest != "" {
		n.HistoryAnchor = CloneCertifiedState(state.HistoryAnchor)
	}
	n.StateHistory = append([]StateCertificateMessage(nil), state.StateHistory...)
	if state.Certificate != nil {
		qc := *state.Certificate
		n.StateCertificate = &qc
	}
	n.State.ConfigVersion = state.Certified.ConfigVersion
	n.State.F = state.Certified.F
	n.State.Epoch = state.Certified.Epoch
	n.State.RPrev = append([]byte(nil), state.Certified.Random...)
	n.State.Members = append([]p2p.NodeID(nil), state.Certified.Members...)
	n.State.SCL = append([]p2p.NodeID(nil), state.Certified.SCL...)
	n.State.RSQ = append([]p2p.NodeID(nil), state.Certified.RSQ...)
	n.State.Seqs = cloneSeqMap(state.Certified.Seqs)
	n.State.RmMark = cloneMarkMap(state.Certified.RmMark)
	n.State.ProducerSeq = maxUint64(n.State.ProducerSeq, state.ProducerSeq)
	n.Retirement = make(map[string]*RetirementObligation, len(state.Retirement))
	for key, obligation := range state.Retirement {
		copyObligation := obligation
		n.Retirement[key] = &copyObligation
	}
	if state.ErasedVersions[state.Certified.ConfigVersion] {
		return errors.New("persisted tombstone erases the active PVSS configuration")
	}
	return nil
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
