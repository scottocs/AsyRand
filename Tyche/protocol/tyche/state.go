package tyche

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/rbc"
	"Tyche/utils/p2p"
)

type TransitionType string

const (
	TransitionGenesis TransitionType = "GENESIS"
	TransitionEntropy TransitionType = "ENTROPY"
	TransitionRemove  TransitionType = "REMOVE"
	TransitionJoin    TransitionType = "JOIN"
)

type JoinReady struct {
	ParentHash      string     `json:"parent_hash"`
	RequestDigest   string     `json:"request_digest"`
	Joiner          p2p.NodeID `json:"joiner"`
	CheckpointHash  string     `json:"checkpoint_hash"`
	CandidateConfig string     `json:"candidate_config"`
}

type RetirementReference struct {
	ConfigVersion uint64                  `json:"config_version"`
	TargetEpoch   uint64                  `json:"target_epoch"`
	ObjectID      string                  `json:"object_id"`
	RBCDigest     string                  `json:"rbc_digest"`
	Object        Object                  `json:"object"`
	Delivery      rbc.DeliveryCertificate `json:"delivery"`
}

// CertifiedState is the complete state committed by a StateQC. Runtime-only
// queues and pending network messages must never be added after certification.
type CertifiedState struct {
	ConfigVersion uint64                `json:"config_version"`
	F             int                   `json:"f"`
	Q             int                   `json:"q"`
	PVSSThreshold int                   `json:"pvss_threshold"`
	Epoch         uint64                `json:"epoch"`
	Random        []byte                `json:"random"`
	Members       []p2p.NodeID          `json:"members"`
	SCL           []p2p.NodeID          `json:"scl"`
	RSQ           []p2p.NodeID          `json:"rsq"`
	Seqs          map[p2p.NodeID]uint64 `json:"seqs"`
	RmMark        map[p2p.NodeID]int64  `json:"rm_mark"`
	JReady        *JoinReady            `json:"join_ready,omitempty"`
	Retiring      []RetirementReference `json:"retiring,omitempty"`
	ConfigDigest  string                `json:"config_digest"`
	ParentHash    string                `json:"parent_hash"`
	Transition    TransitionType        `json:"transition"`
}

type StateQC struct {
	ParentConfigVersion uint64                         `json:"parent_config_version"`
	Transition          TransitionType                 `json:"transition"`
	ParentHash          string                         `json:"parent_hash"`
	ChildHash           string                         `json:"child_hash"`
	Signature           crypto.SignedQuorumCertificate `json:"signature"`
}

func CloneCertifiedState(in CertifiedState) CertifiedState {
	out := in
	out.Random = append([]byte(nil), in.Random...)
	out.Members = append([]p2p.NodeID(nil), in.Members...)
	out.SCL = append([]p2p.NodeID(nil), in.SCL...)
	out.RSQ = append([]p2p.NodeID(nil), in.RSQ...)
	out.Seqs = cloneSeqMap(in.Seqs)
	out.RmMark = cloneMarkMap(in.RmMark)
	out.Retiring = append([]RetirementReference(nil), in.Retiring...)
	if in.JReady != nil {
		ready := *in.JReady
		out.JReady = &ready
	}
	return out
}

func HashCertifiedState(state CertifiedState) string {
	state = canonicalCertifiedState(state)
	return hex.EncodeToString(crypto.DomainHash("Tyche/CertifiedState/v1", canonicalJSON(state)))
}

func StateVoteTranscript(parentConfigVersion uint64, transition TransitionType, parentHash, childHash string) []byte {
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], parentConfigVersion)
	return crypto.DomainHash(
		"Tyche/StateVote/v1",
		version[:],
		[]byte(transition),
		[]byte(parentHash),
		[]byte(childHash),
	)
}

func SignStateVote(signer p2p.NodeID, private ed25519.PrivateKey, parent Configuration, transition TransitionType, parentHash, childHash string) (crypto.SignedVote, error) {
	if !parent.Contains(signer) {
		return crypto.SignedVote{}, fmt.Errorf("state voter %s is not in parent configuration", signer)
	}
	return crypto.SignTranscript(string(signer), private, StateVoteTranscript(parent.Version, transition, parentHash, childHash))
}

func BuildStateQC(parent Configuration, transition TransitionType, parentHash, childHash string, votes []crypto.SignedVote) (StateQC, error) {
	if err := parent.Validate(); err != nil {
		return StateQC{}, err
	}
	transcript := StateVoteTranscript(parent.Version, transition, parentHash, childHash)
	cert, err := crypto.BuildSignedQuorumCertificate(votes, parent.PublicKeys(), parent.Q, transcript)
	if err != nil {
		return StateQC{}, err
	}
	return StateQC{
		ParentConfigVersion: parent.Version,
		Transition:          transition,
		ParentHash:          parentHash,
		ChildHash:           childHash,
		Signature:           cert,
	}, nil
}

func VerifyStateQC(parentConfig Configuration, parent, child CertifiedState, qc StateQC) error {
	if err := parentConfig.Validate(); err != nil {
		return err
	}
	parentHash := HashCertifiedState(parent)
	childHash := HashCertifiedState(child)
	if qc.ParentConfigVersion != parentConfig.Version || parent.ConfigVersion != parentConfig.Version {
		return errors.New("StateQC parent configuration mismatch")
	}
	if qc.ParentHash != parentHash || child.ParentHash != parentHash {
		return errors.New("StateQC does not name the exact parent state")
	}
	if qc.ChildHash != childHash {
		return errors.New("StateQC child hash mismatch")
	}
	if qc.Transition != child.Transition {
		return errors.New("StateQC transition type mismatch")
	}
	if err := ValidateSuccessor(parent, child); err != nil {
		return err
	}
	transcript := StateVoteTranscript(parentConfig.Version, qc.Transition, qc.ParentHash, qc.ChildHash)
	return crypto.VerifySignedQuorumCertificate(qc.Signature, parentConfig.PublicKeys(), parentConfig.Q, transcript)
}

func EntropySuccessor(parent CertifiedState, random []byte, source p2p.NodeID, seq uint64) (CertifiedState, error) {
	if len(random) == 0 {
		return CertifiedState{}, errors.New("entropy successor requires reconstructed randomness")
	}
	if !contains(parent.Members, source) {
		return CertifiedState{}, errors.New("entropy source is not a parent member")
	}
	child := CloneCertifiedState(parent)
	child.ParentHash = HashCertifiedState(parent)
	child.Transition = TransitionEntropy
	child.Epoch++
	child.Random = append([]byte(nil), random...)
	if child.Seqs[source]+1 != seq {
		return CertifiedState{}, fmt.Errorf("entropy sequence=%d, want %d", seq, child.Seqs[source]+1)
	}
	child.Seqs[source] = seq
	window := 2 * child.F
	if window > 0 && len(child.RSQ) >= window {
		oldest := child.RSQ[0]
		child.RSQ = append([]p2p.NodeID(nil), child.RSQ[1:]...)
		if oldest != "" && contains(child.Members, oldest) && child.RmMark[oldest] < 0 && !contains(child.SCL, oldest) {
			child.SCL = append(child.SCL, oldest)
		}
	}
	if window > 0 && !contains(child.RSQ, source) {
		child.RSQ = append(child.RSQ, source)
		child.SCL = removeIDCopy(child.SCL, source)
	}
	child.JReady = cloneReady(parent.JReady)
	return canonicalCertifiedState(child), nil
}

func RemoveSuccessor(parent CertifiedState, removed p2p.NodeID, childConfig Configuration) (CertifiedState, error) {
	if !contains(parent.Members, removed) {
		return CertifiedState{}, fmt.Errorf("removed node %s is not in parent configuration", removed)
	}
	if parent.RmMark[removed] < 0 {
		return CertifiedState{}, fmt.Errorf("removed node %s has no certified removal marker", removed)
	}
	if childConfig.Version != parent.ConfigVersion+1 {
		return CertifiedState{}, errors.New("REMOVE child configuration must increment version exactly once")
	}
	expected := removeIDCopy(parent.Members, removed)
	if !sameMembers(expected, childConfig.Members) {
		return CertifiedState{}, errors.New("REMOVE child configuration does not remove exactly the marked member")
	}
	if err := childConfig.Validate(); err != nil {
		return CertifiedState{}, err
	}
	child := CloneCertifiedState(parent)
	child.ConfigVersion = childConfig.Version
	child.F = childConfig.F
	child.Q = childConfig.Q
	child.PVSSThreshold = childConfig.PVSSThreshold
	child.ConfigDigest = childConfig.Digest()
	child.ParentHash = HashCertifiedState(parent)
	child.Transition = TransitionRemove
	child.Members = append([]p2p.NodeID(nil), childConfig.Members...)
	child.SCL = removeIDCopy(child.SCL, removed)
	child.RSQ = removeIDCopy(child.RSQ, removed)
	delete(child.Seqs, removed)
	delete(child.RmMark, removed)
	child.JReady = nil
	return canonicalCertifiedState(child), nil
}

func JoinSuccessor(parent CertifiedState, ready JoinReady, childConfig Configuration) (CertifiedState, error) {
	if parent.JReady == nil || *parent.JReady != ready {
		return CertifiedState{}, errors.New("JOIN requires the exact JReady certified in the parent")
	}
	if contains(parent.Members, ready.Joiner) {
		return CertifiedState{}, errors.New("joiner already belongs to parent configuration")
	}
	if childConfig.Version != parent.ConfigVersion+1 {
		return CertifiedState{}, errors.New("JOIN child configuration must increment version exactly once")
	}
	expected := normalizeMembers(append(append([]p2p.NodeID(nil), parent.Members...), ready.Joiner))
	if !sameMembers(expected, childConfig.Members) {
		return CertifiedState{}, errors.New("JOIN child configuration does not add exactly the ready joiner")
	}
	if childConfig.Digest() != ready.CandidateConfig {
		return CertifiedState{}, errors.New("JReady candidate configuration mismatch")
	}
	if err := childConfig.Validate(); err != nil {
		return CertifiedState{}, err
	}
	for _, mark := range parent.RmMark {
		if mark >= 0 {
			return CertifiedState{}, errors.New("JOIN is forbidden while a certified removal marker is pending")
		}
	}
	child := CloneCertifiedState(parent)
	child.ConfigVersion = childConfig.Version
	child.F = childConfig.F
	child.Q = childConfig.Q
	child.PVSSThreshold = childConfig.PVSSThreshold
	child.ConfigDigest = childConfig.Digest()
	child.ParentHash = HashCertifiedState(parent)
	child.Transition = TransitionJoin
	child.Members = append([]p2p.NodeID(nil), childConfig.Members...)
	child.SCL = append(child.SCL, ready.Joiner)
	child.Seqs[ready.Joiner] = 0
	child.RmMark[ready.Joiner] = -1
	child.JReady = nil
	return canonicalCertifiedState(child), nil
}

func ValidateSuccessor(parent, child CertifiedState) error {
	if child.ParentHash != HashCertifiedState(parent) {
		return errors.New("successor parent hash mismatch")
	}
	switch child.Transition {
	case TransitionEntropy:
		if child.ConfigVersion != parent.ConfigVersion || child.Epoch != parent.Epoch+1 {
			return errors.New("invalid ENTROPY version or epoch transition")
		}
		if !sameMembers(child.Members, parent.Members) || child.ConfigDigest != parent.ConfigDigest {
			return errors.New("ENTROPY changed configuration")
		}
		for _, member := range parent.Members {
			before := parent.RmMark[member]
			after, exists := child.RmMark[member]
			if !exists {
				return fmt.Errorf("ENTROPY removed marker entry for %s", member)
			}
			if before >= 0 && after != before {
				return fmt.Errorf("ENTROPY changed certified marker for %s", member)
			}
			if before < 0 && after >= 0 && after < int64(parent.Seqs[member]+1) {
				return fmt.Errorf("ENTROPY installed stale marker for %s", member)
			}
		}
	case TransitionRemove:
		if child.ConfigVersion != parent.ConfigVersion+1 || child.Epoch != parent.Epoch {
			return errors.New("invalid REMOVE version or epoch transition")
		}
		if string(child.Random) != string(parent.Random) || len(parent.Members)-len(child.Members) != 1 {
			return errors.New("REMOVE changed randomness or did not remove exactly one member")
		}
	case TransitionJoin:
		if child.ConfigVersion != parent.ConfigVersion+1 || child.Epoch != parent.Epoch {
			return errors.New("invalid JOIN version or epoch transition")
		}
		if string(child.Random) != string(parent.Random) || len(child.Members)-len(parent.Members) != 1 {
			return errors.New("JOIN changed randomness or did not add exactly one member")
		}
	default:
		return fmt.Errorf("unsupported successor transition %q", child.Transition)
	}
	if child.Q != len(child.Members)-child.F || child.PVSSThreshold != child.F+1 {
		return errors.New("successor quorum or PVSS threshold is inconsistent")
	}
	return nil
}

func canonicalCertifiedState(in CertifiedState) CertifiedState {
	out := CloneCertifiedState(in)
	out.Members = normalizeMembers(out.Members)
	out.SCL = append([]p2p.NodeID(nil), out.SCL...)
	out.RSQ = append([]p2p.NodeID(nil), out.RSQ...)
	sort.Slice(out.Retiring, func(i, j int) bool {
		if out.Retiring[i].ConfigVersion != out.Retiring[j].ConfigVersion {
			return out.Retiring[i].ConfigVersion < out.Retiring[j].ConfigVersion
		}
		return out.Retiring[i].ObjectID < out.Retiring[j].ObjectID
	})
	return out
}

func cloneReady(in *JoinReady) *JoinReady {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func cloneSeqMap(in map[p2p.NodeID]uint64) map[p2p.NodeID]uint64 {
	out := make(map[p2p.NodeID]uint64, len(in))
	for id, seq := range in {
		out[id] = seq
	}
	return out
}

func cloneMarkMap(in map[p2p.NodeID]int64) map[p2p.NodeID]int64 {
	out := make(map[p2p.NodeID]int64, len(in))
	for id, mark := range in {
		out[id] = mark
	}
	return out
}

func removeIDCopy(ids []p2p.NodeID, removed p2p.NodeID) []p2p.NodeID {
	out := make([]p2p.NodeID, 0, len(ids))
	for _, id := range ids {
		if id != removed {
			out = append(out, id)
		}
	}
	return out
}
