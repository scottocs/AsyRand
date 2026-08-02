package tyche

import (
	"encoding/hex"
	"errors"
	"fmt"

	"Tyche/Tyche/crypto"
	"Tyche/utils/p2p"
)

// SchedulingState is the deterministic local scheduling state derived from
// the certified beacon prefix. It is not independently voted on or certified.
type SchedulingState struct {
	ConfigVersion uint64                `json:"config_version"`
	F             int                   `json:"f"`
	Q             int                   `json:"q"`
	PVSSThreshold int                   `json:"pvss_threshold"`
	Epoch         uint64                `json:"epoch"`
	Random        []byte                `json:"random"`
	BeaconHead    string                `json:"beacon_head"`
	Members       []p2p.NodeID          `json:"members"`
	SCL           []p2p.NodeID          `json:"scl"`
	RSQ           []p2p.NodeID          `json:"rsq"`
	Seqs          map[p2p.NodeID]uint64 `json:"seqs"`
	ConfigDigest  string                `json:"config_digest"`
}

func CloneSchedulingState(in SchedulingState) SchedulingState {
	out := in
	out.Random = append([]byte(nil), in.Random...)
	out.Members = append([]p2p.NodeID(nil), in.Members...)
	out.SCL = append([]p2p.NodeID(nil), in.SCL...)
	out.RSQ = append([]p2p.NodeID(nil), in.RSQ...)
	out.Seqs = cloneSeqMap(in.Seqs)
	return out
}

func HashSchedulingState(state SchedulingState) string {
	state = canonicalSchedulingState(state)
	return hex.EncodeToString(crypto.DomainHash("Tyche/SchedulingState/v1", canonicalJSON(state)))
}

func EntropySuccessor(parent SchedulingState, random []byte, source p2p.NodeID, seq uint64) (SchedulingState, error) {
	return entropySuccessorForRecord(parent, parent.ConfigVersion, parent.F, random, source, seq)
}

// entropySuccessorForRecord applies a certified beacon record to the local
// scheduling state. recordConfig is the configuration that signed P_e; it may
// be older than parent.ConfigVersion when an already-agreed membership change
// is delivered before that party receives P_e.
func entropySuccessorForRecord(parent SchedulingState, recordConfig uint64, recordF int, random []byte, source p2p.NodeID, seq uint64) (SchedulingState, error) {
	if len(random) == 0 {
		return SchedulingState{}, errors.New("entropy successor requires reconstructed randomness")
	}
	if !contains(parent.Members, source) {
		return SchedulingState{}, errors.New("entropy source is not a parent member")
	}
	child := CloneSchedulingState(parent)
	child.Epoch++
	child.Random = append([]byte(nil), random...)
	child.BeaconHead = BeaconHeaderHash(recordConfig, child.Epoch, parent.BeaconHead, source, seq, random)
	if child.Seqs[source]+1 != seq {
		return SchedulingState{}, fmt.Errorf("entropy sequence=%d, want %d", seq, child.Seqs[source]+1)
	}
	child.Seqs[source] = seq
	// An old record remains governed by the exclusion window of the
	// configuration that certified it, even if a JOIN certificate was
	// delivered first at this replica.
	window := 2 * recordF
	if window > 0 && len(child.RSQ) >= window {
		child.RSQ = append([]p2p.NodeID(nil), child.RSQ[1:]...)
	}
	if window > 0 && !contains(child.RSQ, source) {
		child.RSQ = append(child.RSQ, source)
	}
	return canonicalSchedulingState(child), nil
}

func RemoveSuccessor(parent SchedulingState, removed p2p.NodeID, childConfig Configuration) (SchedulingState, error) {
	if !contains(parent.Members, removed) {
		return SchedulingState{}, fmt.Errorf("removed node %s is not in parent configuration", removed)
	}
	if childConfig.Version != parent.ConfigVersion+1 {
		return SchedulingState{}, errors.New("REMOVE child configuration must increment version exactly once")
	}
	expected := removeIDCopy(parent.Members, removed)
	if !sameMembers(expected, childConfig.Members) {
		return SchedulingState{}, errors.New("REMOVE child configuration does not remove exactly the marked member")
	}
	if err := childConfig.Validate(); err != nil {
		return SchedulingState{}, err
	}
	child := CloneSchedulingState(parent)
	child.ConfigVersion = childConfig.Version
	child.F = childConfig.F
	child.Q = childConfig.Q
	child.PVSSThreshold = childConfig.PVSSThreshold
	child.ConfigDigest = childConfig.Digest()
	child.Members = append([]p2p.NodeID(nil), childConfig.Members...)
	child.SCL = removeIDCopy(child.SCL, removed)
	child.RSQ = removeIDCopy(child.RSQ, removed)
	delete(child.Seqs, removed)
	return canonicalSchedulingState(child), nil
}

func canonicalSchedulingState(in SchedulingState) SchedulingState {
	out := CloneSchedulingState(in)
	out.Members = normalizeMembers(out.Members)
	filteredRSQ := make([]p2p.NodeID, 0, len(out.RSQ))
	for _, member := range out.RSQ {
		if contains(out.Members, member) && !contains(filteredRSQ, member) {
			filteredRSQ = append(filteredRSQ, member)
		}
	}
	// A membership transition may reduce f. Retain only the newest entries
	// allowed by the successor exclusion window; otherwise Members-RSQ can be
	// empty even though n >= 3f+1. Keeping the suffix also commutes with a
	// delayed old-configuration record, which appends the newest source.
	window := 2 * out.F
	if window == 0 {
		filteredRSQ = nil
	} else if len(filteredRSQ) > window {
		filteredRSQ = append([]p2p.NodeID(nil), filteredRSQ[len(filteredRSQ)-window:]...)
	}
	out.RSQ = filteredRSQ
	out.SCL = eligibleSourceList(out.Members, out.RSQ)
	return out
}

// eligibleSourceList is a canonical representation of the eligible set.
// Deriving it from Members-RSQ makes a one-member JOIN commute with delivery
// of an already-certified old-configuration beacon record.
func eligibleSourceList(members, recent []p2p.NodeID) []p2p.NodeID {
	eligible := make([]p2p.NodeID, 0, len(members))
	for _, member := range normalizeMembers(members) {
		if !contains(recent, member) {
			eligible = append(eligible, member)
		}
	}
	return eligible
}

func cloneSeqMap(in map[p2p.NodeID]uint64) map[p2p.NodeID]uint64 {
	out := make(map[p2p.NodeID]uint64, len(in))
	for id, seq := range in {
		out[id] = seq
	}
	return out
}

func cloneMarkMap(in map[p2p.NodeID]RemovalMark) map[p2p.NodeID]RemovalMark {
	out := make(map[p2p.NodeID]RemovalMark, len(in))
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
