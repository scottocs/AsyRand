package tyche

import (
	"encoding/hex"
	"errors"
	"fmt"

	"Tyche/Tyche/crypto"
	"Tyche/Tyche/protocol/aba"
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
	// ControlInstances keeps only each producer's latest tuple-bound ABA,
	// which is exactly the instance needed to evaluate its next sequence.
	ControlInstances map[p2p.NodeID]string `json:"control_instances,omitempty"`
	ConfigDigest     string                `json:"config_digest"`
}

// BeaconHistoryLink retains the certified scheduling transition needed to
// replay source exclusions and verify the fixed-party beacon history.
type BeaconHistoryLink struct {
	Child   SchedulingState `json:"child"`
	QC      BeaconQC        `json:"qc"`
	Skipped []SkippedTuple  `json:"skipped,omitempty"`
}

func CloneSchedulingState(in SchedulingState) SchedulingState {
	out := in
	out.Random = append([]byte(nil), in.Random...)
	out.Members = append([]p2p.NodeID(nil), in.Members...)
	out.SCL = append([]p2p.NodeID(nil), in.SCL...)
	out.RSQ = append([]p2p.NodeID(nil), in.RSQ...)
	out.Seqs = cloneSeqMap(in.Seqs)
	out.ControlInstances = cloneControlMap(in.ControlInstances)
	return out
}

func HashSchedulingState(state SchedulingState) string {
	state = canonicalSchedulingState(state)
	return hex.EncodeToString(crypto.DomainHash("Tyche/SchedulingState/v2", canonicalJSON(state)))
}

func EntropySuccessor(parent SchedulingState, random []byte, source p2p.NodeID, seq uint64, skipped []SkippedTuple) (SchedulingState, error) {
	return entropySuccessorForRecord(parent, parent.ConfigVersion, parent.F, random, source, seq, skipped)
}

// entropySuccessorForRecord applies a certified beacon record to the local
// scheduling state. recordConfig domain-separates the fixed protocol setup.
func entropySuccessorForRecord(parent SchedulingState, recordConfig uint64, recordF int, random []byte, source p2p.NodeID, seq uint64, skipped []SkippedTuple) (SchedulingState, error) {
	if len(random) == 0 {
		return SchedulingState{}, errors.New("entropy successor requires reconstructed randomness")
	}
	if !contains(parent.Members, source) {
		return SchedulingState{}, errors.New("entropy source is not a parent member")
	}
	child := CloneSchedulingState(parent)
	child.Epoch++
	child.Random = append([]byte(nil), random...)
	skippedHash := HashSkippedTuples(skipped)
	child.BeaconHead = BeaconHeaderHash(recordConfig, child.Epoch, parent.BeaconHead, skippedHash, source, seq, random)
	for _, item := range skipped {
		if !contains(child.Members, item.Source) || child.Seqs[item.Source]+1 != item.Seq {
			return SchedulingState{}, errors.New("invalid certified skipped tuple sequence")
		}
		if item.Seq <= 1 || item.Certificate.Value || item.Certificate.Instance == "" ||
			item.Certificate.Instance != parent.ControlInstances[item.Source] {
			return SchedulingState{}, errors.New("skipped tuple is not bound to its predecessor ABA")
		}
		child.Seqs[item.Source] = item.Seq
		if child.ControlInstances == nil {
			child.ControlInstances = make(map[p2p.NodeID]string)
		}
		child.ControlInstances[item.Source] = aba.TupleInstanceFor(recordConfig, child.Epoch, item.Source, item.Seq)
	}
	if child.Seqs[source]+1 != seq {
		return SchedulingState{}, fmt.Errorf("entropy sequence=%d, want %d", seq, child.Seqs[source]+1)
	}
	child.Seqs[source] = seq
	if child.ControlInstances == nil {
		child.ControlInstances = make(map[p2p.NodeID]string)
	}
	child.ControlInstances[source] = aba.TupleInstanceFor(recordConfig, child.Epoch, source, seq)
	window := 2 * recordF
	if window > 0 && len(child.RSQ) >= window {
		child.RSQ = append([]p2p.NodeID(nil), child.RSQ[1:]...)
	}
	if window > 0 && !contains(child.RSQ, source) {
		child.RSQ = append(child.RSQ, source)
	}
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
	// Retain only the newest entries allowed by the fixed exclusion window.
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

// eligibleSourceList is the canonical fixed-member set minus the recent queue.
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

func cloneControlMap(in map[p2p.NodeID]string) map[p2p.NodeID]string {
	out := make(map[p2p.NodeID]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
