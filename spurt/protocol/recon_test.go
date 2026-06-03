package spurt

import (
	"sync/atomic"
	"testing"

	asig "github.com/scottocs/Tyche/spurt/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
)

type countingPVSSScheme struct {
	verifyShares atomic.Int32
}

func (s *countingPVSSScheme) Share(p2p.NodeID, uint64, []p2p.NodeID) (asig.PVSSCommitment, []byte, error) {
	return asig.PVSSCommitment{}, nil, nil
}

func (s *countingPVSSScheme) Verify(asig.PVSSCommitment) bool { return true }

func (s *countingPVSSScheme) Aggregate(p2p.NodeID, uint64, []asig.PVSSCommitment, []p2p.NodeID) (asig.PVSSCommitment, error) {
	return asig.PVSSCommitment{}, nil
}

func (s *countingPVSSScheme) AggregateTrusted(p2p.NodeID, uint64, []asig.PVSSCommitment, []p2p.NodeID) (asig.PVSSCommitment, error) {
	return asig.PVSSCommitment{}, nil
}

func (s *countingPVSSScheme) PreRecon(asig.PVSSCommitment, p2p.NodeID) (asig.PVSSDecryptedShare, error) {
	return asig.PVSSDecryptedShare{}, nil
}

func (s *countingPVSSScheme) PreReconTrusted(asig.PVSSCommitment, p2p.NodeID) (asig.PVSSDecryptedShare, error) {
	return asig.PVSSDecryptedShare{}, nil
}

func (s *countingPVSSScheme) VerifyShare(asig.PVSSCommitment, asig.PVSSDecryptedShare) bool {
	s.verifyShares.Add(1)
	return true
}

func (s *countingPVSSScheme) Recon(asig.PVSSCommitment, []asig.PVSSDecryptedShare, int) ([]byte, error) {
	return []byte("secret"), nil
}

func (s *countingPVSSScheme) ReconTrusted(asig.PVSSCommitment, []asig.PVSSDecryptedShare, int) ([]byte, error) {
	return []byte("secret"), nil
}

func (s *countingPVSSScheme) VerifyAggregationColumn(p2p.NodeID, asig.PVSSCommitment, []asig.PVSSColumnEntry) bool {
	return true
}

func TestHandleReconStopsVerifyingAfterThreshold(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pvss := &countingPVSSScheme{}
	node := &Node{
		ID:     "n0",
		Perf:   &PerfMetrics{},
		State:  NewState(ids, 1, []byte{1}),
		PVSS:   pvss,
		epochs: make(map[uint64]*epochState),
	}
	aggregate := asig.PVSSCommitment{Dealer: "n0", Seq: 1, Threshold: 2, Members: ids, SecretID: "agg/1"}
	es := node.stateAt(1)
	es.aggregate = &aggregate
	es.digest = "digest"

	for _, id := range []p2p.NodeID{"n1", "n2", "n3"} {
		node.handleRecon(ReconMessage{
			Epoch:  1,
			Digest: "digest",
			Share:  asig.PVSSDecryptedShare{CommitmentID: "agg/1", Holder: id},
		}, id)
	}

	if got, want := pvss.verifyShares.Load(), int32(2); got != want {
		t.Fatalf("VerifyShare calls = %d, want %d", got, want)
	}
}
