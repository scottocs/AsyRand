package protocol

import (
	"context"
	"sync/atomic"
	"testing"

	asig "github.com/scottocs/Tyche/asyrand/crypto"
	"github.com/scottocs/Tyche/utils/cryptoexec"
	"github.com/scottocs/Tyche/utils/p2p"
)

type countingPVSS struct {
	verifyShares atomic.Int32
}

func (s *countingPVSS) Share(p2p.NodeID, uint64, []p2p.NodeID) (asig.Commitment, []byte, error) {
	return asig.Commitment{}, nil, nil
}

func (s *countingPVSS) Verify(asig.Commitment) bool { return true }

func (s *countingPVSS) PreRecon(asig.Commitment, p2p.NodeID) (asig.DecryptedShare, error) {
	return asig.DecryptedShare{}, nil
}

func (s *countingPVSS) PreReconTrusted(asig.Commitment, p2p.NodeID) (asig.DecryptedShare, error) {
	return asig.DecryptedShare{}, nil
}

func (s *countingPVSS) VerifyShare(asig.Commitment, asig.DecryptedShare) bool {
	s.verifyShares.Add(1)
	return true
}

func (s *countingPVSS) Recon(asig.Commitment, []asig.DecryptedShare, int) ([]byte, error) {
	return []byte("secret"), nil
}

func (s *countingPVSS) ReconTrusted(asig.Commitment, []asig.DecryptedShare, int) ([]byte, error) {
	return []byte("secret"), nil
}

func TestHandleReconStopsVerifyingAfterThreshold(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	net := p2p.NewMemoryNetwork()
	pvss := &countingPVSS{}
	node := &Node{
		ID:        "n0",
		Transport: net.NewTransport("n0", 16),
		Perf:      &PerfMetrics{},
		State:     NewState(ids, 1, 4, []byte{1}),
		PVSS:      pvss,
		Crypto:    cryptoexec.New(1),
		recon:     make(map[string]*reconState),
		beacons:   make(chan *Beacon, 4),
	}
	for _, id := range ids[1:] {
		net.NewTransport(id, 16)
	}
	commit := asig.Commitment{Dealer: "n0", Seq: 1, Threshold: 2, Members: ids, SecretID: "n0/1"}
	node.ensureReconState(1, "n0", commit, "epoch/1")

	for _, id := range []p2p.NodeID{"n1", "n2", "n3"} {
		node.handleRecon(context.Background(), ReconMessage{
			Epoch:    1,
			Source:   "n0",
			CommitID: "n0/1",
			Share:    asig.DecryptedShare{CommitmentID: "n0/1", Holder: id},
		})
	}

	if got, want := pvss.verifyShares.Load(), int32(2); got != want {
		t.Fatalf("VerifyShare calls = %d, want %d", got, want)
	}
}
