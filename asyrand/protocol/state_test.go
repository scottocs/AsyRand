package protocol

import (
	"context"
	"crypto/ed25519"
	asig "github.com/scottocs/Tyche/asyrand/crypto"
	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"testing"
	"time"
)

func TestStateRemoveSourceOnEmptySource(t *testing.T) {
	state := NewState([]p2p.NodeID{"n0", "n1", "n2", "n3"}, 1, 4, []byte{0})
	source, err := state.Source()
	if err != nil {
		t.Fatal(err)
	}
	state.RemoveSource(source)
	next, err := state.Source()
	if err != nil {
		t.Fatal(err)
	}
	if next == source {
		t.Fatalf("source %s was not removed", source)
	}
}

func TestRunEpochRemovesUnavailableSource(t *testing.T) {
	state := NewState([]p2p.NodeID{"n0", "n1", "n2", "n3"}, 1, 4, []byte{0})
	source, err := state.Source()
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{ID: "n0", State: state}
	beacon, consumed, err := node.RunEpoch(context.Background(), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if beacon != nil || consumed {
		t.Fatalf("RunEpoch returned beacon=%+v consumed=%v, want unavailable source retry", beacon, consumed)
	}
	next, err := state.Source()
	if err != nil {
		t.Fatal(err)
	}
	if next == source {
		t.Fatalf("source %s was not removed after unavailable commitment", source)
	}
}

func TestStateComQIsDictionaryArray(t *testing.T) {
	state := NewState([]p2p.NodeID{"n0", "n1", "n2", "n3"}, 1, 4, []byte{0})
	idx, ok := state.MemberIndex["n1"]
	if !ok {
		t.Fatal("missing member index for n1")
	}
	if len(state.ComQ) != 4 || state.ComQ[idx] == nil {
		t.Fatalf("ComQ is not initialized as one dictionary per member: %+v", state.ComQ)
	}

	seq2 := asig.Commitment{Dealer: "n1", Seq: 2, SecretID: "n1/2"}
	if !state.Enqueue(seq2) {
		t.Fatal("out-of-order commitment was not recorded in ComQ[n1]")
	}
	if state.HasCommitment("n1") {
		t.Fatal("consumer observed seq=2 before seq=1")
	}
	if got, ok := state.ComQ[idx][2]; !ok || got.SecretID != "n1/2" {
		t.Fatalf("ComQ[n1][2] not recorded: %+v", state.ComQ[idx])
	}

	seq1 := asig.Commitment{Dealer: "n1", Seq: 1, SecretID: "n1/1"}
	if !state.Enqueue(seq1) {
		t.Fatal("head commitment was not recorded")
	}
	if !state.HasCommitment("n1") {
		t.Fatal("consumer did not observe seq=1")
	}
	got, ok := state.PopCommitment("n1")
	if !ok || got.Seq != 1 {
		t.Fatalf("first pop = %+v, %v; want seq=1", got, ok)
	}
	got, ok = state.PopCommitment("n1")
	if !ok || got.Seq != 2 {
		t.Fatalf("second pop = %+v, %v; want seq=2", got, ok)
	}
	if state.Enqueue(seq1) {
		t.Fatal("consumed old commitment was accepted again")
	}
}

func TestStateCanSkipMissingCommitmentHead(t *testing.T) {
	state := NewState([]p2p.NodeID{"n0", "n1", "n2", "n3"}, 1, 4, []byte{0})
	seq2 := asig.Commitment{Dealer: "n1", Seq: 2, SecretID: "n1/2"}
	if !state.Enqueue(seq2) {
		t.Fatal("seq=2 commitment was not recorded")
	}
	if state.HasCommitment("n1") {
		t.Fatal("seq=2 should not satisfy missing seq=1 head")
	}
	if !state.AdvanceHeadToNextCommitment("n1") {
		t.Fatal("missing head was not advanced to available commitment")
	}
	if !state.HasCommitment("n1") {
		t.Fatal("advanced head did not expose seq=2")
	}
	got, ok := state.PopCommitment("n1")
	if !ok || got.Seq != 2 {
		t.Fatalf("pop after skip = %+v, %v; want seq=2", got, ok)
	}
}

func TestNodeEpochConsumesSourceCommitment(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	net := p2p.NewMemoryNetwork()
	keys := make(map[p2p.NodeID]asig.KeyPair)
	pubs := make(map[string]ed25519.PublicKey)
	seeds := make(map[p2p.NodeID][]byte)
	for _, id := range ids {
		kp, err := asig.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		keys[id] = kp
		pubs[string(id)] = kp.Public
		seeds[id] = asig.HashBytes([]byte(id))
	}
	pvssKeys := make(map[p2p.NodeID]asig.PVSSKeyPair)
	pvssPublic := make(map[p2p.NodeID]kyber.Point)
	blsKeys := make(map[p2p.NodeID]asig.BLSKeyPair)
	blsPublic := make(map[string]kyber.Point)
	for _, id := range ids {
		pvssKeys[id] = asig.PVSSKeyPairFromSeed(seeds[id])
		pvssPublic[id] = pvssKeys[id].Public
		blsKeys[id] = asig.NewBLSKeyPairFromSeed(seeds[id])
		blsPublic[string(id)] = blsKeys[id].Public
	}

	nodes := make([]*Node, 0, len(ids))
	for _, id := range ids {
		pvssScheme, err := asig.NewScheme(id, 2, pvssKeys[id].Private, pvssPublic)
		if err != nil {
			t.Fatal(err)
		}
		node, err := NewNode(NodeConfig{
			ID: id, Members: ids, F: 1, QueueLen: 4, Keys: keys[id],
			Public: pubs, BLS: blsKeys[id], BLSPublic: blsPublic,
			Transport: net.NewTransport(id, 256), PVSS: pvssScheme,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := node.Start(ctx); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
	}

	source, err := nodes[0].State.Source()
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range nodes {
		if node.ID == source {
			if _, err := node.Produce(ctx); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	time.Sleep(200 * time.Millisecond)

	results := make(chan *Beacon, len(nodes))
	errs := make(chan error, len(nodes))
	for _, node := range nodes {
		go func(node *Node) {
			beacon, _, err := node.RunEpoch(ctx, time.Second)
			if err != nil {
				errs <- err
				return
			}
			results <- beacon
		}(node)
	}

	for range nodes {
		select {
		case err := <-errs:
			t.Fatal(err)
		case beacon := <-results:
			if beacon == nil || beacon.Source != source || len(beacon.Random) == 0 {
				t.Fatalf("unexpected beacon: %+v", beacon)
			}
		case <-ctx.Done():
			t.Fatal("timed out waiting for beacon")
		}
	}
}
