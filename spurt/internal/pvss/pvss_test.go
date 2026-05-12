package pvss

import (
	"bytes"
	"testing"

	asig "github.com/scottocs/asyrand/spurt/internal/crypto"
	"github.com/scottocs/asyrand/spurt/internal/p2p"
	"go.dedis.ch/kyber/v3"
)

func TestPVSSVerifyPreReconAndRecon(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	keys := make(map[p2p.NodeID]KeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = KeyPairFromSeed(asig.HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}
	dealer, err := NewScheme("n0", 2, keys["n0"].Private, public)
	if err != nil {
		t.Fatal(err)
	}
	commit, secret, err := dealer.Share("n0", 1, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !dealer.Verify(commit) {
		t.Fatal("valid pvss commitment did not verify")
	}
	tampered := commit
	tampered.Cipher = copyStringMap(commit.Cipher)
	tampered.Cipher["n1"] = commit.Cipher["n0"]
	tampered.SecretID = commitmentID(tampered)
	if dealer.Verify(tampered) {
		t.Fatal("tampered pvss commitment verified")
	}

	shares := make([]DecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewScheme(id, 2, keys[id].Private, public)
		if err != nil {
			t.Fatal(err)
		}
		share, err := scheme.PreRecon(commit, id)
		if err != nil {
			t.Fatal(err)
		}
		if !scheme.VerifyShare(commit, share) {
			t.Fatalf("valid decrypted share from %s did not verify", id)
		}
		shares = append(shares, share)
	}
	recovered, err := dealer.Recon(commit, shares, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("reconstructed PVSS secret differs from dealer secret")
	}
}

func TestPVSSAggregateRecon(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	keys := make(map[p2p.NodeID]KeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = KeyPairFromSeed(asig.HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}

	commits := make([]Commitment, 0, 2)
	secrets := make([][]byte, 0, 2)
	for i, id := range ids[:2] {
		scheme, err := NewScheme(id, 2, keys[id].Private, public)
		if err != nil {
			t.Fatal(err)
		}
		commit, secret, err := scheme.Share(id, uint64(i+1), ids)
		if err != nil {
			t.Fatal(err)
		}
		commits = append(commits, commit)
		secrets = append(secrets, secret)
	}

	leader, err := NewScheme("n0", 2, keys["n0"].Private, public)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := leader.Aggregate("n0", 1, commits, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !leader.Verify(aggregate) {
		t.Fatal("valid aggregate commitment did not verify")
	}

	shares := make([]DecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewScheme(id, 2, keys[id].Private, public)
		if err != nil {
			t.Fatal(err)
		}
		share, err := scheme.PreRecon(aggregate, id)
		if err != nil {
			t.Fatal(err)
		}
		if !scheme.VerifyShare(aggregate, share) {
			t.Fatalf("valid aggregate decrypted share from %s did not verify", id)
		}
		shares = append(shares, share)
	}

	recovered, err := leader.Recon(aggregate, shares, 2)
	if err != nil {
		t.Fatal(err)
	}
	group := suite()
	var expected kyber.Point
	for _, raw := range secrets {
		p := group.GT().Point()
		if err := p.UnmarshalBinary(raw); err != nil {
			t.Fatal(err)
		}
		if expected == nil {
			expected = p
		} else {
			expected = group.GT().Point().Add(expected, p)
		}
	}
	expectedBytes, err := expected.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, expectedBytes) {
		t.Fatal("reconstructed aggregate secret differs from sum of dealer secrets")
	}
}

func copyStringMap(in map[p2p.NodeID]string) map[p2p.NodeID]string {
	out := make(map[p2p.NodeID]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
