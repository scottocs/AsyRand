package pvss

import (
	"bytes"
	"fmt"
	"testing"

	asig "github.com/scottocs/asyrand/asyrand/internal/crypto"
	"github.com/scottocs/asyrand/asyrand/internal/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
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
	tampered.Proof.STilde = commit.Proof.Challenge
	if dealer.Verify(tampered) {
		t.Fatal("tampered pvss proof verified")
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

func TestInterpolateDegreeBoundedRejectsInconsistentTail(t *testing.T) {
	group := suite()
	threshold := 2
	poly := share.NewPriPoly(group, threshold, group.Scalar().SetInt64(7), group.RandomStream())
	shares := poly.Shares(4)
	shares[3] = &share.PriShare{I: shares[3].I, V: group.Scalar().Add(shares[3].V, group.Scalar().One())}

	if _, ok := interpolateDegreeBounded(group, shares, threshold); ok {
		t.Fatal("degree-bounded interpolation accepted an inconsistent tail share")
	}
}

func BenchmarkPVSSVerify(b *testing.B) {
	for _, n := range []int{4, 8, 16, 32, 64} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			ids := make([]p2p.NodeID, n)
			keys := make(map[p2p.NodeID]KeyPair, n)
			public := make(map[p2p.NodeID]kyber.Point, n)
			for i := range ids {
				id := p2p.NodeID(fmt.Sprintf("n%d", i))
				ids[i] = id
				keys[id] = KeyPairFromSeed(asig.HashBytes([]byte(id)))
				public[id] = keys[id].Public
			}
			threshold := n/3 + 1
			dealer, err := NewScheme(ids[0], threshold, keys[ids[0]].Private, public)
			if err != nil {
				b.Fatal(err)
			}
			commit, _, err := dealer.Share(ids[0], 1, ids)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if !dealer.Verify(commit) {
					b.Fatal("valid pvss commitment did not verify")
				}
			}
		})
	}
}

func BenchmarkInterpolateDegreeBounded(b *testing.B) {
	for _, n := range []int{4, 8, 16, 32, 64} {
		n := n
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			group := suite()
			threshold := n/3 + 1
			poly := share.NewPriPoly(group, threshold, group.Scalar().Pick(group.RandomStream()), group.RandomStream())
			shares := poly.Shares(n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, ok := interpolateDegreeBounded(group, shares, threshold); !ok {
					b.Fatal("valid degree-bounded shares were rejected")
				}
			}
		})
	}
}
