package crypto

import (
	"bytes"
	"fmt"
	"maps"
	"testing"

	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

// Run with TYCHE_CRYPTO_PARALLELISM=1 and =2 in separate processes. The
// distributed benchmark still decides whether the shorter generation path
// improves complete beacon latency under the shared CPU budget.
func BenchmarkPVSSProduction(b *testing.B) {
	for _, n := range []int{16, 31} {
		b.Run(fmt.Sprintf("n%d", n), func(b *testing.B) {
			ids := make([]p2p.NodeID, n)
			keys := make(map[p2p.NodeID]PVSSKeyPair, n)
			public := make(map[p2p.NodeID]kyber.Point, n)
			for i := range ids {
				ids[i] = p2p.NodeID(fmt.Sprintf("node%d", i))
				keys[ids[i]] = PVSSKeyPairFromSeed([]byte(ids[i]))
				public[ids[i]] = keys[ids[i]].Public
			}
			scheme, err := NewPVSSScheme(ids[0], (n-1)/3+1, keys[ids[0]].Private, public)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			var last PVSSCommitment
			for i := 0; i < b.N; i++ {
				cryptoexec.WithCPUGroup(func() { last, _, err = scheme.Share(ids[0], uint64(i+1), ids) })
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if !scheme.Verify(last) {
				b.Fatal("generated commitment failed complete verification")
			}
		})
	}
}

func TestPVSSVerifyPreReconAndRecon(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}
	dealer, err := NewPVSSScheme("n0", 2, keys["n0"].Private, public)
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
	// Every independent partition must reject a bad proof, including the
	// last member rather than only the caller's first partition.
	for _, id := range ids {
		bad := commit
		bad.DLEQ = maps.Clone(commit.DLEQ)
		proof := bad.DLEQ[id]
		proof.Response = "00"
		bad.DLEQ[id] = proof
		bad.SecretID = commitmentID(bad)
		if dealer.Verify(bad) {
			t.Fatalf("invalid DLEQ accepted for member %s", id)
		}
	}

	shares := make([]PVSSDecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewPVSSScheme(id, 2, keys[id].Private, public)
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
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}

	commits := make([]PVSSCommitment, 0, 2)
	secrets := make([][]byte, 0, 2)
	for i, id := range ids[:2] {
		scheme, err := NewPVSSScheme(id, 2, keys[id].Private, public)
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

	leader, err := NewPVSSScheme("n0", 2, keys["n0"].Private, public)
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
	for _, id := range ids {
		bad := aggregate
		bad.Cipher = copyStringMap(aggregate.Cipher)
		bad.Cipher[id] = "00"
		bad.SecretID = commitmentID(bad)
		if leader.Verify(bad) || verifyAggregate(bad) {
			t.Fatalf("invalid aggregate point accepted for member %s", id)
		}
	}
	column := make([]PVSSColumnEntry, 0, len(commits))
	for _, c := range commits {
		column = append(column, PVSSColumnEntry{
			Source: PVSSSource{Dealer: c.Dealer, Seq: c.Seq, SecretID: c.SecretID},
			Commit: c.Commit["n0"],
			Cipher: c.Cipher["n0"],
			Proof:  c.DLEQ["n0"],
		})
	}
	if !leader.VerifyAggregationColumn("n0", aggregate, column) {
		t.Fatal("valid private aggregation column did not verify")
	}
	badColumn := append([]PVSSColumnEntry(nil), column...)
	badColumn[0].Cipher = commits[1].Cipher["n0"]
	if leader.VerifyAggregationColumn("n0", aggregate, badColumn) {
		t.Fatal("tampered private aggregation column verified")
	}

	shares := make([]PVSSDecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewPVSSScheme(id, 2, keys[id].Private, public)
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
