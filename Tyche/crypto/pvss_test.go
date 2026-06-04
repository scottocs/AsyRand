package crypto

import (
	"bytes"
	"sync"
	"testing"

	"github.com/scottocs/Tyche/utils/p2p"
)

func TestSilentSetupPVSSVerifyPreReconAndRecon(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := Setup("epoch-1", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	setupVrfCache = sync.Map{}
	if !SetupVrf(pp) {
		t.Fatal("valid silent setup did not verify")
	}
	dealer, err := NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	commit, secret, err := dealer.Share("n0", 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dealer.Verify(commit) {
		t.Fatal("valid constant-online pvss object did not verify")
	}

	tampered := commit
	tampered.C2 = commit.C1[0].Value
	tampered.SecretID = commitmentID(tampered)
	if dealer.Verify(tampered) {
		t.Fatal("tampered pvss object verified")
	}
	for i, c1 := range commit.C1 {
		wantGroup := "G2"
		if i < 2 {
			wantGroup = "G1"
		}
		if c1.Group != wantGroup || c1.Value == "" {
			t.Fatalf("unexpected C1 encoding at column %d: %+v", i, c1)
		}
	}

	shares := make([]DecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		share, err := scheme.PreRecon(commit, id)
		if err != nil {
			t.Fatal(err)
		}
		if !dealer.VerifyShare(commit, share) {
			t.Fatalf("valid decrypted share from %s did not verify", id)
		}
		shares = append(shares, share)
	}
	recovered, err := dealer.Recon(commit, shares)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("reconstructed PVSS secret differs from dealer secret")
	}
}

func TestSilentSetupRejectsBadSetupAndShares(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3", "n4"}
	pp, keys, err := Setup("epoch-2", 3, ids)
	if err != nil {
		t.Fatal(err)
	}
	bad := cloneParams(pp)
	bad.KeyShares["n3"] = bad.KeyShares["n0"]
	if SetupVrf(bad) {
		t.Fatal("malformed setup verified")
	}
	bad = cloneParams(pp)
	k := bad.RealKeys["n2"]
	k.H2 = bad.RealKeys["n1"].H2
	bad.RealKeys["n2"] = k
	if SetupVrf(bad) {
		t.Fatal("malformed setup hint H2 verified")
	}
	bad = cloneParams(pp)
	k = bad.RealKeys["n2"]
	k.H5["n4"] = bad.RealKeys["n1"].H5["n4"]
	bad.RealKeys["n2"] = k
	if SetupVrf(bad) {
		t.Fatal("malformed setup hint H5 verified")
	}

	dealer, err := NewScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	commit, _, err := dealer.Share("n0", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	shares := make([]DecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewScheme(id, keys[id].Private, pp)
		if err != nil {
			t.Fatal(err)
		}
		share, err := scheme.PreRecon(commit, id)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, share)
	}
	if _, err := dealer.Recon(commit, shares); err == nil {
		t.Fatal("reconstruction below threshold succeeded")
	}

	scheme, err := NewScheme("n2", keys["n2"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	share, err := scheme.PreRecon(commit, "n2")
	if err != nil {
		t.Fatal(err)
	}
	share.Value = shares[0].Value
	if dealer.VerifyShare(commit, share) {
		t.Fatal("tampered reconstruction share verified")
	}
}
