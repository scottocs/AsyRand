package crypto

import (
	"bytes"
	"testing"

	"Tyche/utils/p2p"
)

func TestScrapeDDHVerifyPreReconAndRecon(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	pp, keys, err := ScrapeDDHSetup("scrape-epoch-1", 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !ScrapeDDHSetupVrf(pp) {
		t.Fatal("valid scrape-ddh setup did not verify")
	}
	dealer, err := NewScrapeDDHScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	commit, secret, err := dealer.Share("n0", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dealer.Verify(commit) {
		t.Fatal("valid scrape-ddh commitment did not verify")
	}

	shares := make([]DecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewScrapeDDHScheme(id, keys[id].Private, pp)
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
		t.Fatal("reconstructed scrape-ddh secret differs from dealer secret")
	}
}

func TestScrapeDDHRejectsTamperingAndLowThreshold(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3", "n4"}
	pp, keys, err := ScrapeDDHSetup("scrape-epoch-2", 3, ids)
	if err != nil {
		t.Fatal(err)
	}
	bad := cloneScrapeDDHParams(pp)
	bad.PublicKeys["n3"] = "not-hex"
	if ScrapeDDHSetupVrf(bad) {
		t.Fatal("malformed scrape-ddh setup verified")
	}

	dealer, err := NewScrapeDDHScheme("n0", keys["n0"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	commit, _, err := dealer.Share("n0", 9, nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := commit
	tampered.EncryptedShares = append([]EncodedPoint(nil), commit.EncryptedShares...)
	tampered.EncryptedShares[0] = commit.EncryptedShares[1]
	tampered.SecretID = scrapeDDHCommitmentID(tampered)
	if dealer.Verify(tampered) {
		t.Fatal("tampered scrape-ddh commitment verified")
	}

	shares := make([]DecryptedShare, 0, 2)
	for _, id := range ids[:2] {
		scheme, err := NewScrapeDDHScheme(id, keys[id].Private, pp)
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
		t.Fatal("scrape-ddh reconstruction below threshold succeeded")
	}

	scheme, err := NewScrapeDDHScheme("n2", keys["n2"].Private, pp)
	if err != nil {
		t.Fatal(err)
	}
	share, err := scheme.PreRecon(commit, "n2")
	if err != nil {
		t.Fatal(err)
	}
	share.Value = shares[0].Value
	if dealer.VerifyShare(commit, share) {
		t.Fatal("tampered scrape-ddh reconstruction share verified")
	}
}
