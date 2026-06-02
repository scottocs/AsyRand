package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestAggregateSignatureVerify(t *testing.T) {
	msg := []byte("asyrand beacon certificate")
	pubs := make(map[string]ed25519.PublicKey)
	agg := NewAggregateSignature()

	for _, id := range []string{"n0", "n1", "n2"} {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		pubs[id] = kp.Public
		agg.Add(id, Sign(kp.Private, msg))
	}

	if err := agg.Verify(msg, pubs, 2); err != nil {
		t.Fatalf("aggregate signature should verify: %v", err)
	}
	if err := agg.Verify([]byte("other message"), pubs, 2); err == nil {
		t.Fatal("aggregate signature verified for a different message")
	}
}

func TestQuorumCertificateVerify(t *testing.T) {
	members := map[string]struct{}{"n0": {}, "n1": {}, "n2": {}}
	shares := make([]VoteShare, 0, len(members))
	for id := range members {
		share, err := NewVoteShare(id)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, share)
	}
	cert, err := BuildQuorumCertificate(shares, members, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyQuorumCertificate(cert, members, 2); err != nil {
		t.Fatalf("quorum certificate should verify: %v", err)
	}
	if err := VerifyQuorumCertificate(cert, members, 4); err == nil {
		t.Fatal("quorum certificate verified below threshold")
	}
	cert.Signers = append(cert.Signers, "unknown")
	if err := VerifyQuorumCertificate(cert, members, 2); err == nil {
		t.Fatal("quorum certificate verified with an unknown signer")
	}
}
