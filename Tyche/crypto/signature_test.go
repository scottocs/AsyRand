package crypto

import (
	"crypto/ed25519"
	"testing"
)

func TestSignedVoteRejectsTamperAndReplay(t *testing.T) {
	key, err := GenerateIdentityKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string][]byte{"n0": key.Public}
	vote, err := SignTranscript("n0", key.Private, []byte("configuration-7/state-a"))
	if err != nil {
		t.Fatal(err)
	}
	public := map[string]ed25519.PublicKey{"n0": keys["n0"]}
	if err := VerifySignedVote(vote, public, []byte("configuration-7/state-a")); err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedVote(vote, public, []byte("configuration-8/state-a")); err == nil {
		t.Fatal("cross-configuration replay was accepted")
	}
	vote.Signature[0] ^= 1
	if err := VerifySignedVote(vote, public, []byte("configuration-7/state-a")); err == nil {
		t.Fatal("tampered signature was accepted")
	}
}

func TestQuorumCertificateCountsDistinctSigners(t *testing.T) {
	transcript := []byte("state transition")
	var votes []SignedVote
	public := make(map[string]ed25519.PublicKey)
	for _, signer := range []string{"n0", "n1", "n2"} {
		key, err := GenerateIdentityKeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		public[signer] = key.Public
		vote, err := SignTranscript(signer, key.Private, transcript)
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	if _, err := BuildSignedQuorumCertificate([]SignedVote{votes[0], votes[0], votes[1]}, public, 3, transcript); err == nil {
		t.Fatal("duplicate signer satisfied quorum")
	}
	cert, err := BuildSignedQuorumCertificate(votes, public, 3, transcript)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedQuorumCertificate(cert, public, 3, transcript); err != nil {
		t.Fatal(err)
	}
}
