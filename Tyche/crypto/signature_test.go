package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
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
	encoded, err := json.Marshal(vote)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "algorithm") || strings.Contains(string(encoded), "transcript_hash") {
		t.Fatalf("new vote repeats fixed transcript metadata: %s", encoded)
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
	if len(cert.SignerBitmap) != 1 || cert.SignerBitmap[0] != 0b111 {
		t.Fatalf("unexpected signer bitmap: %08b", cert.SignerBitmap)
	}
	if len(cert.Signatures) != 3*ed25519.SignatureSize || len(cert.Votes) != 0 || cert.TranscriptHash != "" {
		t.Fatalf("certificate is not compact: %+v", cert)
	}
	signers, err := SignedQuorumCertificateSigners(cert, public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(signers, ",") != "n0,n1,n2" {
		t.Fatalf("unexpected compact signers: %v", signers)
	}

	tampered := cert
	tampered.Signatures = append([]byte(nil), cert.Signatures...)
	tampered.Signatures[0] ^= 1
	if err := VerifySignedQuorumCertificate(tampered, public, 3, transcript); err == nil {
		t.Fatal("tampered compact signature was accepted")
	}
	unusedBit := cert
	unusedBit.SignerBitmap = append([]byte(nil), cert.SignerBitmap...)
	unusedBit.SignerBitmap[0] |= 1 << 7
	if err := VerifySignedQuorumCertificate(unusedBit, public, 3, transcript); err == nil {
		t.Fatal("unused signer bit was accepted")
	}

	legacyHash := hex.EncodeToString(DomainHash("Tyche/AuthenticatedTranscript/v1", transcript))
	legacyVotes := append([]SignedVote(nil), votes...)
	for i := range legacyVotes {
		legacyVotes[i].Algorithm = IdentitySignatureAlgorithm
		legacyVotes[i].TranscriptHash = legacyHash
	}
	legacy := SignedQuorumCertificate{TranscriptHash: legacyHash, Votes: legacyVotes}
	if err := VerifySignedQuorumCertificate(legacy, public, 3, transcript); err != nil {
		t.Fatalf("legacy certificate compatibility failed: %v", err)
	}
	compactJSON, err := json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
	legacyJSON, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if len(compactJSON) >= len(legacyJSON) {
		t.Fatalf("compact certificate did not reduce JSON size: compact=%d legacy=%d", len(compactJSON), len(legacyJSON))
	}
}
