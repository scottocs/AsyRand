package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
)

const IdentitySignatureAlgorithm = "ed25519"

// IdentityKeyPair is independent from a node's PVSS reconstruction key.
type IdentityKeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func GenerateIdentityKeyPair(reader io.Reader) (IdentityKeyPair, error) {
	if reader == nil {
		reader = rand.Reader
	}
	public, private, err := ed25519.GenerateKey(reader)
	if err != nil {
		return IdentityKeyPair{}, err
	}
	return IdentityKeyPair{
		Public:  append(ed25519.PublicKey(nil), public...),
		Private: append(ed25519.PrivateKey(nil), private...),
	}, nil
}

// IdentityKeyPairFromSeed is intended for deterministic tests and reproducible
// experiments. Production deployments must load an independently generated
// secret seed from protected configuration.
func IdentityKeyPairFromSeed(seed []byte) (IdentityKeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return IdentityKeyPair{}, fmt.Errorf("ed25519 seed has length %d, want %d", len(seed), ed25519.SeedSize)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return IdentityKeyPair{
		Public:  append(ed25519.PublicKey(nil), public...),
		Private: append(ed25519.PrivateKey(nil), private...),
	}, nil
}

type SignedVote struct {
	Signer         string `json:"signer"`
	Algorithm      string `json:"algorithm"`
	TranscriptHash string `json:"transcript_hash"`
	Signature      []byte `json:"signature"`
}

type SignedQuorumCertificate struct {
	TranscriptHash string       `json:"transcript_hash"`
	Votes          []SignedVote `json:"votes"`
}

func SignTranscript(signer string, private ed25519.PrivateKey, transcript []byte) (SignedVote, error) {
	if signer == "" {
		return SignedVote{}, errors.New("empty vote signer")
	}
	if len(private) != ed25519.PrivateKeySize {
		return SignedVote{}, errors.New("invalid ed25519 private key")
	}
	digest := DomainHash("Tyche/AuthenticatedTranscript/v1", transcript)
	return SignedVote{
		Signer:         signer,
		Algorithm:      IdentitySignatureAlgorithm,
		TranscriptHash: hex.EncodeToString(digest),
		Signature:      ed25519.Sign(private, digest),
	}, nil
}

func VerifySignedVote(vote SignedVote, publicKeys map[string]ed25519.PublicKey, transcript []byte) error {
	if vote.Algorithm != IdentitySignatureAlgorithm {
		return fmt.Errorf("unsupported signature algorithm %q", vote.Algorithm)
	}
	public := publicKeys[vote.Signer]
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("unknown or invalid public key for signer %q", vote.Signer)
	}
	digest := DomainHash("Tyche/AuthenticatedTranscript/v1", transcript)
	if vote.TranscriptHash != hex.EncodeToString(digest) {
		return errors.New("vote transcript hash mismatch")
	}
	if !ed25519.Verify(public, digest, vote.Signature) {
		return errors.New("invalid vote signature")
	}
	return nil
}

func BuildSignedQuorumCertificate(votes []SignedVote, publicKeys map[string]ed25519.PublicKey, threshold int, transcript []byte) (SignedQuorumCertificate, error) {
	if threshold <= 0 {
		return SignedQuorumCertificate{}, errors.New("quorum threshold must be positive")
	}
	valid := make(map[string]SignedVote, len(votes))
	for _, vote := range votes {
		if _, duplicate := valid[vote.Signer]; duplicate {
			continue
		}
		if err := VerifySignedVote(vote, publicKeys, transcript); err != nil {
			continue
		}
		valid[vote.Signer] = vote
	}
	if len(valid) < threshold {
		return SignedQuorumCertificate{}, fmt.Errorf("not enough valid signed votes: got %d, want %d", len(valid), threshold)
	}
	signers := make([]string, 0, len(valid))
	for signer := range valid {
		signers = append(signers, signer)
	}
	sort.Strings(signers)
	selected := make([]SignedVote, 0, threshold)
	for _, signer := range signers[:threshold] {
		selected = append(selected, valid[signer])
	}
	return SignedQuorumCertificate{
		TranscriptHash: selected[0].TranscriptHash,
		Votes:          selected,
	}, nil
}

func VerifySignedQuorumCertificate(cert SignedQuorumCertificate, publicKeys map[string]ed25519.PublicKey, threshold int, transcript []byte) error {
	if threshold <= 0 {
		return errors.New("quorum threshold must be positive")
	}
	if len(cert.Votes) < threshold {
		return fmt.Errorf("quorum certificate below threshold: got %d, want %d", len(cert.Votes), threshold)
	}
	expected := hex.EncodeToString(DomainHash("Tyche/AuthenticatedTranscript/v1", transcript))
	if cert.TranscriptHash != expected {
		return errors.New("certificate transcript hash mismatch")
	}
	seen := make(map[string]struct{}, len(cert.Votes))
	for _, vote := range cert.Votes {
		if _, duplicate := seen[vote.Signer]; duplicate {
			return fmt.Errorf("duplicate quorum signer %q", vote.Signer)
		}
		seen[vote.Signer] = struct{}{}
		if err := VerifySignedVote(vote, publicKeys, transcript); err != nil {
			return fmt.Errorf("invalid vote from %q: %w", vote.Signer, err)
		}
	}
	return nil
}
