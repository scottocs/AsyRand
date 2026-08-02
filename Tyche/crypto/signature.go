package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/bits"
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
	Signature      []byte `json:"signature"`
	Algorithm      string `json:"algorithm,omitempty"`
	TranscriptHash string `json:"transcript_hash,omitempty"`
}

type SignedQuorumCertificate struct {
	// SignerBitmap is indexed by lexicographically sorted configuration
	// member IDs. Signatures concatenates one fixed-size Ed25519 signature for
	// each set bit, in bitmap order. Votes and TranscriptHash are retained
	// only to verify certificates persisted by older releases.
	SignerBitmap   []byte       `json:"signer_bitmap,omitempty"`
	Signatures     []byte       `json:"signatures,omitempty"`
	TranscriptHash string       `json:"transcript_hash,omitempty"`
	Votes          []SignedVote `json:"votes,omitempty"`
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
		Signer:    signer,
		Signature: ed25519.Sign(private, digest),
	}, nil
}

func VerifySignedVote(vote SignedVote, publicKeys map[string]ed25519.PublicKey, transcript []byte) error {
	if vote.Algorithm != "" && vote.Algorithm != IdentitySignatureAlgorithm {
		return fmt.Errorf("unsupported signature algorithm %q", vote.Algorithm)
	}
	public := publicKeys[vote.Signer]
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("unknown or invalid public key for signer %q", vote.Signer)
	}
	digest := DomainHash("Tyche/AuthenticatedTranscript/v1", transcript)
	if vote.TranscriptHash != "" && vote.TranscriptHash != hex.EncodeToString(digest) {
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
	return encodeSignedQuorumCertificate(valid, publicKeys, threshold)
}

// EncodeVerifiedSignedQuorumCertificate compacts votes that the caller has
// already authenticated against one identical transcript. It is intended for
// protocol receive paths that verify each vote before storing it; callers must
// not use it on untrusted, unverified votes.
func EncodeVerifiedSignedQuorumCertificate(votes []SignedVote, publicKeys map[string]ed25519.PublicKey, threshold int) (SignedQuorumCertificate, error) {
	if threshold <= 0 {
		return SignedQuorumCertificate{}, errors.New("quorum threshold must be positive")
	}
	valid := make(map[string]SignedVote, len(votes))
	for _, vote := range votes {
		if vote.Signer == "" || len(publicKeys[vote.Signer]) != ed25519.PublicKeySize {
			return SignedQuorumCertificate{}, fmt.Errorf("unknown or invalid verified signer %q", vote.Signer)
		}
		if len(vote.Signature) != ed25519.SignatureSize {
			return SignedQuorumCertificate{}, fmt.Errorf("verified signer %q has an invalid signature length", vote.Signer)
		}
		if _, duplicate := valid[vote.Signer]; duplicate {
			continue
		}
		valid[vote.Signer] = vote
	}
	if len(valid) < threshold {
		return SignedQuorumCertificate{}, fmt.Errorf("not enough verified signed votes: got %d, want %d", len(valid), threshold)
	}
	return encodeSignedQuorumCertificate(valid, publicKeys, threshold)
}

func encodeSignedQuorumCertificate(valid map[string]SignedVote, publicKeys map[string]ed25519.PublicKey, threshold int) (SignedQuorumCertificate, error) {
	members := sortedPublicKeyIDs(publicKeys)
	bitmap := make([]byte, signerBitmapSize(len(members)))
	signatures := make([]byte, 0, threshold*ed25519.SignatureSize)
	selected := 0
	for index, signer := range members {
		vote, ok := valid[signer]
		if !ok {
			continue
		}
		bitmap[index/8] |= byte(1 << uint(index%8))
		signatures = append(signatures, vote.Signature...)
		selected++
		if selected == threshold {
			break
		}
	}
	return SignedQuorumCertificate{
		SignerBitmap: bitmap,
		Signatures:   signatures,
	}, nil
}

func VerifySignedQuorumCertificate(cert SignedQuorumCertificate, publicKeys map[string]ed25519.PublicKey, threshold int, transcript []byte) error {
	if threshold <= 0 {
		return errors.New("quorum threshold must be positive")
	}
	if len(cert.SignerBitmap) > 0 || len(cert.Signatures) > 0 {
		return verifyCompactQuorumCertificate(cert, publicKeys, threshold, transcript)
	}
	return verifyLegacyQuorumCertificate(cert, publicKeys, threshold, transcript)
}

func verifyCompactQuorumCertificate(cert SignedQuorumCertificate, publicKeys map[string]ed25519.PublicKey, threshold int, transcript []byte) error {
	if cert.TranscriptHash != "" || len(cert.Votes) != 0 {
		return errors.New("compact quorum certificate contains legacy fields")
	}
	members := sortedPublicKeyIDs(publicKeys)
	if len(cert.SignerBitmap) != signerBitmapSize(len(members)) {
		return fmt.Errorf("quorum signer bitmap has length %d, want %d", len(cert.SignerBitmap), signerBitmapSize(len(members)))
	}
	if err := validateUnusedSignerBits(cert.SignerBitmap, len(members)); err != nil {
		return err
	}
	count := bitmapPopCount(cert.SignerBitmap)
	if count < threshold {
		return fmt.Errorf("quorum certificate below threshold: got %d, want %d", count, threshold)
	}
	if len(cert.Signatures) != count*ed25519.SignatureSize {
		return fmt.Errorf("quorum signatures have length %d, want %d", len(cert.Signatures), count*ed25519.SignatureSize)
	}
	digest := DomainHash("Tyche/AuthenticatedTranscript/v1", transcript)
	offset := 0
	for index, signer := range members {
		if cert.SignerBitmap[index/8]&(1<<uint(index%8)) == 0 {
			continue
		}
		public := publicKeys[signer]
		if len(public) != ed25519.PublicKeySize {
			return fmt.Errorf("unknown or invalid public key for signer %q", signer)
		}
		signature := cert.Signatures[offset : offset+ed25519.SignatureSize]
		if !ed25519.Verify(public, digest, signature) {
			return fmt.Errorf("invalid compact vote from %q", signer)
		}
		offset += ed25519.SignatureSize
	}
	return nil
}

func verifyLegacyQuorumCertificate(cert SignedQuorumCertificate, publicKeys map[string]ed25519.PublicKey, threshold int, transcript []byte) error {
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

// SignedQuorumCertificateSigners returns the canonical signer list without
// re-verifying signatures. Call VerifySignedQuorumCertificate before using the
// result as authorization evidence.
func SignedQuorumCertificateSigners(cert SignedQuorumCertificate, publicKeys map[string]ed25519.PublicKey) ([]string, error) {
	if len(cert.SignerBitmap) == 0 && len(cert.Signatures) == 0 {
		seen := make(map[string]struct{}, len(cert.Votes))
		signers := make([]string, 0, len(cert.Votes))
		for _, vote := range cert.Votes {
			if _, duplicate := seen[vote.Signer]; duplicate {
				return nil, fmt.Errorf("duplicate quorum signer %q", vote.Signer)
			}
			if _, known := publicKeys[vote.Signer]; !known {
				return nil, fmt.Errorf("unknown quorum signer %q", vote.Signer)
			}
			seen[vote.Signer] = struct{}{}
			signers = append(signers, vote.Signer)
		}
		sort.Strings(signers)
		return signers, nil
	}
	members := sortedPublicKeyIDs(publicKeys)
	if len(cert.SignerBitmap) != signerBitmapSize(len(members)) {
		return nil, fmt.Errorf("quorum signer bitmap has invalid length")
	}
	if err := validateUnusedSignerBits(cert.SignerBitmap, len(members)); err != nil {
		return nil, err
	}
	count := bitmapPopCount(cert.SignerBitmap)
	if len(cert.Signatures) != count*ed25519.SignatureSize {
		return nil, fmt.Errorf("quorum signature count does not match signer bitmap")
	}
	signers := make([]string, 0, count)
	for index, signer := range members {
		if cert.SignerBitmap[index/8]&(1<<uint(index%8)) != 0 {
			signers = append(signers, signer)
		}
	}
	return signers, nil
}

func SignedQuorumCertificateSignerCount(cert SignedQuorumCertificate) int {
	if len(cert.SignerBitmap) > 0 || len(cert.Signatures) > 0 {
		return bitmapPopCount(cert.SignerBitmap)
	}
	return len(cert.Votes)
}

func sortedPublicKeyIDs(publicKeys map[string]ed25519.PublicKey) []string {
	members := make([]string, 0, len(publicKeys))
	for member := range publicKeys {
		members = append(members, member)
	}
	sort.Strings(members)
	return members
}

func signerBitmapSize(memberCount int) int {
	return (memberCount + 7) / 8
}

func bitmapPopCount(bitmap []byte) int {
	count := 0
	for _, value := range bitmap {
		count += bits.OnesCount8(value)
	}
	return count
}

func validateUnusedSignerBits(bitmap []byte, memberCount int) error {
	if memberCount == 0 || len(bitmap) == 0 || memberCount%8 == 0 {
		return nil
	}
	used := uint(memberCount % 8)
	if bitmap[len(bitmap)-1]&^byte((1<<used)-1) != 0 {
		return errors.New("quorum signer bitmap sets an unused member bit")
	}
	return nil
}
