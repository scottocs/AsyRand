package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"unicode/utf8"

	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/share"
)

const pvssVersion = "AsyRand-v1/SCRAPE-DDH/edwards25519"
const pvssPointCacheLimit = 4096

// Independently map public labels to curve points and clear the cofactor.
// Do NOT derive h as Hash(label)*g: that would publish log_g(h).
var pvssGeneratorG = suite().Point().Pick(suite().XOF([]byte(pvssVersion + "/generator/g")))
var pvssGeneratorH = suite().Point().Pick(suite().XOF([]byte(pvssVersion + "/generator/h")))

// Little-endian order of the prime-order Edwards25519 subgroup.
var pvssGroupOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
}

type PVSSKeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

type PVSSCommitment struct {
	Version   string       `json:"version"`
	SetupID   string       `json:"setup_id"`
	Dealer    p2p.NodeID   `json:"dealer"`
	Seq       uint64       `json:"seq"`
	Threshold int          `json:"threshold"`
	Members   []p2p.NodeID `json:"members"`
	// SCRAPE: g^F(alpha_i). ALBATROSS: LDEI nonce commitments pk_i^F'(alpha_i).
	// Version selects the proof relation; these fields are not interchangeable.
	Commit   map[p2p.NodeID]string `json:"commit"`
	Cipher   map[p2p.NodeID]string `json:"cipher"`
	Proof    PVSSProof             `json:"proof"`
	SecretID string                `json:"secret_id"`
	// Deprecated SPURT fields: source compatibility only. Verify rejects their
	// use because AsyRand reconstructs individual dealer objects.
	DLEQ      map[p2p.NodeID]DLEQProof `json:"dleq,omitempty"`
	Aggregate bool                     `json:"aggregate,omitempty"`
	Sources   []PVSSSource             `json:"sources,omitempty"`
}

// SCRAPE uses Responses for its batched DLEQ proof. ALBATROSS uses exactly t
// Coefficients for the response polynomial F'+cF, in increasing degree order.
// In both schemes one challenge binds the complete statement and context.
type PVSSProof struct {
	Challenge    string                `json:"challenge"`
	Responses    map[p2p.NodeID]string `json:"responses"`
	Coefficients []string              `json:"coefficients,omitempty"`
}

// Deprecated SPURT types, retained while the upper-layer protocol is migrated.
type PVSSSource struct {
	Dealer   p2p.NodeID `json:"dealer"`
	Seq      uint64     `json:"seq"`
	SecretID string     `json:"secret_id"`
}

type DLEQProof struct {
	A         string `json:"a"`
	B         string `json:"b"`
	Challenge string `json:"challenge"`
	Response  string `json:"response"`
}

type PVSSColumnEntry struct {
	Source PVSSSource `json:"source"`
	Commit string     `json:"commit"`
	Cipher string     `json:"cipher"`
	Proof  DLEQProof  `json:"proof"`
}

// Chaum-Pedersen proof of log_h(pk_i)=log_d_i(cipher_i).
// SCRAPE uses compact (C,R); ALBATROSS uses the paper's expanded (A,B,R)
// and recomputes the challenge. R is w-challenge*x_i in both schemes.
type PVSSDecryptionProof struct {
	C string `json:"c,omitempty"`
	R string `json:"r"`
	A string `json:"a,omitempty"`
	B string `json:"b,omitempty"`
}

type PVSSDecryptedShare struct {
	CommitmentID string              `json:"commitment_id"`
	Holder       p2p.NodeID          `json:"holder"`
	Value        string              `json:"value"`
	Proof        PVSSDecryptionProof `json:"proof"`
}

type PVSSScheme interface {
	Share(p2p.NodeID, uint64, []p2p.NodeID) (PVSSCommitment, []byte, error)
	Verify(PVSSCommitment) bool
	Aggregate(p2p.NodeID, uint64, []PVSSCommitment, []p2p.NodeID) (PVSSCommitment, error)
	AggregateTrusted(p2p.NodeID, uint64, []PVSSCommitment, []p2p.NodeID) (PVSSCommitment, error)
	PreRecon(PVSSCommitment, p2p.NodeID) (PVSSDecryptedShare, error)
	PreReconTrusted(PVSSCommitment, p2p.NodeID) (PVSSDecryptedShare, error)
	VerifyShare(PVSSCommitment, PVSSDecryptedShare) bool
	Recon(PVSSCommitment, []PVSSDecryptedShare, int) ([]byte, error)
	ReconTrusted(PVSSCommitment, []PVSSDecryptedShare, int) ([]byte, error)
	VerifyAggregationColumn(p2p.NodeID, PVSSCommitment, []PVSSColumnEntry) bool
}

// PVSSPairingFreeScheme implements contextual SCRAPE-DDH or single-secret
// ALBATROSS, selected by its constructor. Both reconstruct h^s, not s, and use
// the same subgroup and shareholder keys, with DLEQ decryption proofs.
type PVSSPairingFreeScheme struct {
	checks         *verification.Cache
	version        string
	id             p2p.NodeID
	threshold      int
	private        kyber.Scalar
	public         map[p2p.NodeID]kyber.Point
	members        []p2p.NodeID
	index          map[p2p.NodeID]int
	g, h           kyber.Point
	setupID        string
	cacheMu        sync.RWMutex
	points         map[string]kyber.Point
	pointKeys      []string
	pointNext      int
	verifiedShares map[string]struct{}
	shareKeys      []string
	shareNext      int
}

func suite() *edwards25519.SuiteEd25519 {
	return edwards25519.NewBlakeSHA256Ed25519()
}

// SetupID is the immutable fingerprint of pp, threshold and shareholder keys.
func (s *PVSSPairingFreeScheme) SetupID() string { return s.setupID }

// GeneratePVSSKeyPair samples a nonzero secret key using crypto/rand.
func GeneratePVSSKeyPair() (PVSSKeyPair, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return PVSSKeyPair{}, err
	}
	return PVSSKeyPairFromSeed(seed), nil
}

// PVSSKeyPairFromSeed is deterministic. Seeds must be private and have enough
// entropy; public node identifiers are suitable only for tests.
func PVSSKeyPairFromSeed(seed []byte) PVSSKeyPair {
	group := suite()
	stream := group.XOF(pvssHash(pvssVersion+"/key", seed))
	var sk kyber.Scalar
	for {
		sk = group.Scalar().Pick(stream)
		if !sk.Equal(group.Scalar().Zero()) {
			break
		}
	}
	return PVSSKeyPair{Private: sk, Public: group.Point().Mul(sk, pvssGeneratorH)}
}

func NewPVSSScheme(id p2p.NodeID, threshold int, private kyber.Scalar, public map[p2p.NodeID]kyber.Point, caches ...*verification.Cache) (*PVSSPairingFreeScheme, error) {
	return newPVSSScheme(pvssVersion, id, threshold, private, public, caches...)
}

func newPVSSScheme(version string, id p2p.NodeID, threshold int, private kyber.Scalar, public map[p2p.NodeID]kyber.Point, caches ...*verification.Cache) (*PVSSPairingFreeScheme, error) {
	if id == "" || private == nil {
		return nil, errors.New("invalid PVSS identity, threshold or private key")
	}
	privateBytes, err := private.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := scalarFromHex(hex.EncodeToString(privateBytes))
	if sk == nil || sk.Equal(suite().Scalar().Zero()) {
		return nil, errors.New("PVSS private key must be a canonical nonzero scalar")
	}
	s, err := newPVSSVerifier(version, threshold, public, caches...)
	if err != nil {
		return nil, err
	}
	pub := s.public[id]
	if pub == nil || !suite().Point().Mul(sk, s.h).Equal(pub) {
		return nil, errors.New("PVSS private key does not match the local shareholder public key")
	}
	s.id, s.private = id, sk
	return s, nil
}

// NewPVSSVerifier creates a public-only verifier. It can verify transcripts,
// verify published decryption shares and reconstruct Z without any secret key.
// Share and PreRecon are unavailable on this instance.
func NewPVSSVerifier(threshold int, public map[p2p.NodeID]kyber.Point, caches ...*verification.Cache) (*PVSSPairingFreeScheme, error) {
	return newPVSSVerifier(pvssVersion, threshold, public, caches...)
}

func newPVSSVerifier(version string, threshold int, public map[p2p.NodeID]kyber.Point, caches ...*verification.Cache) (*PVSSPairingFreeScheme, error) {
	if threshold <= 0 || threshold > len(public) {
		return nil, errors.New("invalid PVSS threshold or empty shareholder key set")
	}
	s := &PVSSPairingFreeScheme{
		checks:    verification.Select(caches...),
		version:   version,
		threshold: threshold,
		public:    make(map[p2p.NodeID]kyber.Point, len(public)),
		index:     make(map[p2p.NodeID]int, len(public)),
		g:         pvssGeneratorG.Clone(), h: pvssGeneratorH.Clone(),
		points: make(map[string]kyber.Point), verifiedShares: make(map[string]struct{}),
	}
	for member, pub := range public {
		if member == "" || !utf8.ValidString(string(member)) || pub == nil {
			return nil, errors.New("missing PVSS shareholder identity or public key")
		}
		raw, err := pub.MarshalBinary()
		if err != nil {
			return nil, err
		}
		p, err := pointFromHex(hex.EncodeToString(raw))
		if err != nil || p.Equal(suite().Point().Null()) {
			return nil, fmt.Errorf("invalid PVSS public key for %s", member)
		}
		s.public[member] = p
		s.members = append(s.members, member)
	}
	s.members = normalizeMembers(s.members)
	type shareholder struct {
		ID    p2p.NodeID
		Alpha int
		Key   string
	}
	keys := make([]shareholder, len(s.members))
	for i, member := range s.members {
		s.index[member] = i
		keys[i] = shareholder{member, i + 1, mustPointHex(s.public[member])}
	}
	// Bind pp, the threshold, evaluation points and all ordered public keys.
	s.setupID = hex.EncodeToString(pvssHash(version+"/setup", pvssEncode(struct {
		G, H, Order         string
		Cofactor, Threshold int
		Keys                []shareholder
	}{mustPointHex(s.g), mustPointHex(s.h), hex.EncodeToString(pvssGroupOrder[:]), 8, threshold, keys})))
	return s, nil
}

func (s *PVSSPairingFreeScheme) Share(dealer p2p.NodeID, seq uint64, members []p2p.NodeID) (PVSSCommitment, []byte, error) {
	if s.private == nil || dealer != s.id || seq == 0 || !s.sameMembers(normalizeMembers(members)) {
		return PVSSCommitment{}, nil, errors.New("PVSS sharing requires the local dealer, a positive sequence and the fixed membership")
	}
	if s.version == albatrossPVSSVersion {
		return s.shareALBATROSS(dealer, seq)
	}
	group := suite()
	secret := group.Scalar().Pick(group.RandomStream())
	poly := share.NewPriPoly(group, s.threshold, secret, group.RandomStream())
	shares := poly.Shares(len(s.members)) // alpha_i=i+1, alpha_0=0.
	c := PVSSCommitment{
		Version: pvssVersion, SetupID: s.setupID, Dealer: dealer, Seq: seq,
		Threshold: s.threshold, Members: append([]p2p.NodeID(nil), s.members...),
		Commit: make(map[p2p.NodeID]string, len(s.members)),
		Cipher: make(map[p2p.NodeID]string, len(s.members)),
	}
	witnesses := make([]kyber.Scalar, len(s.members))
	for i, member := range s.members {
		witnesses[i] = shares[i].V
		commit := group.Point().Mul(shares[i].V, s.g)
		cipher := group.Point().Mul(shares[i].V, s.public[member])
		c.Commit[member] = mustPointHex(commit)
		c.Cipher[member] = mustPointHex(cipher)
		// Generated points are already in the prime-order subgroup. Retain the
		// same immutable encodings instead of parsing and checking them again.
		s.cachePoint(c.Commit[member], commit)
		s.cachePoint(c.Cipher[member], cipher)
	}
	c.Proof = s.proveSharing(c, witnesses)
	c.SecretID = commitmentID(c)
	return c, mustPointBytes(group.Point().Mul(secret, s.h)), nil
}

func (s *PVSSPairingFreeScheme) proveSharing(c PVSSCommitment, witnesses []kyber.Scalar) PVSSProof {
	group := suite()
	nonces := make([]kyber.Scalar, len(s.members))
	a, b := make([]kyber.Point, len(s.members)), make([]kyber.Point, len(s.members))
	for i, member := range s.members {
		nonces[i] = group.Scalar().Pick(group.RandomStream())
		a[i] = group.Point().Mul(nonces[i], s.g)
		b[i] = group.Point().Mul(nonces[i], s.public[member])
	}
	epsilon := sharingChallenge(c, a, b)
	proof := PVSSProof{Challenge: scalarHex(epsilon), Responses: make(map[p2p.NodeID]string, len(s.members))}
	for i, member := range s.members {
		proof.Responses[member] = scalarHex(group.Scalar().Sub(nonces[i], group.Scalar().Mul(epsilon, witnesses[i])))
	}
	return proof
}

func (s *PVSSPairingFreeScheme) VerificationCache() *verification.Cache { return s.checks }
func (s *PVSSPairingFreeScheme) Verify(c PVSSCommitment) bool {
	return s.checks.Check(verification.JSONKey("asyrand/pvss-sharing", s.setupID, c), func() bool { return s.verifySharingUncached(c) })
}
func (s *PVSSPairingFreeScheme) verifySharingUncached(c PVSSCommitment) bool {
	if s.version == albatrossPVSSVersion {
		return s.verifyALBATROSS(c)
	}
	if !s.validHeader(c) {
		return false
	}
	group := suite()
	epsilon := scalarFromHex(c.Proof.Challenge)
	if epsilon == nil {
		return false
	}
	a, b := make([]kyber.Point, len(s.members)), make([]kyber.Point, len(s.members))
	v := make([]kyber.Point, len(s.members))
	for i, member := range s.members {
		var err error
		v[i], err = s.pointFromHex(c.Commit[member])
		if err != nil {
			return false
		}
		cipher, err := s.pointFromHex(c.Cipher[member])
		if err != nil {
			return false
		}
		z := scalarFromHex(c.Proof.Responses[member])
		if z == nil {
			return false
		}
		a[i] = group.Point().Add(group.Point().Mul(z, s.g), group.Point().Mul(epsilon, v[i]))
		b[i] = group.Point().Add(group.Point().Mul(z, s.public[member]), group.Point().Mul(epsilon, cipher))
	}
	if !sharingChallenge(c, a, b).Equal(epsilon) {
		return false
	}
	weights := dualCodeWord(c)
	acc := group.Point().Null()
	for i := range v {
		acc.Add(acc, group.Point().Mul(weights[i], v[i]))
	}
	return acc.Equal(group.Point().Null())
}

func (s *PVSSPairingFreeScheme) PreRecon(c PVSSCommitment, holder p2p.NodeID) (PVSSDecryptedShare, error) {
	if !s.Verify(c) {
		return PVSSDecryptedShare{}, errors.New("invalid PVSS sharing transcript")
	}
	return s.PreReconTrusted(c, holder)
}

// PreReconTrusted omits the scheme's sharing proof checks. The caller MUST have
// verified this exact transcript and must not mutate it afterwards.
func (s *PVSSPairingFreeScheme) PreReconTrusted(c PVSSCommitment, holder p2p.NodeID) (PVSSDecryptedShare, error) {
	if s.private == nil || holder != s.id || !s.validHeader(c) {
		return PVSSDecryptedShare{}, errors.New("invalid PVSS transcript or local share holder")
	}
	cipher, err := s.pointFromHex(c.Cipher[holder])
	if err != nil {
		return PVSSDecryptedShare{}, err
	}
	group := suite()
	d := group.Point().Mul(group.Scalar().Inv(s.private), cipher)
	w := group.Scalar().Pick(group.RandomStream())
	a := group.Point().Mul(w, s.h)
	b := group.Point().Mul(w, d)
	epsilon := s.decryptionChallenge(c, holder, d, cipher, a, b)
	z := group.Scalar().Sub(w, group.Scalar().Mul(epsilon, s.private))
	sh := PVSSDecryptedShare{
		CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(d),
		Proof: PVSSDecryptionProof{C: scalarHex(epsilon), R: scalarHex(z)},
	}
	if s.version == albatrossPVSSVersion {
		sh.Proof = PVSSDecryptionProof{A: mustPointHex(a), B: mustPointHex(b), R: scalarHex(z)}
		s.cachePoint(sh.Proof.A, a)
		s.cachePoint(sh.Proof.B, b)
	}
	s.cachePoint(sh.Value, d)
	// The local proof was generated with the matching private key. Cache the
	// exact object/share binding, just as after successful VerifyShare.
	s.cacheShare(c, sh)
	return sh, nil
}

// VerifyShare checks a reconstruction share against its object. As in the
// paper's VerifyKey interface, the sharing transcript is validated separately.
func (s *PVSSPairingFreeScheme) VerifyShare(c PVSSCommitment, sh PVSSDecryptedShare) bool {
	valid := s.checks.Check(verification.JSONKey("asyrand/pvss-share", s.setupID, c, sh), func() bool { return s.verifyShareUncached(c, sh) })
	if valid {
		// Refill the bounded decoding-era memo without repeating a proof check.
		s.cacheMu.Lock()
		cacheInsert(s.verifiedShares, &s.shareKeys, &s.shareNext, shareVerificationKey(c, sh), struct{}{})
		s.cacheMu.Unlock()
	}
	return valid
}
func (s *PVSSPairingFreeScheme) verifyShareUncached(c PVSSCommitment, sh PVSSDecryptedShare) bool {
	if !s.validHeader(c) || sh.CommitmentID != c.SecretID || s.public[sh.Holder] == nil {
		return false
	}
	key := shareVerificationKey(c, sh)
	s.cacheMu.RLock()
	_, verified := s.verifiedShares[key]
	s.cacheMu.RUnlock()
	if verified {
		return true
	}
	d, err := s.pointFromHex(sh.Value)
	if err != nil {
		return false
	}
	cipher, err := s.pointFromHex(c.Cipher[sh.Holder])
	if err != nil {
		return false
	}
	z := scalarFromHex(sh.Proof.R)
	if z == nil {
		return false
	}
	group := suite()
	if s.version == albatrossPVSSVersion {
		if sh.Proof.C != "" {
			return false
		}
		a, err := s.pointFromHex(sh.Proof.A)
		if err != nil {
			return false
		}
		b, err := s.pointFromHex(sh.Proof.B)
		if err != nil {
			return false
		}
		epsilon := s.decryptionChallenge(c, sh.Holder, d, cipher, a, b)
		wantA := group.Point().Add(group.Point().Mul(z, s.h), group.Point().Mul(epsilon, s.public[sh.Holder]))
		wantB := group.Point().Add(group.Point().Mul(z, d), group.Point().Mul(epsilon, cipher))
		if !wantA.Equal(a) || !wantB.Equal(b) {
			return false
		}
	} else {
		epsilon := scalarFromHex(sh.Proof.C)
		if epsilon == nil || sh.Proof.A != "" || sh.Proof.B != "" {
			return false
		}
		a := group.Point().Add(group.Point().Mul(z, s.h), group.Point().Mul(epsilon, s.public[sh.Holder]))
		b := group.Point().Add(group.Point().Mul(z, d), group.Point().Mul(epsilon, cipher))
		if !s.decryptionChallenge(c, sh.Holder, d, cipher, a, b).Equal(epsilon) {
			return false
		}
	}
	s.cacheMu.Lock()
	cacheInsert(s.verifiedShares, &s.shareKeys, &s.shareNext, key, struct{}{})
	s.cacheMu.Unlock()
	return true
}

// validHeader must precede a lookup: SecretID binds the complete transcript,
// and the key additionally binds every share field, including holder and proof.
// A verifier owns one immutable setup, so successes cannot cross key sets.
func shareVerificationKey(c PVSSCommitment, sh PVSSDecryptedShare) string {
	return hex.EncodeToString(pvssHash(c.Version+"/verified-share", []byte(c.SecretID), pvssEncode(sh)))
}
func (s *PVSSPairingFreeScheme) cacheShare(c PVSSCommitment, sh PVSSDecryptedShare) {
	s.checks.Check(verification.JSONKey("asyrand/pvss-share", s.setupID, c, sh), func() bool { return true })
	key := shareVerificationKey(c, sh)
	s.cacheMu.Lock()
	cacheInsert(s.verifiedShares, &s.shareKeys, &s.shareNext, key, struct{}{})
	s.cacheMu.Unlock()
}

func (s *PVSSPairingFreeScheme) Recon(c PVSSCommitment, shares []PVSSDecryptedShare, threshold int) ([]byte, error) {
	if !s.Verify(c) {
		return nil, errors.New("invalid PVSS sharing transcript")
	}
	return s.ReconTrusted(c, shares, threshold)
}

// ReconTrusted omits sharing verification but still verifies every share used
// for interpolation. The same verified-transcript precondition applies here.
func (s *PVSSPairingFreeScheme) ReconTrusted(c PVSSCommitment, shares []PVSSDecryptedShare, threshold int) ([]byte, error) {
	if threshold == 0 {
		threshold = s.threshold
	}
	if threshold != s.threshold || !s.validHeader(c) {
		return nil, errors.New("PVSS transcript or reconstruction threshold mismatch")
	}
	seen := make(map[p2p.NodeID]bool, threshold)
	pubShares := make([]*share.PubShare, 0, threshold)
	for _, sh := range shares {
		if seen[sh.Holder] || !s.VerifyShare(c, sh) {
			continue
		}
		plain, _ := s.pointFromHex(sh.Value) // Already parsed by VerifyShare.
		seen[sh.Holder] = true
		pubShares = append(pubShares, &share.PubShare{I: s.index[sh.Holder], V: plain})
		if len(pubShares) == threshold {
			break
		}
	}
	if len(pubShares) < threshold {
		return nil, errors.New("not enough distinct valid PVSS decryption shares")
	}
	secret, err := share.RecoverCommit(suite(), pubShares, threshold, len(s.members))
	if err != nil {
		return nil, err
	}
	return secret.MarshalBinary() // Canonical Encode(Z), Z=h^s in G.
}

var ErrPVSSAggregationUnsupported = errors.New("AsyRand PVSS reconstructs individual objects; SPURT aggregation is unsupported")

func (s *PVSSPairingFreeScheme) Aggregate(p2p.NodeID, uint64, []PVSSCommitment, []p2p.NodeID) (PVSSCommitment, error) {
	return PVSSCommitment{}, ErrPVSSAggregationUnsupported
}

func (s *PVSSPairingFreeScheme) AggregateTrusted(p2p.NodeID, uint64, []PVSSCommitment, []p2p.NodeID) (PVSSCommitment, error) {
	return PVSSCommitment{}, ErrPVSSAggregationUnsupported
}

func (s *PVSSPairingFreeScheme) VerifyAggregationColumn(p2p.NodeID, PVSSCommitment, []PVSSColumnEntry) bool {
	return false
}

func CommitmentID(c PVSSCommitment) string { return c.SecretID }

func commitmentID(c PVSSCommitment) string {
	c.SecretID = ""
	return hex.EncodeToString(pvssHash(c.Version+"/object-id", pvssEncode(c)))
}

func (s *PVSSPairingFreeScheme) sameMembers(members []p2p.NodeID) bool {
	if len(members) != len(s.members) {
		return false
	}
	for i, member := range members {
		if member != s.members[i] {
			return false
		}
	}
	return true
}

func (s *PVSSPairingFreeScheme) validHeader(c PVSSCommitment) bool {
	n := len(s.members)
	if c.Version != s.version || c.SetupID != s.setupID || c.Seq == 0 || s.public[c.Dealer] == nil ||
		c.Threshold != s.threshold || !s.sameMembers(c.Members) || c.Aggregate || len(c.Sources) != 0 || len(c.DLEQ) != 0 ||
		len(c.Commit) != n || len(c.Cipher) != n || len(c.Proof.Challenge) != 64 || len(c.SecretID) != 64 {
		return false
	}
	if s.version == albatrossPVSSVersion {
		if len(c.Proof.Responses) != 0 || len(c.Proof.Coefficients) != s.threshold {
			return false
		}
		for _, coefficient := range c.Proof.Coefficients {
			if len(coefficient) != 64 {
				return false
			}
		}
	} else if len(c.Proof.Responses) != n || len(c.Proof.Coefficients) != 0 {
		return false
	}
	for _, member := range s.members {
		if len(c.Commit[member]) != 64 || len(c.Cipher[member]) != 64 ||
			(s.version != albatrossPVSSVersion && len(c.Proof.Responses[member]) != 64) {
			return false
		}
	}
	return commitmentID(c) == c.SecretID
}

func normalizeMembers(members []p2p.NodeID) []p2p.NodeID {
	out := append([]p2p.NodeID(nil), members...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Encode chi and C without pi or SecretID to avoid circular proof challenges.
// SetupID commits to pp, ordered keys, threshold and evaluation points.
func objectBytes(c PVSSCommitment) []byte {
	return pvssEncode(struct {
		Version, SetupID string
		Dealer           p2p.NodeID
		Seq              uint64
		Threshold        int
		Members          []p2p.NodeID
		Commit, Cipher   map[p2p.NodeID]string
	}{c.Version, c.SetupID, c.Dealer, c.Seq, c.Threshold, c.Members, c.Commit, c.Cipher})
}

func sharingChallenge(c PVSSCommitment, a, b []kyber.Point) kyber.Scalar {
	commitments := make([][2]string, len(a))
	for i := range a {
		commitments[i] = [2]string{mustPointHex(a[i]), mustPointHex(b[i])}
	}
	return oracleScalar(pvssVersion+"/share-dleq", objectBytes(c), pvssEncode(commitments))
}

func (s *PVSSPairingFreeScheme) decryptionChallenge(c PVSSCommitment, holder p2p.NodeID, d, cipher, a, b kyber.Point) kyber.Scalar {
	statement := []string{string(holder), mustPointHex(s.h), mustPointHex(s.public[holder]), mustPointHex(d), mustPointHex(cipher), mustPointHex(a), mustPointHex(b)}
	return oracleScalar(s.version+"/decrypt-dleq", objectBytes(c), []byte(c.SecretID), pvssEncode(statement))
}

// Uniformly sample n-t field coefficients defining q(X) of degree < n-t.
// y_i=q(alpha_i)/product_{j!=i}(alpha_i-alpha_j) is a uniform dual-code word.
// If t=n, the dual space is {0} and the check is correctly vacuous.
func dualCodeWord(c PVSSCommitment) []kyber.Scalar {
	group := suite()
	stream := group.XOF(pvssHash(pvssVersion+"/rs-dual", objectBytes(c), pvssEncode(c.Proof)))
	coeffs := make([]kyber.Scalar, len(c.Members)-c.Threshold)
	for i := range coeffs {
		coeffs[i] = group.Scalar().Pick(stream)
	}
	out := make([]kyber.Scalar, len(c.Members))
	for i := range out {
		x := group.Scalar().SetInt64(int64(i + 1))
		value := group.Scalar().Zero()
		for j := len(coeffs) - 1; j >= 0; j-- {
			value.Mul(value, x).Add(value, coeffs[j])
		}
		den := group.Scalar().One()
		for j := range out {
			if j != i {
				den.Mul(den, group.Scalar().SetInt64(int64(i-j)))
			}
		}
		out[i] = group.Scalar().Div(value, den)
	}
	return out
}

// Rejection sampling avoids bias from reducing a 256-bit hash modulo the
// subgroup order, under the paper's domain-separated random-oracle model.
func oracleScalar(domain string, parts ...[]byte) kyber.Scalar {
	group := suite()
	return group.Scalar().Pick(group.XOF(pvssHash(domain, parts...)))
}

func pvssHash(domain string, parts ...[]byte) []byte {
	var buf bytes.Buffer
	for _, part := range append([][]byte{[]byte(domain)}, parts...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		buf.Write(size[:])
		buf.Write(part)
	}
	return HashBytes(buf.Bytes())
}

func pvssEncode(v any) []byte {
	b, err := CanonicalBytes(v)
	if err != nil {
		panic(err)
	} // Internal values have only JSON-encodable fields.
	return b
}

func mustPointBytes(p kyber.Point) []byte {
	b, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func mustPointHex(p kyber.Point) string { return hex.EncodeToString(mustPointBytes(p)) }

func scalarHex(s kyber.Scalar) string {
	b, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func scalarFromHex(raw string) kyber.Scalar {
	if len(raw) != 64 {
		return nil
	}
	b, err := hex.DecodeString(raw)
	if err != nil || hex.EncodeToString(b) != raw {
		return nil
	}
	s := suite().Scalar()
	if err := s.UnmarshalBinary(b); err != nil {
		return nil
	}
	canonical, err := s.MarshalBinary()
	if err != nil || !bytes.Equal(b, canonical) {
		return nil
	}
	return s
}

func pointFromHex(raw string) (kyber.Point, error) {
	if len(raw) != 64 {
		return nil, errors.New("PVSS point must have a 32-byte encoding")
	}
	b, err := hex.DecodeString(raw)
	if err != nil || hex.EncodeToString(b) != raw {
		return nil, errors.New("noncanonical PVSS point hex encoding")
	}
	group := suite()
	p := group.Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	canonical, err := p.MarshalBinary()
	if err != nil || !bytes.Equal(b, canonical) {
		return nil, errors.New("noncanonical PVSS curve point")
	}
	// Small-order rejection alone would miss subgroup points with added torsion.
	// Multiply by the INTEGER order, not a scalar reduced modulo that order.
	acc := group.Point().Null()
	for i := 252; i >= 0; i-- {
		acc.Add(acc, acc)
		if pvssGroupOrder[i/8]&(1<<uint(i%8)) != 0 {
			acc.Add(acc, p)
		}
	}
	if !acc.Equal(group.Point().Null()) {
		return nil, errors.New("PVSS point is outside the prime-order subgroup")
	}
	return p, nil
}

func (s *PVSSPairingFreeScheme) pointFromHex(raw string) (kyber.Point, error) {
	s.cacheMu.RLock()
	p := s.points[raw]
	s.cacheMu.RUnlock()
	if p != nil {
		return p.Clone(), nil
	}
	p, err := pointFromHex(raw)
	if err != nil {
		return nil, err
	}
	s.cachePoint(raw, p)
	return p, nil
}

// FIFO replacement keeps both caches bounded and useful after a long run.
// Previously the first 4096 points permanently occupied the entire cache.
func cacheInsert[V any](values map[string]V, keys *[]string, next *int, key string, value V) {
	if _, exists := values[key]; exists {
		return
	}
	if len(*keys) < pvssPointCacheLimit {
		*keys = append(*keys, key)
	} else {
		delete(values, (*keys)[*next])
		(*keys)[*next] = key
		*next = (*next + 1) % pvssPointCacheLimit
	}
	values[key] = value
}
func (s *PVSSPairingFreeScheme) cachePoint(raw string, p kyber.Point) {
	s.cacheMu.Lock()
	cacheInsert(s.points, &s.pointKeys, &s.pointNext, raw, p.Clone())
	s.cacheMu.Unlock()
}
