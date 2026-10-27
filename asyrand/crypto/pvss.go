package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	fasted "filippo.io/edwards25519"
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

// l-1 is canonical and does not reduce to zero. Kyber's variable-base Mul
// multiplies these integer bits even for a point with a torsion component.
// [(l-1)]P+P therefore tests [l]P=0, preserving the full subgroup check.
var pvssOrderMinusOne = func() kyber.Scalar {
	raw := pvssGroupOrder
	raw[0]--
	return suite().Scalar().SetBytes(raw[:])
}()

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
	privateInverse kyber.Scalar
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
	pointHits      atomic.Uint64
	pointMisses    atomic.Uint64
	headerChecks   atomic.Uint64
	preparedBuilds atomic.Uint64
	shareHits      atomic.Uint64
	shareChecks    atomic.Uint64
}

// VerifiedPVSS owns a deep-copied, validated object and its decoded ciphertexts.
// Its private fields prevent callers from mutating inputs after verification.
// Handles are local to one scheme, never transferred between committee nodes.
type VerifiedPVSS struct {
	owner     *PVSSPairingFreeScheme
	object    PVSSCommitment
	context   []byte
	cipher    map[p2p.NodeID]kyber.Point
	mu        sync.Mutex
	shares    map[string]kyber.Point
	shareKeys []string
	shareNext int
}

func (s *PVSSPairingFreeScheme) WorkStats() map[string]uint64 {
	return map[string]uint64{"point_cache_hits": s.pointHits.Load(), "point_cache_misses": s.pointMisses.Load(),
		"full_header_checks": s.headerChecks.Load(), "prepared_objects": s.preparedBuilds.Load(),
		"prepared_share_hits": s.shareHits.Load(), "prepared_share_checks": s.shareChecks.Load()}
}

// Prepare verifies a complete immutable copy before issuing a reusable handle.
// SecretID alone is never sufficient to trust an arbitrary caller's object.
func (s *PVSSPairingFreeScheme) Prepare(c PVSSCommitment) (*VerifiedPVSS, bool) {
	owned := c
	owned.Members = append([]p2p.NodeID(nil), c.Members...)
	owned.Commit = maps.Clone(c.Commit)
	owned.Cipher = maps.Clone(c.Cipher)
	owned.Proof.Responses = maps.Clone(c.Proof.Responses)
	owned.Proof.Coefficients = append([]string(nil), c.Proof.Coefficients...)
	owned.DLEQ = maps.Clone(c.DLEQ)
	owned.Sources = append([]PVSSSource(nil), c.Sources...)
	if !s.Verify(owned) {
		return nil, false
	}
	v := &VerifiedPVSS{owner: s, object: owned, context: objectBytes(owned),
		cipher: make(map[p2p.NodeID]kyber.Point, len(s.members)), shares: make(map[string]kyber.Point)}
	for _, id := range s.members {
		point, err := s.pointFromHex(owned.Cipher[id])
		if err != nil {
			return nil, false
		}
		v.cipher[id] = point
	}
	s.preparedBuilds.Add(1)
	return v, true
}

func (s *PVSSPairingFreeScheme) owns(v *VerifiedPVSS) bool { return v != nil && v.owner == s }

func (s *PVSSPairingFreeScheme) PreReconPrepared(v *VerifiedPVSS, holder p2p.NodeID) (PVSSDecryptedShare, error) {
	if !s.owns(v) || s.private == nil || holder != s.id {
		return PVSSDecryptedShare{}, errors.New("invalid prepared PVSS object or holder")
	}
	return s.makeDecryptionShare(v.object, holder, v.cipher[holder], v.context, v)
}

func preparedShareKey(v *VerifiedPVSS, sh PVSSDecryptedShare) string {
	return hex.EncodeToString(pvssHash(v.object.Version+"/prepared-share", []byte(v.object.SetupID), []byte(v.object.SecretID), pvssEncode(sh)))
}

func (v *VerifiedPVSS) remember(key string, point kyber.Point) {
	v.mu.Lock()
	defer v.mu.Unlock()
	cacheInsert(v.shares, &v.shareKeys, &v.shareNext, key, point.Clone())
}

func (s *PVSSPairingFreeScheme) checkedPreparedShare(v *VerifiedPVSS, sh PVSSDecryptedShare) (kyber.Point, bool) {
	if !s.owns(v) || sh.CommitmentID != v.object.SecretID || s.public[sh.Holder] == nil {
		return nil, false
	}
	key := preparedShareKey(v, sh)
	v.mu.Lock()
	point := v.shares[key]
	v.mu.Unlock()
	if point != nil {
		s.shareHits.Add(1)
		return point.Clone(), true
	}
	s.shareChecks.Add(1)
	d, err := s.pointFromHex(sh.Value)
	if err != nil {
		return nil, false
	}
	if !s.verifyDecryptionProof(v.object, sh, d, v.cipher[sh.Holder], v.context) {
		return nil, false
	}
	v.remember(key, d)
	return d, true
}

func (s *PVSSPairingFreeScheme) VerifyPreparedShare(v *VerifiedPVSS, sh PVSSDecryptedShare) bool {
	_, valid := s.checkedPreparedShare(v, sh)
	return valid
}

func (s *PVSSPairingFreeScheme) ReconPrepared(v *VerifiedPVSS, shares []PVSSDecryptedShare, threshold int) ([]byte, error) {
	if !s.owns(v) || (threshold != 0 && threshold != s.threshold) {
		return nil, errors.New("prepared PVSS owner or threshold mismatch")
	}
	seen := make(map[p2p.NodeID]bool, s.threshold)
	parts := make([]*share.PubShare, 0, s.threshold)
	for _, sh := range shares {
		if seen[sh.Holder] {
			continue
		}
		point, valid := s.checkedPreparedShare(v, sh)
		if !valid {
			continue
		}
		seen[sh.Holder] = true
		parts = append(parts, &share.PubShare{I: s.index[sh.Holder], V: point})
		if len(parts) == s.threshold {
			break
		}
	}
	if len(parts) != s.threshold {
		return nil, errors.New("not enough distinct valid prepared shares")
	}
	point, err := recoverPVSSCommit(parts, s.threshold, len(s.members))
	if err != nil {
		return nil, err
	}
	return point.MarshalBinary()
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
	s.privateInverse = suite().Scalar().Inv(sk)
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
		a[i] = group.Point().Add(publicPointMul(z, s.g), publicPointMul(epsilon, v[i]))
		b[i] = group.Point().Add(publicPointMul(z, s.public[member]), publicPointMul(epsilon, cipher))
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
	return s.makeDecryptionShare(c, holder, cipher, objectBytes(c), nil)
}

func (s *PVSSPairingFreeScheme) makeDecryptionShare(c PVSSCommitment, holder p2p.NodeID, cipher kyber.Point, context []byte, prepared *VerifiedPVSS) (PVSSDecryptedShare, error) {
	group := suite()
	d := group.Point().Mul(s.privateInverse, cipher)
	w := group.Scalar().Pick(group.RandomStream())
	a := group.Point().Mul(w, s.h)
	b := group.Point().Mul(w, d)
	epsilon := s.decryptionChallengeContext(c, context, holder, d, cipher, a, b)
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
	if prepared != nil {
		prepared.remember(preparedShareKey(prepared, sh), d)
	} else {
		s.cacheShare(c, sh)
	}
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
	if !s.verifyDecryptionProof(c, sh, d, cipher, objectBytes(c)) {
		return false
	}
	s.cacheMu.Lock()
	cacheInsert(s.verifiedShares, &s.shareKeys, &s.shareNext, key, struct{}{})
	s.cacheMu.Unlock()
	return true
}

func (s *PVSSPairingFreeScheme) verifyDecryptionProof(c PVSSCommitment, sh PVSSDecryptedShare, d, cipher kyber.Point, context []byte) bool {
	z := scalarFromHex(sh.Proof.R)
	if z == nil {
		return false
	}
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
		epsilon := s.decryptionChallengeContext(c, context, sh.Holder, d, cipher, a, b)
		// Both complete equations use only validated, immutable public inputs.
		// Partition their tail as well as the outer set of foreign shares.
		if !cryptoexec.AllLabeled("recon-proof-equations", 2, func(i int) bool {
			if i == 0 {
				return publicPointDoubleMulEqual(z, s.h, epsilon, s.public[sh.Holder], a)
			}
			return publicPointDoubleMulEqual(z, d, epsilon, cipher, b)
		}) {
			return false
		}
	} else {
		epsilon := scalarFromHex(sh.Proof.C)
		if epsilon == nil || sh.Proof.A != "" || sh.Proof.B != "" {
			return false
		}
		a := publicPointDoubleMul(z, s.h, epsilon, s.public[sh.Holder])
		b := publicPointDoubleMul(z, d, epsilon, cipher)
		if !s.decryptionChallengeContext(c, context, sh.Holder, d, cipher, a, b).Equal(epsilon) {
			return false
		}
	}
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
	secret, err := recoverPVSSCommit(pubShares, threshold, len(s.members))
	if err != nil {
		return nil, err
	}
	return secret.MarshalBinary() // Canonical Encode(Z), Z=h^s in G.
}

// Interpolation uses published shares and indices only. One batch inversion
// computes all Lagrange weights, then a joint public multi-scalar multiplication
// shares the doubling chain. Secret generation/decryption retains its own Mul.
func recoverPVSSCommit(parts []*share.PubShare, threshold, n int) (kyber.Point, error) {
	if threshold < 1 || n < threshold || len(parts) != threshold {
		return nil, errors.New("invalid PVSS interpolation dimensions")
	}
	seen := make(map[int]bool, threshold)
	for _, part := range parts {
		if part == nil || part.V == nil || part.I < 0 || part.I >= n || seen[part.I] {
			return nil, errors.New("invalid PVSS interpolation share")
		}
		seen[part.I] = true
	}
	one := publicScalar(suite().Scalar().One())
	xs := make([]*fasted.Scalar, threshold)
	points := make([]*fasted.Point, threshold)
	for i, part := range parts {
		xs[i] = publicScalar(suite().Scalar().SetInt64(int64(part.I + 1)))
		points[i] = publicPoint(part.V)
	}
	numerators, denominators, prefixes := make([]*fasted.Scalar, threshold), make([]*fasted.Scalar, threshold), make([]*fasted.Scalar, threshold)
	product := new(fasted.Scalar).Set(one)
	for i := range parts {
		numerator, denominator := new(fasted.Scalar).Set(one), new(fasted.Scalar).Set(one)
		for j := range parts {
			if i != j {
				numerator.Multiply(numerator, xs[j])
				denominator.Multiply(denominator, new(fasted.Scalar).Subtract(xs[j], xs[i]))
			}
		}
		numerators[i], denominators[i] = numerator, denominator
		prefixes[i] = new(fasted.Scalar).Set(product)
		product.Multiply(product, denominator)
	}
	// Distinct nonnegative indices make each difference nonzero modulo l.
	inverse := new(fasted.Scalar).Invert(product)
	weights := make([]*fasted.Scalar, threshold)
	for i := threshold - 1; i >= 0; i-- {
		weights[i] = new(fasted.Scalar).Multiply(inverse, prefixes[i])
		weights[i].Multiply(weights[i], numerators[i])
		inverse.Multiply(inverse, denominators[i])
	}
	return publicPointResult(new(fasted.Point).VarTimeMultiScalarMult(weights, points)), nil
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
	s.headerChecks.Add(1)
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
	return s.decryptionChallengeContext(c, objectBytes(c), holder, d, cipher, a, b)
}
func (s *PVSSPairingFreeScheme) decryptionChallengeContext(c PVSSCommitment, context []byte, holder p2p.NodeID, d, cipher, a, b kyber.Point) kyber.Scalar {
	statement := []string{string(holder), mustPointHex(s.h), mustPointHex(s.public[holder]), mustPointHex(d), mustPointHex(cipher), mustPointHex(a), mustPointHex(b)}
	return oracleScalar(s.version+"/decrypt-dleq", context, []byte(c.SecretID), pvssEncode(statement))
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

// Verification-only multiplication. Every caller supplies published proof data;
// key generation, sharing and decryption with secrets keep constant-time Mul.
func publicPointMul(scalar kyber.Scalar, point kyber.Point) kyber.Point {
	return publicPointResult(new(fasted.Point).ScalarMult(publicScalar(scalar), publicPoint(point)))
}

// Public proof equations share their doubling chain. Both inputs have already
// passed canonical decoding and the complete prime-subgroup check. This path
// is never used for private keys, secret polynomial coefficients or nonces.
func publicPointDoubleMul(a kyber.Scalar, A kyber.Point, b kyber.Scalar, B kyber.Point) kyber.Point {
	return publicPointResult(new(fasted.Point).VarTimeMultiScalarMult(
		[]*fasted.Scalar{publicScalar(a), publicScalar(b)},
		[]*fasted.Point{publicPoint(A), publicPoint(B)}))
}

// Compare the canonical result directly. Converting a public equation result
// back through Kyber would decompress a point only to compare it immediately.
// Inputs still come from complete canonical and prime-order validation.
func publicPointDoubleMulEqual(a kyber.Scalar, A kyber.Point, b kyber.Scalar, B kyber.Point, want kyber.Point) bool {
	result := new(fasted.Point).VarTimeMultiScalarMult(
		[]*fasted.Scalar{publicScalar(a), publicScalar(b)},
		[]*fasted.Point{publicPoint(A), publicPoint(B)})
	return bytes.Equal(result.Bytes(), mustPointBytes(want))
}

func publicScalar(s kyber.Scalar) *fasted.Scalar {
	raw, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	x, err := new(fasted.Scalar).SetCanonicalBytes(raw)
	if err != nil {
		panic(err)
	}
	return x
}

func publicPoint(p kyber.Point) *fasted.Point {
	x, err := new(fasted.Point).SetBytes(mustPointBytes(p))
	if err != nil {
		panic(err)
	}
	return x
}

func publicPointResult(p *fasted.Point) kyber.Point {
	x := suite().Point()
	if err := x.UnmarshalBinary(p.Bytes()); err != nil {
		panic(err)
	}
	return x
}

func pointFromHex(raw string) (kyber.Point, error) {
	if len(raw) != 64 {
		return nil, errors.New("PVSS point must have a 32-byte encoding")
	}
	b, err := hex.DecodeString(raw)
	if err != nil || hex.EncodeToString(b) != raw {
		return nil, errors.New("noncanonical PVSS point hex encoding")
	}
	native, err := new(fasted.Point).SetBytes(b)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b, native.Bytes()) {
		return nil, errors.New("noncanonical PVSS curve point")
	}
	// Small-order rejection alone would miss subgroup points with added torsion.
	// Multiply by the INTEGER order, not a scalar reduced modulo that order.
	acc := new(fasted.Point).ScalarMult(publicScalar(pvssOrderMinusOne), native)
	acc.Add(acc, native)
	if acc.Equal(fasted.NewIdentityPoint()) != 1 {
		return nil, errors.New("PVSS point is outside the prime-order subgroup")
	}
	// Convert once for the existing Kyber interfaces, after canonicality and
	// the full integer-order test. Re-encoding through Kyber repeats an inverse.
	p := suite().Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *PVSSPairingFreeScheme) pointFromHex(raw string) (kyber.Point, error) {
	s.cacheMu.RLock()
	p := s.points[raw]
	s.cacheMu.RUnlock()
	if p != nil {
		s.pointHits.Add(1)
		return p.Clone(), nil
	}
	s.pointMisses.Add(1)
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
