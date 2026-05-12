package pvss

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	asig "github.com/scottocs/asyrand/asyrand/internal/crypto"
	"github.com/scottocs/asyrand/asyrand/internal/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/proof/dleq"
	"go.dedis.ch/kyber/v3/share"
)

type KeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

type Commitment struct {
	Dealer    p2p.NodeID            `json:"dealer"`
	Seq       uint64                `json:"seq"`
	Threshold int                   `json:"threshold"`
	Members   []p2p.NodeID          `json:"members"`
	Cipher    map[p2p.NodeID]string `json:"cipher"`
	Proof     Proof                 `json:"proof"`
	SecretID  string                `json:"secret_id"`
}

type Proof struct {
	CPrime    map[p2p.NodeID]string `json:"c_prime"`
	Challenge string                `json:"challenge"`
	STilde    string                `json:"s_tilde"`
	PTilde    map[p2p.NodeID]string `json:"p_tilde"`
}

type DecryptionProof struct {
	C  string `json:"c"`
	R  string `json:"r"`
	VG string `json:"vg"`
	VH string `json:"vh"`
}

type DecryptedShare struct {
	CommitmentID string          `json:"commitment_id"`
	Holder       p2p.NodeID      `json:"holder"`
	Value        string          `json:"value"`
	Proof        DecryptionProof `json:"proof"`
}

type Scheme interface {
	Share(dealer p2p.NodeID, seq uint64, members []p2p.NodeID) (Commitment, []byte, error)
	Verify(Commitment) bool
	PreRecon(Commitment, p2p.NodeID) (DecryptedShare, error)
	PreReconTrusted(Commitment, p2p.NodeID) (DecryptedShare, error)
	VerifyShare(Commitment, DecryptedShare) bool
	Recon(Commitment, []DecryptedShare, int) ([]byte, error)
	ReconTrusted(Commitment, []DecryptedShare, int) ([]byte, error)
}

type PairingFreeScheme struct {
	id        p2p.NodeID
	threshold int
	private   kyber.Scalar
	public    map[p2p.NodeID]kyber.Point
}

func NewScheme(id p2p.NodeID, threshold int, private kyber.Scalar, public map[p2p.NodeID]kyber.Point) (*PairingFreeScheme, error) {
	if id == "" {
		return nil, errors.New("pvss node id is required")
	}
	if threshold <= 0 {
		return nil, errors.New("pvss threshold must be positive")
	}
	if private == nil {
		return nil, errors.New("pvss private key is required")
	}
	if len(public) == 0 {
		return nil, errors.New("pvss public keys are required")
	}
	cp := make(map[p2p.NodeID]kyber.Point, len(public))
	for id, pub := range public {
		cp[id] = pub.Clone()
	}
	return &PairingFreeScheme{id: id, threshold: threshold, private: private.Clone(), public: cp}, nil
}

func KeyPairFromSeed(seed []byte) KeyPair {
	suite := suite()
	sk := suite.Scalar().SetBytes(asig.HashBytes([]byte("AsyRand-v1/PVSS/key"), seed))
	if sk.Equal(suite.Scalar().Zero()) {
		sk = suite.Scalar().One()
	}
	return KeyPair{Private: sk, Public: suite.Point().Mul(sk, nil)}
}

func (s *PairingFreeScheme) Share(dealer p2p.NodeID, seq uint64, members []p2p.NodeID) (Commitment, []byte, error) {
	if dealer != s.id {
		return Commitment{}, nil, fmt.Errorf("pvss scheme for %s cannot deal as %s", s.id, dealer)
	}
	members = normalizeMembers(members)
	if len(members) < s.threshold {
		return Commitment{}, nil, errors.New("not enough members for pvss threshold")
	}
	group := suite()
	// AsyRand paper, PVSS construction: share a secret exponent with Shamir,
	// encrypt each share as pk_i^{p(i)}, and prove consistency with a
	// Fiat-Shamir transformed Sigma transcript.
	secret := group.Scalar().Pick(group.RandomStream())
	poly := share.NewPriPoly(group, s.threshold, secret, group.RandomStream())
	blind := share.NewPriPoly(group, s.threshold, nil, group.RandomStream())
	shares := poly.Shares(len(members))
	blindShares := blind.Shares(len(members))

	cipher := make(map[p2p.NodeID]string, len(members))
	cPrime := make(map[p2p.NodeID]string, len(members))
	for i, member := range members {
		pk := s.public[member]
		if pk == nil {
			return Commitment{}, nil, fmt.Errorf("missing pvss public key for %s", member)
		}
		cipher[member] = mustPointHex(group.Point().Mul(shares[i].V, pk))
		cPrime[member] = mustPointHex(group.Point().Mul(blindShares[i].V, pk))
	}
	challenge := challengeScalar(dealer, seq, members, cipher, cPrime)
	pTilde := make(map[p2p.NodeID]string, len(members))
	for i, member := range members {
		cp := group.Scalar().Mul(challenge, shares[i].V)
		resp := group.Scalar().Sub(blindShares[i].V, cp)
		pTilde[member] = mustScalarHex(resp)
	}
	sTilde := group.Scalar().Sub(blind.Secret(), group.Scalar().Mul(challenge, secret))
	commit := Commitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members, Cipher: cipher,
		Proof: Proof{CPrime: cPrime, Challenge: mustScalarHex(challenge), STilde: mustScalarHex(sTilde), PTilde: pTilde},
	}
	commit.SecretID = commitmentID(commit)
	secretPoint := group.Point().Mul(secret, nil)
	return commit, mustPointBytes(secretPoint), nil
}

func (s *PairingFreeScheme) Verify(c Commitment) bool {
	if c.Dealer == "" || c.SecretID == "" || c.Threshold <= 0 || len(c.Members) < c.Threshold {
		return false
	}
	if commitmentID(c) != c.SecretID {
		return false
	}
	members := normalizeMembers(c.Members)
	group := suite()
	// Verify the Sigma response C'_i = pk_i^{p_tilde(i)} C_i^c for every
	// encrypted share, then check that all p_tilde(i) values are evaluations of
	// one degree-(t-1) polynomial.
	challenge := challengeScalar(c.Dealer, c.Seq, members, c.Cipher, c.Proof.CPrime)
	recordedChallenge, err := scalarFromHex(c.Proof.Challenge)
	if err != nil || !challenge.Equal(recordedChallenge) {
		return false
	}

	pShares := make([]*share.PriShare, 0, len(members))
	for i, member := range members {
		pk := s.public[member]
		if pk == nil {
			return false
		}
		cipher, err := pointFromHex(c.Cipher[member])
		if err != nil {
			return false
		}
		cPrime, err := pointFromHex(c.Proof.CPrime[member])
		if err != nil {
			return false
		}
		pTilde, err := scalarFromHex(c.Proof.PTilde[member])
		if err != nil {
			return false
		}
		left := cPrime
		right := group.Point().Add(group.Point().Mul(pTilde, pk), group.Point().Mul(challenge, cipher))
		if !left.Equal(right) {
			return false
		}
		pShares = append(pShares, &share.PriShare{I: i, V: pTilde})
	}
	sTilde, err := scalarFromHex(c.Proof.STilde)
	if err != nil {
		return false
	}
	secret, ok := interpolateDegreeBounded(group, pShares, c.Threshold)
	if !ok || !secret.Equal(sTilde) {
		return false
	}
	return true
}

func (s *PairingFreeScheme) PreRecon(c Commitment, holder p2p.NodeID) (DecryptedShare, error) {
	if !s.Verify(c) {
		return DecryptedShare{}, errors.New("invalid pvss commitment")
	}
	return s.PreReconTrusted(c, holder)
}

func (s *PairingFreeScheme) PreReconTrusted(c Commitment, holder p2p.NodeID) (DecryptedShare, error) {
	if holder != s.id {
		return DecryptedShare{}, fmt.Errorf("pvss scheme for %s cannot decrypt as %s", s.id, holder)
	}
	cipher, err := pointFromHex(c.Cipher[holder])
	if err != nil {
		return DecryptedShare{}, err
	}
	group := suite()
	plain := group.Point().Mul(group.Scalar().Inv(s.private), cipher)
	proof, err := decryptionProof(group, s.private, plain, cipher)
	if err != nil {
		return DecryptedShare{}, err
	}
	return DecryptedShare{CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(plain), Proof: proof}, nil
}

func (s *PairingFreeScheme) VerifyShare(c Commitment, sh DecryptedShare) bool {
	if sh.CommitmentID != c.SecretID {
		return false
	}
	pk := s.public[sh.Holder]
	if pk == nil {
		return false
	}
	cipher, err := pointFromHex(c.Cipher[sh.Holder])
	if err != nil {
		return false
	}
	plain, err := pointFromHex(sh.Value)
	if err != nil {
		return false
	}
	proof, err := parseDecryptionProof(sh.Proof)
	if err != nil {
		return false
	}
	group := suite()
	return proof.Verify(group, group.Point().Base(), plain, pk, cipher) == nil
}

func (s *PairingFreeScheme) Recon(c Commitment, shares []DecryptedShare, threshold int) ([]byte, error) {
	if threshold <= 0 {
		threshold = c.Threshold
	}
	if threshold != c.Threshold {
		return nil, errors.New("pvss threshold mismatch")
	}
	return s.ReconTrusted(c, shares, threshold)
}

func (s *PairingFreeScheme) ReconTrusted(c Commitment, shares []DecryptedShare, threshold int) ([]byte, error) {
	if threshold <= 0 {
		threshold = c.Threshold
	}
	if threshold != c.Threshold {
		return nil, errors.New("pvss threshold mismatch")
	}
	group := suite()
	index := memberIndex(c.Members)
	seen := make(map[p2p.NodeID]bool, len(shares))
	pubShares := make([]*share.PubShare, 0, len(shares))
	for _, sh := range shares {
		if seen[sh.Holder] || sh.CommitmentID != c.SecretID {
			continue
		}
		i, ok := index[sh.Holder]
		if !ok {
			continue
		}
		plain, err := pointFromHex(sh.Value)
		if err != nil {
			continue
		}
		seen[sh.Holder] = true
		pubShares = append(pubShares, &share.PubShare{I: i, V: plain})
	}
	if len(pubShares) < threshold {
		return nil, errors.New("not enough valid decrypted pvss shares")
	}
	secret, err := share.RecoverCommit(group, pubShares, threshold, len(c.Members))
	if err != nil {
		return nil, err
	}
	return secret.MarshalBinary()
}

func CommitmentID(c Commitment) string {
	return c.SecretID
}

func decryptionProof(group *bn256.Suite, sk kyber.Scalar, plain kyber.Point, cipher kyber.Point) (DecryptionProof, error) {
	proof, _, _, err := dleq.NewDLEQProof(group, group.Point().Base(), plain, sk)
	if err != nil {
		return DecryptionProof{}, err
	}
	return DecryptionProof{C: mustScalarHex(proof.C), R: mustScalarHex(proof.R), VG: mustPointHex(proof.VG), VH: mustPointHex(proof.VH)}, nil
}

func parseDecryptionProof(p DecryptionProof) (*dleq.Proof, error) {
	c, err := scalarFromHex(p.C)
	if err != nil {
		return nil, err
	}
	r, err := scalarFromHex(p.R)
	if err != nil {
		return nil, err
	}
	vg, err := pointFromHex(p.VG)
	if err != nil {
		return nil, err
	}
	vh, err := pointFromHex(p.VH)
	if err != nil {
		return nil, err
	}
	return &dleq.Proof{C: c, R: r, VG: vg, VH: vh}, nil
}

func suite() *bn256.Suite {
	return bn256.NewSuiteG1()
}

func normalizeMembers(members []p2p.NodeID) []p2p.NodeID {
	out := append([]p2p.NodeID(nil), members...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func memberIndex(members []p2p.NodeID) map[p2p.NodeID]int {
	members = normalizeMembers(members)
	out := make(map[p2p.NodeID]int, len(members))
	for i, member := range members {
		out[member] = i
	}
	return out
}

type barycentricKey struct {
	n int
	t int
}

type barycentricWeights struct {
	secret []kyber.Scalar
	tail   [][]kyber.Scalar
}

var barycentricCache sync.Map

func interpolateDegreeBounded(group *bn256.Suite, shares []*share.PriShare, threshold int) (kyber.Scalar, bool) {
	if threshold <= 0 || len(shares) < threshold {
		return nil, false
	}
	for i, sh := range shares {
		if sh == nil || sh.V == nil || sh.I != i {
			return nil, false
		}
	}
	// Barycentric/Lagrange weights depend only on (n,t); cache them so Verify
	// keeps the paper's degree-bounded intpl check without rebuilding weights.
	weights := cachedBarycentricWeights(group, len(shares), threshold)
	secret := evalBarycentric(group, shares[:threshold], weights.secret)
	for i, sh := range shares[threshold:] {
		if !evalBarycentric(group, shares[:threshold], weights.tail[i]).Equal(sh.V) {
			return nil, false
		}
	}
	return secret, true
}

func cachedBarycentricWeights(group *bn256.Suite, n, threshold int) *barycentricWeights {
	key := barycentricKey{n: n, t: threshold}
	if cached, ok := barycentricCache.Load(key); ok {
		return cached.(*barycentricWeights)
	}
	weights := buildBarycentricWeights(group, n, threshold)
	actual, _ := barycentricCache.LoadOrStore(key, weights)
	return actual.(*barycentricWeights)
}

func buildBarycentricWeights(group *bn256.Suite, n, threshold int) *barycentricWeights {
	weights := &barycentricWeights{
		secret: lagrangeWeightsAt(group, 0, threshold),
		tail:   make([][]kyber.Scalar, n-threshold),
	}
	for i := threshold; i < n; i++ {
		weights.tail[i-threshold] = lagrangeWeightsAt(group, i+1, threshold)
	}
	return weights
}

func lagrangeWeightsAt(group *bn256.Suite, target int, threshold int) []kyber.Scalar {
	weights := make([]kyber.Scalar, threshold)
	for j := 0; j < threshold; j++ {
		num := group.Scalar().One()
		den := group.Scalar().One()
		xj := group.Scalar().SetInt64(int64(j + 1))
		x := group.Scalar().SetInt64(int64(target))
		for k := 0; k < threshold; k++ {
			if k == j {
				continue
			}
			xk := group.Scalar().SetInt64(int64(k + 1))
			num.Mul(num, group.Scalar().Sub(x, xk))
			den.Mul(den, group.Scalar().Sub(xj, xk))
		}
		weights[j] = group.Scalar().Div(num, den)
	}
	return weights
}

func evalBarycentric(group *bn256.Suite, shares []*share.PriShare, weights []kyber.Scalar) kyber.Scalar {
	out := group.Scalar().Zero()
	for i, sh := range shares {
		out.Add(out, group.Scalar().Mul(sh.V, weights[i]))
	}
	return out
}

func challengeScalar(dealer p2p.NodeID, seq uint64, members []p2p.NodeID, cipher, cPrime map[p2p.NodeID]string) kyber.Scalar {
	buf := bytes.Buffer{}
	buf.WriteString("AsyRand-v1/PVSS/share-proof/")
	buf.WriteString(string(dealer))
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d", seq))
	for _, member := range members {
		buf.WriteByte('/')
		buf.WriteString(string(member))
		buf.WriteByte(':')
		buf.WriteString(cipher[member])
		buf.WriteByte(':')
		buf.WriteString(cPrime[member])
	}
	return suite().Scalar().SetBytes(asig.HashBytes(buf.Bytes()))
}

func commitmentID(c Commitment) string {
	members := normalizeMembers(c.Members)
	buf := bytes.Buffer{}
	buf.WriteString("AsyRand-v1/PVSS/commitment/")
	buf.WriteString(string(c.Dealer))
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d/%d", c.Seq, c.Threshold))
	for _, member := range members {
		buf.WriteByte('/')
		buf.WriteString(string(member))
		buf.WriteByte(':')
		buf.WriteString(c.Cipher[member])
		buf.WriteByte(':')
		buf.WriteString(c.Proof.CPrime[member])
		buf.WriteByte(':')
		buf.WriteString(c.Proof.PTilde[member])
	}
	buf.WriteByte('/')
	buf.WriteString(c.Proof.Challenge)
	buf.WriteByte('/')
	buf.WriteString(c.Proof.STilde)
	return hex.EncodeToString(asig.HashBytes(buf.Bytes()))
}

func mustPointBytes(p kyber.Point) []byte {
	b, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func mustPointHex(p kyber.Point) string {
	return hex.EncodeToString(mustPointBytes(p))
}

func pointFromHex(v string) (kyber.Point, error) {
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	p := suite().Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}

func mustScalarHex(s kyber.Scalar) string {
	b, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func scalarFromHex(v string) (kyber.Scalar, error) {
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	s := suite().Scalar()
	if err := s.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return s, nil
}
