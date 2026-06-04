package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"

	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

const (
	matrixRows = 5
	matrixCols = 8
	sa1Cols    = 2
	sa2Cols    = 6

	reconPlanCacheLimit = 64
)

// reconAggregationPlan is the setup/public part of the silent-setup Decrypt
// aggregation for a fixed qualified holder set. It corresponds to the B, Q0,
// Bhat, aggregated-public-key, and sumcheck commitments in Appendix E of the
// constant-online PVSS construction; ciphertext-dependent sigma and pairings
// are still computed for every reconstruction.
type reconAggregationPlan struct {
	bEvals []kyber.Scalar
	bG2    kyber.Point
	q0G1   kyber.Point
	bhatG1 kyber.Point
	apk    kyber.Point
	qx     kyber.Point
	qz     kyber.Point
	qhatx  kyber.Point
}

var setupVrfCache sync.Map

type PublicParams struct {
	Epoch      string                  `json:"epoch"`
	Threshold  int                     `json:"threshold"`
	Members    []p2p.NodeID            `json:"members"`
	Slots      []p2p.NodeID            `json:"slots"`
	G1         string                  `json:"g1"`
	G2         string                  `json:"g2"`
	GTPrime    string                  `json:"gt_prime"`
	MasterG1   string                  `json:"master_g1"`
	KeyShares  map[p2p.NodeID]string   `json:"key_shares"`
	RealKeys   map[p2p.NodeID]SetupKey `json:"real_keys"`
	DummyKey   SetupKey                `json:"dummy_key"`
	EK         EncryptionKey           `json:"ek"`
	AK         AuditKey                `json:"ak"`
	MatrixA    [][]string              `json:"matrix_a"`
	PowerOfTau PowerOfTauCRS           `json:"power_of_tau"`
}

type PowerOfTauCRS struct {
	G1Powers []string `json:"g1_powers"`
	G2Powers []string `json:"g2_powers"`
}

type SetupKey struct {
	PK1 string                `json:"pk1"`
	PK2 string                `json:"pk2"`
	H1  string                `json:"h1"`
	H2  string                `json:"h2"`
	H3  string                `json:"h3"`
	H4  string                `json:"h4"`
	H5  map[p2p.NodeID]string `json:"h5"`
}

type EncryptionKey struct {
	X string `json:"x"`
	Z string `json:"z"`
}

type AuditKey struct {
	Accepted []p2p.NodeID          `json:"accepted"`
	H2       map[p2p.NodeID]string `json:"h2"`
	H3       map[p2p.NodeID]string `json:"h3"`
	H4       map[p2p.NodeID]string `json:"h4"`
	A        map[p2p.NodeID]string `json:"a"`
}

type CiphertextPrime struct {
	C0 string         `json:"c0"`
	C1 []EncodedPoint `json:"c1"`
	C2 string         `json:"c2"`
}

type Proof struct {
	CPrime         CiphertextPrime `json:"c_prime"`
	Challenge      string          `json:"challenge"`
	GammaResponse  string          `json:"gamma_response"`
	VResponses     []string        `json:"v_responses"`
	SecretResponse string          `json:"secret_response"`
}

type SilentSetupScheme struct {
	id          p2p.NodeID
	private     kyber.Scalar
	pp          PublicParams
	publicG2    map[p2p.NodeID]kyber.Point
	publicG1    map[p2p.NodeID]kyber.Point
	gtPrime     kyber.Point
	pairingBase kyber.Point
	ask         kyber.Point
	zG2         kyber.Point
	hMinus1     kyber.Point
	aggHints    map[p2p.NodeID]kyber.Point
	hintX       map[p2p.NodeID]kyber.Point
	hintMinus0  map[p2p.NodeID]kyber.Point
	slotIndex   map[p2p.NodeID]int
	slotPoints  []kyber.Scalar
	lagrange0   map[p2p.NodeID]kyber.Scalar
	g1Powers    []kyber.Point
	g2Powers    []kyber.Point
	reconPlanMu sync.Mutex
	reconPlans  map[string]*reconAggregationPlan
}

func Setup(epoch string, threshold int, members []p2p.NodeID) (PublicParams, map[p2p.NodeID]KeyPair, error) {
	members = normalizeMembers(members)
	if epoch == "" {
		return PublicParams{}, nil, errors.New("pvss epoch is required")
	}
	if threshold <= 0 || len(members) < threshold {
		return PublicParams{}, nil, errors.New("invalid pvss threshold")
	}
	group := suite()
	slots := append([]p2p.NodeID{dummyID()}, members...)
	setupRand := group.XOF(setupSeed(epoch, threshold, members))
	pot, tau, err := newPowerOfTau(len(slots)+threshold+4, setupRand)
	if err != nil {
		return PublicParams{}, nil, err
	}
	if !VerifyPowerOfTau(pot) {
		return PublicParams{}, nil, errors.New("invalid generated power-of-tau transcript")
	}

	keys := make(map[p2p.NodeID]KeyPair, len(members))
	keyShares := make(map[p2p.NodeID]string, len(members))
	realKeys := make(map[p2p.NodeID]SetupKey, len(members))
	for i, id := range slots {
		sk := group.G1().Scalar().Pick(setupRand)
		if id == dummyID() {
			sk = group.G1().Scalar().One()
		}
		setupKey := deriveSetupKey(group, slots, id, i, sk, tau)
		if id == dummyID() {
			continue
		}
		keys[id] = KeyPair{Private: sk, Public: mustPoint(setupKey.PK1, pointG1FromHex)}
		keyShares[id] = setupKey.PK2
		realKeys[id] = setupKey
	}
	dummy := deriveSetupKey(group, slots, dummyID(), 0, group.G1().Scalar().One(), tau)
	ek, ak := deriveSilentKeys(group, slots, realKeys, dummy)
	matrixA := deriveMatrixA(group, epoch, threshold, pot, ek, ak)
	ask := mustPoint(ek.X, pointG1FromHex)
	pp := PublicParams{
		Epoch: epoch, Threshold: threshold, Members: members, Slots: slots,
		G1: mustPointHex(baseG1(group)), G2: mustPointHex(baseG2(group)),
		GTPrime:   mustPointHex(gtPrime(group, epoch)),
		MasterG1:  mustPointHex(ask),
		KeyShares: keyShares, RealKeys: realKeys, DummyKey: dummy,
		EK: ek, AK: ak, MatrixA: matrixA, PowerOfTau: pot,
	}
	markSetupVrf(pp)
	return pp, keys, nil
}

func NewScheme(id p2p.NodeID, private kyber.Scalar, pp PublicParams) (*SilentSetupScheme, error) {
	if id == "" {
		return nil, errors.New("pvss node id is required")
	}
	if private == nil {
		return nil, errors.New("pvss private key is required")
	}
	if !SetupVrf(pp) {
		return nil, errors.New("invalid silent-setup pvss parameters")
	}
	public := make(map[p2p.NodeID]kyber.Point, len(pp.KeyShares))
	publicG1 := make(map[p2p.NodeID]kyber.Point, len(pp.KeyShares))
	hintX := make(map[p2p.NodeID]kyber.Point, len(pp.Slots))
	hintMinus0 := make(map[p2p.NodeID]kyber.Point, len(pp.Slots))
	aggHints := make(map[p2p.NodeID]kyber.Point, len(pp.Slots))
	slotIdx := make(map[p2p.NodeID]int, len(pp.Slots))
	slotPoints := make([]kyber.Scalar, len(pp.Slots))
	lagrange0 := make(map[p2p.NodeID]kyber.Scalar, len(pp.Slots))
	for id, raw := range pp.KeyShares {
		p, err := pointG2FromHex(raw)
		if err != nil {
			return nil, err
		}
		public[id] = p
	}
	for _, id := range pp.Slots {
		var k SetupKey
		if id == dummyID() {
			k = pp.DummyKey
			pk1, err := pointG1FromHex(k.PK1)
			if err != nil {
				return nil, err
			}
			publicG1[id] = pk1
		} else {
			k = pp.RealKeys[id]
			pk1, err := pointG1FromHex(k.PK1)
			if err != nil {
				return nil, err
			}
			publicG1[id] = pk1
		}
		h2, err := pointG1FromHex(k.H2)
		if err != nil {
			return nil, err
		}
		h4, err := pointG1FromHex(k.H4)
		if err != nil {
			return nil, err
		}
		a, err := pointG1FromHex(pp.AK.A[id])
		if err != nil {
			return nil, err
		}
		hintX[id], hintMinus0[id], aggHints[id] = h2, h4, a
	}
	group := suite()
	for i, id := range pp.Slots {
		slotIdx[id] = i
		slotPoints[i] = slotPoint(group, i)
		lagrange0[id] = lagrangeBasisAt(group.G1(), i, group.G1().Scalar().Zero(), len(pp.Slots))
	}
	g1Powers := make([]kyber.Point, len(pp.PowerOfTau.G1Powers))
	for i, raw := range pp.PowerOfTau.G1Powers {
		p, err := pointG1FromHex(raw)
		if err != nil {
			return nil, err
		}
		g1Powers[i] = p
	}
	g2Powers := make([]kyber.Point, len(pp.PowerOfTau.G2Powers))
	for i, raw := range pp.PowerOfTau.G2Powers {
		p, err := pointG2FromHex(raw)
		if err != nil {
			return nil, err
		}
		g2Powers[i] = p
	}
	gtp, err := pointGTFromHex(pp.GTPrime)
	if err != nil {
		return nil, err
	}
	ask, err := pointG1FromHex(pp.EK.X)
	if err != nil {
		return nil, err
	}
	zG2, err := vanishingCommitG2(group, pp.PowerOfTau, len(pp.Slots))
	if err != nil {
		return nil, err
	}
	return &SilentSetupScheme{
		id: id, private: private.Clone(), pp: cloneParams(pp), publicG2: public, publicG1: publicG1,
		gtPrime: gtp, pairingBase: group.Pair(baseG1(group), baseG2(group)),
		ask: ask, zG2: zG2, hMinus1: group.G2().Point().Neg(baseG2(group)),
		aggHints: aggHints, hintX: hintX, hintMinus0: hintMinus0,
		slotIndex: slotIdx, slotPoints: slotPoints,
		lagrange0: lagrange0, g1Powers: g1Powers, g2Powers: g2Powers,
		reconPlans: make(map[string]*reconAggregationPlan),
	}, nil
}

func (s *SilentSetupScheme) PrivateKey() kyber.Scalar {
	if s == nil || s.private == nil {
		return nil
	}
	return s.private.Clone()
}

func (s *SilentSetupScheme) Epoch() string {
	if s == nil {
		return ""
	}
	return s.pp.Epoch
}

func (s *SilentSetupScheme) Params() PublicParams {
	if s == nil {
		return PublicParams{}
	}
	return cloneParams(s.pp)
}

func SetupVrf(pp PublicParams) bool {
	if pp.Epoch == "" || pp.Threshold <= 0 || len(pp.Members) < pp.Threshold || len(pp.Slots) != len(pp.Members)+1 {
		return false
	}
	cacheKey := setupVrfCacheKey(pp)
	if cacheKey != "" {
		if cached, ok := setupVrfCache.Load(cacheKey); ok && cached == true {
			return true
		}
	}
	if !VerifyPowerOfTau(pp.PowerOfTau) || len(pp.MatrixA) != matrixRows {
		return false
	}
	group := suite()
	expectedSlots := append([]p2p.NodeID{dummyID()}, normalizeMembers(pp.Members)...)
	if !reflect.DeepEqual(pp.Slots, expectedSlots) {
		return false
	}
	polys, err := setupVerificationPolys(group, pp.PowerOfTau, pp.Slots)
	if err != nil {
		return false
	}
	for _, row := range pp.MatrixA {
		if len(row) != matrixCols {
			return false
		}
		for _, raw := range row {
			if _, err := pointGTFromHex(raw); err != nil {
				return false
			}
		}
	}
	for _, id := range pp.Members {
		k, ok := pp.RealKeys[id]
		if !ok || !verifySetupKey(group, pp.Slots, polys, id, k) {
			return false
		}
		if pp.KeyShares[id] != k.PK2 {
			return false
		}
	}
	if !verifySetupKey(group, pp.Slots, polys, dummyID(), pp.DummyKey) {
		return false
	}
	expectedEK, expectedAK := deriveSilentKeys(group, pp.Slots, pp.RealKeys, pp.DummyKey)
	if pp.EK != expectedEK || pp.MasterG1 != expectedEK.X || !reflect.DeepEqual(pp.AK, expectedAK) {
		return false
	}
	if !reflect.DeepEqual(pp.MatrixA, deriveMatrixA(group, pp.Epoch, pp.Threshold, pp.PowerOfTau, pp.EK, pp.AK)) {
		return false
	}
	for _, raw := range []string{pp.EK.X, pp.EK.Z, pp.MasterG1} {
		if _, err := pointG1FromHex(raw); err != nil {
			return false
		}
	}
	if _, err := pointGTFromHex(pp.GTPrime); err != nil {
		return false
	}
	markSetupVrf(pp)
	return true
}

func setupVrfCacheKey(pp PublicParams) string {
	raw, err := json.Marshal(pp)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(HashBytes([]byte("Tyche-v1/silent-pvss/setup-vrf-cache"), raw))
}

func markSetupVrf(pp PublicParams) {
	if key := setupVrfCacheKey(pp); key != "" {
		setupVrfCache.Store(key, true)
	}
}

func (s *SilentSetupScheme) Share(dealer p2p.NodeID, seq uint64, secret kyber.Scalar) (Commitment, []byte, error) {
	if dealer != s.id {
		return Commitment{}, nil, fmt.Errorf("pvss scheme for %s cannot deal as %s", s.id, dealer)
	}
	group := suite()
	if secret == nil {
		secret = group.G1().Scalar().Pick(group.RandomStream())
	}
	gamma := group.G1().Scalar().Pick(group.RandomStream())
	v := randomScalars(group, matrixRows)
	c0 := group.G2().Point().Mul(gamma, baseG2(group))
	c1, err := s.encryptBody(group, c0, v)
	if err != nil {
		return Commitment{}, nil, err
	}
	c2 := group.GT().Point().Add(group.GT().Point().Mul(secret, s.gtPrime), group.GT().Point().Mul(v[4], s.pairingBase))
	out := Commitment{
		Dealer: dealer, Seq: seq, Epoch: s.pp.Epoch, Threshold: s.pp.Threshold,
		Members: normalizeMembers(s.pp.Members), C0: mustPointHex(c0), C1: c1, C2: mustPointHex(c2),
	}
	out.Proof = s.encProof(group, out, gamma, v, secret)
	out.SecretID = commitmentID(out)
	return out, mustPointBytes(group.GT().Point().Mul(secret, s.gtPrime)), nil
}

func (s *SilentSetupScheme) Verify(c Commitment) bool {
	if c.Dealer == "" || c.SecretID == "" || c.Epoch != s.pp.Epoch || c.Threshold != s.pp.Threshold || len(c.Members) < c.Threshold || len(c.C1) != matrixCols {
		return false
	}
	if commitmentID(c) != c.SecretID {
		return false
	}
	group := suite()
	c0, err := pointG2FromHex(c.C0)
	if err != nil {
		return false
	}
	sa1, sa2, ok := parseSilentCiphertext(c.C1)
	if !ok {
		return false
	}
	c2, err := pointGTFromHex(c.C2)
	if err != nil {
		return false
	}
	cp0, err := pointG2FromHex(c.Proof.CPrime.C0)
	if err != nil {
		return false
	}
	cpSa1, cpSa2, ok := parseSilentCiphertext(c.Proof.CPrime.C1)
	if !ok {
		return false
	}
	cp2, err := pointGTFromHex(c.Proof.CPrime.C2)
	if err != nil {
		return false
	}
	chal := scalarFromHex(group.G1(), c.Proof.Challenge)
	gammaHat := scalarFromHex(group.G1(), c.Proof.GammaResponse)
	secretHat := scalarFromHex(group.G1(), c.Proof.SecretResponse)
	vHat := scalarsFromHex(group.G1(), c.Proof.VResponses)
	if chal == nil || gammaHat == nil || secretHat == nil || len(vHat) != matrixRows {
		return false
	}
	if !encChallenge(group, c).Equal(chal) {
		return false
	}
	c0Check := group.G2().Point().Add(group.G2().Point().Mul(chal, c0), group.G2().Point().Mul(gammaHat, baseG2(group)))
	if !cp0.Equal(c0Check) {
		return false
	}
	avHat, err := s.encryptBody(group, c0, vHat)
	if err != nil {
		return false
	}
	avSa1, avSa2, ok := parseSilentCiphertext(avHat)
	if !ok {
		return false
	}
	for j := 0; j < sa1Cols; j++ {
		want := group.G1().Point().Add(group.G1().Point().Mul(chal, sa1[j]), avSa1[j])
		if !cpSa1[j].Equal(want) {
			return false
		}
	}
	for j := 0; j < sa2Cols; j++ {
		want := group.G2().Point().Add(group.G2().Point().Mul(chal, sa2[j]), avSa2[j])
		if !cpSa2[j].Equal(want) {
			return false
		}
	}
	c2Check := group.GT().Point().Add(group.GT().Point().Mul(chal, c2), group.GT().Point().Mul(vHat[4], s.pairingBase))
	c2Check.Add(c2Check, group.GT().Point().Mul(secretHat, s.gtPrime))
	return cp2.Equal(c2Check)
}

func (s *SilentSetupScheme) PreRecon(c Commitment, holder p2p.NodeID) (DecryptedShare, error) {
	if holder != s.id {
		return DecryptedShare{}, fmt.Errorf("pvss scheme for %s cannot decrypt as %s", s.id, holder)
	}
	if !s.Verify(c) {
		return DecryptedShare{}, errors.New("invalid pvss commitment")
	}
	return s.PreReconVerified(c, holder)
}

func (s *SilentSetupScheme) PreReconVerified(c Commitment, holder p2p.NodeID) (DecryptedShare, error) {
	if holder != s.id {
		return DecryptedShare{}, fmt.Errorf("pvss scheme for %s cannot decrypt as %s", s.id, holder)
	}
	group := suite()
	c0, err := pointG2FromHex(c.C0)
	if err != nil {
		return DecryptedShare{}, err
	}
	d := group.G2().Point().Mul(s.private, c0)
	proof := dleqProveG2(group, baseG2(group), c0, s.publicG2[holder], d, s.private)
	return DecryptedShare{CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(d), Proof: proof}, nil
}

func (s *SilentSetupScheme) VerifyShare(c Commitment, sh DecryptedShare) bool {
	if sh.CommitmentID != c.SecretID {
		return false
	}
	pk := s.publicG2[sh.Holder]
	if pk == nil {
		return false
	}
	c0, err := pointG2FromHex(c.C0)
	if err != nil {
		return false
	}
	d, err := pointG2FromHex(sh.Value)
	if err != nil {
		return false
	}
	return dleqVerifyG2(suite(), baseG2(suite()), c0, pk, d, sh.Proof)
}

func (s *SilentSetupScheme) Recon(c Commitment, shares []DecryptedShare) ([]byte, error) {
	if !s.Verify(c) {
		return nil, errors.New("invalid pvss commitment")
	}
	return s.ReconVerified(c, shares)
}

func (s *SilentSetupScheme) ReconVerified(c Commitment, shares []DecryptedShare) ([]byte, error) {
	return s.reconShares(c, shares, true)
}

func (s *SilentSetupScheme) ReconFromVerifiedShares(c Commitment, shares []DecryptedShare) ([]byte, error) {
	return s.reconShares(c, shares, false)
}

func (s *SilentSetupScheme) reconShares(c Commitment, shares []DecryptedShare, verifyProofs bool) ([]byte, error) {
	group := suite()
	index := memberIndex(c.Members)
	seen := make(map[p2p.NodeID]bool, len(shares))
	selected := make(map[p2p.NodeID]kyber.Point, len(shares))
	for _, sh := range shares {
		if seen[sh.Holder] || (verifyProofs && !s.VerifyShare(c, sh)) {
			continue
		}
		if _, ok := index[sh.Holder]; !ok {
			continue
		}
		d, err := pointG2FromHex(sh.Value)
		if err != nil {
			continue
		}
		seen[sh.Holder] = true
		selected[sh.Holder] = d
	}
	if len(selected) < c.Threshold {
		return nil, errors.New("not enough valid decrypted pvss shares")
	}
	sa1, sa2, ok := parseSilentCiphertext(c.C1)
	if !ok {
		return nil, errors.New("invalid silent-setup ciphertext encoding")
	}
	c2, err := pointGTFromHex(c.C2)
	if err != nil {
		return nil, err
	}
	c0, err := pointG2FromHex(c.C0)
	if err != nil {
		return nil, err
	}
	encKey, err := s.aggregateDecryptKey(group, c, c0, sa1, sa2, selected)
	if err != nil {
		return nil, err
	}
	secret := group.GT().Point().Sub(c2, encKey)
	return secret.MarshalBinary()
}

func NewPowerOfTau(size int) (PowerOfTauCRS, kyber.Scalar, error) {
	return newPowerOfTau(size, suite().RandomStream())
}

func newPowerOfTau(size int, stream cipher.Stream) (PowerOfTauCRS, kyber.Scalar, error) {
	if size <= 0 {
		return PowerOfTauCRS{}, nil, errors.New("power-of-tau size must be positive")
	}
	group := suite()
	tau := group.G1().Scalar().Pick(stream)
	if tau.Equal(group.G1().Scalar().Zero()) {
		tau = group.G1().Scalar().One()
	}
	pow := group.G1().Scalar().One()
	crs := PowerOfTauCRS{G1Powers: make([]string, size), G2Powers: make([]string, size)}
	for i := 0; i < size; i++ {
		crs.G1Powers[i] = mustPointHex(group.G1().Point().Mul(pow, baseG1(group)))
		crs.G2Powers[i] = mustPointHex(group.G2().Point().Mul(pow, baseG2(group)))
		pow.Mul(pow, tau)
	}
	return crs, tau, nil
}

func setupSeed(epoch string, threshold int, members []p2p.NodeID) []byte {
	parts := [][]byte{
		[]byte("Tyche-v1/silent-pvss/setup"),
		[]byte(epoch),
		[]byte(fmt.Sprintf("%d", threshold)),
	}
	for _, id := range members {
		parts = append(parts, []byte(id))
	}
	return HashBytes(parts...)
}

func VerifyPowerOfTau(crs PowerOfTauCRS) bool {
	if len(crs.G1Powers) == 0 || len(crs.G1Powers) != len(crs.G2Powers) {
		return false
	}
	group := suite()
	prev1, err := pointG1FromHex(crs.G1Powers[0])
	if err != nil || !prev1.Equal(baseG1(group)) {
		return false
	}
	prev2, err := pointG2FromHex(crs.G2Powers[0])
	if err != nil || !prev2.Equal(baseG2(group)) {
		return false
	}
	for i := 1; i < len(crs.G1Powers); i++ {
		g1i, err := pointG1FromHex(crs.G1Powers[i])
		if err != nil {
			return false
		}
		g2i, err := pointG2FromHex(crs.G2Powers[i])
		if err != nil {
			return false
		}
		if !group.Pair(g1i, prev2).Equal(group.Pair(prev1, g2i)) {
			return false
		}
		prev1, prev2 = g1i, g2i
	}
	return true
}

func KeyPairFromSeed(seed []byte) KeyPair {
	group := suite()
	sk := group.G1().Scalar().SetBytes(HashBytes([]byte("Tyche-v1/silent-pvss/key"), seed))
	if sk.Equal(group.G1().Scalar().Zero()) {
		sk = group.G1().Scalar().One()
	}
	return KeyPair{Private: sk, Public: group.G1().Point().Mul(sk, baseG1(group))}
}

func CommitmentID(c Commitment) string { return c.SecretID }

func RandomScalar() kyber.Scalar {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return suite().G1().Scalar().SetBytes(b)
}

func deriveSetupKey(group *bn256.Suite, slots []p2p.NodeID, id p2p.NodeID, idx int, sk, tau kyber.Scalar) SetupKey {
	li := lagrangeBasisAt(group.G1(), idx, tau, len(slots))
	li0 := lagrangeBasisAt(group.G1(), idx, group.G1().Scalar().Zero(), len(slots))
	zTau := vanishing(group.G1(), tau, len(slots))
	liMinusLi0 := group.G1().Scalar().Sub(li, li0)
	h5 := make(map[p2p.NodeID]string, len(slots))
	for j, other := range slots {
		lj := lagrangeBasisAt(group.G1(), j, tau, len(slots))
		var numerator kyber.Scalar
		if j == idx {
			numerator = group.G1().Scalar().Sub(group.G1().Scalar().Mul(li, li), li)
		} else {
			numerator = group.G1().Scalar().Mul(li, lj)
		}
		exp := group.G1().Scalar().Div(group.G1().Scalar().Mul(sk, numerator), zTau)
		h5[other] = mustPointHex(group.G1().Point().Mul(exp, baseG1(group)))
	}
	return SetupKey{
		PK1: mustPointHex(group.G1().Point().Mul(sk, baseG1(group))),
		PK2: mustPointHex(group.G2().Point().Mul(sk, baseG2(group))),
		H1:  mustPointHex(group.G1().Point().Mul(group.G1().Scalar().Mul(sk, li), baseG1(group))),
		H2:  mustPointHex(group.G1().Point().Mul(group.G1().Scalar().Div(group.G1().Scalar().Mul(sk, liMinusLi0), tau), baseG1(group))),
		H3:  mustPointHex(group.G1().Point().Mul(group.G1().Scalar().Div(group.G1().Scalar().Mul(sk, group.G1().Scalar().Sub(group.G1().Scalar().Mul(li, li), li)), zTau), baseG1(group))),
		H4:  mustPointHex(group.G1().Point().Mul(group.G1().Scalar().Mul(sk, liMinusLi0), baseG1(group))),
		H5:  h5,
	}
}

type setupVrfPolys struct {
	liG2        []kyber.Point
	liMinus0G2  []kyber.Point
	liOverXG2   []kyber.Point
	liLjOverZG2 [][]kyber.Point
}

func verifySetupKey(group *bn256.Suite, slots []p2p.NodeID, polys setupVrfPolys, id p2p.NodeID, k SetupKey) bool {
	pk1, err1 := pointG1FromHex(k.PK1)
	pk2, err2 := pointG2FromHex(k.PK2)
	if err1 != nil || err2 != nil || !group.Pair(pk1, baseG2(group)).Equal(group.Pair(baseG1(group), pk2)) {
		return false
	}
	idx, ok := slotIndexOf(slots, id)
	if !ok {
		return false
	}
	h1, err1 := pointG1FromHex(k.H1)
	h2, err2 := pointG1FromHex(k.H2)
	h3, err3 := pointG1FromHex(k.H3)
	h4, err4 := pointG1FromHex(k.H4)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return false
	}
	if !pairingEq(group, h1, baseG2(group), pk1, polys.liG2[idx]) ||
		!pairingEq(group, h2, baseG2(group), pk1, polys.liOverXG2[idx]) ||
		!pairingEq(group, h3, baseG2(group), pk1, polys.liLjOverZG2[idx][idx]) ||
		!pairingEq(group, h4, baseG2(group), pk1, polys.liMinus0G2[idx]) {
		return false
	}
	if len(k.H5) != len(slots) {
		return false
	}
	for j, other := range slots {
		h5, err := pointG1FromHex(k.H5[other])
		if err != nil {
			return false
		}
		if !pairingEq(group, h5, baseG2(group), pk1, polys.liLjOverZG2[idx][j]) {
			return false
		}
	}
	return true
}

func setupVerificationPolys(group *bn256.Suite, pot PowerOfTauCRS, slots []p2p.NodeID) (setupVrfPolys, error) {
	n := len(slots)
	out := setupVrfPolys{
		liG2:        make([]kyber.Point, n),
		liMinus0G2:  make([]kyber.Point, n),
		liOverXG2:   make([]kyber.Point, n),
		liLjOverZG2: make([][]kyber.Point, n),
	}
	lagrange := make([][]kyber.Scalar, n)
	vanish := vanishingPoly(group.G1(), n)
	for i := 0; i < n; i++ {
		li := lagrangeBasisPoly(group.G1(), i, n)
		lagrange[i] = li
		li0 := evalPoly(group.G1(), li, group.G1().Scalar().Zero())
		liMinus0 := polySubConst(group.G1(), li, li0)
		liOverX, err := divByLinear(group.G1(), liMinus0, group.G1().Scalar().Zero())
		if err != nil {
			return setupVrfPolys{}, err
		}
		out.liG2[i], err = commitPolyG2(group, pot, li)
		if err != nil {
			return setupVrfPolys{}, err
		}
		out.liMinus0G2[i], err = commitPolyG2(group, pot, liMinus0)
		if err != nil {
			return setupVrfPolys{}, err
		}
		out.liOverXG2[i], err = commitPolyG2(group, pot, liOverX)
		if err != nil {
			return setupVrfPolys{}, err
		}
		out.liLjOverZG2[i] = make([]kyber.Point, n)
	}
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			numerator := polyMul(group.G1(), lagrange[i], lagrange[j])
			if i == j {
				numerator = polySub(group.G1(), numerator, lagrange[i])
			}
			quotient, remainder, err := divPolyMonic(group.G1(), numerator, vanish)
			if err != nil || !polyIsZero(group.G1(), remainder) {
				return setupVrfPolys{}, errors.New("invalid setup verification polynomial")
			}
			out.liLjOverZG2[i][j], err = commitPolyG2(group, pot, quotient)
			if err != nil {
				return setupVrfPolys{}, err
			}
		}
	}
	return out, nil
}

func pairingEq(group *bn256.Suite, a1, a2, b1, b2 kyber.Point) bool {
	return group.Pair(a1, a2).Equal(group.Pair(b1, b2))
}

func slotIndexOf(slots []p2p.NodeID, id p2p.NodeID) (int, bool) {
	for i, candidate := range slots {
		if candidate == id {
			return i, true
		}
	}
	return -1, false
}

func deriveSilentKeys(group *bn256.Suite, slots []p2p.NodeID, real map[p2p.NodeID]SetupKey, dummy SetupKey) (EncryptionKey, AuditKey) {
	x := mustPoint(dummy.H1, pointG1FromHex)
	ak := AuditKey{
		Accepted: append([]p2p.NodeID{dummyID()}, slots[1:]...),
		H2:       make(map[p2p.NodeID]string), H3: make(map[p2p.NodeID]string),
		H4: make(map[p2p.NodeID]string), A: make(map[p2p.NodeID]string),
	}
	all := map[p2p.NodeID]SetupKey{dummyID(): dummy}
	for id, k := range real {
		all[id] = k
		x.Add(x, mustPoint(k.H1, pointG1FromHex))
	}
	for _, id := range ak.Accepted {
		k := all[id]
		ak.H2[id], ak.H3[id], ak.H4[id] = k.H2, k.H3, k.H4
		acc := group.G1().Point().Null()
		for _, j := range ak.Accepted {
			acc.Add(acc, mustPoint(all[j].H5[id], pointG1FromHex))
		}
		ak.A[id] = mustPointHex(acc)
	}
	return EncryptionKey{X: mustPointHex(x), Z: mustPointHex(baseG1(group))}, ak
}

func deriveMatrixA(group *bn256.Suite, epoch string, threshold int, pot PowerOfTauCRS, ek EncryptionKey, ak AuditKey) [][]string {
	out := make([][]string, matrixRows)
	for i := range out {
		out[i] = make([]string, matrixCols)
		for j := range out[i] {
			out[i][j] = mustPointHex(group.GT().Point().Null())
		}
	}
	g1 := baseG1(group)
	g2 := baseG2(group)
	pairG1 := func(p kyber.Point) string { return mustPointHex(group.Pair(p, g2)) }
	pairG2 := func(p kyber.Point) string { return mustPointHex(group.Pair(g1, p)) }
	g1Power := func(i int) kyber.Point {
		if i < 0 {
			i = 0
		}
		if i >= len(pot.G1Powers) {
			i = len(pot.G1Powers) - 1
		}
		return mustPoint(pot.G1Powers[i], pointG1FromHex)
	}
	g2Power := func(i int) kyber.Point {
		if i < 0 {
			i = 0
		}
		if i >= len(pot.G2Powers) {
			i = len(pot.G2Powers) - 1
		}
		return mustPoint(pot.G2Powers[i], pointG2FromHex)
	}
	x := mustPoint(ek.X, pointG1FromHex)
	z := mustPoint(ek.Z, pointG1FromHex)

	out[0][0] = pairG1(x)
	out[0][1] = pairG2(g2)
	out[0][2] = pairG1(z)
	out[0][3] = pairG2(g2Power(1))
	out[1][3] = pairG2(g2Power(1))
	out[1][4] = pairG2(g2)
	out[2][1] = pairG2(g2Power(1))
	out[2][5] = pairG1(g1)
	out[3][0] = pairG1(g1Power(threshold))
	out[3][6] = pairG2(g2)
	out[4][0] = pairG1(g1)
	out[4][7] = pairG1(g1Power(0))
	return out
}

func (s *SilentSetupScheme) encryptBody(group *bn256.Suite, gammaG2 kyber.Point, v []kyber.Scalar) ([]EncodedPoint, error) {
	if len(v) != matrixRows {
		return nil, errors.New("invalid encryption witness dimensions")
	}
	g1t, err := powerG1(group, s.pp.PowerOfTau, s.pp.Threshold+1)
	if err != nil {
		return nil, err
	}
	hTau, err := powerG2(group, s.pp.PowerOfTau, 1)
	if err != nil {
		return nil, err
	}
	sa1 := make([]kyber.Point, sa1Cols)
	sa2 := make([]kyber.Point, sa2Cols)
	sa1[0] = group.G1().Point().Add(group.G1().Point().Mul(v[0], s.ask), group.G1().Point().Mul(v[3], g1t))
	sa1[0].Add(sa1[0], group.G1().Point().Mul(v[4], baseG1(group)))
	sa1[1] = group.G1().Point().Mul(v[2], baseG1(group))
	sa2[0] = group.G2().Point().Add(group.G2().Point().Mul(v[0], baseG2(group)), group.G2().Point().Mul(v[2], gammaG2))
	sa2[1] = group.G2().Point().Mul(v[0], s.zG2)
	sa2[2] = group.G2().Point().Mul(group.G2().Scalar().Add(v[0], v[1]), hTau)
	sa2[3] = group.G2().Point().Mul(v[1], baseG2(group))
	sa2[4] = group.G2().Point().Mul(v[3], baseG2(group))
	sa2[5] = group.G2().Point().Mul(v[4], group.G2().Point().Add(hTau, s.hMinus1))
	out := make([]EncodedPoint, 0, matrixCols)
	out = append(out, pointsHexAs(sa1, "G1")...)
	out = append(out, pointsHexAs(sa2, "G2")...)
	return out, nil
}

func (s *SilentSetupScheme) aggregateDecryptKey(group *bn256.Suite, c Commitment, c0 kyber.Point, sa1, sa2 []kyber.Point, selected map[p2p.NodeID]kyber.Point) (kyber.Point, error) {
	plan, err := s.reconAggregationPlan(group, selected)
	if err != nil {
		return nil, err
	}
	sigma := group.G2().Point().Null()
	for _, id := range s.pp.Slots {
		partySelected := id == dummyID()
		if id != dummyID() {
			_, partySelected = selected[id]
		}
		if !partySelected {
			continue
		}
		slotIdx := s.slotIndex[id]
		shareWeight := group.G1().Scalar().Mul(plan.bEvals[slotIdx], s.lagrange0[id])
		if id == dummyID() {
			sigma.Add(sigma, group.G2().Point().Mul(shareWeight, c0))
		} else {
			sigma.Add(sigma, group.G2().Point().Mul(shareWeight, selected[id]))
		}
	}
	w1 := []kyber.Point{
		group.G1().Point().Neg(plan.apk),
		group.G1().Point().Neg(plan.qz),
		group.G1().Point().Neg(plan.qx),
		plan.qhatx,
		group.G1().Point().Neg(plan.bhatG1),
		group.G1().Point().Neg(plan.q0G1),
		sa1[0],
		sa1[1],
	}
	w2 := []kyber.Point{sa2[0], sa2[1], sa2[2], sa2[3], sa2[4], sa2[5], plan.bG2, sigma}
	out := group.GT().Point().Null()
	for i := range w1 {
		out.Add(out, group.Pair(w1[i], w2[i]))
	}
	return out, nil
}

func (s *SilentSetupScheme) reconAggregationPlan(group *bn256.Suite, selected map[p2p.NodeID]kyber.Point) (*reconAggregationPlan, error) {
	key := s.reconPlanKey(selected)
	s.reconPlanMu.Lock()
	if plan := s.reconPlans[key]; plan != nil {
		s.reconPlanMu.Unlock()
		return plan, nil
	}
	s.reconPlanMu.Unlock()

	points := make([]kyber.Scalar, 0, len(s.pp.Members)+1-len(selected))
	points = append(points, s.slotPoints[0])
	for i, id := range s.pp.Slots {
		if id == dummyID() {
			continue
		}
		if _, ok := selected[id]; !ok {
			points = append(points, s.slotPoints[i])
		}
	}
	b := interpolateMostlyZero(group.G1(), group.G1().Scalar().One(), points)
	bEvals := make([]kyber.Scalar, len(s.pp.Slots))
	for i := range s.pp.Slots {
		bEvals[i] = evalPoly(group.G1(), b, s.slotPoints[i])
	}
	bG2, err := s.commitPolyG2(group, b)
	if err != nil {
		return nil, err
	}
	q0, err := divByLinear(group.G1(), polySubConst(group.G1(), b, group.G1().Scalar().One()), s.slotPoints[0])
	if err != nil {
		return nil, err
	}
	q0G1, err := s.commitPolyG1(group, q0)
	if err != nil {
		return nil, err
	}
	bhat := make([]kyber.Scalar, s.pp.Threshold+1+len(b))
	for i := range b {
		bhat[s.pp.Threshold+1+i] = b[i]
	}
	bhatG1, err := s.commitPolyG1(group, bhat)
	if err != nil {
		return nil, err
	}
	apk := group.G1().Point().Null()
	qx := group.G1().Point().Null()
	qz := group.G1().Point().Null()
	qhatx := group.G1().Point().Null()
	for _, id := range s.pp.Slots {
		partySelected := id == dummyID()
		if id != dummyID() {
			_, partySelected = selected[id]
		}
		if !partySelected {
			continue
		}
		slotIdx := s.slotIndex[id]
		w := bEvals[slotIdx]
		shareWeight := group.G1().Scalar().Mul(w, s.lagrange0[id])
		apk.Add(apk, group.G1().Point().Mul(shareWeight, s.publicG1[id]))
		if hx := s.hintX[id]; hx != nil {
			qx.Add(qx, group.G1().Point().Mul(w, hx))
		}
		if hz := s.aggHints[id]; hz != nil {
			qz.Add(qz, group.G1().Point().Mul(w, hz))
		}
		if hm := s.hintMinus0[id]; hm != nil {
			qhatx.Add(qhatx, group.G1().Point().Mul(w, hm))
		}
	}
	plan := &reconAggregationPlan{
		bEvals: bEvals,
		bG2:    bG2,
		q0G1:   q0G1,
		bhatG1: bhatG1,
		apk:    apk,
		qx:     qx,
		qz:     qz,
		qhatx:  qhatx,
	}
	s.reconPlanMu.Lock()
	if existing := s.reconPlans[key]; existing != nil {
		s.reconPlanMu.Unlock()
		return existing, nil
	}
	if len(s.reconPlans) < reconPlanCacheLimit {
		s.reconPlans[key] = plan
	}
	s.reconPlanMu.Unlock()
	return plan, nil
}

func (s *SilentSetupScheme) reconPlanKey(selected map[p2p.NodeID]kyber.Point) string {
	indices := make([]int, 0, len(selected))
	for id := range selected {
		if idx, ok := s.slotIndex[id]; ok {
			indices = append(indices, idx)
		}
	}
	sort.Ints(indices)
	var buf bytes.Buffer
	for _, idx := range indices {
		fmt.Fprintf(&buf, "%d,", idx)
	}
	return buf.String()
}

func (s *SilentSetupScheme) encProof(group *bn256.Suite, c Commitment, gamma kyber.Scalar, v []kyber.Scalar, secret kyber.Scalar) Proof {
	gammaPrime := group.G1().Scalar().Pick(group.RandomStream())
	vPrime := randomScalars(group, matrixRows)
	secretPrime := group.G1().Scalar().Pick(group.RandomStream())
	c0Prime := group.G2().Point().Mul(gammaPrime, baseG2(group))
	c0, _ := pointG2FromHex(c.C0)
	c1Prime, _ := s.encryptBody(group, c0, vPrime)
	c2Prime := group.GT().Point().Add(group.GT().Point().Mul(secretPrime, s.gtPrime), group.GT().Point().Mul(vPrime[4], s.pairingBase))
	cp := CiphertextPrime{C0: mustPointHex(c0Prime), C1: c1Prime, C2: mustPointHex(c2Prime)}
	proof := Proof{CPrime: cp}
	tmp := c
	tmp.Proof = proof
	chal := encChallenge(group, tmp)
	proof.Challenge = scalarHex(chal)
	proof.GammaResponse = scalarHex(group.G1().Scalar().Sub(gammaPrime, group.G1().Scalar().Mul(chal, gamma)))
	proof.SecretResponse = scalarHex(group.G1().Scalar().Sub(secretPrime, group.G1().Scalar().Mul(chal, secret)))
	proof.VResponses = make([]string, matrixRows)
	for i := range v {
		proof.VResponses[i] = scalarHex(group.G1().Scalar().Sub(vPrime[i], group.G1().Scalar().Mul(chal, v[i])))
	}
	return proof
}

func encChallenge(group *bn256.Suite, c Commitment) kyber.Scalar {
	buf := bytes.Buffer{}
	buf.WriteString("Tyche-v1/silent-pvss/inst2")
	buf.WriteString(string(c.Dealer))
	buf.WriteByte('/')
	buf.WriteString(c.Epoch)
	buf.WriteByte('/')
	buf.WriteString(c.C0)
	for _, x := range c.C1 {
		buf.WriteByte('/')
		buf.WriteString(x.Group)
		buf.WriteByte(':')
		buf.WriteString(x.Value)
	}
	buf.WriteByte('/')
	buf.WriteString(c.C2)
	buf.WriteByte('/')
	buf.WriteString(c.Proof.CPrime.C0)
	for _, x := range c.Proof.CPrime.C1 {
		buf.WriteByte('/')
		buf.WriteString(x.Group)
		buf.WriteByte(':')
		buf.WriteString(x.Value)
	}
	buf.WriteByte('/')
	buf.WriteString(c.Proof.CPrime.C2)
	return group.G1().Scalar().SetBytes(HashBytes(buf.Bytes()))
}

func dleqProveG2(group *bn256.Suite, g, h, gx, hx kyber.Point, x kyber.Scalar) DecryptionProof {
	w := group.G2().Scalar().Pick(group.RandomStream())
	a := group.G2().Point().Mul(w, g)
	b := group.G2().Point().Mul(w, h)
	c := dleqChallengeG2(group, g, h, gx, hx, a, b)
	z := group.G2().Scalar().Add(w, group.G2().Scalar().Mul(c, x))
	return DecryptionProof{A: mustPointHex(a), B: mustPointHex(b), Challenge: scalarHex(c), Response: scalarHex(z)}
}

func dleqVerifyG2(group *bn256.Suite, g, h, gx, hx kyber.Point, proof DecryptionProof) bool {
	a, err := pointG2FromHex(proof.A)
	if err != nil {
		return false
	}
	b, err := pointG2FromHex(proof.B)
	if err != nil {
		return false
	}
	c := scalarFromHex(group.G2(), proof.Challenge)
	z := scalarFromHex(group.G2(), proof.Response)
	if c == nil || z == nil || !dleqChallengeG2(group, g, h, gx, hx, a, b).Equal(c) {
		return false
	}
	return group.G2().Point().Mul(z, g).Equal(group.G2().Point().Add(a, group.G2().Point().Mul(c, gx))) &&
		group.G2().Point().Mul(z, h).Equal(group.G2().Point().Add(b, group.G2().Point().Mul(c, hx)))
}

func dleqChallengeG2(group *bn256.Suite, g, h, gx, hx, a, b kyber.Point) kyber.Scalar {
	buf := bytes.Buffer{}
	buf.WriteString("Tyche-v1/silent-pvss/dleq-g2")
	for _, p := range []kyber.Point{g, h, gx, hx, a, b} {
		buf.WriteByte('/')
		buf.Write(mustPointBytes(p))
	}
	return group.G2().Scalar().SetBytes(HashBytes(buf.Bytes()))
}

func lagrangeBasisAt(group kyber.Group, i int, x kyber.Scalar, n int) kyber.Scalar {
	xi := group.Scalar().SetInt64(int64(i + 1))
	num := group.Scalar().One()
	den := group.Scalar().One()
	for j := 0; j < n; j++ {
		if j == i {
			continue
		}
		xj := group.Scalar().SetInt64(int64(j + 1))
		num.Mul(num, group.Scalar().Sub(x, xj))
		den.Mul(den, group.Scalar().Sub(xi, xj))
	}
	return group.Scalar().Div(num, den)
}

func vanishing(group kyber.Group, x kyber.Scalar, n int) kyber.Scalar {
	out := group.Scalar().One()
	for i := 0; i < n; i++ {
		xi := group.Scalar().SetInt64(int64(i + 1))
		out.Mul(out, group.Scalar().Sub(x, xi))
	}
	return out
}

func randomScalars(group *bn256.Suite, n int) []kyber.Scalar {
	out := make([]kyber.Scalar, n)
	for i := range out {
		out[i] = group.G1().Scalar().Pick(group.RandomStream())
	}
	return out
}

func suite() *bn256.Suite                   { return bn256.NewSuite() }
func baseG1(group *bn256.Suite) kyber.Point { return group.G1().Point().Base() }
func baseG2(group *bn256.Suite) kyber.Point { return group.G2().Point().Base() }

func gtPrime(group *bn256.Suite, epoch string) kyber.Point {
	x := group.GT().Scalar().SetBytes(HashBytes([]byte("Tyche-v1/silent-pvss/gt-prime/"), []byte(epoch)))
	if x.Equal(group.GT().Scalar().Zero()) {
		x = group.GT().Scalar().One()
	}
	return group.GT().Point().Mul(x, group.Pair(baseG1(group), baseG2(group)))
}

func hashGT(group *bn256.Suite, parts ...[]byte) kyber.Point {
	x := group.GT().Scalar().SetBytes(HashBytes(parts...))
	if x.Equal(group.GT().Scalar().Zero()) {
		x = group.GT().Scalar().One()
	}
	return group.GT().Point().Mul(x, group.Pair(baseG1(group), baseG2(group)))
}

func dummyID() p2p.NodeID { return "__dummy__" }

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

func slotIndex(slots []p2p.NodeID, id p2p.NodeID) int {
	for i, slot := range slots {
		if slot == id {
			return i
		}
	}
	return -1
}

func commitmentID(c Commitment) string {
	buf := bytes.Buffer{}
	buf.WriteString("Tyche-v1/silent-pvss/commitment/")
	buf.WriteString(string(c.Dealer))
	buf.WriteByte('/')
	buf.WriteString(c.Epoch)
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d/%d", c.Seq, c.Threshold))
	buf.WriteByte('/')
	buf.WriteString(c.C0)
	for _, x := range c.C1 {
		buf.WriteByte('/')
		buf.WriteString(x.Group)
		buf.WriteByte(':')
		buf.WriteString(x.Value)
	}
	buf.WriteByte('/')
	buf.WriteString(c.C2)
	buf.WriteByte('/')
	buf.WriteString(c.Proof.Challenge)
	for _, x := range c.Proof.VResponses {
		buf.WriteByte('/')
		buf.WriteString(x)
	}
	for _, member := range normalizeMembers(c.Members) {
		buf.WriteByte('/')
		buf.WriteString(string(member))
	}
	return hex.EncodeToString(HashBytes(buf.Bytes()))
}

func cloneParams(pp PublicParams) PublicParams {
	out := pp
	out.Members = append([]p2p.NodeID(nil), pp.Members...)
	out.Slots = append([]p2p.NodeID(nil), pp.Slots...)
	out.KeyShares = cloneStringMap(pp.KeyShares)
	out.RealKeys = make(map[p2p.NodeID]SetupKey, len(pp.RealKeys))
	for k, v := range pp.RealKeys {
		v.H5 = cloneStringMap(v.H5)
		out.RealKeys[k] = v
	}
	out.DummyKey.H5 = cloneStringMap(pp.DummyKey.H5)
	out.AK.Accepted = append([]p2p.NodeID(nil), pp.AK.Accepted...)
	out.AK.H2 = cloneStringMap(pp.AK.H2)
	out.AK.H3 = cloneStringMap(pp.AK.H3)
	out.AK.H4 = cloneStringMap(pp.AK.H4)
	out.AK.A = cloneStringMap(pp.AK.A)
	out.MatrixA = make([][]string, len(pp.MatrixA))
	for i := range pp.MatrixA {
		out.MatrixA[i] = append([]string(nil), pp.MatrixA[i]...)
	}
	out.PowerOfTau.G1Powers = append([]string(nil), pp.PowerOfTau.G1Powers...)
	out.PowerOfTau.G2Powers = append([]string(nil), pp.PowerOfTau.G2Powers...)
	return out
}

func cloneStringMap[T ~string](in map[p2p.NodeID]T) map[p2p.NodeID]T {
	out := make(map[p2p.NodeID]T, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func pointsHexAs(points []kyber.Point, group string) []EncodedPoint {
	out := make([]EncodedPoint, len(points))
	for i, p := range points {
		out[i] = EncodedPoint{Group: group, Value: mustPointHex(p)}
	}
	return out
}

func pointsGTFromEncoded(raw []EncodedPoint) ([]kyber.Point, error) {
	out := make([]kyber.Point, len(raw))
	for i, x := range raw {
		if x.Group != "GT" {
			return nil, fmt.Errorf("expected GT point, got %s", x.Group)
		}
		p, err := pointGTFromHex(x.Value)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

func parseSilentCiphertext(raw []EncodedPoint) ([]kyber.Point, []kyber.Point, bool) {
	if len(raw) != matrixCols {
		return nil, nil, false
	}
	sa1 := make([]kyber.Point, sa1Cols)
	sa2 := make([]kyber.Point, sa2Cols)
	for i := 0; i < sa1Cols; i++ {
		if raw[i].Group != "G1" {
			return nil, nil, false
		}
		p, err := pointG1FromHex(raw[i].Value)
		if err != nil {
			return nil, nil, false
		}
		sa1[i] = p
	}
	for i := 0; i < sa2Cols; i++ {
		if raw[sa1Cols+i].Group != "G2" {
			return nil, nil, false
		}
		p, err := pointG2FromHex(raw[sa1Cols+i].Value)
		if err != nil {
			return nil, nil, false
		}
		sa2[i] = p
	}
	return sa1, sa2, true
}

func powerG1(group *bn256.Suite, pot PowerOfTauCRS, i int) (kyber.Point, error) {
	if i < 0 || i >= len(pot.G1Powers) {
		return nil, errors.New("missing G1 power")
	}
	return pointG1FromHex(pot.G1Powers[i])
}

func powerG2(group *bn256.Suite, pot PowerOfTauCRS, i int) (kyber.Point, error) {
	if i < 0 || i >= len(pot.G2Powers) {
		return nil, errors.New("missing G2 power")
	}
	return pointG2FromHex(pot.G2Powers[i])
}

func commitPolyG1(group *bn256.Suite, pot PowerOfTauCRS, coeffs []kyber.Scalar) (kyber.Point, error) {
	if len(coeffs) > len(pot.G1Powers) {
		return nil, errors.New("polynomial degree exceeds G1 power-of-tau")
	}
	out := group.G1().Point().Null()
	for i, coeff := range coeffs {
		if coeff == nil {
			continue
		}
		p, err := pointG1FromHex(pot.G1Powers[i])
		if err != nil {
			return nil, err
		}
		out.Add(out, group.G1().Point().Mul(coeff, p))
	}
	return out, nil
}

func commitPolyG2(group *bn256.Suite, pot PowerOfTauCRS, coeffs []kyber.Scalar) (kyber.Point, error) {
	if len(coeffs) > len(pot.G2Powers) {
		return nil, errors.New("polynomial degree exceeds G2 power-of-tau")
	}
	out := group.G2().Point().Null()
	for i, coeff := range coeffs {
		if coeff == nil {
			continue
		}
		p, err := pointG2FromHex(pot.G2Powers[i])
		if err != nil {
			return nil, err
		}
		out.Add(out, group.G2().Point().Mul(coeff, p))
	}
	return out, nil
}

func (s *SilentSetupScheme) commitPolyG1(group *bn256.Suite, coeffs []kyber.Scalar) (kyber.Point, error) {
	if len(coeffs) > len(s.g1Powers) {
		return nil, errors.New("polynomial degree exceeds G1 power-of-tau")
	}
	out := group.G1().Point().Null()
	for i, coeff := range coeffs {
		if coeff == nil {
			continue
		}
		out.Add(out, group.G1().Point().Mul(coeff, s.g1Powers[i]))
	}
	return out, nil
}

func (s *SilentSetupScheme) commitPolyG2(group *bn256.Suite, coeffs []kyber.Scalar) (kyber.Point, error) {
	if len(coeffs) > len(s.g2Powers) {
		return nil, errors.New("polynomial degree exceeds G2 power-of-tau")
	}
	out := group.G2().Point().Null()
	for i, coeff := range coeffs {
		if coeff == nil {
			continue
		}
		out.Add(out, group.G2().Point().Mul(coeff, s.g2Powers[i]))
	}
	return out, nil
}

func vanishingCommitG2(group *bn256.Suite, pot PowerOfTauCRS, n int) (kyber.Point, error) {
	z := []kyber.Scalar{group.G1().Scalar().One()}
	for i := 0; i < n; i++ {
		z = mulPolyLinear(group.G1(), z, group.G1().Scalar().Neg(slotPoint(group, i)))
	}
	return commitPolyG2(group, pot, z)
}

func slotPoint(group *bn256.Suite, i int) kyber.Scalar {
	return group.G1().Scalar().SetInt64(int64(i + 1))
}

func lagrangeBasisPoly(group kyber.Group, i int, n int) []kyber.Scalar {
	xi := group.Scalar().SetInt64(int64(i + 1))
	out := []kyber.Scalar{group.Scalar().One()}
	den := group.Scalar().One()
	for j := 0; j < n; j++ {
		if j == i {
			continue
		}
		xj := group.Scalar().SetInt64(int64(j + 1))
		out = mulPolyLinear(group, out, group.Scalar().Neg(xj))
		den.Mul(den, group.Scalar().Sub(xi, xj))
	}
	factor := group.Scalar().Div(group.Scalar().One(), den)
	for k := range out {
		out[k] = group.Scalar().Mul(out[k], factor)
	}
	return out
}

func vanishingPoly(group kyber.Group, n int) []kyber.Scalar {
	out := []kyber.Scalar{group.Scalar().One()}
	for i := 0; i < n; i++ {
		out = mulPolyLinear(group, out, group.Scalar().Neg(group.Scalar().SetInt64(int64(i+1))))
	}
	return out
}

func interpolateMostlyZero(group kyber.Group, eval kyber.Scalar, points []kyber.Scalar) []kyber.Scalar {
	if len(points) == 0 {
		return []kyber.Scalar{group.Scalar().One()}
	}
	out := []kyber.Scalar{group.Scalar().One()}
	for _, point := range points[1:] {
		out = mulPolyLinear(group, out, group.Scalar().Neg(point))
	}
	scale := evalPoly(group, out, points[0])
	factor := group.Scalar().Div(eval, scale)
	for i := range out {
		out[i] = group.Scalar().Mul(out[i], factor)
	}
	return out
}

func mulPolyLinear(group kyber.Group, coeffs []kyber.Scalar, constant kyber.Scalar) []kyber.Scalar {
	out := make([]kyber.Scalar, len(coeffs)+1)
	for i := range out {
		out[i] = group.Scalar().Zero()
	}
	for i, coeff := range coeffs {
		out[i].Add(out[i], group.Scalar().Mul(coeff, constant))
		out[i+1].Add(out[i+1], coeff)
	}
	return out
}

func polyMul(group kyber.Group, a, b []kyber.Scalar) []kyber.Scalar {
	if len(a) == 0 || len(b) == 0 {
		return []kyber.Scalar{group.Scalar().Zero()}
	}
	out := make([]kyber.Scalar, len(a)+len(b)-1)
	for i := range out {
		out[i] = group.Scalar().Zero()
	}
	for i, ai := range a {
		for j, bj := range b {
			out[i+j].Add(out[i+j], group.Scalar().Mul(ai, bj))
		}
	}
	return trimPoly(group, out)
}

func polySub(group kyber.Group, a, b []kyber.Scalar) []kyber.Scalar {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make([]kyber.Scalar, n)
	for i := range out {
		out[i] = group.Scalar().Zero()
		if i < len(a) {
			out[i].Add(out[i], a[i])
		}
		if i < len(b) {
			out[i].Sub(out[i], b[i])
		}
	}
	return trimPoly(group, out)
}

func divPolyMonic(group kyber.Group, numerator, denominator []kyber.Scalar) ([]kyber.Scalar, []kyber.Scalar, error) {
	numerator = trimPoly(group, numerator)
	denominator = trimPoly(group, denominator)
	if len(denominator) == 0 || polyIsZero(group, denominator) {
		return nil, nil, errors.New("division by zero polynomial")
	}
	if len(numerator) < len(denominator) {
		return []kyber.Scalar{group.Scalar().Zero()}, numerator, nil
	}
	lead := denominator[len(denominator)-1]
	if !lead.Equal(group.Scalar().One()) {
		return nil, nil, errors.New("non-monic polynomial divisor")
	}
	rem := make([]kyber.Scalar, len(numerator))
	for i, coeff := range numerator {
		rem[i] = coeff.Clone()
	}
	quot := make([]kyber.Scalar, len(numerator)-len(denominator)+1)
	for i := range quot {
		quot[i] = group.Scalar().Zero()
	}
	for deg := len(numerator) - 1; deg >= len(denominator)-1; deg-- {
		factor := rem[deg].Clone()
		qIdx := deg - len(denominator) + 1
		quot[qIdx] = factor.Clone()
		if factor.Equal(group.Scalar().Zero()) {
			continue
		}
		for j := 0; j < len(denominator); j++ {
			rem[qIdx+j].Sub(rem[qIdx+j], group.Scalar().Mul(factor, denominator[j]))
		}
	}
	return trimPoly(group, quot), trimPoly(group, rem[:len(denominator)-1]), nil
}

func trimPoly(group kyber.Group, coeffs []kyber.Scalar) []kyber.Scalar {
	last := len(coeffs) - 1
	for last > 0 && coeffs[last].Equal(group.Scalar().Zero()) {
		last--
	}
	out := make([]kyber.Scalar, last+1)
	for i := range out {
		out[i] = coeffs[i].Clone()
	}
	return out
}

func polyIsZero(group kyber.Group, coeffs []kyber.Scalar) bool {
	for _, coeff := range coeffs {
		if coeff != nil && !coeff.Equal(group.Scalar().Zero()) {
			return false
		}
	}
	return true
}

func evalPoly(group kyber.Group, coeffs []kyber.Scalar, x kyber.Scalar) kyber.Scalar {
	out := group.Scalar().Zero()
	pow := group.Scalar().One()
	for _, coeff := range coeffs {
		out.Add(out, group.Scalar().Mul(coeff, pow))
		pow.Mul(pow, x)
	}
	return out
}

func polySubConst(group kyber.Group, coeffs []kyber.Scalar, c kyber.Scalar) []kyber.Scalar {
	out := make([]kyber.Scalar, len(coeffs))
	for i, coeff := range coeffs {
		out[i] = coeff.Clone()
	}
	if len(out) == 0 {
		out = []kyber.Scalar{group.Scalar().Zero()}
	}
	out[0].Sub(out[0], c)
	return out
}

func divByLinear(group kyber.Group, coeffs []kyber.Scalar, root kyber.Scalar) ([]kyber.Scalar, error) {
	if len(coeffs) < 2 {
		return nil, errors.New("polynomial degree too small for division")
	}
	n := len(coeffs) - 1
	out := make([]kyber.Scalar, n)
	out[n-1] = coeffs[n].Clone()
	for i := n - 2; i >= 0; i-- {
		out[i] = group.Scalar().Add(coeffs[i+1], group.Scalar().Mul(root, out[i+1]))
	}
	rem := group.Scalar().Add(coeffs[0], group.Scalar().Mul(root, out[0]))
	if !rem.Equal(group.Scalar().Zero()) {
		return nil, errors.New("non-zero polynomial division remainder")
	}
	return out, nil
}

func scalarsFromHex(group kyber.Group, raw []string) []kyber.Scalar {
	out := make([]kyber.Scalar, len(raw))
	for i, x := range raw {
		out[i] = scalarFromHex(group, x)
		if out[i] == nil {
			return nil
		}
	}
	return out
}

func mustPoint[T kyber.Point](raw string, f func(string) (T, error)) T {
	p, err := f(raw)
	if err != nil {
		panic(err)
	}
	return p
}

func mustPointBytes(p kyber.Point) []byte {
	b, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

func mustPointHex(p kyber.Point) string { return hex.EncodeToString(mustPointBytes(p)) }

func pointG1FromHex(raw string) (kyber.Point, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	p := suite().G1().Point()
	return p, p.UnmarshalBinary(b)
}

func pointG2FromHex(raw string) (kyber.Point, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	p := suite().G2().Point()
	return p, p.UnmarshalBinary(b)
}

func pointGTFromHex(raw string) (kyber.Point, error) {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	p := suite().GT().Point()
	return p, p.UnmarshalBinary(b)
}

func scalarHex(s kyber.Scalar) string {
	b, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func scalarFromHex(group kyber.Group, raw string) kyber.Scalar {
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil
	}
	s := group.Scalar()
	if err := s.UnmarshalBinary(b); err != nil {
		return nil
	}
	return s
}
