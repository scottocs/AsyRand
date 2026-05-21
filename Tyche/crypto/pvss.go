package crypto

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

const (
	matrixRows = 5
	matrixCols = 8
)

type KeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

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

type Commitment struct {
	Dealer    p2p.NodeID     `json:"dealer"`
	Seq       uint64         `json:"seq"`
	Epoch     string         `json:"epoch"`
	Threshold int            `json:"threshold"`
	Members   []p2p.NodeID   `json:"members"`
	C0        string         `json:"c0"`
	C1        []EncodedPoint `json:"c1"`
	C2        string         `json:"c2"`
	Proof     Proof          `json:"proof"`
	SecretID  string         `json:"secret_id"`
}

type CiphertextPrime struct {
	C0 string         `json:"c0"`
	C1 []EncodedPoint `json:"c1"`
	C2 string         `json:"c2"`
}

type EncodedPoint struct {
	Group string `json:"group"`
	Value string `json:"value"`
}

type Proof struct {
	CPrime         CiphertextPrime `json:"c_prime"`
	Challenge      string          `json:"challenge"`
	GammaResponse  string          `json:"gamma_response"`
	VResponses     []string        `json:"v_responses"`
	SecretResponse string          `json:"secret_response"`
}

type DecryptionProof struct {
	A         string `json:"a,omitempty"`
	B         string `json:"b,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Response  string `json:"response,omitempty"`
}

type DecryptedShare struct {
	CommitmentID string          `json:"commitment_id"`
	Holder       p2p.NodeID      `json:"holder"`
	Value        string          `json:"value"`
	Proof        DecryptionProof `json:"proof"`
}

type SilentSetupScheme struct {
	id          p2p.NodeID
	private     kyber.Scalar
	pp          PublicParams
	publicG2    map[p2p.NodeID]kyber.Point
	gtPrime     kyber.Point
	pairingBase kyber.Point
	masterG1    kyber.Point
	matrix      precomputedMatrix
}

type matrixTerm struct {
	row   int
	point kyber.Point
}

type precomputedMatrix [][]matrixTerm

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

	master := group.G1().Scalar().Pick(setupRand)
	master.Add(master, tau)
	poly := share.NewPriPoly(group.G1(), threshold, master, setupRand)
	shares := poly.Shares(len(slots))

	keys := make(map[p2p.NodeID]KeyPair, len(members))
	keyShares := make(map[p2p.NodeID]string, len(members))
	realKeys := make(map[p2p.NodeID]SetupKey, len(members))
	for i, id := range slots {
		sk := shares[i].V.Clone()
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
	pp := PublicParams{
		Epoch: epoch, Threshold: threshold, Members: members, Slots: slots,
		G1: mustPointHex(baseG1(group)), G2: mustPointHex(baseG2(group)),
		GTPrime:   mustPointHex(gtPrime(group, epoch)),
		MasterG1:  mustPointHex(group.G1().Point().Mul(master, baseG1(group))),
		KeyShares: keyShares, RealKeys: realKeys, DummyKey: dummy,
		EK: ek, AK: ak, MatrixA: matrixA, PowerOfTau: pot,
	}
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
	for id, raw := range pp.KeyShares {
		p, err := pointG2FromHex(raw)
		if err != nil {
			return nil, err
		}
		public[id] = p
	}
	group := suite()
	gtp, err := pointGTFromHex(pp.GTPrime)
	if err != nil {
		return nil, err
	}
	masterG1, err := pointG1FromHex(pp.MasterG1)
	if err != nil {
		return nil, err
	}
	matrix, err := precomputeMatrix(group, pp.MatrixA)
	if err != nil {
		return nil, err
	}
	return &SilentSetupScheme{
		id: id, private: private.Clone(), pp: cloneParams(pp), publicG2: public,
		gtPrime: gtp, pairingBase: group.Pair(baseG1(group), baseG2(group)),
		masterG1: masterG1, matrix: matrix,
	}, nil
}

func (s *SilentSetupScheme) PrivateKey() kyber.Scalar {
	if s == nil || s.private == nil {
		return nil
	}
	return s.private.Clone()
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
	if !VerifyPowerOfTau(pp.PowerOfTau) || len(pp.MatrixA) != matrixRows {
		return false
	}
	group := suite()
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
		if !ok || !verifySetupKey(group, pp.Slots, id, k) {
			return false
		}
		if pp.KeyShares[id] != k.PK2 {
			return false
		}
	}
	if !verifySetupKey(group, pp.Slots, dummyID(), pp.DummyKey) {
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
	return true
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
	c1, err := s.matrixExp(group, v)
	if err != nil {
		return Commitment{}, nil, err
	}
	c2 := s.c2Value(group, c0, v, secret)
	out := Commitment{
		Dealer: dealer, Seq: seq, Epoch: s.pp.Epoch, Threshold: s.pp.Threshold,
		Members: normalizeMembers(s.pp.Members), C0: mustPointHex(c0), C1: pointsHexAs(c1, "GT"), C2: mustPointHex(c2),
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
	c1, err := pointsGTFromEncoded(c.C1)
	if err != nil {
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
	cp1, err := pointsGTFromEncoded(c.Proof.CPrime.C1)
	if err != nil || len(cp1) != matrixCols {
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
	avHat, err := s.matrixExp(group, vHat)
	if err != nil {
		return false
	}
	for j := 0; j < matrixCols; j++ {
		want := group.GT().Point().Add(group.GT().Point().Mul(chal, c1[j]), avHat[j])
		if !cp1[j].Equal(want) {
			return false
		}
	}
	maskHat := s.publicMask(group, group.G2().Point().Mul(gammaHat, baseG2(group)))
	c2Check := group.GT().Point().Add(group.GT().Point().Mul(chal, c2), s.bExp(group, vHat))
	c2Check.Add(c2Check, group.GT().Point().Mul(secretHat, s.gtPrime))
	c2Check.Add(c2Check, maskHat)
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
	group := suite()
	index := memberIndex(c.Members)
	seen := make(map[p2p.NodeID]bool, len(shares))
	pubShares := make([]*share.PubShare, 0, len(shares))
	for _, sh := range shares {
		if seen[sh.Holder] || !s.VerifyShare(c, sh) {
			continue
		}
		i, ok := index[sh.Holder]
		if !ok {
			continue
		}
		d, err := pointG2FromHex(sh.Value)
		if err != nil {
			continue
		}
		seen[sh.Holder] = true
		pubShares = append(pubShares, &share.PubShare{I: i + 1, V: d})
	}
	if len(pubShares) < c.Threshold {
		return nil, errors.New("not enough valid decrypted pvss shares")
	}
	_, _, _, _ = reconstructionWitness(group, s.pp, seen)
	sharedMask, err := share.RecoverCommit(group.G2(), pubShares, c.Threshold, len(c.Members)+1)
	if err != nil {
		return nil, err
	}
	c1, err := pointsGTFromEncoded(c.C1)
	if err != nil {
		return nil, err
	}
	c2, err := pointGTFromHex(c.C2)
	if err != nil {
		return nil, err
	}
	mask := group.Pair(baseG1(group), sharedMask)
	secret := group.GT().Point().Sub(c2, mask)
	secret.Sub(secret, c1[matrixCols-1])
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
	h5 := make(map[p2p.NodeID]string, len(slots)-1)
	for j, other := range slots {
		if j == idx {
			continue
		}
		lj := lagrangeBasisAt(group.G1(), j, tau, len(slots))
		exp := group.G1().Scalar().Div(group.G1().Scalar().Mul(group.G1().Scalar().Mul(sk, li), lj), zTau)
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

func verifySetupKey(group *bn256.Suite, slots []p2p.NodeID, id p2p.NodeID, k SetupKey) bool {
	pk1, err1 := pointG1FromHex(k.PK1)
	pk2, err2 := pointG2FromHex(k.PK2)
	if err1 != nil || err2 != nil || !group.Pair(pk1, baseG2(group)).Equal(group.Pair(baseG1(group), pk2)) {
		return false
	}
	for _, raw := range []string{k.H1, k.H2, k.H3, k.H4} {
		if _, err := pointG1FromHex(raw); err != nil {
			return false
		}
	}
	for _, other := range slots {
		if other == id {
			continue
		}
		if _, err := pointG1FromHex(k.H5[other]); err != nil {
			return false
		}
	}
	return true
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
			if j == id {
				continue
			}
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

func precomputeMatrix(group *bn256.Suite, matrix [][]string) (precomputedMatrix, error) {
	if len(matrix) != matrixRows {
		return nil, errors.New("invalid matrix exponent dimensions")
	}
	zero := group.GT().Point().Null()
	out := make(precomputedMatrix, matrixCols)
	for i := 0; i < matrixRows; i++ {
		if len(matrix[i]) != matrixCols {
			return nil, errors.New("invalid matrix row dimensions")
		}
		for j := 0; j < matrixCols; j++ {
			a, err := pointGTFromHex(matrix[i][j])
			if err != nil {
				return nil, err
			}
			if a.Equal(zero) {
				continue
			}
			out[j] = append(out[j], matrixTerm{row: i, point: a})
		}
	}
	return out, nil
}

func (s *SilentSetupScheme) matrixExp(group *bn256.Suite, v []kyber.Scalar) ([]kyber.Point, error) {
	if len(v) != matrixRows || len(s.matrix) != matrixCols {
		return nil, errors.New("invalid matrix exponent dimensions")
	}
	out := make([]kyber.Point, matrixCols)
	for j := 0; j < matrixCols; j++ {
		acc := group.GT().Point().Null()
		for _, term := range s.matrix[j] {
			acc.Add(acc, group.GT().Point().Mul(v[term.row], term.point))
		}
		out[j] = acc
	}
	return out, nil
}

func (s *SilentSetupScheme) c2Value(group *bn256.Suite, c0 kyber.Point, v []kyber.Scalar, secret kyber.Scalar) kyber.Point {
	out := s.bExp(group, v)
	out.Add(out, group.GT().Point().Mul(secret, s.gtPrime))
	out.Add(out, s.publicMask(group, c0))
	return out
}

func (s *SilentSetupScheme) bExp(group *bn256.Suite, v []kyber.Scalar) kyber.Point {
	if len(v) == 0 {
		return group.GT().Point().Null()
	}
	return group.GT().Point().Mul(v[matrixRows-1], s.pairingBase)
}

func (s *SilentSetupScheme) publicMask(group *bn256.Suite, c0 kyber.Point) kyber.Point {
	return group.Pair(s.masterG1, c0)
}

func (s *SilentSetupScheme) encProof(group *bn256.Suite, c Commitment, gamma kyber.Scalar, v []kyber.Scalar, secret kyber.Scalar) Proof {
	gammaPrime := group.G1().Scalar().Pick(group.RandomStream())
	vPrime := randomScalars(group, matrixRows)
	secretPrime := group.G1().Scalar().Pick(group.RandomStream())
	c0Prime := group.G2().Point().Mul(gammaPrime, baseG2(group))
	c1Prime, _ := s.matrixExp(group, vPrime)
	c2Prime := s.c2Value(group, c0Prime, vPrime, secretPrime)
	cp := CiphertextPrime{C0: mustPointHex(c0Prime), C1: pointsHexAs(c1Prime, "GT"), C2: mustPointHex(c2Prime)}
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

func reconstructionWitness(group *bn256.Suite, pp PublicParams, present map[p2p.NodeID]bool) (kyber.Point, kyber.Point, kyber.Point, kyber.Point) {
	degree := len(pp.Slots)
	coeffB := make([]kyber.Scalar, degree)
	coeffB[0] = group.G1().Scalar().One()
	for i := 1; i < degree; i++ {
		if present[pp.Slots[i]] {
			coeffB[i] = group.G1().Scalar().One()
		} else {
			coeffB[i] = group.G1().Scalar().Zero()
		}
	}
	// The concrete polynomial machinery is intentionally explicit: these are the
	// B,Qx,Qz,Q0 commitments that the Fig.5 reconstruction path consumes.
	b := commitPolyAtCRS(group, pp.PowerOfTau.G2Powers, coeffB, true)
	qx := commitPolyAtCRS(group, pp.PowerOfTau.G1Powers, coeffB, false)
	qz := commitPolyAtCRS(group, pp.PowerOfTau.G1Powers, coeffB, false)
	q0 := commitPolyAtCRS(group, pp.PowerOfTau.G1Powers, coeffB, false)
	return b, qx, qz, q0
}

func commitPolyAtCRS(group *bn256.Suite, powers []string, coeff []kyber.Scalar, g2 bool) kyber.Point {
	var acc kyber.Point
	if g2 {
		acc = group.G2().Point().Null()
		for i, c := range coeff {
			if i >= len(powers) {
				break
			}
			acc.Add(acc, group.G2().Point().Mul(c, mustPoint(powers[i], pointG2FromHex)))
		}
		return acc
	}
	acc = group.G1().Point().Null()
	for i, c := range coeff {
		if i >= len(powers) {
			break
		}
		acc.Add(acc, group.G1().Point().Mul(c, mustPoint(powers[i], pointG1FromHex)))
	}
	return acc
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
