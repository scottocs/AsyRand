package crypto

import (
	"bytes"
	"errors"
	"fmt"

	"tyche.local/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

type ScrapeDDHParams struct {
	Epoch      string                `json:"epoch"`
	Threshold  int                   `json:"threshold"`
	Members    []p2p.NodeID          `json:"members"`
	G          string                `json:"g"`
	H          string                `json:"h"`
	PublicKeys map[p2p.NodeID]string `json:"public_keys"`
}

type ScrapeDDHDistributionProof struct {
	A1        []EncodedPoint `json:"a1"`
	A2        []EncodedPoint `json:"a2"`
	Challenge string         `json:"challenge"`
	Responses []string       `json:"responses"`
}

type ScrapeDDHScheme struct {
	id      p2p.NodeID
	private kyber.Scalar
	pp      ScrapeDDHParams
	g       kyber.Point
	h       kyber.Point
	public  map[p2p.NodeID]kyber.Point
}

func ScrapeDDHSetup(epoch string, threshold int, members []p2p.NodeID) (ScrapeDDHParams, map[p2p.NodeID]KeyPair, error) {
	members = normalizeMembers(members)
	if epoch == "" {
		return ScrapeDDHParams{}, nil, errors.New("scrape-ddh epoch is required")
	}
	if threshold <= 0 || len(members) < threshold {
		return ScrapeDDHParams{}, nil, errors.New("invalid scrape-ddh threshold")
	}
	group := suite()
	setupRand := group.XOF(setupSeed(epoch, threshold, members))
	g := baseG1(group)
	h := hashG1(group, []byte("Tyche-v1/scrape-ddh/h/"), []byte(epoch))
	keys := make(map[p2p.NodeID]KeyPair, len(members))
	pubs := make(map[p2p.NodeID]string, len(members))
	for _, id := range members {
		sk := group.G1().Scalar().Pick(setupRand)
		if sk.Equal(group.G1().Scalar().Zero()) {
			sk = group.G1().Scalar().One()
		}
		pk := group.G1().Point().Mul(sk, h)
		keys[id] = KeyPair{Private: sk, Public: pk}
		pubs[id] = mustPointHex(pk)
	}
	pp := ScrapeDDHParams{
		Epoch: epoch, Threshold: threshold, Members: members,
		G: mustPointHex(g), H: mustPointHex(h), PublicKeys: pubs,
	}
	return pp, keys, nil
}

func NewScrapeDDHScheme(id p2p.NodeID, private kyber.Scalar, pp ScrapeDDHParams) (*ScrapeDDHScheme, error) {
	if id == "" {
		return nil, errors.New("scrape-ddh node id is required")
	}
	if private == nil {
		return nil, errors.New("scrape-ddh private key is required")
	}
	if !ScrapeDDHSetupVrf(pp) {
		return nil, errors.New("invalid scrape-ddh parameters")
	}
	pp.Members = normalizeMembers(pp.Members)
	g, err := pointG1FromHex(pp.G)
	if err != nil {
		return nil, err
	}
	h, err := pointG1FromHex(pp.H)
	if err != nil {
		return nil, err
	}
	public := make(map[p2p.NodeID]kyber.Point, len(pp.PublicKeys))
	for id, raw := range pp.PublicKeys {
		pk, err := pointG1FromHex(raw)
		if err != nil {
			return nil, err
		}
		public[id] = pk
	}
	return &ScrapeDDHScheme{id: id, private: private.Clone(), pp: cloneScrapeDDHParams(pp), g: g, h: h, public: public}, nil
}

func ScrapeDDHSetupVrf(pp ScrapeDDHParams) bool {
	if pp.Epoch == "" || pp.Threshold <= 0 || len(pp.Members) < pp.Threshold || len(pp.PublicKeys) != len(pp.Members) {
		return false
	}
	if _, err := pointG1FromHex(pp.G); err != nil {
		return false
	}
	if _, err := pointG1FromHex(pp.H); err != nil {
		return false
	}
	for _, id := range normalizeMembers(pp.Members) {
		if _, ok := pp.PublicKeys[id]; !ok {
			return false
		}
		if _, err := pointG1FromHex(pp.PublicKeys[id]); err != nil {
			return false
		}
	}
	return true
}

func (s *ScrapeDDHScheme) Params() ScrapeDDHParams {
	if s == nil {
		return ScrapeDDHParams{}
	}
	return cloneScrapeDDHParams(s.pp)
}

func (s *ScrapeDDHScheme) Epoch() string {
	if s == nil {
		return ""
	}
	return s.pp.Epoch
}

func (s *ScrapeDDHScheme) PrivateKey() kyber.Scalar {
	if s == nil || s.private == nil {
		return nil
	}
	return s.private.Clone()
}

func (s *ScrapeDDHScheme) Share(dealer p2p.NodeID, seq uint64, secret kyber.Scalar) (Commitment, []byte, error) {
	if dealer != s.id {
		return Commitment{}, nil, fmt.Errorf("scrape-ddh scheme for %s cannot deal as %s", s.id, dealer)
	}
	group := suite()
	if secret == nil {
		secret = group.G1().Scalar().Pick(group.RandomStream())
	}
	coeff := make([]kyber.Scalar, s.pp.Threshold)
	coeff[0] = secret.Clone()
	for i := 1; i < len(coeff); i++ {
		coeff[i] = group.G1().Scalar().Pick(group.RandomStream())
	}
	shares := evalPolynomial(group.G1(), coeff, len(s.pp.Members))
	enc := make([]kyber.Point, len(shares))
	commits := make([]kyber.Point, len(shares))
	for i, id := range s.pp.Members {
		enc[i] = group.G1().Point().Mul(shares[i], s.public[id])
		commits[i] = group.G1().Point().Mul(shares[i], s.g)
	}
	out := Commitment{
		Scheme: "scrape-ddh",
		Dealer: dealer, Seq: seq, Epoch: s.pp.Epoch, Threshold: s.pp.Threshold,
		Members: normalizeMembers(s.pp.Members), EncryptedShares: pointsHexAs(enc, "G1"),
		ShareCommits: pointsHexAs(commits, "G1"),
	}
	out.ScrapeProof = s.distributionProof(group, out, shares)
	out.SecretID = scrapeDDHCommitmentID(out)
	return out, mustPointBytes(group.G1().Point().Mul(secret, s.h)), nil
}

func (s *ScrapeDDHScheme) Verify(c Commitment) bool {
	if c.Dealer == "" || c.SecretID == "" || c.Epoch != s.pp.Epoch || c.Threshold != s.pp.Threshold ||
		len(c.Members) != len(s.pp.Members) || len(c.EncryptedShares) != len(c.Members) || len(c.ShareCommits) != len(c.Members) {
		return false
	}
	if scrapeDDHCommitmentID(c) != c.SecretID {
		return false
	}
	if !sameNodeIDs(c.Members, s.pp.Members) {
		return false
	}
	group := suite()
	enc, err := pointsG1FromEncoded(c.EncryptedShares)
	if err != nil {
		return false
	}
	commits, err := pointsG1FromEncoded(c.ShareCommits)
	if err != nil {
		return false
	}
	if !s.verifyDistributionProof(group, c, enc, commits) {
		return false
	}
	dual := scrapeDualCodeword(group.G1(), c)
	acc := group.G1().Point().Null()
	for i, v := range commits {
		acc.Add(acc, group.G1().Point().Mul(dual[i], v))
	}
	return acc.Equal(group.G1().Point().Null())
}

func (s *ScrapeDDHScheme) PreRecon(c Commitment, holder p2p.NodeID) (DecryptedShare, error) {
	if holder != s.id {
		return DecryptedShare{}, fmt.Errorf("scrape-ddh scheme for %s cannot decrypt as %s", s.id, holder)
	}
	if !s.Verify(c) {
		return DecryptedShare{}, errors.New("invalid scrape-ddh commitment")
	}
	return s.PreReconVerified(c, holder)
}

func (s *ScrapeDDHScheme) PreReconVerified(c Commitment, holder p2p.NodeID) (DecryptedShare, error) {
	if holder != s.id {
		return DecryptedShare{}, fmt.Errorf("scrape-ddh scheme for %s cannot decrypt as %s", s.id, holder)
	}
	idx := nodeIndexInOrder(c.Members)[holder]
	enc, err := pointG1FromHex(c.EncryptedShares[idx].Value)
	if err != nil {
		return DecryptedShare{}, err
	}
	inv := suite().G1().Scalar().Div(suite().G1().Scalar().One(), s.private)
	value := suite().G1().Point().Mul(inv, enc)
	proof := dleqProveG1(suite(), s.h, value, s.public[holder], enc, s.private)
	return DecryptedShare{CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(value), Proof: proof}, nil
}

func (s *ScrapeDDHScheme) VerifyShare(c Commitment, sh DecryptedShare) bool {
	if sh.CommitmentID != c.SecretID {
		return false
	}
	idx, ok := nodeIndexInOrder(c.Members)[sh.Holder]
	if !ok || s.public[sh.Holder] == nil {
		return false
	}
	enc, err := pointG1FromHex(c.EncryptedShares[idx].Value)
	if err != nil {
		return false
	}
	value, err := pointG1FromHex(sh.Value)
	if err != nil {
		return false
	}
	return dleqVerifyG1(suite(), s.h, value, s.public[sh.Holder], enc, sh.Proof)
}

func (s *ScrapeDDHScheme) Recon(c Commitment, shares []DecryptedShare) ([]byte, error) {
	if !s.Verify(c) {
		return nil, errors.New("invalid scrape-ddh commitment")
	}
	return s.ReconVerified(c, shares)
}

func (s *ScrapeDDHScheme) ReconVerified(c Commitment, shares []DecryptedShare) ([]byte, error) {
	return s.reconShares(c, shares, true)
}

func (s *ScrapeDDHScheme) ReconFromVerifiedShares(c Commitment, shares []DecryptedShare) ([]byte, error) {
	return s.reconShares(c, shares, false)
}

func (s *ScrapeDDHScheme) reconShares(c Commitment, shares []DecryptedShare, verifyProofs bool) ([]byte, error) {
	group := suite()
	index := nodeIndexInOrder(c.Members)
	seen := make(map[p2p.NodeID]bool, len(shares))
	points := make([]kyber.Point, 0, c.Threshold)
	xs := make([]int, 0, c.Threshold)
	for _, sh := range shares {
		if seen[sh.Holder] || (verifyProofs && !s.VerifyShare(c, sh)) {
			continue
		}
		i, ok := index[sh.Holder]
		if !ok {
			continue
		}
		value, err := pointG1FromHex(sh.Value)
		if err != nil {
			continue
		}
		seen[sh.Holder] = true
		points = append(points, value)
		xs = append(xs, i+1)
		if len(points) == c.Threshold {
			break
		}
	}
	if len(points) < c.Threshold {
		return nil, errors.New("not enough valid scrape-ddh decrypted shares")
	}
	secret := group.G1().Point().Null()
	for i, p := range points {
		lambda := lagrangeAtZeroForX(group.G1(), xs, i)
		secret.Add(secret, group.G1().Point().Mul(lambda, p))
	}
	return secret.MarshalBinary()
}

func (s *ScrapeDDHScheme) distributionProof(group *bn256.Suite, c Commitment, shares []kyber.Scalar) ScrapeDDHDistributionProof {
	w := randomScalars(group, len(shares))
	a1 := make([]kyber.Point, len(shares))
	a2 := make([]kyber.Point, len(shares))
	for i, id := range c.Members {
		a1[i] = group.G1().Point().Mul(w[i], s.g)
		a2[i] = group.G1().Point().Mul(w[i], s.public[id])
	}
	proof := ScrapeDDHDistributionProof{A1: pointsHexAs(a1, "G1"), A2: pointsHexAs(a2, "G1")}
	tmp := c
	tmp.ScrapeProof = proof
	chal := scrapeDDHDistributionChallenge(group, tmp)
	proof.Challenge = scalarHex(chal)
	proof.Responses = make([]string, len(shares))
	for i := range shares {
		z := group.G1().Scalar().Add(w[i], group.G1().Scalar().Mul(chal, shares[i]))
		proof.Responses[i] = scalarHex(z)
	}
	return proof
}

func (s *ScrapeDDHScheme) verifyDistributionProof(group *bn256.Suite, c Commitment, enc, commits []kyber.Point) bool {
	a1, err := pointsG1FromEncoded(c.ScrapeProof.A1)
	if err != nil || len(a1) != len(c.Members) {
		return false
	}
	a2, err := pointsG1FromEncoded(c.ScrapeProof.A2)
	if err != nil || len(a2) != len(c.Members) {
		return false
	}
	chal := scalarFromHex(group.G1(), c.ScrapeProof.Challenge)
	z := scalarsFromHex(group.G1(), c.ScrapeProof.Responses)
	if chal == nil || len(z) != len(c.Members) || !scrapeDDHDistributionChallenge(group, c).Equal(chal) {
		return false
	}
	for i, id := range c.Members {
		left1 := group.G1().Point().Mul(z[i], s.g)
		right1 := group.G1().Point().Add(a1[i], group.G1().Point().Mul(chal, commits[i]))
		left2 := group.G1().Point().Mul(z[i], s.public[id])
		right2 := group.G1().Point().Add(a2[i], group.G1().Point().Mul(chal, enc[i]))
		if !left1.Equal(right1) || !left2.Equal(right2) {
			return false
		}
	}
	return true
}

func scrapeDDHDistributionChallenge(group *bn256.Suite, c Commitment) kyber.Scalar {
	buf := bytes.Buffer{}
	buf.WriteString("Tyche-v1/scrape-ddh/distribution")
	writeScrapeCommitmentBody(&buf, c)
	for _, p := range c.ScrapeProof.A1 {
		buf.WriteByte('/')
		buf.WriteString(p.Group)
		buf.WriteByte(':')
		buf.WriteString(p.Value)
	}
	for _, p := range c.ScrapeProof.A2 {
		buf.WriteByte('/')
		buf.WriteString(p.Group)
		buf.WriteByte(':')
		buf.WriteString(p.Value)
	}
	return group.G1().Scalar().SetBytes(HashBytes(buf.Bytes()))
}

func scrapeDDHCommitmentID(c Commitment) string {
	buf := bytes.Buffer{}
	buf.WriteString("Tyche-v1/scrape-ddh/commitment")
	writeScrapeCommitmentBody(&buf, c)
	buf.WriteByte('/')
	buf.WriteString(c.ScrapeProof.Challenge)
	for _, z := range c.ScrapeProof.Responses {
		buf.WriteByte('/')
		buf.WriteString(z)
	}
	return fmt.Sprintf("%x", HashBytes(buf.Bytes()))
}

func writeScrapeCommitmentBody(buf *bytes.Buffer, c Commitment) {
	buf.WriteByte('/')
	buf.WriteString(string(c.Dealer))
	buf.WriteByte('/')
	buf.WriteString(c.Epoch)
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d/%d", c.Seq, c.Threshold))
	for _, member := range normalizeMembers(c.Members) {
		buf.WriteByte('/')
		buf.WriteString(string(member))
	}
	for _, p := range c.EncryptedShares {
		buf.WriteByte('/')
		buf.WriteString(p.Group)
		buf.WriteByte(':')
		buf.WriteString(p.Value)
	}
	for _, p := range c.ShareCommits {
		buf.WriteByte('/')
		buf.WriteString(p.Group)
		buf.WriteByte(':')
		buf.WriteString(p.Value)
	}
}

func scrapeDualCodeword(group kyber.Group, c Commitment) []kyber.Scalar {
	n := len(c.Members)
	degree := n - c.Threshold
	coeff := make([]kyber.Scalar, degree)
	for i := range coeff {
		coeff[i] = group.Scalar().SetBytes(HashBytes([]byte("Tyche-v1/scrape-ddh/dual"), []byte(c.SecretID), []byte(fmt.Sprintf("/%d", i))))
	}
	out := make([]kyber.Scalar, n)
	for i := 0; i < n; i++ {
		xi := group.Scalar().SetInt64(int64(i + 1))
		den := group.Scalar().One()
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			xj := group.Scalar().SetInt64(int64(j + 1))
			den.Mul(den, group.Scalar().Sub(xi, xj))
		}
		out[i] = group.Scalar().Mul(evalScalarPolynomial(group, coeff, xi), group.Scalar().Div(group.Scalar().One(), den))
	}
	return out
}

func evalPolynomial(group kyber.Group, coeff []kyber.Scalar, n int) []kyber.Scalar {
	out := make([]kyber.Scalar, n)
	for i := range out {
		x := group.Scalar().SetInt64(int64(i + 1))
		out[i] = evalScalarPolynomial(group, coeff, x)
	}
	return out
}

func evalScalarPolynomial(group kyber.Group, coeff []kyber.Scalar, x kyber.Scalar) kyber.Scalar {
	acc := group.Scalar().Zero()
	for i := len(coeff) - 1; i >= 0; i-- {
		acc.Mul(acc, x)
		acc.Add(acc, coeff[i])
	}
	return acc
}

func lagrangeAtZeroForX(group kyber.Group, xs []int, i int) kyber.Scalar {
	xi := group.Scalar().SetInt64(int64(xs[i]))
	num := group.Scalar().One()
	den := group.Scalar().One()
	for j, x := range xs {
		if i == j {
			continue
		}
		xj := group.Scalar().SetInt64(int64(x))
		num.Mul(num, group.Scalar().Sub(group.Scalar().Zero(), xj))
		den.Mul(den, group.Scalar().Sub(xi, xj))
	}
	return group.Scalar().Div(num, den)
}

func dleqProveG1(group *bn256.Suite, g, h, gx, hx kyber.Point, x kyber.Scalar) DecryptionProof {
	w := group.G1().Scalar().Pick(group.RandomStream())
	a := group.G1().Point().Mul(w, g)
	b := group.G1().Point().Mul(w, h)
	c := dleqChallengeG1(group, g, h, gx, hx, a, b)
	z := group.G1().Scalar().Add(w, group.G1().Scalar().Mul(c, x))
	return DecryptionProof{A: mustPointHex(a), B: mustPointHex(b), Challenge: scalarHex(c), Response: scalarHex(z)}
}

func dleqVerifyG1(group *bn256.Suite, g, h, gx, hx kyber.Point, proof DecryptionProof) bool {
	a, err := pointG1FromHex(proof.A)
	if err != nil {
		return false
	}
	b, err := pointG1FromHex(proof.B)
	if err != nil {
		return false
	}
	c := scalarFromHex(group.G1(), proof.Challenge)
	z := scalarFromHex(group.G1(), proof.Response)
	if c == nil || z == nil || !dleqChallengeG1(group, g, h, gx, hx, a, b).Equal(c) {
		return false
	}
	return group.G1().Point().Mul(z, g).Equal(group.G1().Point().Add(a, group.G1().Point().Mul(c, gx))) &&
		group.G1().Point().Mul(z, h).Equal(group.G1().Point().Add(b, group.G1().Point().Mul(c, hx)))
}

func dleqChallengeG1(group *bn256.Suite, g, h, gx, hx, a, b kyber.Point) kyber.Scalar {
	buf := bytes.Buffer{}
	buf.WriteString("Tyche-v1/scrape-ddh/dleq-g1")
	for _, p := range []kyber.Point{g, h, gx, hx, a, b} {
		buf.WriteByte('/')
		buf.Write(mustPointBytes(p))
	}
	return group.G1().Scalar().SetBytes(HashBytes(buf.Bytes()))
}

func hashG1(group *bn256.Suite, parts ...[]byte) kyber.Point {
	x := group.G1().Scalar().SetBytes(HashBytes(parts...))
	if x.Equal(group.G1().Scalar().Zero()) {
		x = group.G1().Scalar().One()
	}
	return group.G1().Point().Mul(x, baseG1(group))
}

func pointsG1FromEncoded(raw []EncodedPoint) ([]kyber.Point, error) {
	out := make([]kyber.Point, len(raw))
	for i, x := range raw {
		if x.Group != "G1" {
			return nil, fmt.Errorf("expected G1 point, got %s", x.Group)
		}
		p, err := pointG1FromHex(x.Value)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

func cloneScrapeDDHParams(pp ScrapeDDHParams) ScrapeDDHParams {
	out := pp
	out.Members = append([]p2p.NodeID(nil), pp.Members...)
	out.PublicKeys = cloneStringMap(pp.PublicKeys)
	return out
}

func sameNodeIDs(a, b []p2p.NodeID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nodeIndexInOrder(members []p2p.NodeID) map[p2p.NodeID]int {
	out := make(map[p2p.NodeID]int, len(members))
	for i, member := range members {
		out[member] = i
	}
	return out
}
