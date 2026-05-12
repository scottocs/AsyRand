package pvss

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	asig "github.com/scottocs/asyrand/spurt/internal/crypto"
	"github.com/scottocs/asyrand/spurt/internal/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
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
	Commit    map[p2p.NodeID]string `json:"commit"`
	Cipher    map[p2p.NodeID]string `json:"cipher"`
	Proof     Proof                 `json:"proof,omitempty"`
	SecretID  string                `json:"secret_id"`
	Aggregate bool                  `json:"aggregate,omitempty"`
	Sources   []Source              `json:"sources,omitempty"`
}

type Source struct {
	Dealer   p2p.NodeID `json:"dealer"`
	Seq      uint64     `json:"seq"`
	SecretID string     `json:"secret_id"`
}

type Proof struct {
	CPrime    map[p2p.NodeID]string `json:"c_prime,omitempty"`
	Challenge string                `json:"challenge,omitempty"`
	STilde    string                `json:"s_tilde,omitempty"`
	PTilde    map[p2p.NodeID]string `json:"p_tilde,omitempty"`
}

type DecryptionProof struct {
	C  string `json:"c,omitempty"`
	R  string `json:"r,omitempty"`
	VG string `json:"vg,omitempty"`
	VH string `json:"vh,omitempty"`
}

type DecryptedShare struct {
	CommitmentID string          `json:"commitment_id"`
	Holder       p2p.NodeID      `json:"holder"`
	Value        string          `json:"value"`
	Proof        DecryptionProof `json:"proof,omitempty"`
}

type Scheme interface {
	Share(dealer p2p.NodeID, seq uint64, members []p2p.NodeID) (Commitment, []byte, error)
	Verify(Commitment) bool
	Aggregate(dealer p2p.NodeID, seq uint64, commitments []Commitment, members []p2p.NodeID) (Commitment, error)
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
	group := suite()
	sk := group.G1().Scalar().SetBytes(asig.HashBytes([]byte("Spurt-v1/PVSS/key"), seed))
	if sk.Equal(group.G1().Scalar().Zero()) {
		sk = group.G1().Scalar().One()
	}
	return KeyPair{Private: sk, Public: group.G1().Point().Mul(sk, h0Point(group))}
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
	// SPURT Figure 2: sample p with p(0)=s, publish v_j=g1^{p(j)} in G2
	// and c_j=pk_j^{p(j)} in G1. Reconstruction later returns e(h0^s,h1).
	secret := group.G1().Scalar().Pick(group.RandomStream())
	poly := share.NewPriPoly(group.G1(), s.threshold, secret, group.RandomStream())
	shares := poly.Shares(len(members))

	commit := make(map[p2p.NodeID]string, len(members))
	cipher := make(map[p2p.NodeID]string, len(members))
	for i, member := range members {
		pk := s.public[member]
		if pk == nil {
			return Commitment{}, nil, fmt.Errorf("missing pvss public key for %s", member)
		}
		commit[member] = mustPointHex(group.G2().Point().Mul(shares[i].V, g1Point(group)))
		cipher[member] = mustPointHex(group.G1().Point().Mul(shares[i].V, pk))
	}
	out := Commitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members,
		Commit: commit, Cipher: cipher,
	}
	out.SecretID = commitmentID(out)
	secretPoint := group.G1().Point().Mul(secret, h0Point(group))
	beaconSecret := group.Pair(secretPoint, h1Point(group))
	return out, mustPointBytes(beaconSecret), nil
}

func (s *PairingFreeScheme) Verify(c Commitment) bool {
	if c.Aggregate {
		return verifyAggregate(c)
	}
	if c.Dealer == "" || c.SecretID == "" || c.Threshold <= 0 || len(c.Members) < c.Threshold {
		return false
	}
	if commitmentID(c) != c.SecretID {
		return false
	}
	members := normalizeMembers(c.Members)
	group := suite()
	// SPURT Figure 2 verification: pairing consistency for every encrypted
	// share, plus the Reed-Solomon dual-code check on the v-vector.
	for _, member := range members {
		pk := s.public[member]
		if pk == nil {
			return false
		}
		vj, err := pointG2FromHex(c.Commit[member])
		if err != nil {
			return false
		}
		cj, err := pointG1FromHex(c.Cipher[member])
		if err != nil {
			return false
		}
		if !group.Pair(pk, vj).Equal(group.Pair(cj, g1Point(group))) {
			return false
		}
	}
	return verifyRSDualCodeG2(group, c, members)
}

func (s *PairingFreeScheme) Aggregate(dealer p2p.NodeID, seq uint64, commitments []Commitment, members []p2p.NodeID) (Commitment, error) {
	members = normalizeMembers(members)
	if len(commitments) < s.threshold {
		return Commitment{}, errors.New("not enough pvss commitments to aggregate")
	}
	group := suite()
	commit := make(map[p2p.NodeID]string, len(members))
	cipher := make(map[p2p.NodeID]string, len(members))
	for _, member := range members {
		var vSum kyber.Point
		var cSum kyber.Point
		for _, c := range commitments {
			if !s.Verify(c) {
				return Commitment{}, errors.New("invalid pvss commitment in aggregate")
			}
			if c.Threshold != s.threshold {
				return Commitment{}, errors.New("pvss threshold mismatch in aggregate")
			}
			vj, err := pointG2FromHex(c.Commit[member])
			if err != nil {
				return Commitment{}, err
			}
			cj, err := pointG1FromHex(c.Cipher[member])
			if err != nil {
				return Commitment{}, err
			}
			if vSum == nil {
				vSum = vj.Clone()
				cSum = cj.Clone()
			} else {
				vSum = group.G2().Point().Add(vSum, vj)
				cSum = group.G1().Point().Add(cSum, cj)
			}
		}
		if vSum == nil || cSum == nil {
			return Commitment{}, errors.New("empty aggregate share")
		}
		commit[member] = mustPointHex(vSum)
		cipher[member] = mustPointHex(cSum)
	}
	sources := make([]Source, 0, len(commitments))
	for _, c := range commitments {
		sources = append(sources, Source{Dealer: c.Dealer, Seq: c.Seq, SecretID: c.SecretID})
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Dealer == sources[j].Dealer {
			return sources[i].Seq < sources[j].Seq
		}
		return sources[i].Dealer < sources[j].Dealer
	})
	agg := Commitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members,
		Commit: commit, Cipher: cipher, Aggregate: true, Sources: sources,
	}
	agg.SecretID = commitmentID(agg)
	return agg, nil
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
	cipher, err := pointG1FromHex(c.Cipher[holder])
	if err != nil {
		return DecryptedShare{}, err
	}
	group := suite()
	plain := group.G1().Point().Mul(group.G1().Scalar().Inv(s.private), cipher)
	return DecryptedShare{CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(plain)}, nil
}

func (s *PairingFreeScheme) VerifyShare(c Commitment, sh DecryptedShare) bool {
	if sh.CommitmentID != c.SecretID {
		return false
	}
	group := suite()
	plain, err := pointG1FromHex(sh.Value)
	if err != nil {
		return false
	}
	vj, err := pointG2FromHex(c.Commit[sh.Holder])
	if err != nil {
		return false
	}
	return group.Pair(plain, g1Point(group)).Equal(group.Pair(h0Point(group), vj))
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
		if seen[sh.Holder] || sh.CommitmentID != c.SecretID || !s.VerifyShare(c, sh) {
			continue
		}
		i, ok := index[sh.Holder]
		if !ok {
			continue
		}
		plain, err := pointG1FromHex(sh.Value)
		if err != nil {
			continue
		}
		seen[sh.Holder] = true
		pubShares = append(pubShares, &share.PubShare{I: i, V: plain})
	}
	if len(pubShares) < threshold {
		return nil, errors.New("not enough valid decrypted pvss shares")
	}
	// Interpolate h0^s from decrypted shares h0^{p(j)}, then pair with h1 as
	// in PVSS.Reconstruct(h0,h1,...) of SPURT Figure 2.
	secretCommit, err := share.RecoverCommit(group.G1(), pubShares, threshold, len(c.Members))
	if err != nil {
		return nil, err
	}
	return group.Pair(secretCommit, h1Point(group)).MarshalBinary()
}

func CommitmentID(c Commitment) string {
	return c.SecretID
}

func suite() *bn256.Suite {
	return bn256.NewSuite()
}

func h0Point(group *bn256.Suite) kyber.Point {
	return group.G1().Point().Base()
}

func g1Point(group *bn256.Suite) kyber.Point {
	return group.G2().Point().Base()
}

func h1Point(group *bn256.Suite) kyber.Point {
	h := group.G2().Scalar().SetBytes(asig.HashBytes([]byte("Spurt-v1/PVSS/h1")))
	if h.Equal(group.G2().Scalar().Zero()) {
		h = group.G2().Scalar().One()
	}
	return group.G2().Point().Mul(h, nil)
}

func verifyPublicPolynomial(group kyber.Group, shares []*share.PubShare, threshold int) bool {
	if threshold <= 0 || len(shares) < threshold {
		return false
	}
	poly, err := share.RecoverPubPoly(group, shares[:threshold], threshold, len(shares))
	if err != nil {
		return false
	}
	for _, sh := range shares[threshold:] {
		if !poly.Eval(sh.I).V.Equal(sh.V) {
			return false
		}
	}
	return true
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

func commitmentID(c Commitment) string {
	members := normalizeMembers(c.Members)
	buf := bytes.Buffer{}
	if c.Aggregate {
		buf.WriteString("Spurt-v1/PVSS/aggregate/")
	} else {
		buf.WriteString("Spurt-v1/PVSS/commitment/")
	}
	buf.WriteString(string(c.Dealer))
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d/%d", c.Seq, c.Threshold))
	sources := append([]Source(nil), c.Sources...)
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Dealer == sources[j].Dealer {
			return sources[i].Seq < sources[j].Seq
		}
		return sources[i].Dealer < sources[j].Dealer
	})
	for _, source := range sources {
		buf.WriteByte('/')
		buf.WriteString(string(source.Dealer))
		buf.WriteByte(':')
		buf.WriteString(fmt.Sprintf("%d", source.Seq))
		buf.WriteByte(':')
		buf.WriteString(source.SecretID)
	}
	for _, member := range members {
		buf.WriteByte('/')
		buf.WriteString(string(member))
		buf.WriteByte(':')
		buf.WriteString(c.Commit[member])
		buf.WriteByte(':')
		buf.WriteString(c.Cipher[member])
	}
	return hex.EncodeToString(asig.HashBytes(buf.Bytes()))
}

func verifyAggregate(c Commitment) bool {
	if c.Dealer == "" || c.SecretID == "" || c.Threshold <= 0 || len(c.Members) < c.Threshold || len(c.Sources) < c.Threshold {
		return false
	}
	if commitmentID(c) != c.SecretID {
		return false
	}
	seen := make(map[p2p.NodeID]bool, len(c.Sources))
	for _, source := range c.Sources {
		if source.Dealer == "" || source.Seq == 0 || source.SecretID == "" || seen[source.Dealer] {
			return false
		}
		seen[source.Dealer] = true
	}
	members := normalizeMembers(c.Members)
	for _, member := range members {
		if _, err := pointG1FromHex(c.Cipher[member]); err != nil {
			return false
		}
		if _, err := pointG2FromHex(c.Commit[member]); err != nil {
			return false
		}
	}
	return verifyRSDualCodeG2(suite(), c, members)
}

func verifyRSDualCodeG2(group *bn256.Suite, c Commitment, members []p2p.NodeID) bool {
	// Figure 2 samples y^\perp from the RS dual code and checks
	// prod_j v_j^{y_j}=1. The sample is derived deterministically from the
	// transcript so all verifiers make the same public-verification decision.
	weights, err := dualCodeWord(group.G2(), c, members)
	if err != nil {
		return false
	}
	acc := group.G2().Point().Null()
	for i, member := range members {
		vj, err := pointG2FromHex(c.Commit[member])
		if err != nil {
			return false
		}
		acc.Add(acc, group.G2().Point().Mul(weights[i], vj))
	}
	return acc.Equal(group.G2().Point().Null())
}

func dualCodeWord(group kyber.Group, c Commitment, members []p2p.NodeID) ([]kyber.Scalar, error) {
	if c.Threshold <= 0 || len(members) < c.Threshold {
		return nil, errors.New("invalid Reed-Solomon parameters")
	}
	degree := len(members) - c.Threshold - 1
	coeffs := make([]kyber.Scalar, max(1, degree+1))
	seed := dualCodeSeed(c, members)
	for i := range coeffs {
		coeffs[i] = group.Scalar().SetBytes(asig.HashBytes(seed, []byte(fmt.Sprintf("/%d", i))))
	}
	out := make([]kyber.Scalar, len(members))
	for i := range members {
		xi := group.Scalar().SetInt64(int64(i + 1))
		out[i] = group.Scalar().Mul(evalScalarPoly(group, coeffs, xi), dualMultiplier(group, i, len(members)))
	}
	return out, nil
}

func dualCodeSeed(c Commitment, members []p2p.NodeID) []byte {
	buf := bytes.Buffer{}
	buf.WriteString("Spurt-v1/PVSS/rs-dual/")
	buf.WriteString(c.SecretID)
	for _, member := range members {
		buf.WriteByte('/')
		buf.WriteString(string(member))
		buf.WriteByte(':')
		buf.WriteString(c.Commit[member])
	}
	return asig.HashBytes(buf.Bytes())
}

func evalScalarPoly(group kyber.Group, coeffs []kyber.Scalar, x kyber.Scalar) kyber.Scalar {
	out := group.Scalar().Zero()
	for i := len(coeffs) - 1; i >= 0; i-- {
		out.Mul(out, x)
		out.Add(out, coeffs[i])
	}
	return out
}

func dualMultiplier(group kyber.Group, i, n int) kyber.Scalar {
	xi := group.Scalar().SetInt64(int64(i + 1))
	den := group.Scalar().One()
	for j := 0; j < n; j++ {
		if j == i {
			continue
		}
		xj := group.Scalar().SetInt64(int64(j + 1))
		den.Mul(den, group.Scalar().Sub(xi, xj))
	}
	return group.Scalar().Inv(den)
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

func pointG1FromHex(v string) (kyber.Point, error) {
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	p := suite().G1().Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}

func pointG2FromHex(v string) (kyber.Point, error) {
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	p := suite().G2().Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}
