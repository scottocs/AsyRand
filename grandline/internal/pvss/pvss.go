package pvss

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	asig "github.com/scottocs/asyrand/grandline/internal/crypto"
	"github.com/scottocs/asyrand/grandline/internal/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type KeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

type Commitment struct {
	Dealer        p2p.NodeID            `json:"dealer"`
	Seq           uint64                `json:"seq"`
	Threshold     int                   `json:"threshold"`
	Members       []p2p.NodeID          `json:"members"`
	Commit        map[p2p.NodeID]string `json:"commit"`
	Cipher        map[p2p.NodeID]string `json:"cipher"`
	Proof         Proof                 `json:"proof"`
	Contributions []Contribution        `json:"contributions,omitempty"`
	SecretID      string                `json:"secret_id"`
}

type Proof struct {
	Zeta      string `json:"zeta,omitempty"`
	A         string `json:"a,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Response  string `json:"response,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type Contribution struct {
	Dealer p2p.NodeID `json:"dealer"`
	Seq    uint64     `json:"seq"`
	Proof  Proof      `json:"proof"`
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
	sk := group.G2().Scalar().SetBytes(asig.HashBytes([]byte("GRandLine-v1/APVSS/key"), seed))
	if sk.Equal(group.G2().Scalar().Zero()) {
		sk = group.G2().Scalar().One()
	}
	return KeyPair{Private: sk, Public: group.G2().Point().Mul(sk, hPoint(group))}
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
	// GRandLine Figure 1 Dist: sample f, publish commitments C_i=g^{f(i)}
	// in G1 and encrypted shares E_i=pk_i^{f(i)} in G2.
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
		commit[member] = mustPointHex(group.G1().Point().Mul(shares[i].V, gPoint(group)))
		cipher[member] = mustPointHex(group.G2().Point().Mul(shares[i].V, pk))
	}
	proof := schnorrProve(group, dealer, seq, secret, s.private)
	out := Commitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members,
		Commit: commit, Cipher: cipher, Proof: proof,
		Contributions: []Contribution{{Dealer: dealer, Seq: seq, Proof: proof}},
	}
	out.SecretID = commitmentID(out)
	secretPoint := group.G2().Point().Mul(secret, hPoint(group))
	return out, mustPointBytes(secretPoint), nil
}

func (s *PairingFreeScheme) Verify(c Commitment) bool {
	if c.Dealer == "" || c.SecretID == "" || c.Threshold <= 0 || len(c.Members) < c.Threshold {
		return false
	}
	if commitmentID(c) != c.SecretID {
		return false
	}
	group := suite()
	members := normalizeMembers(c.Members)
	commitShares := make([]*share.PubShare, 0, len(members))
	// GRandLine Figure 1 Ver: check e(g,E_i)=e(C_i,pk_i), verify the RS
	// dual-code equation on C, and bind C_0 to the contributors' proofs.
	for i, member := range members {
		pk := s.public[member]
		if pk == nil {
			return false
		}
		ci, err := pointG1FromHex(c.Commit[member])
		if err != nil {
			return false
		}
		ei, err := pointG2FromHex(c.Cipher[member])
		if err != nil {
			return false
		}
		if !group.Pair(gPoint(group), ei).Equal(group.Pair(ci, pk)) {
			return false
		}
		commitShares = append(commitShares, &share.PubShare{I: i, V: ci})
	}
	if !verifyRSDualCodeG1(group, c, members) {
		return false
	}
	c0, err := share.RecoverCommit(group.G1(), commitShares, c.Threshold, len(members))
	if err != nil {
		return false
	}
	zetaProduct := group.G1().Point().Null()
	contributions := c.Contributions
	if len(contributions) == 0 {
		contributions = []Contribution{{Dealer: c.Dealer, Seq: c.Seq, Proof: c.Proof}}
	}
	for _, contribution := range contributions {
		zeta, err := pointG1FromHex(contribution.Proof.Zeta)
		pk := s.public[contribution.Dealer]
		if err != nil || pk == nil || !schnorrVerify(group, contribution.Dealer, contribution.Seq, contribution.Proof, pk) {
			return false
		}
		zetaProduct.Add(zetaProduct, zeta)
	}
	return zetaProduct.Equal(c0)
}

func (s *PairingFreeScheme) Aggregate(dealer p2p.NodeID, seq uint64, commitments []Commitment, members []p2p.NodeID) (Commitment, error) {
	members = normalizeMembers(members)
	if len(commitments) == 0 {
		return Commitment{}, errors.New("empty pvss aggregate")
	}
	group := suite()
	// GRandLine Figure 1 Agg multiplies transcript coordinates: C_i is the
	// sum/product of commitments and E_i is the sum/product of encryptions.
	commit := make(map[p2p.NodeID]string, len(members))
	cipher := make(map[p2p.NodeID]string, len(members))
	contributions := make([]Contribution, 0, len(commitments))
	for _, member := range members {
		var cSum kyber.Point
		var eSum kyber.Point
		for _, transcript := range commitments {
			if !s.Verify(transcript) {
				return Commitment{}, errors.New("invalid pvss transcript in aggregate")
			}
			if transcript.Threshold != s.threshold {
				return Commitment{}, errors.New("pvss threshold mismatch in aggregate")
			}
			ci, err := pointG1FromHex(transcript.Commit[member])
			if err != nil {
				return Commitment{}, err
			}
			ei, err := pointG2FromHex(transcript.Cipher[member])
			if err != nil {
				return Commitment{}, err
			}
			if cSum == nil {
				cSum = ci.Clone()
				eSum = ei.Clone()
			} else {
				cSum = group.G1().Point().Add(cSum, ci)
				eSum = group.G2().Point().Add(eSum, ei)
			}
		}
		commit[member] = mustPointHex(cSum)
		cipher[member] = mustPointHex(eSum)
	}
	for _, transcript := range commitments {
		if len(transcript.Contributions) == 0 {
			contributions = append(contributions, Contribution{Dealer: transcript.Dealer, Seq: transcript.Seq, Proof: transcript.Proof})
			continue
		}
		contributions = append(contributions, transcript.Contributions...)
	}
	sort.Slice(contributions, func(i, j int) bool {
		if contributions[i].Dealer == contributions[j].Dealer {
			return contributions[i].Seq < contributions[j].Seq
		}
		return contributions[i].Dealer < contributions[j].Dealer
	})
	out := Commitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members,
		Commit: commit, Cipher: cipher, Contributions: contributions,
	}
	out.SecretID = commitmentID(out)
	return out, nil
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
	cipher, err := pointG2FromHex(c.Cipher[holder])
	if err != nil {
		return DecryptedShare{}, err
	}
	group := suite()
	plain := group.G2().Point().Mul(group.G2().Scalar().Inv(s.private), cipher)
	return DecryptedShare{CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(plain)}, nil
}

func (s *PairingFreeScheme) VerifyShare(c Commitment, sh DecryptedShare) bool {
	if sh.CommitmentID != c.SecretID {
		return false
	}
	group := suite()
	plain, err := pointG2FromHex(sh.Value)
	if err != nil {
		return false
	}
	ci, err := pointG1FromHex(c.Commit[sh.Holder])
	if err != nil {
		return false
	}
	return group.Pair(ci, hPoint(group)).Equal(group.Pair(gPoint(group), plain))
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
		plain, err := pointG2FromHex(sh.Value)
		if err != nil {
			continue
		}
		seen[sh.Holder] = true
		pubShares = append(pubShares, &share.PubShare{I: i, V: plain})
	}
	if len(pubShares) < threshold {
		return nil, errors.New("not enough valid decrypted pvss shares")
	}
	// GRandLine Figure 1 Rec reconstructs the APVSS secret S=h^{f(0)} in G2
	// by Lagrange interpolation in the exponent from valid decrypted shares.
	secret, err := share.RecoverCommit(group.G2(), pubShares, threshold, len(c.Members))
	if err != nil {
		return nil, err
	}
	return secret.MarshalBinary()
}

func CommitmentID(c Commitment) string {
	return c.SecretID
}

func suite() *bn256.Suite {
	return bn256.NewSuite()
}

func gPoint(group *bn256.Suite) kyber.Point {
	return group.G1().Point().Base()
}

func hPoint(group *bn256.Suite) kyber.Point {
	return group.G2().Point().Base()
}

func schnorrProve(group *bn256.Suite, dealer p2p.NodeID, seq uint64, secret, signingKey kyber.Scalar) Proof {
	// Figure 1 writes pi=<zeta,theta>_L: zeta=g^alpha, theta is the
	// Fiat-Shamir Schnorr proof of alpha, and Signature binds the proof to L.
	nonce := group.G1().Scalar().Pick(group.RandomStream())
	zeta := group.G1().Point().Mul(secret, gPoint(group))
	a := group.G1().Point().Mul(nonce, gPoint(group))
	challenge := schnorrChallenge(group, dealer, seq, zeta, a)
	response := group.G1().Scalar().Sub(nonce, group.G1().Scalar().Mul(challenge, secret))
	proof := Proof{Zeta: mustPointHex(zeta), A: mustPointHex(a), Challenge: mustScalarHex(challenge), Response: mustScalarHex(response)}
	proof.Signature = mustPointHex(group.G1().Point().Mul(signingKey, proofSignatureBase(group, dealer, seq, proof)))
	return proof
}

func schnorrVerify(group *bn256.Suite, dealer p2p.NodeID, seq uint64, proof Proof, publicKey kyber.Point) bool {
	zeta, err := pointG1FromHex(proof.Zeta)
	if err != nil {
		return false
	}
	a, err := pointG1FromHex(proof.A)
	if err != nil {
		return false
	}
	challenge, err := scalarFromHex(proof.Challenge)
	if err != nil {
		return false
	}
	response, err := scalarFromHex(proof.Response)
	if err != nil {
		return false
	}
	if !schnorrChallenge(group, dealer, seq, zeta, a).Equal(challenge) {
		return false
	}
	right := group.G1().Point().Add(group.G1().Point().Mul(response, gPoint(group)), group.G1().Point().Mul(challenge, zeta))
	if !a.Equal(right) {
		return false
	}
	signature, err := pointG1FromHex(proof.Signature)
	if err != nil {
		return false
	}
	return group.Pair(signature, hPoint(group)).Equal(group.Pair(proofSignatureBase(group, dealer, seq, proof), publicKey))
}

func proofSignatureBase(group *bn256.Suite, dealer p2p.NodeID, seq uint64, proof Proof) kyber.Point {
	msg := proofSignatureMessage(dealer, seq, proof)
	scalar := group.G1().Scalar().SetBytes(asig.HashBytes(msg))
	if scalar.Equal(group.G1().Scalar().Zero()) {
		scalar = group.G1().Scalar().One()
	}
	return group.G1().Point().Mul(scalar, gPoint(group))
}

func proofSignatureMessage(dealer p2p.NodeID, seq uint64, proof Proof) []byte {
	buf := bytes.Buffer{}
	buf.WriteString("GRandLine-v1/APVSS/contribution-signature/")
	buf.WriteString(string(dealer))
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d", seq))
	buf.WriteByte('/')
	buf.WriteString(proof.Zeta)
	buf.WriteByte('/')
	buf.WriteString(proof.A)
	buf.WriteByte('/')
	buf.WriteString(proof.Challenge)
	buf.WriteByte('/')
	buf.WriteString(proof.Response)
	return buf.Bytes()
}

func schnorrChallenge(group *bn256.Suite, dealer p2p.NodeID, seq uint64, zeta, a kyber.Point) kyber.Scalar {
	zetaBytes, _ := zeta.MarshalBinary()
	aBytes, _ := a.MarshalBinary()
	return group.G1().Scalar().SetBytes(asig.HashBytes([]byte("GRandLine-v1/APVSS/schnorr"), []byte(dealer), []byte(fmt.Sprintf("/%d", seq)), zetaBytes, aBytes))
}

func verifyRSDualCodeG1(group *bn256.Suite, c Commitment, members []p2p.NodeID) bool {
	// Figure 1 samples a vector from LC^\perp and checks prod_i C_i^{nu_i}=1.
	// We derive the sample from the transcript for deterministic verification.
	weights, err := dualCodeWord(group.G1(), c, members)
	if err != nil {
		return false
	}
	acc := group.G1().Point().Null()
	for i, member := range members {
		ci, err := pointG1FromHex(c.Commit[member])
		if err != nil {
			return false
		}
		acc.Add(acc, group.G1().Point().Mul(weights[i], ci))
	}
	return acc.Equal(group.G1().Point().Null())
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
	buf.WriteString("GRandLine-v1/APVSS/rs-dual/")
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
	buf.WriteString("GRandLine-v1/APVSS/transcript/")
	buf.WriteString(string(c.Dealer))
	buf.WriteByte('/')
	buf.WriteString(fmt.Sprintf("%d/%d", c.Seq, c.Threshold))
	for _, contribution := range c.Contributions {
		buf.WriteByte('/')
		buf.WriteString(string(contribution.Dealer))
		buf.WriteByte(':')
		buf.WriteString(fmt.Sprintf("%d", contribution.Seq))
		buf.WriteByte(':')
		buf.WriteString(contribution.Proof.Zeta)
		buf.WriteByte(':')
		buf.WriteString(contribution.Proof.A)
		buf.WriteByte(':')
		buf.WriteString(contribution.Proof.Challenge)
		buf.WriteByte(':')
		buf.WriteString(contribution.Proof.Response)
		buf.WriteByte(':')
		buf.WriteString(contribution.Proof.Signature)
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
	s := suite().G1().Scalar()
	if err := s.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return s, nil
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
