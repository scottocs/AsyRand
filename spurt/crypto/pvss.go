package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"

	"tyche.local/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

type PVSSKeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

type PVSSCommitment struct {
	Dealer    p2p.NodeID               `json:"dealer"`
	Seq       uint64                   `json:"seq"`
	Threshold int                      `json:"threshold"`
	Members   []p2p.NodeID             `json:"members"`
	Commit    map[p2p.NodeID]string    `json:"commit"`
	Cipher    map[p2p.NodeID]string    `json:"cipher"`
	Proof     PVSSProof                `json:"proof,omitempty"`
	DLEQ      map[p2p.NodeID]DLEQProof `json:"dleq,omitempty"`
	SecretID  string                   `json:"secret_id"`
	Aggregate bool                     `json:"aggregate,omitempty"`
	Sources   []PVSSSource             `json:"sources,omitempty"`
}

type PVSSSource struct {
	Dealer   p2p.NodeID `json:"dealer"`
	Seq      uint64     `json:"seq"`
	SecretID string     `json:"secret_id"`
}

type PVSSProof struct {
	CPrime    map[p2p.NodeID]string `json:"c_prime,omitempty"`
	Challenge string                `json:"challenge,omitempty"`
	STilde    string                `json:"s_tilde,omitempty"`
	PTilde    map[p2p.NodeID]string `json:"p_tilde,omitempty"`
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

type PVSSDecryptionProof struct {
	C  string `json:"c,omitempty"`
	R  string `json:"r,omitempty"`
	VG string `json:"vg,omitempty"`
	VH string `json:"vh,omitempty"`
}

type PVSSDecryptedShare struct {
	CommitmentID string              `json:"commitment_id"`
	Holder       p2p.NodeID          `json:"holder"`
	Value        string              `json:"value"`
	Proof        PVSSDecryptionProof `json:"proof,omitempty"`
}

type PVSSScheme interface {
	Share(dealer p2p.NodeID, seq uint64, members []p2p.NodeID) (PVSSCommitment, []byte, error)
	Verify(PVSSCommitment) bool
	Aggregate(dealer p2p.NodeID, seq uint64, commitments []PVSSCommitment, members []p2p.NodeID) (PVSSCommitment, error)
	AggregateTrusted(dealer p2p.NodeID, seq uint64, commitments []PVSSCommitment, members []p2p.NodeID) (PVSSCommitment, error)
	PreRecon(PVSSCommitment, p2p.NodeID) (PVSSDecryptedShare, error)
	PreReconTrusted(PVSSCommitment, p2p.NodeID) (PVSSDecryptedShare, error)
	VerifyShare(PVSSCommitment, PVSSDecryptedShare) bool
	Recon(PVSSCommitment, []PVSSDecryptedShare, int) ([]byte, error)
	ReconTrusted(PVSSCommitment, []PVSSDecryptedShare, int) ([]byte, error)
	VerifyAggregationColumn(p2p.NodeID, PVSSCommitment, []PVSSColumnEntry) bool
}

type PVSSPairingFreeScheme struct {
	id        p2p.NodeID
	threshold int
	private   kyber.Scalar
	public    map[p2p.NodeID]kyber.Point

	// The protocol messages keep points and scalars as hex strings so they can
	// be serialized in JSON. Verification paths repeatedly touch the same
	// aggregate column, DLEQ proof, and private column entries, so cache parsed
	// kyber objects here. Each caller receives a Clone, which avoids accidental
	// mutation of cached points while removing repeated hex decode/unmarshal
	// work from the hot path.
	cacheMu     sync.RWMutex
	g1PointMemo map[string]kyber.Point
	g2PointMemo map[string]kyber.Point
	scalarMemo  map[string]kyber.Scalar
}

func NewPVSSScheme(id p2p.NodeID, threshold int, private kyber.Scalar, public map[p2p.NodeID]kyber.Point) (*PVSSPairingFreeScheme, error) {
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
	return &PVSSPairingFreeScheme{
		id:          id,
		threshold:   threshold,
		private:     private.Clone(),
		public:      cp,
		g1PointMemo: make(map[string]kyber.Point),
		g2PointMemo: make(map[string]kyber.Point),
		scalarMemo:  make(map[string]kyber.Scalar),
	}, nil
}

func PVSSKeyPairFromSeed(seed []byte) PVSSKeyPair {
	group := suite()
	sk := group.G1().Scalar().SetBytes(HashBytes([]byte("Spurt-v1/PVSS/key"), seed))
	if sk.Equal(group.G1().Scalar().Zero()) {
		sk = group.G1().Scalar().One()
	}
	return PVSSKeyPair{Private: sk, Public: group.G1().Point().Mul(sk, h0Point(group))}
}

func (s *PVSSPairingFreeScheme) Share(dealer p2p.NodeID, seq uint64, members []p2p.NodeID) (PVSSCommitment, []byte, error) {
	if dealer != s.id {
		return PVSSCommitment{}, nil, fmt.Errorf("pvss scheme for %s cannot deal as %s", s.id, dealer)
	}
	members = normalizeMembers(members)
	if len(members) < s.threshold {
		return PVSSCommitment{}, nil, errors.New("not enough members for pvss threshold")
	}
	group := suite()
	// SPURT Figure 2: sample p with p(0)=s, publish v_j=g1^{p(j)} in G2
	// and c_j=pk_j^{p(j)} in G1. Reconstruction later returns e(h0^s,h1).
	secret := group.G1().Scalar().Pick(group.RandomStream())
	poly := share.NewPriPoly(group.G1(), s.threshold, secret, group.RandomStream())
	shares := poly.Shares(len(members))

	commit := make(map[p2p.NodeID]string, len(members))
	cipher := make(map[p2p.NodeID]string, len(members))
	proofs := make(map[p2p.NodeID]DLEQProof, len(members))
	for i, member := range members {
		pk := s.public[member]
		if pk == nil {
			return PVSSCommitment{}, nil, fmt.Errorf("missing pvss public key for %s", member)
		}
		vj := group.G2().Point().Mul(shares[i].V, g1Point(group))
		cj := group.G1().Point().Mul(shares[i].V, pk)
		commit[member] = mustPointHex(vj)
		cipher[member] = mustPointHex(cj)
		proofs[member] = dleqProveShare(group, member, g1Point(group), pk, vj, cj, shares[i].V)
	}
	out := PVSSCommitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members,
		Commit: commit, Cipher: cipher, DLEQ: proofs,
	}
	out.SecretID = commitmentID(out)
	secretPoint := group.G1().Point().Mul(secret, h0Point(group))
	beaconSecret := group.Pair(secretPoint, h1Point(group))
	return out, mustPointBytes(beaconSecret), nil
}

func (s *PVSSPairingFreeScheme) Verify(c PVSSCommitment) bool {
	if c.Aggregate {
		return s.verifyAggregate(c)
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
		vj, err := s.pointG2FromHex(c.Commit[member])
		if err != nil {
			return false
		}
		cj, err := s.pointG1FromHex(c.Cipher[member])
		if err != nil {
			return false
		}
		if !group.Pair(pk, vj).Equal(group.Pair(cj, g1Point(group))) {
			return false
		}
	}
	return s.verifyRSDualCodeG2(group, c, members)
}

func (s *PVSSPairingFreeScheme) Aggregate(dealer p2p.NodeID, seq uint64, commitments []PVSSCommitment, members []p2p.NodeID) (PVSSCommitment, error) {
	for _, c := range commitments {
		if !s.Verify(c) {
			return PVSSCommitment{}, errors.New("invalid pvss commitment in aggregate")
		}
	}
	return s.AggregateTrusted(dealer, seq, commitments, members)
}

func (s *PVSSPairingFreeScheme) AggregateTrusted(dealer p2p.NodeID, seq uint64, commitments []PVSSCommitment, members []p2p.NodeID) (PVSSCommitment, error) {
	members = normalizeMembers(members)
	if len(commitments) < s.threshold {
		return PVSSCommitment{}, errors.New("not enough pvss commitments to aggregate")
	}
	// AggregateTrusted is for commitments that this node has already verified
	// before storing in its local queue. It preserves cheap structural checks
	// here, but avoids repeating the expensive pairing/R-S verification for the
	// same commitment during every leader aggregation.
	for _, c := range commitments {
		if c.Dealer == "" || c.Seq == 0 || c.SecretID == "" || c.Threshold != s.threshold {
			return PVSSCommitment{}, errors.New("invalid trusted pvss commitment in aggregate")
		}
		if commitmentID(c) != c.SecretID {
			return PVSSCommitment{}, errors.New("trusted pvss commitment id mismatch")
		}
	}
	group := suite()
	commit := make(map[p2p.NodeID]string, len(members))
	cipher := make(map[p2p.NodeID]string, len(members))
	for _, member := range members {
		var vSum kyber.Point
		var cSum kyber.Point
		for _, c := range commitments {
			vj, err := s.pointG2FromHex(c.Commit[member])
			if err != nil {
				return PVSSCommitment{}, err
			}
			cj, err := s.pointG1FromHex(c.Cipher[member])
			if err != nil {
				return PVSSCommitment{}, err
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
			return PVSSCommitment{}, errors.New("empty aggregate share")
		}
		commit[member] = mustPointHex(vSum)
		cipher[member] = mustPointHex(cSum)
	}
	sources := make([]PVSSSource, 0, len(commitments))
	for _, c := range commitments {
		sources = append(sources, PVSSSource{Dealer: c.Dealer, Seq: c.Seq, SecretID: c.SecretID})
	}
	sort.Slice(sources, func(i, j int) bool {
		if sources[i].Dealer == sources[j].Dealer {
			return sources[i].Seq < sources[j].Seq
		}
		return sources[i].Dealer < sources[j].Dealer
	})
	agg := PVSSCommitment{
		Dealer: dealer, Seq: seq, Threshold: s.threshold, Members: members,
		Commit: commit, Cipher: cipher, Aggregate: true, Sources: sources,
	}
	agg.SecretID = commitmentID(agg)
	return agg, nil
}

func (s *PVSSPairingFreeScheme) PreRecon(c PVSSCommitment, holder p2p.NodeID) (PVSSDecryptedShare, error) {
	if !s.Verify(c) {
		return PVSSDecryptedShare{}, errors.New("invalid pvss commitment")
	}
	return s.PreReconTrusted(c, holder)
}

func (s *PVSSPairingFreeScheme) PreReconTrusted(c PVSSCommitment, holder p2p.NodeID) (PVSSDecryptedShare, error) {
	if holder != s.id {
		return PVSSDecryptedShare{}, fmt.Errorf("pvss scheme for %s cannot decrypt as %s", s.id, holder)
	}
	cipher, err := pointG1FromHex(c.Cipher[holder])
	if err != nil {
		return PVSSDecryptedShare{}, err
	}
	group := suite()
	plain := group.G1().Point().Mul(group.G1().Scalar().Inv(s.private), cipher)
	return PVSSDecryptedShare{CommitmentID: c.SecretID, Holder: holder, Value: mustPointHex(plain)}, nil
}

func (s *PVSSPairingFreeScheme) VerifyShare(c PVSSCommitment, sh PVSSDecryptedShare) bool {
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

func (s *PVSSPairingFreeScheme) Recon(c PVSSCommitment, shares []PVSSDecryptedShare, threshold int) ([]byte, error) {
	if threshold <= 0 {
		threshold = c.Threshold
	}
	if threshold != c.Threshold {
		return nil, errors.New("pvss threshold mismatch")
	}
	return s.ReconTrusted(c, shares, threshold)
}

func (s *PVSSPairingFreeScheme) ReconTrusted(c PVSSCommitment, shares []PVSSDecryptedShare, threshold int) ([]byte, error) {
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

func (s *PVSSPairingFreeScheme) VerifyAggregationColumn(holder p2p.NodeID, aggregate PVSSCommitment, entries []PVSSColumnEntry) bool {
	if holder == "" || !aggregate.Aggregate || len(entries) < aggregate.Threshold || len(entries) != len(aggregate.Sources) {
		return false
	}
	group := suite()
	// Public aggregate verification proves that the published aggregate is
	// well formed. This private-column check proves the holder's private
	// vbar/cbar/pi_bar data is exactly the sum of the selected public inputs.
	// It reuses cached parsed points because the same aggregate column was often
	// parsed during public verification immediately before this function.
	aggCommit, err := s.pointG2FromHex(aggregate.Commit[holder])
	if err != nil {
		return false
	}
	aggCipher, err := s.pointG1FromHex(aggregate.Cipher[holder])
	if err != nil {
		return false
	}
	seen := make(map[string]struct{}, len(entries))
	commitSum := group.G2().Point().Null()
	cipherSum := group.G1().Point().Null()
	for _, entry := range entries {
		if entry.Source.Dealer == "" || entry.Source.SecretID == "" || entry.Source.Seq == 0 {
			return false
		}
		key := fmt.Sprintf("%s/%d/%s", entry.Source.Dealer, entry.Source.Seq, entry.Source.SecretID)
		if _, ok := seen[key]; ok {
			return false
		}
		seen[key] = struct{}{}
		if !aggregateHasSource(aggregate, entry.Source) {
			return false
		}
		vj, err := s.pointG2FromHex(entry.Commit)
		if err != nil {
			return false
		}
		cj, err := s.pointG1FromHex(entry.Cipher)
		if err != nil {
			return false
		}
		pk := s.public[holder]
		// The DLEQ proof binds the G2 commitment share v_j and the G1 encrypted
		// share c_j to the same exponent under the holder's public key. This is
		// the private-data validation required before the node accepts the
		// leader's aggregate for reconstruction.
		if pk == nil || !s.dleqVerifyShare(group, holder, g1Point(group), pk, vj, cj, entry.Proof) {
			return false
		}
		commitSum.Add(commitSum, vj)
		cipherSum.Add(cipherSum, cj)
	}
	return commitSum.Equal(aggCommit) && cipherSum.Equal(aggCipher)
}

func (s *PVSSPairingFreeScheme) dleqVerifyShare(group *bn256.Suite, holder p2p.NodeID, g kyber.Point, pk kyber.Point, v kyber.Point, c kyber.Point, proof DLEQProof) bool {
	a, err := s.pointG2FromHex(proof.A)
	if err != nil {
		return false
	}
	b, err := s.pointG1FromHex(proof.B)
	if err != nil {
		return false
	}
	chal := s.scalarFromHex(group.G1(), proof.Challenge)
	resp := s.scalarFromHex(group.G1(), proof.Response)
	if chal == nil || resp == nil || !dleqShareChallenge(group, holder, g, pk, v, c, a, b).Equal(chal) {
		return false
	}
	leftV := group.G2().Point().Mul(resp, g)
	rightV := group.G2().Point().Add(a, group.G2().Point().Mul(chal, v))
	leftC := group.G1().Point().Mul(resp, pk)
	rightC := group.G1().Point().Add(b, group.G1().Point().Mul(chal, c))
	return leftV.Equal(rightV) && leftC.Equal(rightC)
}

func CommitmentID(c PVSSCommitment) string {
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
	h := group.G2().Scalar().SetBytes(HashBytes([]byte("Spurt-v1/PVSS/h1")))
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

func commitmentID(c PVSSCommitment) string {
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
	sources := append([]PVSSSource(nil), c.Sources...)
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
	return hex.EncodeToString(HashBytes(buf.Bytes()))
}

func verifyAggregate(c PVSSCommitment) bool {
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

func (s *PVSSPairingFreeScheme) verifyAggregate(c PVSSCommitment) bool {
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
		if _, err := s.pointG1FromHex(c.Cipher[member]); err != nil {
			return false
		}
		if _, err := s.pointG2FromHex(c.Commit[member]); err != nil {
			return false
		}
	}
	return s.verifyRSDualCodeG2(suite(), c, members)
}

func aggregateHasSource(c PVSSCommitment, source PVSSSource) bool {
	for _, existing := range c.Sources {
		if existing.Dealer == source.Dealer && existing.Seq == source.Seq && existing.SecretID == source.SecretID {
			return true
		}
	}
	return false
}

func dleqProveShare(group *bn256.Suite, holder p2p.NodeID, g kyber.Point, pk kyber.Point, v kyber.Point, c kyber.Point, x kyber.Scalar) DLEQProof {
	r := group.G1().Scalar().Pick(group.RandomStream())
	a := group.G2().Point().Mul(r, g)
	b := group.G1().Point().Mul(r, pk)
	chal := dleqShareChallenge(group, holder, g, pk, v, c, a, b)
	resp := group.G1().Scalar().Add(r, group.G1().Scalar().Mul(chal, x))
	return DLEQProof{A: mustPointHex(a), B: mustPointHex(b), Challenge: scalarHex(chal), Response: scalarHex(resp)}
}

func dleqVerifyShare(group *bn256.Suite, holder p2p.NodeID, g kyber.Point, pk kyber.Point, v kyber.Point, c kyber.Point, proof DLEQProof) bool {
	a, err := pointG2FromHex(proof.A)
	if err != nil {
		return false
	}
	b, err := pointG1FromHex(proof.B)
	if err != nil {
		return false
	}
	chal := scalarFromHex(group.G1(), proof.Challenge)
	resp := scalarFromHex(group.G1(), proof.Response)
	if chal == nil || resp == nil || !dleqShareChallenge(group, holder, g, pk, v, c, a, b).Equal(chal) {
		return false
	}
	leftV := group.G2().Point().Mul(resp, g)
	rightV := group.G2().Point().Add(a, group.G2().Point().Mul(chal, v))
	leftC := group.G1().Point().Mul(resp, pk)
	rightC := group.G1().Point().Add(b, group.G1().Point().Mul(chal, c))
	return leftV.Equal(rightV) && leftC.Equal(rightC)
}

func dleqShareChallenge(group *bn256.Suite, holder p2p.NodeID, g kyber.Point, pk kyber.Point, v kyber.Point, c kyber.Point, a kyber.Point, b kyber.Point) kyber.Scalar {
	buf := bytes.Buffer{}
	buf.WriteString("Spurt-v1/PVSS/dleq-share/")
	buf.WriteString(string(holder))
	for _, p := range []kyber.Point{g, pk, v, c, a, b} {
		buf.WriteByte('/')
		buf.Write(mustPointBytes(p))
	}
	return group.G1().Scalar().SetBytes(HashBytes(buf.Bytes()))
}

func verifyRSDualCodeG2(group *bn256.Suite, c PVSSCommitment, members []p2p.NodeID) bool {
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

func (s *PVSSPairingFreeScheme) verifyRSDualCodeG2(group *bn256.Suite, c PVSSCommitment, members []p2p.NodeID) bool {
	weights, err := dualCodeWord(group.G2(), c, members)
	if err != nil {
		return false
	}
	acc := group.G2().Point().Null()
	for i, member := range members {
		vj, err := s.pointG2FromHex(c.Commit[member])
		if err != nil {
			return false
		}
		acc.Add(acc, group.G2().Point().Mul(weights[i], vj))
	}
	return acc.Equal(group.G2().Point().Null())
}

func dualCodeWord(group kyber.Group, c PVSSCommitment, members []p2p.NodeID) ([]kyber.Scalar, error) {
	if c.Threshold <= 0 || len(members) < c.Threshold {
		return nil, errors.New("invalid Reed-Solomon parameters")
	}
	degree := len(members) - c.Threshold - 1
	coeffs := make([]kyber.Scalar, max(1, degree+1))
	seed := dualCodeSeed(c, members)
	for i := range coeffs {
		coeffs[i] = group.Scalar().SetBytes(HashBytes(seed, []byte(fmt.Sprintf("/%d", i))))
	}
	out := make([]kyber.Scalar, len(members))
	for i := range members {
		xi := group.Scalar().SetInt64(int64(i + 1))
		out[i] = group.Scalar().Mul(evalScalarPoly(group, coeffs, xi), dualMultiplier(group, i, len(members)))
	}
	return out, nil
}

func dualCodeSeed(c PVSSCommitment, members []p2p.NodeID) []byte {
	buf := bytes.Buffer{}
	buf.WriteString("Spurt-v1/PVSS/rs-dual/")
	buf.WriteString(c.SecretID)
	for _, member := range members {
		buf.WriteByte('/')
		buf.WriteString(string(member))
		buf.WriteByte(':')
		buf.WriteString(c.Commit[member])
	}
	return HashBytes(buf.Bytes())
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

func (s *PVSSPairingFreeScheme) scalarFromHex(group kyber.Group, raw string) kyber.Scalar {
	s.cacheMu.RLock()
	if cached := s.scalarMemo[raw]; cached != nil {
		s.cacheMu.RUnlock()
		return cached.Clone()
	}
	s.cacheMu.RUnlock()

	parsed := scalarFromHex(group, raw)
	if parsed == nil {
		return nil
	}
	// Store only successfully parsed scalars. Invalid encodings are cheap to
	// reject and should not poison the cache.
	s.cacheMu.Lock()
	if cached := s.scalarMemo[raw]; cached != nil {
		s.cacheMu.Unlock()
		return cached.Clone()
	}
	s.scalarMemo[raw] = parsed.Clone()
	s.cacheMu.Unlock()
	return parsed
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

func (s *PVSSPairingFreeScheme) pointG1FromHex(v string) (kyber.Point, error) {
	s.cacheMu.RLock()
	if cached := s.g1PointMemo[v]; cached != nil {
		s.cacheMu.RUnlock()
		return cached.Clone(), nil
	}
	s.cacheMu.RUnlock()

	parsed, err := pointG1FromHex(v)
	if err != nil {
		return nil, err
	}
	// Cache by the wire encoding, not by commitment id, because the same point
	// can appear in multiple validation steps and this keeps the lookup local to
	// the parser.
	s.cacheMu.Lock()
	if cached := s.g1PointMemo[v]; cached != nil {
		s.cacheMu.Unlock()
		return cached.Clone(), nil
	}
	s.g1PointMemo[v] = parsed.Clone()
	s.cacheMu.Unlock()
	return parsed, nil
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

func (s *PVSSPairingFreeScheme) pointG2FromHex(v string) (kyber.Point, error) {
	s.cacheMu.RLock()
	if cached := s.g2PointMemo[v]; cached != nil {
		s.cacheMu.RUnlock()
		return cached.Clone(), nil
	}
	s.cacheMu.RUnlock()

	parsed, err := pointG2FromHex(v)
	if err != nil {
		return nil, err
	}
	// Return clones from the cache because kyber Point methods mutate their
	// receiver. Sharing the cached object directly would make later checks
	// depend on prior arithmetic.
	s.cacheMu.Lock()
	if cached := s.g2PointMemo[v]; cached != nil {
		s.cacheMu.Unlock()
		return cached.Clone(), nil
	}
	s.g2PointMemo[v] = parsed.Clone()
	s.cacheMu.Unlock()
	return parsed, nil
}
