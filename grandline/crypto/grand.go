package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"Tyche/utils/p2p"
	"Tyche/utils/pairing"
	"Tyche/utils/verification"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

type GRandResult struct {
	Reference    *ReferenceCommitments `json:"reference,omitempty"`
	N            int
	Threshold    int
	Transcript   PVSSCommitment
	PublicKey    string
	PublicShares map[p2p.NodeID]string
	SecretShares map[p2p.NodeID]string
}

type GRandShare struct {
	N            int
	Threshold    int
	PublicKey    string
	PublicShares map[p2p.NodeID]string
	SecretShare  string
}

type BeaconCommitment struct {
	Signer p2p.NodeID `json:"signer"`
	CM1    string     `json:"cm1"`
	CM2    string     `json:"cm2"`
}

type VerifiedBeaconCommitment struct {
	Signer      p2p.NodeID
	Commitment  BeaconCommitment
	PublicShare kyber.Point
	CM1         kyber.Point
	CM2         kyber.Point
}

type BeaconDLEQProof struct {
	A1        string `json:"a1"`
	A2        string `json:"a2"`
	Challenge string `json:"challenge"`
	Response  string `json:"response"`
}

type BeaconShare struct {
	Epoch  uint64          `json:"epoch"`
	Signer p2p.NodeID      `json:"signer"`
	Sigma1 string          `json:"sigma1"`
	Sigma2 string          `json:"sigma2"`
	Proof  BeaconDLEQProof `json:"proof"`
}

func SetupGRandFromAPVSS(ids []p2p.NodeID, schemes map[p2p.NodeID]*PVSSPairingFreeScheme, threshold int) (GRandResult, error) {
	ids = normalizeMembers(ids)
	if len(ids) == 0 {
		return GRandResult{}, errors.New("grand setup needs at least one participant")
	}
	if threshold <= 0 || threshold > len(ids) {
		return GRandResult{}, errors.New("invalid grand threshold")
	}
	transcripts := make([]PVSSCommitment, 0, len(ids))
	for i, id := range ids {
		scheme := schemes[id]
		if scheme == nil {
			return GRandResult{}, fmt.Errorf("missing APVSS scheme for %s", id)
		}
		transcript, _, err := scheme.Share(id, uint64(i+1), ids)
		if err != nil {
			return GRandResult{}, err
		}
		transcripts = append(transcripts, transcript)
	}
	aggregator := schemes[ids[0]]
	aggregate, err := aggregator.Aggregate("grand", 1, transcripts, ids)
	if err != nil {
		return GRandResult{}, err
	}
	if !aggregator.Verify(aggregate) {
		return GRandResult{}, errors.New("generated GRand aggregate transcript does not verify")
	}
	publicKey, err := recoverG1PublicKey(aggregate, ids)
	if err != nil {
		return GRandResult{}, err
	}
	secrets := make(map[p2p.NodeID]string, len(ids))
	for _, id := range ids {
		scheme := schemes[id]
		dec, err := scheme.PreReconTrusted(aggregate, id)
		if err != nil {
			return GRandResult{}, err
		}
		if !scheme.VerifyShare(aggregate, dec) {
			return GRandResult{}, fmt.Errorf("invalid GRand decrypted share for %s", id)
		}
		secrets[id] = dec.Value
	}
	publicShares := make(map[p2p.NodeID]string, len(ids))
	for _, id := range ids {
		publicShares[id] = aggregate.Commit[id]
	}
	return GRandResult{
		N: len(ids), Threshold: threshold, Transcript: aggregate, PublicKey: publicKey,
		PublicShares: publicShares, SecretShares: secrets,
	}, nil
}

func (r GRandResult) ShareFor(id p2p.NodeID) GRandShare {
	publicShares := make(map[p2p.NodeID]string, len(r.PublicShares))
	for k, v := range r.PublicShares {
		publicShares[k] = v
	}
	return GRandShare{
		N: r.N, Threshold: r.Threshold, PublicKey: r.PublicKey,
		PublicShares: publicShares, SecretShare: r.SecretShares[id],
	}
}

func NewBeaconCommitment(signer p2p.NodeID, secretShare string) (BeaconCommitment, kyber.Scalar, error) {
	group := suite()
	sk, err := pointG2FromHex(secretShare)
	if err != nil {
		return BeaconCommitment{}, nil, err
	}
	alpha := group.G1().Scalar().Pick(group.RandomStream())
	for alpha.Equal(group.G1().Scalar().Zero()) {
		alpha.Pick(group.RandomStream())
	}
	cm1 := group.G1().Point().Mul(alpha, gPoint(group))
	negAlpha := group.G2().Scalar().Neg(group.G2().Scalar().Set(alpha))
	cm2 := group.G2().Point().Add(group.G2().Point().Mul(negAlpha, hPoint(group)), sk)
	return BeaconCommitment{Signer: signer, CM1: mustPointHex(cm1), CM2: mustPointHex(cm2)}, alpha, nil
}

func VerifyBeaconCommitment(publicShare string, commitment BeaconCommitment, caches ...*verification.Cache) bool {
	_, ok := DecodeAndVerifyBeaconCommitment(publicShare, commitment, caches...)
	return ok
}

func DecodeAndVerifyBeaconCommitment(publicShare string, commitment BeaconCommitment, caches ...*verification.Cache) (*VerifiedBeaconCommitment, bool) {
	group := suite()
	pk, err := pointG1FromHex(publicShare)
	if err != nil {
		return nil, false
	}
	cm1, err := pointG1FromHex(commitment.CM1)
	if err != nil {
		return nil, false
	}
	cm2, err := pointG2FromHex(commitment.CM2)
	if err != nil {
		return nil, false
	}
	valid := verification.Optional(caches...).Check(verification.JSONKey("grandline/beacon-commitment", publicShare, commitment), func() bool {
		negativePK := group.G1().Point().Neg(pk)
		return group.PairProduct([2]kyber.Point{negativePK, hPoint(group)},
			[2]kyber.Point{cm1, hPoint(group)}, [2]kyber.Point{gPoint(group), cm2}).Equal(group.GT().Point().Null())
	})
	if !valid {
		return nil, false
	}
	return &VerifiedBeaconCommitment{
		Signer:      commitment.Signer,
		Commitment:  commitment,
		PublicShare: pk,
		CM1:         cm1,
		CM2:         cm2,
	}, true
}

func NewBeaconShare(epoch uint64, msg []byte, signer p2p.NodeID, secretShare string, alpha kyber.Scalar) (BeaconShare, error) {
	group := suite()
	cm1 := group.G1().Point().Mul(alpha, gPoint(group))
	return NewBeaconShareWithCommitment(epoch, msg, signer, secretShare, alpha, cm1)
}

func NewBeaconShareWithCommitment(epoch uint64, msg []byte, signer p2p.NodeID, secretShare string, alpha kyber.Scalar, cm1 kyber.Point) (BeaconShare, error) {
	if alpha == nil {
		return BeaconShare{}, errors.New("nil beacon commitment alpha")
	}
	if cm1 == nil {
		return BeaconShare{}, errors.New("nil beacon commitment cm1")
	}
	group := suite()
	sk, err := pointG2FromHex(secretShare)
	if err != nil {
		return BeaconShare{}, err
	}
	gr := hashToG1(group, msg)
	sigma1 := group.G1().Point().Mul(alpha, gr)
	sigma2 := group.Pair(gr, sk)
	proof := proveBeaconDLEQ(group, msg, alpha, cm1, sigma1, gr)
	return BeaconShare{
		Epoch: epoch, Signer: signer, Sigma1: mustPointHex(sigma1),
		Sigma2: mustPointHexGT(sigma2), Proof: proof,
	}, nil
}

func VerifyBeaconShare(msg []byte, publicShare string, commitment BeaconCommitment, share BeaconShare, caches ...*verification.Cache) bool {
	if share.Signer == "" || share.Signer != commitment.Signer {
		return false
	}
	verified, ok := DecodeAndVerifyBeaconCommitment(publicShare, commitment, caches...)
	if !ok {
		return false
	}
	return VerifyBeaconShareWithCommitment(msg, verified, share, caches...)
}

func VerifyBeaconShareWithCommitment(msg []byte, commitment *VerifiedBeaconCommitment, share BeaconShare, caches ...*verification.Cache) bool {
	if commitment == nil || commitment.CM1 == nil || commitment.CM2 == nil {
		return false
	}
	cache := verification.Optional(caches...)
	key := verification.JSONKey("grandline/beacon-share", msg, commitment.Signer, mustPointBytes(commitment.CM1), mustPointBytes(commitment.CM2), share)
	return cache.Check(key, func() bool { return verifyBeaconShareUncached(msg, commitment, share, cache) })
}
func verifyBeaconShareUncached(msg []byte, commitment *VerifiedBeaconCommitment, share BeaconShare, cache *verification.Cache) bool {
	_, ok := NewBeaconEpoch(share.Epoch, msg).verifyUncached(commitment, share, cache)
	return ok
}

func RecoverBeacon(msg []byte, shares []BeaconShare, threshold int, members []p2p.NodeID) ([]byte, string, error) {
	if threshold <= 0 {
		return nil, "", errors.New("invalid beacon threshold")
	}
	members = normalizeMembers(members)
	indices := memberIndex(members)
	group := suite()
	seen := make(map[p2p.NodeID]bool, len(shares))
	pubShares := make([]*share.PubShare, 0, len(shares))
	for _, sh := range shares {
		if seen[sh.Signer] {
			continue
		}
		sigma2, err := pointGTFromHex(sh.Sigma2)
		if err != nil {
			continue
		}
		idx, ok := indices[sh.Signer]
		if !ok {
			continue
		}
		seen[sh.Signer] = true
		pubShares = append(pubShares, &share.PubShare{I: idx, V: sigma2})
	}
	if len(pubShares) < threshold {
		return nil, "", errors.New("not enough valid beacon shares")
	}
	sigma, err := share.RecoverCommit(group.GT(), pubShares, threshold, len(members))
	if err != nil {
		return nil, "", err
	}
	raw, err := sigma.MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	return HashBytes(raw), hex.EncodeToString(raw), nil
}

func recoverG1PublicKey(c PVSSCommitment, members []p2p.NodeID) (string, error) {
	group := suite()
	index := memberIndex(members)
	pubShares := make([]*share.PubShare, 0, len(members))
	for _, member := range members {
		ci, err := pointG1FromHex(c.Commit[member])
		if err != nil {
			return "", err
		}
		pubShares = append(pubShares, &share.PubShare{I: index[member], V: ci})
	}
	pk, err := share.RecoverCommit(group.G1(), pubShares, c.Threshold, len(members))
	if err != nil {
		return "", err
	}
	return mustPointHex(pk), nil
}

func hashToG1(group interface{ G1() kyber.Group }, msg []byte) kyber.Point {
	return pairing.HashG2(msg, []byte("TYCHE_GRANDLINE_BEACON_BLS12381G2_XMD:SHA-256_SSWU_RO_"))
}

func proveBeaconDLEQ(group interface {
	G1() kyber.Group
}, msg []byte, alpha kyber.Scalar, cm1 kyber.Point, sigma1 kyber.Point, gr kyber.Point) BeaconDLEQProof {
	nonce := group.G1().Scalar().Pick(suite().RandomStream())
	a1 := group.G1().Point().Mul(nonce, gPoint(suite()))
	a2 := group.G1().Point().Mul(nonce, gr)
	challenge := beaconDLEQChallenge(group, msg, cm1, sigma1, a1, a2)
	response := group.G1().Scalar().Sub(nonce, group.G1().Scalar().Mul(challenge, alpha))
	return BeaconDLEQProof{
		A1: mustPointHex(a1), A2: mustPointHex(a2),
		Challenge: mustScalarHex(challenge), Response: mustScalarHex(response),
	}
}

func verifyBeaconDLEQWithCM1(group interface {
	G1() kyber.Group
}, msg []byte, cm1 kyber.Point, sigma1 kyber.Point, proof BeaconDLEQProof, gr kyber.Point, caches ...*verification.Cache) bool {
	key := verification.JSONKey("grandline/beacon-dleq", msg, mustPointBytes(cm1), mustPointBytes(sigma1), mustPointBytes(gr), proof)
	return verification.Optional(caches...).Check(key, func() bool { return verifyBeaconDLEQUncached(group, msg, cm1, sigma1, proof, gr) })
}
func verifyBeaconDLEQUncached(group interface{ G1() kyber.Group }, msg []byte, cm1 kyber.Point, sigma1 kyber.Point, proof BeaconDLEQProof, gr kyber.Point) bool {
	a1, err := pointG1FromHex(proof.A1)
	if err != nil {
		return false
	}
	a2, err := pointG1FromHex(proof.A2)
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
	if !beaconDLEQChallenge(group, msg, cm1, sigma1, a1, a2).Equal(challenge) {
		return false
	}
	checkA1 := group.G1().Point().Add(group.G1().Point().Mul(response, gPoint(suite())), group.G1().Point().Mul(challenge, cm1))
	checkA2 := group.G1().Point().Add(group.G1().Point().Mul(response, gr), group.G1().Point().Mul(challenge, sigma1))
	return a1.Equal(checkA1) && a2.Equal(checkA2)
}

func beaconDLEQChallenge(group interface {
	G1() kyber.Group
}, msg []byte, cm1, sigma1, a1, a2 kyber.Point) kyber.Scalar {
	parts := [][]byte{[]byte("GRandLine-v3/beacon-dleq"), msg}
	for _, p := range []kyber.Point{cm1, sigma1, a1, a2} {
		raw, _ := p.MarshalBinary()
		parts = append(parts, raw)
	}
	return group.G1().Scalar().SetBytes(HashBytes(parts...))
}

func mustPointHexGT(p kyber.Point) string {
	raw, err := p.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

func pointGTFromHex(v string) (kyber.Point, error) {
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	p := suite().GT().Point()
	if err := p.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return p, nil
}

func CanonicalCommitments(commits map[p2p.NodeID]BeaconCommitment) []BeaconCommitment {
	out := make([]BeaconCommitment, 0, len(commits))
	for _, commit := range commits {
		out = append(out, commit)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Signer < out[j].Signer })
	return out
}

func CommitmentDigest(commits []BeaconCommitment) []byte {
	var buf bytes.Buffer
	buf.WriteString("GRandLine-v3/commitments/")
	for _, commit := range commits {
		buf.WriteString(string(commit.Signer))
		buf.WriteByte('/')
		buf.WriteString(commit.CM1)
		buf.WriteByte('/')
		buf.WriteString(commit.CM2)
		buf.WriteByte('/')
	}
	return HashBytes(buf.Bytes())
}

// ValidateGRandSetup validates a common offline setup used by the benchmark
// runner. It is not an implementation of the paper's distributed DKG protocol.
func ValidateGRandSetup(r GRandResult, members []p2p.NodeID, schemes map[p2p.NodeID]*PVSSPairingFreeScheme, threshold int) error {
	members = normalizeMembers(members)
	if len(members) == 0 || r.N != len(members) || r.Threshold != threshold || r.Transcript.Threshold != threshold || len(r.Transcript.Members) != len(members) || len(r.PublicShares) != len(members) || len(r.SecretShares) != len(members) {
		return errors.New("GRand setup dimensions do not match the committee")
	}
	for i, id := range members {
		if r.Transcript.Members[i] != id {
			return errors.New("GRand setup membership mismatch")
		}
	}
	verifier := schemes[members[0]]
	if verifier == nil || !verifier.Verify(r.Transcript) {
		return errors.New("invalid GRand setup transcript")
	}
	pk, err := recoverG1PublicKey(r.Transcript, members)
	if err != nil || pk != r.PublicKey {
		return errors.New("GRand setup public key mismatch")
	}
	group := suite()
	key, err := pointG1FromHex(pk)
	if err != nil || key.Equal(group.G1().Point().Null()) {
		return errors.New("invalid GRand group public key")
	}
	for _, id := range members {
		if r.PublicShares[id] != r.Transcript.Commit[id] {
			return errors.New("GRand public share mismatch")
		}
		pub, err := pointG1FromHex(r.PublicShares[id])
		if err != nil {
			return err
		}
		secret, err := pointG2FromHex(r.SecretShares[id])
		if err != nil {
			return err
		}
		if !group.Pair(pub, hPoint(group)).Equal(group.Pair(gPoint(group), secret)) {
			return errors.New("GRand secret share mismatch")
		}
	}
	return nil
}
