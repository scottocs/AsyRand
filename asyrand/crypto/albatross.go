package crypto

import (
	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"go.dedis.ch/kyber/v3"
)

const albatrossPVSSVersion = "AsyRand-v1/ALBATROSS-DDH/edwards25519"

// NewALBATROSSPVSSScheme creates the single-secret ALBATROSS PVSS from
// Cascudo and David, ASIACRYPT 2020, Sections 3.2 and 4.1:
// https://iacr.org/archive/asiacrypt2020/12491371/12491371.pdf
//
// It uses the existing PVSS keys and generator h, encrypts h^F(alpha_i) under
// each shareholder key, and proves low-degree exponent interpolation (LDEI).
// Unlike SCRAPE, Commit contains nonce commitments, not public share values.
// The response polynomial is encoded by exactly threshold coefficients.
// Decryption publishes the paper's (d,a,b,z) Chaum-Pedersen transcript, with a
// separate protocol domain and verifier-derived challenge. NewPVSSScheme
// remains the SCRAPE constructor for explicit comparisons.
func NewALBATROSSPVSSScheme(id p2p.NodeID, threshold int, private kyber.Scalar, public map[p2p.NodeID]kyber.Point, caches ...*verification.Cache) (*PVSSPairingFreeScheme, error) {
	return newPVSSScheme(albatrossPVSSVersion, id, threshold, private, public, caches...)
}

// NewALBATROSSPVSSVerifier verifies sharing/decryption proofs and reconstructs
// group values without a shareholder secret key.
func NewALBATROSSPVSSVerifier(threshold int, public map[p2p.NodeID]kyber.Point, caches ...*verification.Cache) (*PVSSPairingFreeScheme, error) {
	return newPVSSVerifier(albatrossPVSSVersion, threshold, public, caches...)
}

func (s *PVSSPairingFreeScheme) shareALBATROSS(dealer p2p.NodeID, seq uint64) (PVSSCommitment, []byte, error) {
	group := suite()
	stream := group.RandomStream()
	coefficients := make([]kyber.Scalar, s.threshold)
	for i := range coefficients {
		coefficients[i] = group.Scalar().Pick(stream)
	}
	c := PVSSCommitment{
		Version: s.version, SetupID: s.setupID, Dealer: dealer, Seq: seq,
		Threshold: s.threshold, Members: append([]p2p.NodeID(nil), s.members...),
		Cipher: make(map[p2p.NodeID]string, len(s.members)),
	}
	ciphertexts := make([]kyber.Point, len(s.members))
	cryptoexec.AllLabeled("pvss-share", len(s.members), func(i int) bool {
		member := s.members[i]
		cipher := group.Point().Mul(evaluatePVSSPolynomial(coefficients, i+1), s.public[member])
		ciphertexts[i] = cipher
		return true
	})
	for i, member := range s.members {
		cipher := ciphertexts[i]
		c.Cipher[member] = mustPointHex(cipher)
		s.cachePoint(c.Cipher[member], cipher)
	}
	s.proveALBATROSSSharing(&c, coefficients)
	c.SecretID = commitmentID(c)
	return c, mustPointBytes(group.Point().Mul(coefficients[0], s.h)), nil
}

func (s *PVSSPairingFreeScheme) proveALBATROSSSharing(c *PVSSCommitment, coefficients []kyber.Scalar) {
	group := suite()
	stream := group.RandomStream()
	nonces := make([]kyber.Scalar, s.threshold)
	for i := range nonces {
		nonces[i] = group.Scalar().Pick(stream)
	}
	c.Commit = make(map[p2p.NodeID]string, len(s.members))
	commitments := make([]kyber.Point, len(s.members))
	cryptoexec.AllLabeled("pvss-share", len(s.members), func(i int) bool {
		member := s.members[i]
		commitment := group.Point().Mul(evaluatePVSSPolynomial(nonces, i+1), s.public[member])
		commitments[i] = commitment
		return true
	})
	for i, member := range s.members {
		commitment := commitments[i]
		c.Commit[member] = mustPointHex(commitment)
		s.cachePoint(c.Commit[member], commitment)
	}
	challenge := albatrossSharingChallenge(*c)
	c.Proof = PVSSProof{Challenge: scalarHex(challenge), Coefficients: make([]string, s.threshold)}
	for i := range nonces {
		response := group.Scalar().Add(nonces[i], group.Scalar().Mul(challenge, coefficients[i]))
		c.Proof.Coefficients[i] = scalarHex(response)
	}
}

func (s *PVSSPairingFreeScheme) verifyALBATROSS(c PVSSCommitment) bool {
	if !s.validHeader(c) {
		return false
	}
	challenge := scalarFromHex(c.Proof.Challenge)
	if challenge == nil || !albatrossSharingChallenge(c).Equal(challenge) {
		return false
	}
	coefficients := make([]kyber.Scalar, s.threshold)
	for i, encoded := range c.Proof.Coefficients {
		coefficients[i] = scalarFromHex(encoded)
		if coefficients[i] == nil {
			return false
		}
	}
	negativeChallenge := suite().Scalar().Neg(challenge)
	return cryptoexec.AllLabeled("pvss-verify", len(s.members), func(i int) bool {
		member := s.members[i]
		commitment, err := s.pointFromHex(c.Commit[member])
		if err != nil {
			return false
		}
		cipher, err := s.pointFromHex(c.Cipher[member])
		if err != nil {
			return false
		}
		if !publicPointDoubleMulEqual(evaluatePVSSPolynomial(coefficients, i+1), s.public[member], negativeChallenge, cipher, commitment) {
			return false
		}
		return true
	})
}

func albatrossSharingChallenge(c PVSSCommitment) kyber.Scalar {
	// objectBytes includes the complete context, ciphertexts and LDEI nonce
	// commitments, but excludes the response/challenge and the object ID.
	return oracleScalar(albatrossPVSSVersion+"/share-ldei", objectBytes(c))
}

// Coefficients are in increasing degree order; receivers must validate the
// exact threshold-length encoding before evaluating an untrusted polynomial.
func evaluatePVSSPolynomial(coefficients []kyber.Scalar, alpha int) kyber.Scalar {
	group := suite()
	x := group.Scalar().SetInt64(int64(alpha))
	value := group.Scalar().Zero()
	for i := len(coefficients) - 1; i >= 0; i-- {
		value.Mul(value, x).Add(value, coefficients[i])
	}
	return value
}
