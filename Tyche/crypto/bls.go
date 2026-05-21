package crypto

import (
	"encoding/hex"
	"errors"
	"sort"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/sign/bls"
)

type BLSKeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

// BLSSignatureShare is a normal per-node BLS signature over the READY
// transcript. It is intentionally not a threshold-BLS share: every signer owns
// an independent key, and the verifier still checks which public keys
// contributed to the final quorum certificate.
type BLSSignatureShare struct {
	Signer string `json:"signer"`
	Sig    []byte `json:"sig"`
}

// BLSAggregateSignature compresses a quorum of READY signatures into one BLS
// aggregate signature plus the signer list needed to reconstruct the aggregate
// public key. This gives Tyche the same kind of compact READY certificate used
// by the AsyRand/SPURT implementations without changing the beacon randomness
// construction.
type BLSAggregateSignature struct {
	Signers []string `json:"signers"`
	SigHex  string   `json:"sig_hex"`
}

// NewBLSKeyPairFromSeed is deterministic so tests and local benchmarks are
// reproducible. Production deployments should replace this with configured or
// securely generated long-lived BLS keys.
func NewBLSKeyPairFromSeed(seed []byte) BLSKeyPair {
	suite := pairingSuite()
	sk := suite.G2().Scalar().SetBytes(HashBytes([]byte("Tyche-v1/BLS/key"), seed))
	if sk.Equal(suite.G2().Scalar().Zero()) {
		sk = suite.G2().Scalar().One()
	}
	return BLSKeyPair{Private: sk, Public: suite.G2().Point().Mul(sk, nil)}
}

// SignBLS signs a canonical READY statement with this node's independent BLS
// key. The caller is responsible for choosing a transcript that binds the epoch,
// source, sequence number, and random hash.
func SignBLS(signer string, priv kyber.Scalar, msg []byte) (BLSSignatureShare, error) {
	if priv == nil {
		return BLSSignatureShare{}, errors.New("nil BLS private key")
	}
	sig, err := bls.Sign(pairingSuite(), priv, msg)
	if err != nil {
		return BLSSignatureShare{}, err
	}
	return BLSSignatureShare{Signer: signer, Sig: sig}, nil
}

// VerifyBLSShare validates one READY signature before it is counted in the
// READY quorum. This prevents a node from contributing a sender id without a
// cryptographic vote over the exact beacon statement.
func VerifyBLSShare(share BLSSignatureShare, pubs map[string]kyber.Point, msg []byte) bool {
	pub := pubs[share.Signer]
	if pub == nil || len(share.Sig) == 0 {
		return false
	}
	return bls.Verify(pairingSuite(), pub, msg, share.Sig) == nil
}

// AggregateBLSTrusted is used after the protocol code has already verified and
// de-duplicated individual READY shares. It still verifies the resulting
// aggregate signature before returning, so the final Beacon never carries an
// unchecked certificate.
func AggregateBLSTrusted(shares []BLSSignatureShare, pubs map[string]kyber.Point, msg []byte, threshold int) (BLSAggregateSignature, error) {
	if len(shares) < threshold {
		return BLSAggregateSignature{}, errors.New("not enough BLS signature shares")
	}
	return aggregateVerifiedBLS(shares, pubs, msg, threshold)
}

// VerifyBLSAggregate checks an exported Beacon certificate. The signer list is
// part of the certificate because this is ordinary BLS aggregation, not
// threshold BLS with one group public key.
func VerifyBLSAggregate(agg BLSAggregateSignature, pubs map[string]kyber.Point, msg []byte, threshold int) error {
	if len(agg.Signers) < threshold {
		return errors.New("aggregate signature below threshold")
	}
	seen := make(map[string]bool, len(agg.Signers))
	pks := make([]kyber.Point, 0, len(agg.Signers))
	for _, signer := range agg.Signers {
		if seen[signer] {
			return errors.New("duplicate aggregate signer")
		}
		seen[signer] = true
		pub := pubs[signer]
		if pub == nil {
			return errors.New("unknown aggregate signer: " + signer)
		}
		pks = append(pks, pub)
	}
	sig, err := hex.DecodeString(agg.SigHex)
	if err != nil {
		return err
	}
	aggPub := bls.AggregatePublicKeys(pairingSuite(), pks...)
	return bls.Verify(pairingSuite(), aggPub, msg, sig)
}

// aggregateVerifiedBLS sorts signers to make the certificate deterministic,
// aggregates the first threshold valid signatures, and immediately verifies the
// aggregate. Keeping this check here avoids returning malformed certificates
// from bugs in the surrounding protocol code.
func aggregateVerifiedBLS(valid []BLSSignatureShare, pubs map[string]kyber.Point, msg []byte, threshold int) (BLSAggregateSignature, error) {
	sort.Slice(valid, func(i, j int) bool { return valid[i].Signer < valid[j].Signer })
	sigs := make([][]byte, threshold)
	pks := make([]kyber.Point, threshold)
	signers := make([]string, threshold)
	for i := 0; i < threshold; i++ {
		sigs[i] = valid[i].Sig
		pks[i] = pubs[valid[i].Signer]
		if pks[i] == nil {
			return BLSAggregateSignature{}, errors.New("unknown aggregate signer: " + valid[i].Signer)
		}
		signers[i] = valid[i].Signer
	}
	aggSig, err := bls.AggregateSignatures(pairingSuite(), sigs...)
	if err != nil {
		return BLSAggregateSignature{}, err
	}
	aggPub := bls.AggregatePublicKeys(pairingSuite(), pks...)
	if err := bls.Verify(pairingSuite(), aggPub, msg, aggSig); err != nil {
		return BLSAggregateSignature{}, err
	}
	return BLSAggregateSignature{Signers: signers, SigHex: hex.EncodeToString(aggSig)}, nil
}

func pairingSuite() *bn256.Suite {
	return bn256.NewSuite()
}
