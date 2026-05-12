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

type BLSSignatureShare struct {
	Signer string `json:"signer"`
	Sig    []byte `json:"sig"`
}

type BLSAggregateSignature struct {
	Signers []string `json:"signers"`
	SigHex  string   `json:"sig_hex"`
}

func NewBLSKeyPairFromSeed(seed []byte) BLSKeyPair {
	suite := pairingSuite()
	sk := suite.G2().Scalar().SetBytes(HashBytes([]byte("AsyRand-v1/BLS/key"), seed))
	if sk.Equal(suite.G2().Scalar().Zero()) {
		sk = suite.G2().Scalar().One()
	}
	return BLSKeyPair{Private: sk, Public: suite.G2().Point().Mul(sk, nil)}
}

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

func VerifyBLSShare(share BLSSignatureShare, pubs map[string]kyber.Point, msg []byte) bool {
	pub := pubs[share.Signer]
	if pub == nil || len(share.Sig) == 0 {
		return false
	}
	return bls.Verify(pairingSuite(), pub, msg, share.Sig) == nil
}

func AggregateBLS(shares []BLSSignatureShare, pubs map[string]kyber.Point, msg []byte, threshold int) (BLSAggregateSignature, error) {
	verified, err := filterValidBLSShares(shares, pubs, msg)
	if err != nil {
		return BLSAggregateSignature{}, err
	}
	if len(verified) < threshold {
		return BLSAggregateSignature{}, errors.New("not enough valid BLS signature shares")
	}
	return aggregateVerifiedBLS(verified, pubs, msg, threshold)
}

func AggregateBLSTrusted(shares []BLSSignatureShare, pubs map[string]kyber.Point, msg []byte, threshold int) (BLSAggregateSignature, error) {
	if len(shares) < threshold {
		return BLSAggregateSignature{}, errors.New("not enough BLS signature shares")
	}
	return aggregateVerifiedBLS(shares, pubs, msg, threshold)
}

func filterValidBLSShares(shares []BLSSignatureShare, pubs map[string]kyber.Point, msg []byte) ([]BLSSignatureShare, error) {
	seen := make(map[string]bool, len(shares))
	valid := make([]BLSSignatureShare, 0, len(shares))
	for _, share := range shares {
		if seen[share.Signer] || !VerifyBLSShare(share, pubs, msg) {
			continue
		}
		seen[share.Signer] = true
		valid = append(valid, share)
	}
	return valid, nil
}

func aggregateVerifiedBLS(valid []BLSSignatureShare, pubs map[string]kyber.Point, msg []byte, threshold int) (BLSAggregateSignature, error) {
	sort.Slice(valid, func(i, j int) bool { return valid[i].Signer < valid[j].Signer })
	sigs := make([][]byte, threshold)
	pks := make([]kyber.Point, threshold)
	signers := make([]string, threshold)
	for i := 0; i < threshold; i++ {
		sigs[i] = valid[i].Sig
		pks[i] = pubs[valid[i].Signer]
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

func pairingSuite() *bn256.Suite {
	return bn256.NewSuite()
}
