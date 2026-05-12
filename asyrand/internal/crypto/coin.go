package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

type CoinShare struct {
	Signer string `json:"signer"`
	Sig    []byte `json:"sig"`
}

type ThresholdCoin struct {
	Threshold int
	N         int
	Public    *share.PubPoly
	Private   *share.PriShare
	Signer    string
}

func NewThresholdCoin(signer string, priv *share.PriShare, pub *share.PubPoly, threshold, n int) ThresholdCoin {
	return ThresholdCoin{Signer: signer, Private: priv, Public: pub, Threshold: threshold, N: n}
}

func CoinMessage(instance string, round uint64) []byte {
	return []byte(fmt.Sprintf("AsyRandV1/ABA/Coin/%s/%d", instance, round))
}

func (c ThresholdCoin) Share(instance string, round uint64) CoinShare {
	if c.Private == nil {
		return CoinShare{Signer: c.Signer}
	}
	sig, err := tbls.Sign(pairingSuite(), c.Private, CoinMessage(instance, round))
	if err != nil {
		return CoinShare{Signer: c.Signer}
	}
	return CoinShare{Signer: c.Signer, Sig: sig}
}

func (c ThresholdCoin) Combine(instance string, round uint64, shares []CoinShare) (bool, error) {
	if c.Public == nil {
		return false, errors.New("nil threshold public key")
	}
	msg := CoinMessage(instance, round)
	seen := make(map[string]bool, len(shares))
	parts := make([][]byte, 0, len(shares))
	for _, share := range shares {
		if seen[share.Signer] || len(share.Sig) == 0 {
			continue
		}
		seen[share.Signer] = true
		if err := tbls.Verify(pairingSuite(), c.Public, msg, share.Sig); err != nil {
			continue
		}
		parts = append(parts, share.Sig)
	}
	if len(parts) < c.Threshold {
		return false, errors.New("not enough valid coin shares")
	}
	intact, err := tbls.Recover(pairingSuite(), c.Public, msg, parts, c.Threshold, c.N)
	if err != nil {
		return false, err
	}
	if err := bls.Verify(pairingSuite(), c.Public.Commit(), msg, intact); err != nil {
		return false, err
	}
	h := HashBytes(msg, intact)
	return binary.BigEndian.Uint64(h[:8])%2 == 1, nil
}
