package crypto

import (
	"Tyche/utils/cryptoexec"
	"Tyche/utils/verification"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{Public: pub, Private: priv}, nil
}

func Sign(priv ed25519.PrivateKey, msg []byte) []byte {
	digest := sha256.Sum256(msg)
	var signature []byte
	cryptoexec.WithCPUGroupFast(func() { signature = ed25519.Sign(priv, digest[:]) })
	return signature
}

func Verify(pub ed25519.PublicKey, msg, sig []byte, caches ...*verification.Cache) bool {
	valid, _ := VerifyOnce(pub, msg, sig, verification.Optional(caches...))
	return valid
}

func VerifyOnce(pub ed25519.PublicKey, msg, sig []byte, cache *verification.Cache) (bool, bool) {
	digest := sha256.Sum256(msg)
	return cache.Ed25519Once(pub, digest[:], sig)
}

type SignatureShare struct {
	Signer string `json:"signer"`
	SigHex string `json:"sig_hex"`
}

type AggregateSignature struct {
	Shares []SignatureShare `json:"shares"`
}

func NewAggregateSignature() AggregateSignature {
	return AggregateSignature{Shares: make([]SignatureShare, 0)}
}

func (a *AggregateSignature) Add(signer string, sig []byte) {
	for _, share := range a.Shares {
		if share.Signer == signer {
			return
		}
	}
	a.Shares = append(a.Shares, SignatureShare{Signer: signer, SigHex: hex.EncodeToString(sig)})
	sort.Slice(a.Shares, func(i, j int) bool { return a.Shares[i].Signer < a.Shares[j].Signer })
}

func (a AggregateSignature) Verify(msg []byte, pubs map[string]ed25519.PublicKey, threshold int) error {
	if len(a.Shares) < threshold {
		return errors.New("aggregate signature below threshold")
	}
	seen := make(map[string]bool, len(a.Shares))
	valid := 0
	for _, share := range a.Shares {
		if seen[share.Signer] {
			return errors.New("duplicate signer in aggregate signature")
		}
		seen[share.Signer] = true
		pub, ok := pubs[share.Signer]
		if !ok {
			return errors.New("unknown aggregate signer: " + share.Signer)
		}
		sig, err := hex.DecodeString(share.SigHex)
		if err != nil {
			return err
		}
		if Verify(pub, msg, sig) {
			valid++
		}
	}
	if valid < threshold {
		return errors.New("not enough valid aggregate shares")
	}
	return nil
}

func CanonicalBytes(v any) ([]byte, error) {
	return json.Marshal(v)
}

func HashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
