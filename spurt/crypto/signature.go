package crypto

import (
	"Tyche/utils/cryptoexec"
	"Tyche/utils/verification"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
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

func HashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
