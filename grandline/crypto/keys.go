package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
)

// KeyPair supplies the identity keys used by signed APVSS contribution proofs.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func HashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}
