package crypto

import (
	"crypto/sha256"
	"encoding/binary"
)

// HashBytes hashes a sequence of byte strings using an injective,
// length-delimited encoding.  The old implementation concatenated its
// arguments directly, so HashBytes([]byte("ab"), []byte("c")) collided with
// HashBytes([]byte("a"), []byte("bc")).
func HashBytes(parts ...[]byte) []byte {
	h := sha256.New()
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(parts)))
	_, _ = h.Write(size[:])
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

// DomainHash separates independently specified protocol transcripts.
func DomainHash(domain string, parts ...[]byte) []byte {
	framed := make([][]byte, 0, len(parts)+1)
	framed = append(framed, []byte(domain))
	framed = append(framed, parts...)
	return HashBytes(framed...)
}
