package crypto

import (
	"testing"

	"go.dedis.ch/kyber/v3"
)

var operationBenchmarkPoint kyber.Point

// BenchmarkExponentiation measures the group operation g^x (x*P in additive
// notation). Inputs are nontrivial, full-size scalars and subgroup points.
// Input generation is excluded; allocating the output matches production code.
func BenchmarkExponentiation(b *testing.B) {
	ed := suite()
	bn := pairingSuite()
	for _, tc := range []struct {
		name      string
		group     kyber.Group
		generator bool
	}{
		{"Edwards25519/Generator", ed, true},
		{"Edwards25519/VariablePoint", ed, false},
		{"BN256/G1/Generator", bn.G1(), true},
		{"BN256/G1/VariablePoint", bn.G1(), false},
		{"BN256/G2/Generator", bn.G2(), true},
		{"BN256/G2/VariablePoint", bn.G2(), false},
		{"BN256/GT/VariablePoint", bn.GT(), false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			stream := ed.XOF([]byte("asyrand/crypto/operation-benchmark/" + tc.name))
			var scalars [32]kyber.Scalar
			var points [32]kyber.Point
			for i := range scalars {
				scalars[i] = tc.group.Scalar().Pick(stream)
				if !tc.generator {
					points[i] = tc.group.Point().Mul(tc.group.Scalar().Pick(stream), nil)
				}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				operationBenchmarkPoint = tc.group.Point().Mul(scalars[i&31], points[i&31])
			}
		})
	}
}

// BenchmarkPairing includes one complete BN256 pairing, including final
// exponentiation and output allocation, with already prepared G1/G2 inputs.
func BenchmarkPairing(b *testing.B) {
	bn := pairingSuite()
	stream := bn.XOF([]byte("asyrand/crypto/operation-benchmark/pairing"))
	var g1, g2 [32]kyber.Point
	for i := range g1 {
		g1[i] = bn.G1().Point().Mul(bn.G1().Scalar().Pick(stream), nil)
		g2[i] = bn.G2().Point().Mul(bn.G2().Scalar().Pick(stream), nil)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		operationBenchmarkPoint = bn.Pair(g1[i&31], g2[i&31])
	}
}

// BenchmarkBLSOperation provides application-level context. Signing includes
// hashing and serialization; verification includes hashing, parsing, two
// complete pairings, and the equality check.
func BenchmarkBLSOperation(b *testing.B) {
	key := NewBLSKeyPairFromSeed([]byte("benchmark-only BLS private seed"))
	msg := []byte("asyrand/crypto/operation-benchmark/BLS")
	share, err := SignBLS("n0", key.Private, msg)
	if err != nil {
		b.Fatal(err)
	}
	pubs := map[string]kyber.Point{"n0": key.Public}
	if !VerifyBLSShare(share, pubs, msg) {
		b.Fatal("benchmark signature did not verify")
	}
	b.Run("Sign", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := SignBLS("n0", key.Private, msg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("VerifyShare", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !VerifyBLSShare(share, pubs, msg) {
				b.Fatal("signature verification failed")
			}
		}
	})
}
