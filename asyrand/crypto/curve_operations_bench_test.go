package crypto_test

import (
	"Tyche/utils/pairing"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"testing"
)

var curveBenchmarkPoint kyber.Point

func BenchmarkCurveMul(b *testing.B) {
	ed := edwards25519.NewBlakeSHA256Ed25519()
	bls := pairing.NewSuite()
	cases := []struct {
		name  string
		group kyber.Group
	}{
		{"Edwards25519/VariablePoint", ed},
		{"BLS12381/G1/VariablePoint", bls.G1()},
		{"BLS12381/G2/VariablePoint", bls.G2()},
		{"BLS12381/GT/VariablePoint", bls.GT()},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			stream := ed.XOF([]byte("curvebench/full-size-inputs/" + tc.name))
			var scalars [32]kyber.Scalar
			var points [32]kyber.Point
			for i := range scalars {
				scalars[i] = tc.group.Scalar().Pick(stream)
				points[i] = tc.group.Point().Mul(tc.group.Scalar().Pick(stream), nil)
			}
			// Check the wrapper's result outside the measured section.
			check := tc.group.Point().Mul(scalars[0], points[0])
			if check.Equal(tc.group.Point().Null()) {
				b.Fatal("unexpected identity")
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				curveBenchmarkPoint = tc.group.Point().Mul(scalars[i&31], points[i&31])
			}
		})
	}
}

func BenchmarkCurvePairing(b *testing.B) {
	ed := edwards25519.NewBlakeSHA256Ed25519()
	bls := pairing.NewSuite()
	stream := ed.XOF([]byte("curvebench/pairing-inputs"))
	var xs, ys [32]kyber.Point
	for i := range xs {
		xs[i] = bls.G1().Point().Mul(bls.G1().Scalar().Pick(stream), nil)
		ys[i] = bls.G2().Point().Mul(bls.G2().Scalar().Pick(stream), nil)
	}
	b.Run("Single", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			curveBenchmarkPoint = bls.Pair(xs[i&31], ys[i&31])
		}
	})
	b.Run("Product2", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			curveBenchmarkPoint = bls.PairProduct([2]kyber.Point{xs[i&31], ys[i&31]}, [2]kyber.Point{xs[(i+1)&31], ys[(i+1)&31]})
		}
	})
}
