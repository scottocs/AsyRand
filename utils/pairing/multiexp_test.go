package pairing

import (
	"fmt"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"sync"
	"testing"
)

func TestMultiExponentiationAndInterpolation(t *testing.T) {
	suite := NewSuite()
	for _, g := range []kyber.Group{suite.G1(), suite.G2(), suite.GT()} {
		points := make([]kyber.Point, 7)
		weights := make([]kyber.Scalar, 7)
		expected := g.Point().Null()
		before := make([]string, len(points))
		for i := range points {
			points[i] = g.Point().Pick(suite.RandomStream())
			before[i] = points[i].String()
			weights[i] = g.Scalar().SetInt64(int64(i*i + 1))
			expected.Add(expected, g.Point().Mul(weights[i], points[i]))
		}
		actual, err := MultiScalarMul(g, points, weights)
		if err != nil || !actual.Equal(expected) {
			t.Fatal(g.String(), "multiexp differs from independent powers", err)
		}
		for i := range points {
			if points[i].String() != before[i] {
				t.Fatal("multiexp mutated input")
			}
		}
		poly := share.NewPriPoly(g, 3, nil, suite.RandomStream()).Commit(nil)
		input := []*share.PubShare{poly.Eval(6), poly.Eval(1), poly.Eval(4)}
		recovered, err := RecoverCommit(g, input, 3, 7)
		if err != nil || !recovered.Equal(poly.Commit()) {
			t.Fatal("sparse-index interpolation failed", err)
		}
	}
}

func TestGTJointPublicExponentsAndConcurrentImmutability(t *testing.T) {
	s := NewSuite()
	g := s.GT()
	for _, n := range []int{1, 3, 6, 14} {
		points, scalars := make([]kyber.Point, n), make([]kyber.Scalar, n)
		before := make([]string, n)
		want := g.Point().Null()
		for i := range points {
			points[i] = g.Point().Pick(s.RandomStream())
			scalars[i] = g.Scalar().Pick(s.RandomStream())
			if i == 0 {
				scalars[i].Zero()
			} else if i == 1 {
				scalars[i].Neg(g.Scalar().One())
			}
			before[i] = points[i].String()
			want.Add(want, g.Point().Mul(scalars[i], points[i]))
		}
		var wg sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := MultiScalarMul(g, points, scalars)
				if err != nil || !got.Equal(want) {
					t.Error("public GT joint exponentiation changed the result", n, err)
				}
			}()
		}
		wg.Wait()
		for i := range points {
			if points[i].String() != before[i] {
				t.Fatal("GT interpolation mutated a public input", n, i)
			}
		}
	}
}

func BenchmarkGTMultiExponentiation(b *testing.B) {
	s := NewSuite()
	g := s.GT()
	for _, n := range []int{3, 7, 14} {
		points, scalars := make([]kyber.Point, n), make([]kyber.Scalar, n)
		for i := range points {
			points[i] = g.Point().Pick(s.RandomStream())
			scalars[i] = g.Scalar().Pick(s.RandomStream())
		}
		for _, method := range []string{"Separate", "Joint"} {
			b.Run(fmt.Sprintf("n%d/%s", n, method), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					if method == "Joint" {
						if _, err := MultiScalarMul(g, points, scalars); err != nil {
							b.Fatal(err)
						}
					} else {
						result := g.Point().Null()
						for j := range points {
							result.Add(result, g.Point().Mul(scalars[j], points[j]))
						}
					}
				}
			})
		}
	}
}

func BenchmarkPublicDoubleScalar(b *testing.B) {
	s := NewSuite()
	for _, g := range []kyber.Group{s.G1(), s.G2()} {
		x, y := g.Point().Pick(s.RandomStream()), g.Point().Pick(s.RandomStream())
		a, c := g.Scalar().Pick(s.RandomStream()), g.Scalar().Pick(s.RandomStream())
		b.Run(g.String()+"/Separate", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				g.Point().Add(g.Point().Mul(a, x), g.Point().Mul(c, y))
			}
		})
		b.Run(g.String()+"/Multi", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := MultiScalarMul(g, []kyber.Point{x, y}, []kyber.Scalar{a, c}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
