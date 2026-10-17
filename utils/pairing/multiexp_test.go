package pairing

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"testing"
)

func TestMultiExponentiationAndInterpolation(t *testing.T) {
	suite := NewSuite()
	for _, g := range []kyber.Group{suite.G1(), suite.G2()} {
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
