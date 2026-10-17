package pairing

import (
	"go.dedis.ch/kyber/v3"
	"testing"
)

func TestBilinearityGroupAliasingAndEncoding(t *testing.T) {
	s := NewSuite()
	a, b := s.G1().Scalar().SetInt64(17), s.G1().Scalar().SetInt64(29)
	x, y := s.G1().Point().Mul(a, nil), s.G2().Point().Mul(b, nil)
	product := s.G1().Scalar().Mul(a, b)
	if !s.Pair(x, y).Equal(s.GT().Point().Mul(product, nil)) {
		t.Fatal("bilinearity failed")
	}
	for _, g := range []kyber.Group{s.G1(), s.G2(), s.GT()} {
		p := g.Point().Mul(a, nil)
		q := p.Clone()
		q.Add(q, q)
		if !q.Equal(g.Point().Mul(g.Scalar().SetInt64(34), nil)) {
			t.Fatal("aliased add failed", g)
		}
		q.Sub(q, p)
		if !q.Equal(p) {
			t.Fatal("aliased subtraction failed", g)
		}
		q.Mul(b, q)
		if !q.Equal(g.Point().Mul(product, nil)) {
			t.Fatal("aliased multiplication failed", g)
		}
		raw, err := p.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		decoded := g.Point()
		if err := decoded.UnmarshalBinary(raw); err != nil || !decoded.Equal(p) {
			t.Fatal("encoding failed", g, err)
		}
		if err := decoded.UnmarshalBinary(append(raw, 0)); err == nil {
			t.Fatal("trailing bytes accepted", g)
		}
	}
}
