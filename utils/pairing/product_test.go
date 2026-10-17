package pairing

import (
	"bytes"
	"go.dedis.ch/kyber/v3"
	"sync"
	"testing"
)

func TestPairProductEquivalentAndConcurrent(t *testing.T) {
	s := NewSuite()
	x := s.G1().Point().Mul(s.G1().Scalar().SetInt64(7), nil)
	y := s.G2().Point().Mul(s.G2().Scalar().SetInt64(11), nil)
	u := s.G1().Point().Mul(s.G1().Scalar().SetInt64(13), nil)
	v := s.G2().Point().Mul(s.G2().Scalar().SetInt64(17), nil)
	before, _ := x.MarshalBinary()
	want := s.GT().Point().Add(s.Pair(x, y), s.Pair(u, v))
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !s.PairProduct([2]kyber.Point{x, y}, [2]kyber.Point{u, v}).Equal(want) {
				t.Error("product differs from separate pairings")
			}
		}()
	}
	wg.Wait()
	after, _ := x.MarshalBinary()
	if !bytes.Equal(before, after) {
		t.Fatal("input mutated")
	}
	if !s.PairProduct([2]kyber.Point{x, y}, [2]kyber.Point{s.G1().Point().Neg(x), y}).Equal(s.GT().Point().Null()) {
		t.Fatal("inverse pair did not cancel")
	}
	if !s.PairProduct().Equal(s.GT().Point().Null()) {
		t.Fatal("empty product is not identity")
	}
}
