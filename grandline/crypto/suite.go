package crypto

import (
	"Tyche/utils/pairing"
	"go.dedis.ch/kyber/v3"
)

// The algorithms use the group names of Figures 1 and 5. Section 5.1 swaps
// their physical BLS12-381 groups: commitments/CM1/sigma1 are 96-byte G2,
// encrypted shares and secret key shares are 48-byte G1.
type grandSuite struct{ *pairing.Suite }

func suite() *grandSuite                                { return &grandSuite{pairing.NewSuite()} }
func (s *grandSuite) G1() kyber.Group                   { return s.Suite.G2() }
func (s *grandSuite) G2() kyber.Group                   { return s.Suite.G1() }
func (s *grandSuite) Pair(a, b kyber.Point) kyber.Point { return s.Suite.Pair(b, a) }
func (s *grandSuite) PairProduct(pairs ...[2]kyber.Point) kyber.Point {
	physical := make([][2]kyber.Point, len(pairs))
	for i, pair := range pairs {
		physical[i] = [2]kyber.Point{pair[1], pair[0]}
	}
	return s.Suite.PairProduct(physical...)
}
