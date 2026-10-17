package pairing

import (
	"errors"
	"math/big"

	bls "github.com/kilic/bls12-381"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/share"
)

// MultiScalarMul implements the public-scalar multi-exponentiation used in
// SPURT Section V-E. The backend may normalize points, so give it private copies.
func MultiScalarMul(g kyber.Group, points []kyber.Point, scalars []kyber.Scalar) (kyber.Point, error) {
	if len(points) != len(scalars) {
		return nil, errors.New("multiexp dimension mismatch")
	}
	if len(points) == 0 {
		return g.Point().Null(), nil
	}
	kind := g.(group).kind
	values := make([]*big.Int, len(scalars))
	for i, scalar := range scalars {
		p, ok := points[i].(*point)
		if !ok || p.kind != kind {
			return nil, errors.New("multiexp group mismatch")
		}
		s, ok := scalar.(*mod.Int)
		if !ok {
			return nil, errors.New("multiexp scalar mismatch")
		}
		values[i] = new(big.Int).Set(&s.V)
	}
	switch kind {
	case 1:
		inputs := make([]*bls.PointG1, len(points))
		for i, p := range points {
			inputs[i] = new(bls.PointG1).Set(p.(*point).g1)
		}
		result, err := bls.NewG1().MultiExpBig(new(bls.PointG1), inputs, values)
		return &point{kind: 1, g1: result}, err
	case 2:
		inputs := make([]*bls.PointG2, len(points))
		for i, p := range points {
			inputs[i] = new(bls.PointG2).Set(p.(*point).g2)
		}
		result, err := bls.NewG2().MultiExpBig(new(bls.PointG2), inputs, values)
		return &point{kind: 2, g2: result}, err
	default:
		// GT interpolation is also supported; the source-group backend provides
		// the optimized multi-exponentiations required by SPURT.
		result := g.Point().Null()
		for i := range points {
			result.Add(result, g.Point().Mul(scalars[i], points[i]))
		}
		return result, nil
	}
}

// RecoverCommit interpolates a threshold of distinct, already checked public
// shares at zero using one multi-exponentiation instead of independent powers.
func RecoverCommit(g kyber.Group, shares []*share.PubShare, threshold, n int) (kyber.Point, error) {
	if threshold < 1 || n < threshold {
		return nil, errors.New("invalid interpolation threshold")
	}
	selected := make([]*share.PubShare, 0, threshold)
	seen := make(map[int]bool)
	for _, s := range shares {
		if s == nil || s.V == nil || s.I < 0 || s.I >= n || seen[s.I] {
			continue
		}
		seen[s.I] = true
		selected = append(selected, s)
		if len(selected) == threshold {
			break
		}
	}
	if len(selected) < threshold {
		return nil, errors.New("insufficient interpolation shares")
	}
	points := make([]kyber.Point, threshold)
	weights := make([]kyber.Scalar, threshold)
	for i, s := range selected {
		xi := g.Scalar().SetInt64(int64(s.I + 1))
		weight := g.Scalar().One()
		for j, other := range selected {
			if i == j {
				continue
			}
			xj := g.Scalar().SetInt64(int64(other.I + 1))
			weight.Mul(weight, g.Scalar().Div(xj, g.Scalar().Sub(xj, xi)))
		}
		points[i], weights[i] = s.V, weight
	}
	return MultiScalarMul(g, points, weights)
}
