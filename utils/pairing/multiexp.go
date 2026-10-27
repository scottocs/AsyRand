package pairing

import (
	"Tyche/utils/cryptoexec"
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
		if len(points) < 4 {
			result := g.Point().Null()
			for i := range points {
				result.Add(result, g.Point().Mul(scalars[i], points[i]))
			}
			return result, nil
		}
		// Public GT exponents share squarings within each of two independent
		// partitions. This is algebraically the same complete interpolation.
		var terms [2]*bls.E
		cryptoexec.AllLabeled("gt-interpolate", 2, func(part int) bool {
			var inputs []*bls.E
			var exponents []*big.Int
			for i := part; i < len(points); i += 2 {
				inputs = append(inputs, points[i].(*point).gt)
				exponents = append(exponents, values[i])
			}
			terms[part] = publicGTJoint(inputs, exponents)
			return true
		})
		result := bls.NewGT().New()
		bls.NewGT().Mul(result, terms[0], terms[1])
		return &point{kind: 3, gt: result}, nil
	}
}

// publicGTJoint uses width-5 signed digits only for published interpolation
// coefficients. Secret exponents must keep their original scalar paths.
func publicGTJoint(points []*bls.E, values []*big.Int) *bls.E {
	gt := bls.NewGT()
	tables := make([][16]*bls.E, len(points))
	digits := make([][]int8, len(points))
	longest := 0
	for i, value := range values {
		x := new(big.Int).Set(value)
		for x.Sign() != 0 {
			digit := int64(0)
			if x.Bit(0) != 0 {
				digit = int64(x.Uint64() & 31)
				if digit >= 16 {
					digit -= 32
				}
				x.Sub(x, big.NewInt(digit))
			}
			digits[i] = append(digits[i], int8(digit))
			x.Rsh(x, 1)
		}
		longest = max(longest, len(digits[i]))
		if len(digits[i]) == 0 {
			continue
		}
		tables[i][0] = new(bls.E).Set(points[i])
		tables[i][8] = gt.New()
		gt.Inverse(tables[i][8], points[i])
		for _, offset := range []int{0, 8} {
			square := gt.New()
			gt.Square(square, tables[i][offset])
			for j := 1; j < 8; j++ {
				tables[i][offset+j] = gt.New()
				gt.Mul(tables[i][offset+j], tables[i][offset+j-1], square)
			}
		}
	}
	result := gt.New()
	for bit := longest - 1; bit >= 0; bit-- {
		gt.Square(result, result)
		for i, d := range digits {
			if bit >= len(d) || d[bit] == 0 {
				continue
			}
			digit, offset := int(d[bit]), 0
			if digit < 0 {
				digit, offset = -digit, 8
			}
			gt.Mul(result, result, tables[i][offset+digit/2])
		}
	}
	return result
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
