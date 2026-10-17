// Package pairing adapts kilic's BLS12-381 implementation to the Kyber group
// interfaces used by the two paper baselines. Instances do not share mutable
// arithmetic engines, so independent crypto workers may use them concurrently.
package pairing

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"math/big"
	"sync"

	bls "github.com/kilic/bls12-381"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/mod"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/kyber/v3/xof/blake2xb"
)

type Suite struct{}

func NewSuite() *Suite                     { return &Suite{} }
func (*Suite) G1() kyber.Group             { return group{1} }
func (*Suite) G2() kyber.Group             { return group{2} }
func (*Suite) GT() kyber.Group             { return group{3} }
func (*Suite) Hash() hash.Hash             { return sha256.New() }
func (*Suite) XOF(seed []byte) kyber.XOF   { return blake2xb.New(seed) }
func (*Suite) RandomStream() cipher.Stream { return random.New() }
func (*Suite) Pair(a, b kyber.Point) kyber.Point {
	x, y := a.(*point), b.(*point)
	if x.kind != 1 || y.kind != 2 {
		panic("pairing: expected G1 and G2")
	}
	return &point{kind: 3, gt: bls.NewEngine().AddPair(new(bls.PointG1).Set(x.g1), new(bls.PointG2).Set(y.g2)).Result()}
}

// PairProduct evaluates a product of pairings with one final exponentiation.
// Inputs are copied: kilic may normalize points while preparing the engine.
func (*Suite) PairProduct(pairs ...[2]kyber.Point) kyber.Point {
	engine := bls.NewEngine()
	for _, pair := range pairs {
		x, xok := pair[0].(*point)
		y, yok := pair[1].(*point)
		if !xok || !yok || x.kind != 1 || y.kind != 2 {
			panic("pairing: expected G1 and G2")
		}
		engine.AddPair(new(bls.PointG1).Set(x.g1), new(bls.PointG2).Set(y.g2))
	}
	return &point{kind: 3, gt: engine.Result()}
}

// HashG1 and HashG2 use hash-to-curve, never a publicly known scalar times a
// generator. The library clears the cofactor as part of its mapping.
func HashG1(message, domain []byte) kyber.Point {
	p, err := bls.NewG1().HashToCurve(message, domain)
	if err != nil {
		panic(err)
	}
	return &point{kind: 1, g1: p}
}
func HashG2(message, domain []byte) kyber.Point {
	p, err := bls.NewG2().HashToCurve(message, domain)
	if err != nil {
		panic(err)
	}
	return &point{kind: 2, g2: p}
}

type group struct{ kind int }

func (g group) String() string     { return "BLS12-381/" + []string{"", "G1", "G2", "GT"}[g.kind] }
func (group) ScalarLen() int       { return 32 }
func (group) Scalar() kyber.Scalar { return mod.NewInt64(0, bls.NewG1().Q()) }
func (g group) PointLen() int      { return []int{0, 48, 96, 576}[g.kind] }
func (g group) Point() kyber.Point { return (&point{kind: g.kind}).Null() }

type point struct {
	kind int
	g1   *bls.PointG1
	g2   *bls.PointG2
	gt   *bls.E
}

var baseOnce sync.Once
var baseGT *bls.E

func (p *point) Null() kyber.Point {
	switch p.kind {
	case 1:
		p.g1 = bls.NewG1().Zero()
	case 2:
		p.g2 = bls.NewG2().Zero()
	case 3:
		p.gt = bls.NewGT().New()
	}
	return p
}
func (p *point) Base() kyber.Point {
	switch p.kind {
	case 1:
		p.g1 = bls.NewG1().One()
	case 2:
		p.g2 = bls.NewG2().One()
	case 3:
		baseOnce.Do(func() { baseGT = bls.NewEngine().AddPair(bls.NewG1().One(), bls.NewG2().One()).Result() })
		p.gt = new(bls.E).Set(baseGT)
	}
	return p
}
func (p *point) Set(q kyber.Point) kyber.Point {
	x := q.(*point)
	if p.kind != x.kind {
		panic("pairing: incompatible groups")
	}
	switch p.kind {
	case 1:
		p.g1 = new(bls.PointG1).Set(x.g1)
	case 2:
		p.g2 = new(bls.PointG2).Set(x.g2)
	case 3:
		p.gt = new(bls.E).Set(x.gt)
	}
	return p
}
func (p *point) Clone() kyber.Point { return (&point{kind: p.kind}).Set(p) }
func (p *point) Equal(q kyber.Point) bool {
	x, ok := q.(*point)
	if !ok || p.kind != x.kind {
		return false
	}
	switch p.kind {
	case 1:
		return bls.NewG1().Equal(p.g1, x.g1)
	case 2:
		return bls.NewG2().Equal(p.g2, x.g2)
	default:
		return p.gt.Equal(x.gt)
	}
}
func (p *point) Add(a, b kyber.Point) kyber.Point {
	x, y := a.(*point), b.(*point)
	if p.kind != x.kind || p.kind != y.kind {
		panic("pairing: incompatible groups")
	}
	switch p.kind {
	case 1:
		p.g1 = bls.NewG1().Add(new(bls.PointG1), x.g1, y.g1)
	case 2:
		p.g2 = bls.NewG2().Add(new(bls.PointG2), x.g2, y.g2)
	case 3:
		z := bls.NewGT().New()
		bls.NewGT().Mul(z, x.gt, y.gt)
		p.gt = z
	}
	return p
}
func (p *point) Neg(a kyber.Point) kyber.Point {
	x := a.(*point)
	if p.kind != x.kind {
		panic("pairing: incompatible groups")
	}
	switch p.kind {
	case 1:
		p.g1 = bls.NewG1().Neg(new(bls.PointG1), x.g1)
	case 2:
		p.g2 = bls.NewG2().Neg(new(bls.PointG2), x.g2)
	case 3:
		z := bls.NewGT().New()
		bls.NewGT().Inverse(z, x.gt)
		p.gt = z
	}
	return p
}
func (p *point) Sub(a, b kyber.Point) kyber.Point { return p.Add(a, (&point{kind: p.kind}).Neg(b)) }
func (p *point) Mul(s kyber.Scalar, q kyber.Point) kyber.Point {
	if q == nil {
		q = (&point{kind: p.kind}).Base()
	}
	x := q.(*point)
	if p.kind != x.kind {
		panic("pairing: incompatible groups")
	}
	v := new(big.Int).Set(&s.(*mod.Int).V)
	switch p.kind {
	case 1:
		p.g1 = bls.NewG1().MulScalarBig(new(bls.PointG1), x.g1, v)
	case 2:
		p.g2 = bls.NewG2().MulScalarBig(new(bls.PointG2), x.g2, v)
	case 3:
		z := bls.NewGT().New()
		bls.NewGT().Exp(z, x.gt, v)
		p.gt = z
	}
	return p
}
func (p *point) Pick(r cipher.Stream) kyber.Point      { return p.Mul(group{p.kind}.Scalar().Pick(r), nil) }
func (*point) EmbedLen() int                           { return 0 }
func (*point) Embed([]byte, cipher.Stream) kyber.Point { panic("pairing: embedding unsupported") }
func (*point) Data() ([]byte, error)                   { return nil, errors.New("pairing: embedding unsupported") }
func (p *point) MarshalSize() int                      { return group{p.kind}.PointLen() }
func (p *point) MarshalBinary() ([]byte, error) {
	switch p.kind {
	case 1:
		return bls.NewG1().ToCompressed(new(bls.PointG1).Set(p.g1)), nil
	case 2:
		return bls.NewG2().ToCompressed(new(bls.PointG2).Set(p.g2)), nil
	default:
		return bls.NewGT().ToBytes(p.gt), nil
	}
}
func (p *point) UnmarshalBinary(raw []byte) error {
	if len(raw) != p.MarshalSize() {
		return errors.New("pairing: invalid point length")
	}
	var err error
	switch p.kind {
	case 1:
		p.g1, err = bls.NewG1().FromCompressed(raw)
	case 2:
		p.g2, err = bls.NewG2().FromCompressed(raw)
	case 3:
		p.gt, err = bls.NewGT().FromBytes(raw)
	}
	return err
}
func (p *point) MarshalTo(w io.Writer) (int, error) {
	raw, err := p.MarshalBinary()
	if err != nil {
		return 0, err
	}
	return w.Write(raw)
}
func (p *point) UnmarshalFrom(r io.Reader) (int, error) {
	raw := make([]byte, p.MarshalSize())
	n, err := io.ReadFull(r, raw)
	if err != nil {
		return n, err
	}
	return n, p.UnmarshalBinary(raw)
}
func (p *point) String() string { raw, _ := p.MarshalBinary(); return hex.EncodeToString(raw) }
