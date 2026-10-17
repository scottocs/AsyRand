package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sync"

	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// BeaconEpoch owns an immutable hash-to-curve result and decoded successful
// shares. It belongs to one node, never to a cluster-wide verifier cache.
type BeaconEpoch struct {
	epoch    uint64
	msg      []byte
	gr       kyber.Point
	binding  verification.Key
	mu       sync.Mutex
	verified map[verification.Key]*VerifiedBeaconShare
}

func NewBeaconEpoch(epoch uint64, msg []byte) *BeaconEpoch {
	message := append([]byte(nil), msg...)
	return &BeaconEpoch{epoch: epoch, msg: message, gr: hashToG1(suite(), message),
		binding:  verification.JSONKey("grandline/epoch-context", epoch, message),
		verified: make(map[verification.Key]*VerifiedBeaconShare)}
}

// VerifiedBeaconShare is opaque so callers cannot bypass verification or
// mutate a retained GT point. Reconstruction accepts only these bound objects.
type VerifiedBeaconShare struct {
	signer  p2p.NodeID
	binding verification.Key
	sigma   kyber.Point
}

func (e *BeaconEpoch) Accepts(s *VerifiedBeaconShare, id p2p.NodeID) bool {
	return e != nil && s != nil && s.sigma != nil && s.signer == id && s.binding == e.binding
}

// BeaconSigner decodes its own secret once. All arithmetic uses new receivers;
// its fixed points and scalar are never mutated by generation workers.
type BeaconSigner struct {
	id      p2p.NodeID
	sk, cm1 kyber.Point
	alpha   kyber.Scalar
}

func NewBeaconSigner(id p2p.NodeID, secret string, alpha kyber.Scalar, commitment *VerifiedBeaconCommitment) (*BeaconSigner, error) {
	if id == "" || alpha == nil || commitment == nil || commitment.Signer != id || commitment.CM1 == nil || commitment.CM2 == nil {
		return nil, errors.New("invalid beacon signer context")
	}
	sk, err := pointG2FromHex(secret)
	if err != nil {
		return nil, err
	}
	g := suite()
	if alpha.Equal(g.G1().Scalar().Zero()) {
		return nil, errors.New("beacon alpha must be nonzero")
	}
	if !g.G1().Point().Mul(alpha, gPoint(g)).Equal(commitment.CM1) ||
		!g.G2().Point().Add(g.G2().Point().Mul(alpha, hPoint(g)), commitment.CM2).Equal(sk) {
		return nil, errors.New("secret or alpha does not match the fixed commitment")
	}
	return &BeaconSigner{id: id, sk: sk, cm1: commitment.CM1.Clone(), alpha: alpha.Clone()}, nil
}

func (s *BeaconSigner) Share(e *BeaconEpoch) (BeaconShare, *VerifiedBeaconShare, error) {
	if s == nil || e == nil {
		return BeaconShare{}, nil, errors.New("missing beacon context")
	}
	g := suite()
	u := g.G1().Point().Mul(s.alpha, e.gr)
	v := g.Pair(e.gr, s.sk)
	proof := proveBeaconDLEQ(g, e.msg, s.alpha, s.cm1, u, e.gr)
	wire := BeaconShare{Epoch: e.epoch, Signer: s.id, Sigma1: mustPointHex(u), Sigma2: mustPointHexGT(v), Proof: proof}
	return wire, &VerifiedBeaconShare{signer: s.id, binding: e.binding, sigma: v}, nil
}

func beaconShareKey(msg []byte, c *VerifiedBeaconCommitment, sh BeaconShare) verification.Key {
	return verification.JSONKey("grandline/beacon-share", msg, c.Signer, mustPointBytes(c.CM1), mustPointBytes(c.CM2), sh)
}

func (e *BeaconEpoch) VerifyShare(c *VerifiedBeaconCommitment, sh BeaconShare, caches ...*verification.Cache) (*VerifiedBeaconShare, bool) {
	if e == nil || c == nil || c.CM1 == nil || c.CM2 == nil || sh.Epoch != e.epoch || sh.Signer == "" || sh.Signer != c.Signer {
		return nil, false
	}
	key := beaconShareKey(e.msg, c, sh)
	e.mu.Lock()
	old := e.verified[key]
	e.mu.Unlock()
	if old != nil {
		return old, true
	}
	cache := verification.Optional(caches...)
	valid := cache.Check(key, func() bool {
		parsed, ok := e.verifyUncached(c, sh, cache)
		if ok {
			e.mu.Lock()
			e.verified[key] = parsed
			e.mu.Unlock()
		}
		return ok
	})
	if !valid {
		return nil, false
	}
	e.mu.Lock()
	parsed := e.verified[key]
	e.mu.Unlock()
	if parsed != nil {
		return parsed, true
	}
	// A successful check through a legacy API can populate the shared boolean
	// cache first. Decode once for this context; never skip subgroup checks.
	v, err := pointGTFromHex(sh.Sigma2)
	if err != nil {
		return nil, false
	}
	parsed = &VerifiedBeaconShare{signer: sh.Signer, binding: e.binding, sigma: v}
	e.mu.Lock()
	if old = e.verified[key]; old != nil {
		parsed = old
	} else {
		e.verified[key] = parsed
	}
	e.mu.Unlock()
	return parsed, true
}

func (e *BeaconEpoch) verifyUncached(c *VerifiedBeaconCommitment, sh BeaconShare, cache *verification.Cache) (*VerifiedBeaconShare, bool) {
	if c == nil || c.CM1 == nil || c.CM2 == nil || sh.Epoch != e.epoch || sh.Signer == "" || sh.Signer != c.Signer {
		return nil, false
	}
	u, err := pointG1FromHex(sh.Sigma1)
	if err != nil {
		return nil, false
	}
	v, err := pointGTFromHex(sh.Sigma2)
	if err != nil {
		return nil, false
	}
	g := suite()
	if !verifyBeaconDLEQWithCM1(g, e.msg, c.CM1, u, sh.Proof, e.gr, cache) {
		return nil, false
	}
	right := g.PairProduct([2]kyber.Point{e.gr, c.CM2}, [2]kyber.Point{u, hPoint(g)})
	if !v.Equal(right) {
		return nil, false
	}
	return &VerifiedBeaconShare{signer: sh.Signer, binding: e.binding, sigma: v}, true
}

func (e *BeaconEpoch) Recover(shares []*VerifiedBeaconShare, threshold int, members []p2p.NodeID) ([]byte, string, error) {
	if e == nil || threshold < 1 {
		return nil, "", errors.New("invalid reconstruction context")
	}
	members = normalizeMembers(members)
	if threshold > len(members) {
		return nil, "", errors.New("invalid reconstruction threshold")
	}
	indices := memberIndex(members)
	seen := make(map[p2p.NodeID]bool)
	points := make([]*share.PubShare, 0, threshold)
	for _, s := range shares {
		if s == nil || s.sigma == nil || s.binding != e.binding || seen[s.signer] {
			continue
		}
		i, ok := indices[s.signer]
		if !ok {
			continue
		}
		seen[s.signer] = true
		points = append(points, &share.PubShare{I: i, V: s.sigma})
		if len(points) == threshold {
			break
		}
	}
	if len(points) < threshold {
		return nil, "", errors.New("not enough bound verified shares")
	}
	sigma, err := share.RecoverCommit(suite().GT(), points, threshold, len(members))
	if err != nil {
		return nil, "", err
	}
	raw, err := sigma.MarshalBinary()
	if err != nil {
		return nil, "", err
	}
	return HashBytes(raw), hex.EncodeToString(raw), nil
}

// Matches makes it possible to reject accidental context reuse at API edges.
func (e *BeaconEpoch) Matches(epoch uint64, msg []byte) bool {
	return e != nil && e.epoch == epoch && bytes.Equal(e.msg, msg)
}
