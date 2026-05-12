package dkg

import (
	"errors"
	"fmt"

	asig "github.com/scottocs/asyrand/asyrand/internal/crypto"
	"github.com/scottocs/asyrand/asyrand/internal/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	pedersen "go.dedis.ch/kyber/v3/share/dkg/pedersen"
)

type Result struct {
	N         int
	Threshold int
	Public    *share.PubPoly
	Shares    map[p2p.NodeID]*share.PriShare
}

func RunPedersen(ids []p2p.NodeID, seeds map[p2p.NodeID][]byte, threshold int) (Result, error) {
	if len(ids) == 0 {
		return Result{}, errors.New("dkg needs at least one participant")
	}
	if threshold <= 0 || threshold > len(ids) {
		return Result{}, errors.New("invalid dkg threshold")
	}
	suite := bn256.NewSuiteG2()
	longterm := make([]kyber.Scalar, len(ids))
	public := make([]kyber.Point, len(ids))
	for i, id := range ids {
		seed := seeds[id]
		if len(seed) == 0 {
			return Result{}, fmt.Errorf("missing dkg seed for %s", id)
		}
		sk := suite.Scalar().SetBytes(asig.HashBytes([]byte("AsyRand-v1/DKG/longterm"), seed))
		if sk.Equal(suite.Scalar().Zero()) {
			sk = suite.Scalar().One()
		}
		longterm[i] = sk
		public[i] = suite.Point().Mul(sk, nil)
	}
	nodes := make([]*pedersen.DistKeyGenerator, len(ids))
	for i := range ids {
		dkg, err := pedersen.NewDistKeyGenerator(suite, longterm[i], public, threshold)
		if err != nil {
			return Result{}, err
		}
		nodes[i] = dkg
	}

	responses := make([][]*pedersen.Response, len(nodes))
	for _, dealer := range nodes {
		deals, err := dealer.Deals()
		if err != nil {
			return Result{}, err
		}
		for recipient, deal := range deals {
			response, err := nodes[recipient].ProcessDeal(deal)
			if err != nil {
				return Result{}, err
			}
			for j := range nodes {
				if j == recipient {
					continue
				}
				responses[j] = append(responses[j], response)
			}
		}
	}
	for i, node := range nodes {
		for _, response := range responses[i] {
			if _, err := node.ProcessResponse(response); err != nil {
				return Result{}, err
			}
		}
	}

	shares := make(map[p2p.NodeID]*share.PriShare, len(ids))
	var pub *share.PubPoly
	for i, node := range nodes {
		if !node.Certified() {
			return Result{}, fmt.Errorf("dkg node %s is not certified", ids[i])
		}
		dist, err := node.DistKeyShare()
		if err != nil {
			return Result{}, err
		}
		shares[ids[i]] = dist.PriShare()
		if pub == nil {
			pub = share.NewPubPoly(suite, suite.Point().Base(), dist.Commitments())
		}
	}
	return Result{N: len(ids), Threshold: threshold, Public: pub, Shares: shares}, nil
}

func SetupFromSeed(ids []p2p.NodeID, setupSeed []byte, threshold int) (Result, error) {
	if len(ids) == 0 {
		return Result{}, errors.New("dkg setup needs at least one participant")
	}
	if threshold <= 0 || threshold > len(ids) {
		return Result{}, errors.New("invalid dkg setup threshold")
	}
	if len(setupSeed) == 0 {
		setupSeed = asig.HashBytes([]byte("AsyRand-v1/default-dkg-setup"))
	}
	suite := bn256.NewSuiteG2()
	coeffs := make([]kyber.Scalar, threshold)
	for i := range coeffs {
		coeffs[i] = suite.Scalar().SetBytes(asig.HashBytes([]byte("AsyRand-v1/DKG/setup-coeff"), setupSeed, []byte{byte(i)}))
		if coeffs[i].Equal(suite.Scalar().Zero()) {
			coeffs[i] = suite.Scalar().One()
		}
	}
	poly := share.CoefficientsToPriPoly(suite, coeffs)
	pub := poly.Commit(suite.Point().Base())
	rawShares := poly.Shares(len(ids))
	shares := make(map[p2p.NodeID]*share.PriShare, len(ids))
	for i, id := range ids {
		shares[id] = rawShares[i]
	}
	return Result{N: len(ids), Threshold: threshold, Public: pub, Shares: shares}, nil
}
