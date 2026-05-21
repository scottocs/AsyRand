package crypto

import (
	"errors"
	"fmt"

	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	pedersen "go.dedis.ch/kyber/v3/share/dkg/pedersen"
)

type DKGResult struct {
	N         int
	Threshold int
	Public    *share.PubPoly
	Shares    map[p2p.NodeID]*share.PriShare
}

func RunPedersenDKG(ids []p2p.NodeID, seeds map[p2p.NodeID][]byte, threshold int) (DKGResult, error) {
	if len(ids) == 0 {
		return DKGResult{}, errors.New("dkg needs at least one participant")
	}
	if threshold <= 0 || threshold > len(ids) {
		return DKGResult{}, errors.New("invalid dkg threshold")
	}
	suite := bn256.NewSuiteG2()
	longterm := make([]kyber.Scalar, len(ids))
	public := make([]kyber.Point, len(ids))
	for i, id := range ids {
		seed := seeds[id]
		if len(seed) == 0 {
			return DKGResult{}, fmt.Errorf("missing dkg seed for %s", id)
		}
		sk := suite.Scalar().SetBytes(HashBytes([]byte("Tyche-v1/DKG/longterm"), seed))
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
			return DKGResult{}, err
		}
		nodes[i] = dkg
	}

	responses := make([][]*pedersen.Response, len(nodes))
	for _, dealer := range nodes {
		deals, err := dealer.Deals()
		if err != nil {
			return DKGResult{}, err
		}
		for recipient, deal := range deals {
			response, err := nodes[recipient].ProcessDeal(deal)
			if err != nil {
				return DKGResult{}, err
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
				return DKGResult{}, err
			}
		}
	}

	shares := make(map[p2p.NodeID]*share.PriShare, len(ids))
	var pub *share.PubPoly
	for i, node := range nodes {
		if !node.Certified() {
			return DKGResult{}, fmt.Errorf("dkg node %s is not certified", ids[i])
		}
		dist, err := node.DistKeyShare()
		if err != nil {
			return DKGResult{}, err
		}
		shares[ids[i]] = dist.PriShare()
		if pub == nil {
			pub = share.NewPubPoly(suite, suite.Point().Base(), dist.Commitments())
		}
	}
	return DKGResult{N: len(ids), Threshold: threshold, Public: pub, Shares: shares}, nil
}

func SetupDKGFromSeed(ids []p2p.NodeID, setupSeed []byte, threshold int) (DKGResult, error) {
	if len(ids) == 0 {
		return DKGResult{}, errors.New("dkg setup needs at least one participant")
	}
	if threshold <= 0 || threshold > len(ids) {
		return DKGResult{}, errors.New("invalid dkg setup threshold")
	}
	if len(setupSeed) == 0 {
		setupSeed = HashBytes([]byte("Tyche-v1/default-dkg-setup"))
	}
	suite := bn256.NewSuiteG2()
	coeffs := make([]kyber.Scalar, threshold)
	for i := range coeffs {
		coeffs[i] = suite.Scalar().SetBytes(HashBytes([]byte("Tyche-v1/DKG/setup-coeff"), setupSeed, []byte{byte(i)}))
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
	return DKGResult{N: len(ids), Threshold: threshold, Public: pub, Shares: shares}, nil
}
