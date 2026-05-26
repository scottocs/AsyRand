package crypto

import (
	"fmt"

	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

type KeyPair struct {
	Private kyber.Scalar
	Public  kyber.Point
}

const (
	PVSSO1     = "o1"
	PVSSScrape = "scrape"
)

type PVSSParams struct {
	Scheme string           `json:"scheme"`
	O1     *PublicParams    `json:"o1,omitempty"`
	Scrape *ScrapeDDHParams `json:"scrape,omitempty"`
}

func SetupPVSS(backend string, epoch string, threshold int, members []p2p.NodeID) (PVSSParams, map[p2p.NodeID]KeyPair, error) {
	switch backend {
	case "", PVSSO1:
		pp, keys, err := Setup(epoch, threshold, members)
		if err != nil {
			return PVSSParams{}, nil, err
		}
		return WrapPVSSParams(pp), keys, nil
	case PVSSScrape:
		pp, keys, err := ScrapeDDHSetup(epoch, threshold, members)
		if err != nil {
			return PVSSParams{}, nil, err
		}
		return WrapPVSSParams(pp), keys, nil
	default:
		return PVSSParams{}, nil, fmt.Errorf("unsupported pvss backend %q", backend)
	}
}

func WrapPVSSParams(params any) PVSSParams {
	switch pp := params.(type) {
	case PVSSParams:
		return pp
	case *PVSSParams:
		if pp == nil {
			return PVSSParams{}
		}
		return *pp
	case PublicParams:
		return PVSSParams{Scheme: PVSSO1, O1: &pp}
	case *PublicParams:
		if pp == nil {
			return PVSSParams{}
		}
		return PVSSParams{Scheme: PVSSO1, O1: pp}
	case ScrapeDDHParams:
		return PVSSParams{Scheme: PVSSScrape, Scrape: &pp}
	case *ScrapeDDHParams:
		if pp == nil {
			return PVSSParams{}
		}
		return PVSSParams{Scheme: PVSSScrape, Scrape: pp}
	default:
		return PVSSParams{}
	}
}

func (p PVSSParams) Epoch() string {
	switch p.Scheme {
	case PVSSScrape:
		if p.Scrape != nil {
			return p.Scrape.Epoch
		}
	default:
		if p.O1 != nil {
			return p.O1.Epoch
		}
	}
	return ""
}

func (p PVSSParams) Threshold() int {
	switch p.Scheme {
	case PVSSScrape:
		if p.Scrape != nil {
			return p.Scrape.Threshold
		}
	default:
		if p.O1 != nil {
			return p.O1.Threshold
		}
	}
	return 0
}

func (p PVSSParams) Members() []p2p.NodeID {
	switch p.Scheme {
	case PVSSScrape:
		if p.Scrape != nil {
			return append([]p2p.NodeID(nil), p.Scrape.Members...)
		}
	default:
		if p.O1 != nil {
			return append([]p2p.NodeID(nil), p.O1.Members...)
		}
	}
	return nil
}

func VerifyPVSSSetup(p PVSSParams) bool {
	switch p.Scheme {
	case "", PVSSO1:
		return p.O1 != nil && SetupVrf(*p.O1)
	case PVSSScrape:
		return p.Scrape != nil && ScrapeDDHSetupVrf(*p.Scrape)
	default:
		return false
	}
}

type PVSSScheme interface {
	Epoch() string
	PrivateKey() kyber.Scalar
	Share(dealer p2p.NodeID, seq uint64, secret kyber.Scalar) (Commitment, []byte, error)
	Verify(c Commitment) bool
	PreRecon(c Commitment, holder p2p.NodeID) (DecryptedShare, error)
	PreReconVerified(c Commitment, holder p2p.NodeID) (DecryptedShare, error)
	VerifyShare(c Commitment, sh DecryptedShare) bool
	Recon(c Commitment, shares []DecryptedShare) ([]byte, error)
	ReconVerified(c Commitment, shares []DecryptedShare) ([]byte, error)
	ReconFromVerifiedShares(c Commitment, shares []DecryptedShare) ([]byte, error)
}

func NewPVSSScheme(id p2p.NodeID, private kyber.Scalar, params any) (PVSSScheme, error) {
	switch pp := params.(type) {
	case PVSSParams:
		switch pp.Scheme {
		case "", PVSSO1:
			if pp.O1 == nil {
				return nil, fmt.Errorf("nil o1-pvss params")
			}
			return NewScheme(id, private, *pp.O1)
		case PVSSScrape:
			if pp.Scrape == nil {
				return nil, fmt.Errorf("nil scrape-ddh params")
			}
			return NewScrapeDDHScheme(id, private, *pp.Scrape)
		default:
			return nil, fmt.Errorf("unsupported pvss backend %q", pp.Scheme)
		}
	case *PVSSParams:
		if pp == nil {
			return nil, fmt.Errorf("nil pvss params")
		}
		return NewPVSSScheme(id, private, *pp)
	case PublicParams:
		return NewScheme(id, private, pp)
	case *PublicParams:
		if pp == nil {
			return nil, fmt.Errorf("nil o1-pvss params")
		}
		return NewScheme(id, private, *pp)
	case ScrapeDDHParams:
		return NewScrapeDDHScheme(id, private, pp)
	case *ScrapeDDHParams:
		if pp == nil {
			return nil, fmt.Errorf("nil scrape-ddh params")
		}
		return NewScrapeDDHScheme(id, private, *pp)
	default:
		return nil, fmt.Errorf("unsupported pvss params type %T", params)
	}
}

type Commitment struct {
	Scheme    string       `json:"scheme,omitempty"`
	Dealer    p2p.NodeID   `json:"dealer"`
	Seq       uint64       `json:"seq"`
	Epoch     string       `json:"epoch"`
	Threshold int          `json:"threshold"`
	Members   []p2p.NodeID `json:"members"`

	C0    string         `json:"c0,omitempty"`
	C1    []EncodedPoint `json:"c1,omitempty"`
	C2    string         `json:"c2,omitempty"`
	Proof Proof          `json:"proof,omitempty"`

	EncryptedShares []EncodedPoint             `json:"encrypted_shares,omitempty"`
	ShareCommits    []EncodedPoint             `json:"share_commits,omitempty"`
	ScrapeProof     ScrapeDDHDistributionProof `json:"scrape_proof,omitempty"`

	SecretID string `json:"secret_id"`
}

type EncodedPoint struct {
	Group string `json:"group"`
	Value string `json:"value"`
}

type DecryptionProof struct {
	A         string `json:"a,omitempty"`
	B         string `json:"b,omitempty"`
	Challenge string `json:"challenge,omitempty"`
	Response  string `json:"response,omitempty"`
}

type DecryptedShare struct {
	CommitmentID string          `json:"commitment_id"`
	Holder       p2p.NodeID      `json:"holder"`
	Value        string          `json:"value"`
	Proof        DecryptionProof `json:"proof"`
}
