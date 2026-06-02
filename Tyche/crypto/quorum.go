package crypto

import (
	"errors"
	"sort"
)

type VoteShare struct {
	Signer string `json:"signer"`
}

type QuorumCertificate struct {
	Signers []string `json:"signers"`
}

func NewVoteShare(signer string) (VoteShare, error) {
	if signer == "" {
		return VoteShare{}, errors.New("empty vote signer")
	}
	return VoteShare{Signer: signer}, nil
}

func VerifyVoteShare(share VoteShare, members map[string]struct{}) bool {
	_, ok := members[share.Signer]
	return ok
}

func BuildQuorumCertificate(shares []VoteShare, members map[string]struct{}, threshold int) (QuorumCertificate, error) {
	if len(shares) < threshold {
		return QuorumCertificate{}, errors.New("not enough vote shares")
	}
	seen := make(map[string]bool, len(shares))
	signers := make([]string, 0, len(shares))
	for _, share := range shares {
		if seen[share.Signer] || !VerifyVoteShare(share, members) {
			continue
		}
		seen[share.Signer] = true
		signers = append(signers, share.Signer)
	}
	if len(signers) < threshold {
		return QuorumCertificate{}, errors.New("not enough valid vote shares")
	}
	sort.Strings(signers)
	return QuorumCertificate{Signers: append([]string(nil), signers[:threshold]...)}, nil
}

func VerifyQuorumCertificate(cert QuorumCertificate, members map[string]struct{}, threshold int) error {
	if len(cert.Signers) < threshold {
		return errors.New("quorum certificate below threshold")
	}
	seen := make(map[string]bool, len(cert.Signers))
	for _, signer := range cert.Signers {
		if seen[signer] {
			return errors.New("duplicate quorum signer")
		}
		seen[signer] = true
		if _, ok := members[signer]; !ok {
			return errors.New("unknown quorum signer: " + signer)
		}
	}
	return nil
}
