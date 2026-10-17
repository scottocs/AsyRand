package aba

import (
	asig "Tyche/asyrand/crypto"
	"Tyche/utils/verification"
	"encoding/hex"
	"testing"
)

func TestDecisionVotesAndHistoryVerifierShareSignatureChecks(t *testing.T) {
	f := newFixture(t, 4, 1, "column-8")
	cache := verification.New()
	f.public.Verification = cache
	v, err := NewVerifier(f.public)
	if err != nil {
		t.Fatal(err)
	}
	cert := Certificate{CommitteeID: v.CommitteeID(), Instance: "column-8", Bit: One}
	for _, id := range f.public.Members[:3] {
		sig := hex.EncodeToString(asig.Sign(f.keys[id], v.decisionStatement(cert.Instance, cert.Bit)))
		if !v.verifySignature(id, v.decisionStatement(cert.Instance, cert.Bit), sig) {
			t.Fatal("honest decision vote rejected")
		}
		cert.Signatures = append(cert.Signatures, Signature{Signer: id, SigHex: sig})
	}
	publicVerifier, err := NewVerifier(f.public)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := publicVerifier.VerifyCertificate(cert, cert.Instance); err != nil {
			t.Fatal(err)
		}
	}
	if cache.Stats().Executions != 3 {
		t.Fatal("decision signatures reverified", cache.Stats())
	}
	cert.Bit = Zero
	if publicVerifier.VerifyCertificate(cert, cert.Instance) == nil {
		t.Fatal("changed decision reused a valid signature")
	}
}
