package rbc

import (
	"Tyche/utils/verification"
	"testing"
)

func TestReadyReceptionAndCertificatesShareSignatureChecks(t *testing.T) {
	bs := broadcasters()
	cache := verification.New()
	p := Packet{Context: bs[0].cfg.Context, Dealer: bs[0].cfg.ID, Seq: 7, Hash: Hash([]byte("object"))}
	cert := Certificate{Context: p.Context, Dealer: p.Dealer, Seq: p.Seq, Hash: p.Hash}
	for _, b := range bs[:3] {
		msg := b.message("READY", "", p)
		body, ok := Authenticate(p.Context, b.cfg.Public, msg, cache)
		if !ok {
			t.Fatal("honest READY rejected")
		}
		cert.Signatures = append(cert.Signatures, Signature{Signer: b.cfg.ID, Signature: body.Signature})
	}
	if cache.Stats().Executions != 3 {
		t.Fatal("wrong initial signature count", cache.Stats())
	}
	for i := 0; i < 5; i++ {
		if !VerifyCertificate(p.Context, bs[0].cfg.Public, 1, cert, cache) {
			t.Fatal("honest certificate rejected")
		}
	}
	if cache.Stats().Executions != 3 {
		t.Fatal("READY signatures reverified in a certificate", cache.Stats())
	}
	other := verification.New()
	if !VerifyCertificate(p.Context, bs[0].cfg.Public, 1, cert, other) || other.Stats().Executions != 3 {
		t.Fatal("an independent verifier reused node checks")
	}
	cert.Hash = Hash([]byte("another object"))
	if VerifyCertificate(p.Context, bs[0].cfg.Public, 1, cert, cache) {
		t.Fatal("certificate cache ignored changed object")
	}
}
