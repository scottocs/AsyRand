package crypto

import (
	"crypto/ed25519"
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestAggregateSignatureVerify(t *testing.T) {
	msg := []byte("asyrand beacon certificate")
	pubs := make(map[string]ed25519.PublicKey)
	agg := NewAggregateSignature()

	for _, id := range []string{"n0", "n1", "n2"} {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		pubs[id] = kp.Public
		agg.Add(id, Sign(kp.Private, msg))
	}

	if err := agg.Verify(msg, pubs, 2); err != nil {
		t.Fatalf("aggregate signature should verify: %v", err)
	}
	if err := agg.Verify([]byte("other message"), pubs, 2); err == nil {
		t.Fatal("aggregate signature verified for a different message")
	}
}

func TestBLSAggregateSignatureVerify(t *testing.T) {
	msg := []byte("asyrand ready certificate")
	seeds := map[string][]byte{
		"n0": HashBytes([]byte("n0")),
		"n1": HashBytes([]byte("n1")),
		"n2": HashBytes([]byte("n2")),
	}
	pubs := make(map[string]kyber.Point)
	shares := make([]BLSSignatureShare, 0, len(seeds))
	for id, seed := range seeds {
		kp := NewBLSKeyPairFromSeed(seed)
		pubs[id] = kp.Public
		share, err := SignBLS(id, kp.Private, msg)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, share)
	}
	agg, err := AggregateBLS(shares, pubs, msg, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBLSAggregate(agg, pubs, msg, 2); err != nil {
		t.Fatalf("aggregate BLS signature should verify: %v", err)
	}
	if err := VerifyBLSAggregate(agg, pubs, []byte("other"), 2); err == nil {
		t.Fatal("aggregate BLS signature verified for a different message")
	}
}
