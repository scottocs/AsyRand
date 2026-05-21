package crypto

import (
	"bytes"
	"testing"

	"github.com/scottocs/Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

func TestGRandBeaconCommitmentShareAndRecovery(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3", "n4"}
	threshold := 3
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}
	schemes := make(map[p2p.NodeID]*PVSSPairingFreeScheme)
	for _, id := range ids {
		scheme, err := NewPVSSScheme(id, threshold, keys[id].Private, public)
		if err != nil {
			t.Fatal(err)
		}
		schemes[id] = scheme
	}
	grand, err := SetupGRandFromAPVSS(ids, schemes, threshold)
	if err != nil {
		t.Fatal(err)
	}
	msg := HashBytes([]byte("epoch-7"))
	commitments := make(map[p2p.NodeID]BeaconCommitment)
	alphas := make(map[p2p.NodeID]kyber.Scalar)
	for _, id := range ids {
		commitment, alpha, err := NewBeaconCommitment(id, grand.SecretShares[id])
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyBeaconCommitment(grand.PublicShares[id], commitment) {
			t.Fatalf("commitment from %s did not verify", id)
		}
		commitments[id] = commitment
		alphas[id] = alpha
	}
	shares := make([]BeaconShare, 0, threshold)
	for _, id := range ids[:threshold] {
		share, err := NewBeaconShare(7, msg, id, grand.SecretShares[id], alphas[id])
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyBeaconShare(msg, grand.PublicShares[id], commitments[id], share) {
			t.Fatalf("beacon share from %s did not verify", id)
		}
		shares = append(shares, share)
	}
	random, sigHex, err := RecoverBeacon(msg, shares, threshold, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(random) == 0 || sigHex == "" {
		t.Fatal("empty recovered beacon output")
	}
	again, againSig, err := RecoverBeacon(msg, shares, threshold, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(random, again) || sigHex != againSig {
		t.Fatal("beacon recovery is not deterministic")
	}
}

func TestBeaconShareRejectsTamperedDLEQ(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2"}
	threshold := 2
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	public := make(map[p2p.NodeID]kyber.Point)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte(id)))
		public[id] = keys[id].Public
	}
	schemes := make(map[p2p.NodeID]*PVSSPairingFreeScheme)
	for _, id := range ids {
		scheme, err := NewPVSSScheme(id, threshold, keys[id].Private, public)
		if err != nil {
			t.Fatal(err)
		}
		schemes[id] = scheme
	}
	grand, err := SetupGRandFromAPVSS(ids, schemes, threshold)
	if err != nil {
		t.Fatal(err)
	}
	msg := HashBytes([]byte("epoch-1"))
	commitment, alpha, err := NewBeaconCommitment("n0", grand.SecretShares["n0"])
	if err != nil {
		t.Fatal(err)
	}
	share, err := NewBeaconShare(1, msg, "n0", grand.SecretShares["n0"], alpha)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyBeaconShare(msg, grand.PublicShares["n0"], commitment, share) {
		t.Fatal("valid beacon share did not verify")
	}
	share.Proof.Response = share.Proof.Challenge
	if VerifyBeaconShare(msg, grand.PublicShares["n0"], commitment, share) {
		t.Fatal("tampered DLEQ proof verified")
	}
}
