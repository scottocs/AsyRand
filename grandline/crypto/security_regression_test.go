package crypto

import (
	"Tyche/utils/p2p"
	"bytes"
	"go.dedis.ch/kyber/v3"
	"testing"
)

func TestPublicInputCannotPredictBeacon(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	const threshold = 2
	public := make(map[p2p.NodeID]kyber.Point)
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	schemes := make(map[p2p.NodeID]*PVSSPairingFreeScheme)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed(HashBytes([]byte("audit-only/" + string(id))))
		public[id] = keys[id].Public
	}
	for _, id := range ids {
		var err error
		schemes[id], err = NewPVSSScheme(id, threshold, keys[id].Private, public, testSigningKeys(id, ids))
		if err != nil {
			t.Fatal(err)
		}
	}
	setup, err := SetupGRandFromAPVSS(ids, schemes, threshold)
	if err != nil {
		t.Fatal(err)
	}
	msg := HashBytes([]byte("public-input-only-prediction"))
	predicted := auditPredictFromPublic(t, setup.PublicKey, msg)
	parts := make([]BeaconShare, 0, threshold)
	for _, id := range ids[:threshold] {
		commitment, alpha, err := NewBeaconCommitment(id, setup.SecretShares[id])
		if err != nil {
			t.Fatal(err)
		}
		part, err := NewBeaconShare(1, msg, id, setup.SecretShares[id], alpha)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyBeaconShare(msg, setup.PublicShares[id], commitment, part) {
			t.Fatal("invalid honest share")
		}
		parts = append(parts, part)
	}
	actual, _, err := RecoverBeacon(msg, parts, threshold, ids)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(predicted, actual) {
		t.Fatal("public inputs predict beacon without shares")
	}

}
func auditPredictFromPublic(t *testing.T, publicKey string, msg []byte) []byte {
	t.Helper()
	group := suite()
	pk, err := pointG1FromHex(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	scalar := group.G1().Scalar().SetBytes(HashBytes([]byte("GRandLine-v1/H1"), msg))
	if scalar.Equal(group.G1().Scalar().Zero()) {
		scalar = group.G1().Scalar().One()
	}
	predicted := group.GT().Point().Mul(scalar, group.Pair(pk, hPoint(group)))
	raw, err := predicted.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return HashBytes(raw)
}

func TestSignedContributionCannotBeRebound(t *testing.T) {
	group := suite()
	ids := []p2p.NodeID{"n0", "n1"}
	victim, attacker := testSigningKeys("n0", ids), testSigningKeys("n1", ids)
	first := schnorrProve(group, "n0", 1, group.G1().Scalar().SetInt64(7), victim.Private)
	if !schnorrVerify(group, "n0", 1, first, victim.Public["n0"]) {
		t.Fatal("honest proof rejected")
	}
	forged := schnorrProve(group, "n0", 2, group.G1().Scalar().SetInt64(11), attacker.Private)
	forged.Signature = first.Signature
	if schnorrVerify(group, "n0", 2, forged, victim.Public["n0"]) {
		t.Fatal("victim signature rebound to another contribution")
	}
}
