package crypto

import (
	"Tyche/utils/p2p"
	"bytes"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"testing"
)

func TestPublicCommitmentCannotPredictSpurtSecret(t *testing.T) {
	ids := []p2p.NodeID{"n0", "n1", "n2", "n3"}
	public := make(map[p2p.NodeID]kyber.Point)
	keys := make(map[p2p.NodeID]PVSSKeyPair)
	for _, id := range ids {
		keys[id] = PVSSKeyPairFromSeed([]byte("audit-only/" + string(id)))
		public[id] = keys[id].Public
	}
	s, err := NewPVSSScheme(ids[0], 2, keys[ids[0]].Private, public)
	if err != nil {
		t.Fatal(err)
	}
	transcript, expected, err := s.Share(ids[0], 1, ids)
	if err != nil {
		t.Fatal(err)
	}
	predicted := auditSpurtPredictFromPublic(t, transcript)
	if bytes.Equal(expected, predicted) {
		t.Fatal("public commitment predicts hidden secret")
	}

}
func auditSpurtPredictFromPublic(t *testing.T, transcript PVSSCommitment) []byte {
	t.Helper()
	group := suite()
	inputs := make([]*share.PubShare, 0, transcript.Threshold)
	for i, id := range transcript.Members[:transcript.Threshold] {
		p, err := pointG2FromHex(transcript.Commit[id])
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, &share.PubShare{I: i, V: p})
	}
	v0, err := share.RecoverCommit(group.G2(), inputs, transcript.Threshold, len(transcript.Members))
	if err != nil {
		t.Fatal(err)
	}
	a := group.G2().Scalar().SetBytes(HashBytes([]byte("SPURT-v2/PVSS/independent-h1")))
	if a.Equal(group.G2().Scalar().Zero()) {
		a = group.G2().Scalar().One()
	}
	predicted := group.GT().Point().Mul(a, group.Pair(h0Point(group), v0))
	raw, err := predicted.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
