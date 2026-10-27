package crypto

import (
	"Tyche/utils/cryptoexec"
	"Tyche/utils/p2p"
	"Tyche/utils/verification"
	"bytes"
	"encoding/hex"
	"go.dedis.ch/kyber/v3"
	"strings"
	"sync"
	"testing"
)

func runtimeFixture(t testing.TB) (GRandResult, []p2p.NodeID, []*VerifiedBeaconCommitment, []*BeaconSigner) {
	t.Helper()
	ids := []p2p.NodeID{"n0", "n1", "n2"}
	g := suite()
	r := GRandResult{PublicKey: mustPointHex(g.G1().Point().Mul(g.G1().Scalar().SetInt64(7), gPoint(g))), PublicShares: map[p2p.NodeID]string{}, SecretShares: map[p2p.NodeID]string{}}
	for i, id := range ids {
		x := g.G1().Scalar().SetInt64(int64(7 + 3*(i+1)))
		r.PublicShares[id] = mustPointHex(g.G1().Point().Mul(x, gPoint(g)))
		r.SecretShares[id] = mustPointHex(g.G2().Point().Mul(x, hPoint(g)))
	}
	if err := PrepareReferenceCommitments(&r, ids); err != nil {
		t.Fatal(err)
	}
	cs := make([]*VerifiedBeaconCommitment, len(ids))
	ss := make([]*BeaconSigner, len(ids))
	for i, id := range ids {
		var ok bool
		cs[i], ok = DecodeAndVerifyBeaconCommitment(r.PublicShares[id], r.Reference.Commitments[id])
		if !ok {
			t.Fatal("invalid fixture")
		}
		a, err := DecodeReferenceAlpha(r.Reference.Alphas[id])
		if err != nil {
			t.Fatal(err)
		}
		ss[i], err = NewBeaconSigner(id, r.SecretShares[id], a, cs[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	return r, ids, cs, ss
}

// Independent reference retains the pre-optimization GT decoder, including
// its full subgroup test, before applying both complete verification checks.
func decodeThenVerifyGT(e *BeaconEpoch, c *VerifiedBeaconCommitment, sh BeaconShare) bool {
	if sh.Epoch != e.epoch || sh.Signer != c.Signer {
		return false
	}
	u, err := pointG1FromHex(sh.Sigma1)
	if err != nil {
		return false
	}
	v, err := pointGTFromHex(sh.Sigma2)
	if err != nil {
		return false
	}
	g := suite()
	return cryptoexec.AllLabeled("reference-share", 2, func(i int) bool {
		if i == 0 {
			return verifyBeaconDLEQWithCM1(g, e.msg, c.CM1, u, sh.Proof, e.gr, nil)
		}
		return v.Equal(g.PairProduct([2]kyber.Point{e.gr, c.CM2}, [2]kyber.Point{u, hPoint(g)}))
	})
}

func TestGTCanonicalEquationMatchesIndependentDecoder(t *testing.T) {
	_, _, cs, ss := runtimeFixture(t)
	e := NewBeaconEpoch(11, []byte("GT canonical equation / setup-A"))
	for i := range ss {
		wire, _, err := ss[i].Share(e)
		if err != nil {
			t.Fatal(err)
		}
		cases := []BeaconShare{wire}
		upper := wire
		upper.Sigma2 = strings.ToUpper(wire.Sigma2)
		cases = append(cases, upper)
		for _, raw := range []string{"", wire.Sigma2[2:], wire.Sigma2 + "00", strings.Repeat("ff", 576), strings.Repeat("00", 576), strings.Repeat("zz", 576), mustPointHexGT(suite().GT().Point().Null())} {
			bad := wire
			bad.Sigma2 = raw
			cases = append(cases, bad)
		}
		raw, _ := hex.DecodeString(wire.Sigma2)
		for offset := 0; offset < len(raw); offset += 47 {
			bad := wire
			mutated := append([]byte(nil), raw...)
			mutated[offset] ^= 1
			bad.Sigma2 = hex.EncodeToString(mutated)
			cases = append(cases, bad)
		}
		wrongEpoch := wire
		wrongEpoch.Epoch++
		cases = append(cases, wrongEpoch)
		wrongSigner := wire
		wrongSigner.Signer = "intruder"
		cases = append(cases, wrongSigner)
		badProof := wire
		badProof.Proof.Response = mustScalarHex(suite().G1().Scalar().Zero())
		cases = append(cases, badProof)
		badProof = wire
		badProof.Proof.A1 = mustPointHex(suite().G1().Point().Null())
		cases = append(cases, badProof)
		for j, input := range cases {
			want := decodeThenVerifyGT(e, cs[i], input)
			got, ok := e.verifyUncached(cs[i], input, nil)
			if want != ok || ok != (j < 2) {
				t.Fatalf("acceptance differs: signer=%d case=%d reference=%v new=%v", i, j, want, ok)
			}
			if ok {
				point, err := pointGTFromHex(input.Sigma2)
				if err != nil || !got.sigma.Equal(point) {
					t.Fatal("retained GT changed")
				}
			}
		}
	}
}

func BenchmarkColdGTShareVerification(b *testing.B) {
	_, _, cs, ss := runtimeFixture(b)
	e := NewBeaconEpoch(11, []byte("cold GT share"))
	wire, _, err := ss[0].Share(e)
	if err != nil {
		b.Fatal(err)
	}
	for _, method := range []string{"DecodeThenEquation", "CanonicalEquation"} {
		b.Run(method, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if method == "DecodeThenEquation" {
					if !decodeThenVerifyGT(e, cs[0], wire) {
						b.Fatal("valid share rejected")
					}
				} else {
					if _, ok := e.verifyUncached(cs[0], wire, nil); !ok {
						b.Fatal("valid share rejected")
					}
				}
			}
		})
	}
}

func TestDecodedRecoveryEqualsLegacyAndPolynomialSecret(t *testing.T) {
	_, ids, cs, ss := runtimeFixture(t)
	msg := []byte("setup-A/epoch-7")
	e := NewBeaconEpoch(7, msg)
	wires := make([]BeaconShare, 2)
	parts := make([]*VerifiedBeaconShare, 2)
	for i := range parts {
		var err error
		wires[i], _, err = ss[i].Share(e)
		if err != nil {
			t.Fatal(err)
		}
		var ok bool
		parts[i], ok = e.VerifyShare(cs[i], wires[i])
		if !ok {
			t.Fatal("valid share rejected")
		}
	}
	got, sigma, err := e.Recover(parts, 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	old, oldSigma, err := RecoverBeacon(msg, wires, 2, ids)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, old) || sigma != oldSigma {
		t.Fatal("decoded recovery changed output")
	}
	g := suite()
	want := g.Pair(hashToG1(g, msg), g.G2().Point().Mul(g.G2().Scalar().SetInt64(7), hPoint(g)))
	raw, _ := want.MarshalBinary()
	if !bytes.Equal(got, HashBytes(raw)) {
		t.Fatal("recovered value differs from polynomial secret")
	}
	if _, _, err = e.Recover([]*VerifiedBeaconShare{parts[0], parts[0]}, 2, ids); err == nil {
		t.Fatal("duplicate signer counted twice")
	}
	if _, _, err = NewBeaconEpoch(8, msg).Recover(parts, 2, ids); err == nil {
		t.Fatal("cross-epoch shares accepted")
	}
	if _, _, err = NewBeaconEpoch(7, []byte("other setup")).Recover(parts, 2, ids); err == nil {
		t.Fatal("cross-setup shares accepted")
	}
	if e.Accepts(&VerifiedBeaconShare{}, ids[0]) {
		t.Fatal("empty opaque share accepted")
	}
}

func TestEpochContextRetainsDecodedChecksAndRejectsTampering(t *testing.T) {
	_, _, cs, ss := runtimeFixture(t)
	msg := []byte("setup-A/epoch-7")
	e := NewBeaconEpoch(7, msg)
	wire, _, err := ss[0].Share(e)
	if err != nil {
		t.Fatal(err)
	}
	cache := verification.New()
	parts := make([]*VerifiedBeaconShare, 12)
	var wg sync.WaitGroup
	for i := range parts {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var ok bool
			parts[i], ok = e.VerifyShare(cs[0], wire, cache)
			if !ok {
				t.Error("valid share rejected")
			}
		}(i)
	}
	wg.Wait()
	for _, p := range parts {
		if p != parts[0] {
			t.Fatal("decoded share not reused")
		}
	}
	before := cache.Stats().Executions
	if !VerifyBeaconShareWithCommitment(msg, cs[0], wire, cache) {
		t.Fatal("legacy verifier rejected valid cached evidence")
	}
	if cache.Stats().Executions != before {
		t.Fatal("legacy verifier repeated native verification")
	}
	bad := wire
	bad.Sigma2 = mustPointHexGT(suite().GT().Point().Null())
	if _, ok := e.VerifyShare(cs[0], bad, cache); ok {
		t.Fatal("tampered GT accepted")
	}
	bad = wire
	bad.Epoch++
	if _, ok := e.VerifyShare(cs[0], bad, cache); ok {
		t.Fatal("wrong epoch accepted")
	}
	if _, ok := NewBeaconEpoch(7, []byte("other setup")).VerifyShare(cs[0], wire, cache); ok {
		t.Fatal("wrong message accepted")
	}
}

func TestReferenceSnapshotBindsPrivateAlpha(t *testing.T) {
	r, ids, _, _ := runtimeFixture(t)
	original := r.Reference.Alphas[ids[0]]
	r.Reference.Alphas[ids[0]] = r.Reference.Alphas[ids[1]]
	if err := ValidateReferenceCommitments(r, ids); err == nil {
		t.Fatal("wrong private alpha accepted")
	}
	r.Reference.Alphas[ids[0]] = original
	g := suite()
	delta := g.G1().Scalar().SetInt64(19)
	pk, err := pointG1FromHex(r.PublicShares[ids[0]])
	if err != nil {
		t.Fatal(err)
	}
	fake := BeaconCommitment{Signer: ids[0], CM1: mustPointHex(g.G1().Point().Add(pk, g.G1().Point().Mul(delta, gPoint(g)))), CM2: mustPointHex(g.G2().Point().Neg(g.G2().Point().Mul(delta, hPoint(g))))}
	if _, ok := DecodeAndVerifyBeaconCommitment(r.PublicShares[ids[0]], fake); !ok {
		t.Fatal("fixture should satisfy public commitment equation")
	}
	r.Reference.Commitments[ids[0]] = fake
	if err := ValidateReferenceCommitments(r, ids); err == nil {
		t.Fatal("publicly forged commitment accepted into private setup")
	}
}
