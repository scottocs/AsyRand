package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

type pvssFixture struct {
	ids     []p2p.NodeID
	keys    map[p2p.NodeID]PVSSKeyPair
	public  map[p2p.NodeID]kyber.Point
	schemes map[p2p.NodeID]*PVSSPairingFreeScheme
}

func newPVSSFixture(t *testing.T, n, threshold int) pvssFixture {
	t.Helper()
	f := pvssFixture{keys: make(map[p2p.NodeID]PVSSKeyPair), public: make(map[p2p.NodeID]kyber.Point), schemes: make(map[p2p.NodeID]*PVSSPairingFreeScheme)}
	for i := 0; i < n; i++ {
		id := p2p.NodeID(fmt.Sprintf("n%d", i))
		f.ids = append(f.ids, id)
		f.keys[id] = PVSSKeyPairFromSeed([]byte("test-only private seed/" + string(id)))
		f.public[id] = f.keys[id].Public
	}
	for _, id := range f.ids {
		s, err := NewPVSSScheme(id, threshold, f.keys[id].Private, f.public)
		if err != nil {
			t.Fatal(err)
		}
		f.schemes[id] = s
	}
	return f
}

func (f pvssFixture) sharing(t *testing.T) (PVSSCommitment, []byte) {
	t.Helper()
	c, secret, err := f.schemes[f.ids[0]].Share(f.ids[0], 1, f.ids)
	if err != nil {
		t.Fatal(err)
	}
	return c, secret
}

func clonePVSS(t *testing.T, c PVSSCommitment) PVSSCommitment {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var cloned PVSSCommitment
	if err := json.Unmarshal(b, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func TestPVSSVerifyPreReconAndRecon(t *testing.T) {
	for _, param := range [][2]int{{1, 1}, {4, 1}, {4, 2}, {7, 3}, {4, 4}} {
		t.Run(fmt.Sprintf("n=%d/t=%d", param[0], param[1]), func(t *testing.T) {
			f := newPVSSFixture(t, param[0], param[1])
			c, secret := f.sharing(t)
			dealer := f.schemes[f.ids[0]]
			if len(secret) != 32 {
				t.Fatal("secret is not an Edwards25519 group encoding")
			}
			if _, err := pointFromHex(hex.EncodeToString(secret)); err != nil {
				t.Fatal(err)
			}
			shares := make([]PVSSDecryptedShare, 0, len(f.ids))
			for _, id := range f.ids {
				s := f.schemes[id]
				if !s.Verify(c) {
					t.Fatalf("node %s rejected honest sharing", id)
				}
				sh, err := s.PreRecon(c, id)
				if err != nil {
					t.Fatal(err)
				}
				if !dealer.VerifyShare(c, sh) {
					t.Fatalf("node %s produced invalid share", id)
				}
				trusted, err := s.PreReconTrusted(c, id)
				if err != nil || trusted.Value != sh.Value || !dealer.VerifyShare(c, trusted) {
					t.Fatal("trusted decryption failed")
				}
				shares = append(shares, sh)
			}
			for _, set := range [][]PVSSDecryptedShare{shares[:param[1]], shares[len(shares)-param[1]:], shares} {
				z, err := dealer.Recon(c, set, param[1])
				if err != nil || !bytes.Equal(z, secret) {
					t.Fatalf("reconstruction failed: %v", err)
				}
				z, err = dealer.ReconTrusted(c, set, 0)
				if err != nil || !bytes.Equal(z, secret) {
					t.Fatalf("trusted reconstruction failed: %v", err)
				}
			}
			if _, err := dealer.Recon(c, shares[:param[1]-1], param[1]); err == nil {
				t.Fatal("reconstructed below threshold")
			}
		})
	}
}

func TestPVSSAllThresholdSubsets(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, secret := f.sharing(t)
	s := f.schemes[f.ids[0]]
	shares := make([]PVSSDecryptedShare, 4)
	for i, id := range f.ids {
		var err error
		shares[i], err = f.schemes[id].PreRecon(c, id)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		for j := i + 1; j < 4; j++ {
			z, err := s.Recon(c, []PVSSDecryptedShare{shares[j], shares[i]}, 2)
			if err != nil || !bytes.Equal(z, secret) {
				t.Fatalf("subset %d,%d failed: %v", i, j, err)
			}
		}
	}
}

func TestPVSSRejectsMalformedOrRelabelledTranscript(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, _ := f.sharing(t)
	s := f.schemes[f.ids[0]]
	cases := []struct {
		name   string
		change func(*PVSSCommitment)
	}{
		{"dealer", func(c *PVSSCommitment) { c.Dealer = "n1" }},
		{"sequence", func(c *PVSSCommitment) { c.Seq++ }},
		{"zero-sequence", func(c *PVSSCommitment) { c.Seq = 0 }},
		{"unknown-dealer", func(c *PVSSCommitment) { c.Dealer = "other" }},
		{"version", func(c *PVSSCommitment) { c.Version = "Spurt-v1" }},
		{"setup", func(c *PVSSCommitment) { c.SetupID = strings.Repeat("0", 64) }},
		{"threshold-downgrade", func(c *PVSSCommitment) { c.Threshold = 1 }},
		{"threshold-zero", func(c *PVSSCommitment) { c.Threshold = 0 }},
		{"members-duplicate", func(c *PVSSCommitment) { c.Members[1] = c.Members[0] }},
		{"members-reordered", func(c *PVSSCommitment) { c.Members[0], c.Members[1] = c.Members[1], c.Members[0] }},
		{"members-removed", func(c *PVSSCommitment) { c.Members = c.Members[:3] }},
		{"missing-proof", func(c *PVSSCommitment) { c.Proof = PVSSProof{} }},
		{"missing-response", func(c *PVSSCommitment) { delete(c.Proof.Responses, "n1") }},
		{"extra-response", func(c *PVSSCommitment) { c.Proof.Responses["other"] = c.Proof.Responses["n1"] }},
		{"changed-response", func(c *PVSSCommitment) {
			z := scalarFromHex(c.Proof.Responses["n1"])
			c.Proof.Responses["n1"] = scalarHex(suite().Scalar().Add(z, suite().Scalar().One()))
		}},
		{"noncanonical-scalar", func(c *PVSSCommitment) { c.Proof.Challenge = hex.EncodeToString(pvssGroupOrder[:]) }},
		{"changed-cipher", func(c *PVSSCommitment) { c.Cipher["n1"] = c.Cipher["n0"] }},
		{"changed-commit", func(c *PVSSCommitment) { c.Commit["n1"] = c.Commit["n0"] }},
		{"missing-cipher", func(c *PVSSCommitment) { delete(c.Cipher, "n1") }},
		{"extra-cipher", func(c *PVSSCommitment) { c.Cipher["other"] = c.Cipher["n1"] }},
		{"malformed-point", func(c *PVSSCommitment) { c.Cipher["n1"] = strings.Repeat("z", 64) }},
		{"trailing-point-bytes", func(c *PVSSCommitment) { c.Cipher["n1"] += "00" }},
		{"uppercase-point", func(c *PVSSCommitment) { c.Commit["n1"] = strings.ToUpper(c.Commit["n1"]) }},
		{"legacy-aggregate", func(c *PVSSCommitment) { c.Aggregate = true }},
		{"legacy-source", func(c *PVSSCommitment) { c.Sources = []PVSSSource{{Dealer: "n1", Seq: 1, SecretID: "old"}} }},
		{"legacy-DLEQ", func(c *PVSSCommitment) { c.DLEQ = map[p2p.NodeID]DLEQProof{"n1": {}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := clonePVSS(t, c)
			tc.change(&bad)
			bad.SecretID = commitmentID(bad)
			if s.Verify(bad) {
				t.Fatal("modified transcript verified despite a recomputed object ID")
			}
			if _, err := s.PreRecon(bad, "n0"); err == nil {
				t.Fatal("decrypted invalid transcript")
			}
			if _, err := s.Recon(bad, nil, 2); err == nil {
				t.Fatal("reconstructed invalid transcript")
			}
		})
	}
	bad := clonePVSS(t, c)
	bad.SecretID = strings.Repeat("0", 64)
	if s.Verify(bad) {
		t.Fatal("accepted an incorrect object ID")
	}
}

func TestPVSSContextBindsAllShareholderKeys(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, _ := f.sharing(t)
	changed := make(map[p2p.NodeID]kyber.Point, len(f.public))
	for id, p := range f.public {
		changed[id] = p
	}
	changed["n3"] = PVSSKeyPairFromSeed([]byte("different private seed")).Public
	other, err := NewPVSSScheme("n0", 2, f.keys["n0"].Private, changed)
	if err != nil {
		t.Fatal(err)
	}
	if other.Verify(c) {
		t.Fatal("transcript verified under a different shareholder key set")
	}
	c.SetupID = other.setupID
	c.SecretID = commitmentID(c)
	if other.Verify(c) {
		t.Fatal("old proof survived a setup ID change")
	}
}

// Build well-formed DLEQ proofs for chosen evaluations to isolate the RS check.
func chosenPVSS(t *testing.T, f pvssFixture, values []int64) PVSSCommitment {
	t.Helper()
	c, _ := f.sharing(t)
	s := f.schemes[f.ids[0]]
	witnesses := make([]kyber.Scalar, len(values))
	for i, id := range c.Members {
		witnesses[i] = suite().Scalar().SetInt64(values[i])
		c.Commit[id] = mustPointHex(suite().Point().Mul(witnesses[i], s.g))
		c.Cipher[id] = mustPointHex(suite().Point().Mul(witnesses[i], s.public[id]))
	}
	c.Proof = s.proveSharing(c, witnesses)
	c.SecretID = commitmentID(c)
	return c
}

func TestPVSSDualCodeRejectsNonPolynomialEvaluations(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	bad := chosenPVSS(t, f, []int64{1, 2, 3, 5}) // Not a degree <=1 polynomial.
	if f.schemes["n0"].Verify(bad) {
		t.Fatal("valid DLEQs hid a non-polynomial commitment vector")
	}
	good := chosenPVSS(t, f, []int64{2, 3, 4, 5})
	if !f.schemes["n0"].Verify(good) {
		t.Fatal("valid degree-one polynomial rejected")
	}
}

func TestPVSSZeroSecretAndZeroEvaluations(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c := chosenPVSS(t, f, []int64{0, 0, 0, 0})
	s := f.schemes["n0"]
	if !s.Verify(c) {
		t.Fatal("zero is a valid uniform scalar outcome")
	}
	var shares []PVSSDecryptedShare
	for _, id := range f.ids[:2] {
		sh, err := f.schemes[id].PreRecon(c, id)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, sh)
	}
	z, err := s.Recon(c, shares, 2)
	if err != nil || !bytes.Equal(z, mustPointBytes(suite().Point().Null())) {
		t.Fatalf("zero reconstruction failed: %v", err)
	}
}

func TestPVSSDecryptionProofAndReconstructionValidation(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, secret := f.sharing(t)
	s := f.schemes["n0"]
	sh0, err := s.PreRecon(c, "n0")
	if err != nil {
		t.Fatal(err)
	}
	sh1, err := f.schemes["n1"].PreRecon(c, "n1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*PVSSDecryptedShare)
	}{
		{"missing-proof", func(sh *PVSSDecryptedShare) { sh.Proof = PVSSDecryptionProof{} }},
		{"other-holder", func(sh *PVSSDecryptedShare) { sh.Holder = "n1" }},
		{"unknown-holder", func(sh *PVSSDecryptedShare) { sh.Holder = "other" }},
		{"other-object", func(sh *PVSSDecryptedShare) { sh.CommitmentID = strings.Repeat("0", 64) }},
		{"other-value", func(sh *PVSSDecryptedShare) { sh.Value = sh1.Value }},
		{"noncanonical-scalar", func(sh *PVSSDecryptedShare) { sh.Proof.R = hex.EncodeToString(pvssGroupOrder[:]) }},
		{"changed-response", func(sh *PVSSDecryptedShare) {
			z := scalarFromHex(sh.Proof.R)
			sh.Proof.R = scalarHex(suite().Scalar().Add(z, suite().Scalar().One()))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := sh0
			tc.change(&bad)
			if s.VerifyShare(c, bad) {
				t.Fatal("invalid decryption proof accepted")
			}
			if _, err := s.ReconTrusted(c, []PVSSDecryptedShare{bad, sh1}, 2); err == nil {
				t.Fatal("invalid share contributed to threshold")
			}
		})
	}
	relabelled := clonePVSS(t, c)
	relabelled.Seq++
	relabelled.SecretID = commitmentID(relabelled)
	replay := sh0
	replay.CommitmentID = relabelled.SecretID
	if s.VerifyShare(relabelled, replay) {
		t.Fatal("decryption proof survived object relabelling")
	}
	if _, err := s.Recon(c, []PVSSDecryptedShare{sh0, sh0}, 2); err == nil {
		t.Fatal("duplicate holders counted twice")
	}
	if _, err := s.Recon(c, []PVSSDecryptedShare{sh0, sh1}, 1); err == nil {
		t.Fatal("accepted a downgraded reconstruction threshold")
	}
	if _, err := s.ReconTrusted(c, []PVSSDecryptedShare{sh0, sh1}, -1); err == nil {
		t.Fatal("accepted a negative reconstruction threshold")
	}
	invalid := sh0
	invalid.Proof = PVSSDecryptionProof{}
	z, err := s.Recon(c, []PVSSDecryptedShare{invalid, sh0, sh1}, 2)
	if err != nil || !bytes.Equal(z, secret) {
		t.Fatal("invalid duplicate hid a later valid share")
	}
	if _, err := s.PreRecon(c, "n1"); err == nil {
		t.Fatal("decrypted for a different holder")
	}
}

func TestPVSSRejectsTorsionAndNoncanonicalEncodings(t *testing.T) {
	// The order-two Edwards point (0,-1), which is on the curve but not in G.
	torsionHex := "ec" + strings.Repeat("ff", 30) + "7f"
	torsion := suite().Point()
	raw, _ := hex.DecodeString(torsionHex)
	if err := torsion.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	mixed := suite().Point().Add(pvssGeneratorG, torsion)
	for _, raw := range []string{torsionHex, mustPointHex(mixed), mustPointHex(pvssGeneratorG) + "00", strings.ToUpper(mustPointHex(pvssGeneratorG))} {
		if _, err := pointFromHex(raw); err == nil {
			t.Fatal("non-subgroup or noncanonical point accepted")
		}
	}
	if scalarFromHex(hex.EncodeToString(pvssGroupOrder[:])) != nil {
		t.Fatal("scalar equal to subgroup order accepted")
	}
	if _, err := pointFromHex(mustPointHex(suite().Point().Null())); err != nil {
		t.Fatal("identity is valid for zero evaluations")
	}
	f := newPVSSFixture(t, 4, 2)
	c, _ := f.sharing(t)
	c.Commit["n1"] = mustPointHex(mixed)
	c.SecretID = commitmentID(c)
	if f.schemes["n0"].Verify(c) {
		t.Fatal("sharing accepted mixed-order point")
	}
}

func TestPVSSSetupAndMembershipValidation(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	for _, threshold := range []int{-1, 0, 5} {
		if _, err := NewPVSSScheme("n0", threshold, f.keys["n0"].Private, f.public); err == nil {
			t.Fatal("invalid threshold accepted")
		}
	}
	for _, id := range []p2p.NodeID{"", "other"} {
		if _, err := NewPVSSScheme(id, 2, f.keys["n0"].Private, f.public); err == nil {
			t.Fatal("invalid local identity accepted")
		}
	}
	for _, sk := range []kyber.Scalar{nil, suite().Scalar().Zero(), f.keys["n1"].Private} {
		if _, err := NewPVSSScheme("n0", 2, sk, f.public); err == nil {
			t.Fatal("invalid local key accepted")
		}
	}
	for _, pub := range []kyber.Point{nil, suite().Point().Null()} {
		keys := make(map[p2p.NodeID]kyber.Point, len(f.public))
		for id, p := range f.public {
			keys[id] = p
		}
		keys["n3"] = pub
		if _, err := NewPVSSScheme("n0", 2, f.keys["n0"].Private, keys); err == nil {
			t.Fatal("nil or identity public key accepted")
		}
	}
	s := f.schemes["n0"]
	for _, members := range [][]p2p.NodeID{f.ids[:3], {"n0", "n0", "n2", "n3"}, {"n0", "n1", "n2", "other"}} {
		if _, _, err := s.Share("n0", 1, members); err == nil {
			t.Fatal("incorrect membership accepted")
		}
	}
	reversed := []p2p.NodeID{"n3", "n2", "n1", "n0"}
	c, _, err := s.Share("n0", 1, reversed)
	if err != nil || !s.Verify(c) {
		t.Fatal("sharing did not canonicalize its membership input")
	}
	if _, _, err := s.Share("n1", 1, f.ids); err == nil {
		t.Fatal("dealt as a different identity")
	}
	if _, _, err := s.Share("n0", 0, f.ids); err == nil {
		t.Fatal("zero sequence accepted")
	}
}

func TestPVSSLegacyAggregationRejected(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	s := f.schemes["n0"]
	c, _ := f.sharing(t)
	if _, err := s.Aggregate("n0", 1, []PVSSCommitment{c}, f.ids); !errors.Is(err, ErrPVSSAggregationUnsupported) {
		t.Fatal("aggregation did not return explicit unsupported error")
	}
	if _, err := s.AggregateTrusted("n0", 1, []PVSSCommitment{c}, f.ids); !errors.Is(err, ErrPVSSAggregationUnsupported) {
		t.Fatal("trusted aggregation did not reject")
	}
	if s.VerifyAggregationColumn("n0", c, nil) {
		t.Fatal("legacy aggregation column accepted")
	}
}

func TestPVSSPublicCommitmentIsNotReconstructionValue(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, secret := f.sharing(t)
	var publicShares []*share.PubShare
	for i, id := range c.Members[:2] {
		p, err := pointFromHex(c.Commit[id])
		if err != nil {
			t.Fatal(err)
		}
		publicShares = append(publicShares, &share.PubShare{I: i, V: p})
	}
	gs, err := share.RecoverCommit(suite(), publicShares, 2, 4)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(mustPointBytes(gs), secret) {
		t.Fatal("public interpolation returned h^s")
	}
	// This is a regression check for accidentally identical generators, not a
	// test or proof of DDH secrecy or unknown discrete-log relations.
	if pvssGeneratorG.Equal(pvssGeneratorH) {
		t.Fatal("generators must differ")
	}
}

func TestPVSSConcurrentVerificationAndCacheIsolation(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, _ := f.sharing(t)
	s := f.schemes["n0"]
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !s.Verify(c) {
				t.Error("concurrent verification failed")
			}
			sh, err := s.PreReconTrusted(c, "n0")
			if err != nil || !s.VerifyShare(c, sh) {
				t.Error("concurrent decryption failed")
			}
		}()
	}
	wg.Wait()
	p, err := s.pointFromHex(c.Commit["n0"])
	if err != nil {
		t.Fatal(err)
	}
	p.Null()
	cached, err := s.pointFromHex(c.Commit["n0"])
	if err != nil || mustPointHex(cached) != c.Commit["n0"] {
		t.Fatal("caller mutated cached point")
	}
}

func TestPVSSShareCacheBindsCompleteProofAndObject(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, _ := f.sharing(t)
	sh, err := f.schemes["n1"].PreRecon(c, "n1")
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewPVSSVerifier(2, f.public)
	if err != nil || !v.VerifyShare(c, sh) {
		t.Fatal("failed to verify original share", err)
	}
	if len(v.verifiedShares) != 1 || !v.VerifyShare(c, sh) {
		t.Fatal("successful verification was not reusable")
	}
	for _, change := range []func(*PVSSDecryptedShare){
		func(x *PVSSDecryptedShare) { x.Holder = "n2" },
		func(x *PVSSDecryptedShare) { x.CommitmentID = strings.Repeat("0", 64) },
		func(x *PVSSDecryptedShare) { x.Value = mustPointHex(suite().Point().Null()) },
		func(x *PVSSDecryptedShare) {
			x.Proof.C = scalarHex(suite().Scalar().Add(scalarFromHex(x.Proof.C), suite().Scalar().One()))
		},
		func(x *PVSSDecryptedShare) { x.Proof.R = "00" },
	} {
		bad := sh
		change(&bad)
		if v.VerifyShare(c, bad) {
			t.Fatal("cache admitted a modified holder, value or proof")
		}
	}
	bad := clonePVSS(t, c)
	bad.Seq++
	bad.SecretID = commitmentID(bad)
	relabelled := sh
	relabelled.CommitmentID = bad.SecretID
	if v.VerifyShare(bad, relabelled) {
		t.Fatal("cache admitted a share under a different object position")
	}
	bad = clonePVSS(t, c)
	bad.Cipher["n1"] = bad.Cipher["n0"] // Leave SecretID unchanged to test header checking on cache hits.
	if v.VerifyShare(bad, sh) {
		t.Fatal("cache lookup bypassed complete transcript binding")
	}
	// Eviction may reduce performance but must fall back to full verification.
	key := shareVerificationKey(c, sh)
	for i := 0; i < pvssPointCacheLimit; i++ {
		cacheInsert(v.verifiedShares, &v.shareKeys, &v.shareNext, fmt.Sprintf("other-verified-share-%d", i), struct{}{})
	}
	if len(v.verifiedShares) != pvssPointCacheLimit {
		t.Fatal("share cache exceeded its bound")
	}
	if _, retained := v.verifiedShares[key]; retained {
		t.Fatal("old share permanently occupied the cache")
	}
	if !v.VerifyShare(c, sh) {
		t.Fatal("eviction prevented validation of an honest share")
	}
	if _, retained := v.verifiedShares[key]; !retained {
		t.Fatal("cache stopped admitting new verified shares after saturation")
	}
}

func TestPVSSKeyGeneration(t *testing.T) {
	a := PVSSKeyPairFromSeed([]byte("private deterministic test seed"))
	b := PVSSKeyPairFromSeed([]byte("private deterministic test seed"))
	if !a.Private.Equal(b.Private) || !a.Public.Equal(b.Public) {
		t.Fatal("seed derivation is not deterministic")
	}
	key, err := GeneratePVSSKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPVSSScheme("n0", 1, key.Private, map[p2p.NodeID]kyber.Point{"n0": key.Public}); err != nil {
		t.Fatal(err)
	}
}

func TestPVSSPublicOnlyVerifier(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	c, secret := f.sharing(t)
	v, err := NewPVSSVerifier(2, f.public)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verify(c) {
		t.Fatal("public-only verifier rejected valid sharing")
	}
	var shares []PVSSDecryptedShare
	for _, id := range f.ids[:2] {
		sh, err := f.schemes[id].PreRecon(c, id)
		if err != nil || !v.VerifyShare(c, sh) {
			t.Fatalf("public-only share verification failed: %v", err)
		}
		shares = append(shares, sh)
	}
	z, err := v.Recon(c, shares, 2)
	if err != nil || !bytes.Equal(z, secret) {
		t.Fatalf("public-only reconstruction failed: %v", err)
	}
	if _, _, err := v.Share("", 1, f.ids); err == nil {
		t.Fatal("public-only verifier dealt an object")
	}
	for _, holder := range []p2p.NodeID{"", "n0"} {
		if _, err := v.PreReconTrusted(c, holder); err == nil {
			t.Fatal("public-only verifier decrypted a share")
		}
	}
	f.public[p2p.NodeID(string([]byte{0xff}))] = f.keys["n0"].Public
	if _, err := NewPVSSVerifier(2, f.public); err == nil {
		t.Fatal("invalid UTF-8 identity accepted in canonical JSON context")
	}
}
