package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"Tyche/utils/p2p"
	"go.dedis.ch/kyber/v3"
)

func newALBATROSSFixture(t *testing.T, n, threshold int) pvssFixture {
	t.Helper()
	f := pvssFixture{keys: make(map[p2p.NodeID]PVSSKeyPair), public: make(map[p2p.NodeID]kyber.Point), schemes: make(map[p2p.NodeID]*PVSSPairingFreeScheme)}
	for i := 0; i < n; i++ {
		id := p2p.NodeID(fmt.Sprintf("n%d", i))
		f.ids = append(f.ids, id)
		f.keys[id] = PVSSKeyPairFromSeed([]byte("test-only private seed/" + string(id)))
		f.public[id] = f.keys[id].Public
	}
	for _, id := range f.ids {
		s, err := NewALBATROSSPVSSScheme(id, threshold, f.keys[id].Private, f.public)
		if err != nil {
			t.Fatal(err)
		}
		f.schemes[id] = s
	}
	return f
}

func TestALBATROSSRoundTrip(t *testing.T) {
	for _, param := range [][2]int{{1, 1}, {4, 1}, {4, 2}, {7, 3}, {4, 4}, {40, 14}} {
		t.Run(fmt.Sprintf("n=%d/t=%d", param[0], param[1]), func(t *testing.T) {
			f := newALBATROSSFixture(t, param[0], param[1])
			c, secret := f.sharing(t)
			if c.Version != albatrossPVSSVersion || len(c.Proof.Coefficients) != param[1] || len(c.Proof.Responses) != 0 {
				t.Fatal("wrong ALBATROSS proof representation")
			}
			encoded, err := json.Marshal(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &c); err != nil {
				t.Fatal(err)
			}
			v, err := NewALBATROSSPVSSVerifier(param[1], f.public)
			if err != nil || !v.Verify(c) {
				t.Fatal("public sharing verification failed", err)
			}
			var shares []PVSSDecryptedShare
			for _, id := range f.ids {
				sh, err := f.schemes[id].PreRecon(c, id)
				if err != nil || !v.VerifyShare(c, sh) {
					t.Fatal("decryption verification failed", err)
				}
				shares = append(shares, sh)
			}
			for _, subset := range [][]PVSSDecryptedShare{shares[:param[1]], shares[len(shares)-param[1]:], shares} {
				z, err := v.Recon(c, subset, param[1])
				if err != nil || !bytes.Equal(z, secret) {
					t.Fatalf("threshold subset did not reconstruct the original group value: %v", err)
				}
			}
			if _, err := v.ReconTrusted(c, shares[:param[1]-1], 0); err == nil {
				t.Fatal("reconstructed below threshold")
			}
			if _, _, err := v.Share(f.ids[0], 2, f.ids); err == nil {
				t.Fatal("public verifier created a sharing")
			}
			if _, err := v.PreReconTrusted(c, f.ids[0]); err == nil {
				t.Fatal("public verifier decrypted a share")
			}
		})
	}
}

func TestALBATROSSRejectsTampering(t *testing.T) {
	f := newALBATROSSFixture(t, 4, 2)
	c, _ := f.sharing(t)
	v, _ := NewALBATROSSPVSSVerifier(2, f.public)
	cases := []struct {
		name string
		edit func(*PVSSCommitment)
	}{
		{"sequence", func(c *PVSSCommitment) { c.Seq++ }},
		{"zero-sequence", func(c *PVSSCommitment) { c.Seq = 0 }},
		{"dealer", func(c *PVSSCommitment) { c.Dealer = "n1" }},
		{"setup", func(c *PVSSCommitment) { c.SetupID = strings.Repeat("0", 64) }},
		{"threshold", func(c *PVSSCommitment) { c.Threshold = 1 }},
		{"member-order", func(c *PVSSCommitment) { c.Members[0], c.Members[1] = c.Members[1], c.Members[0] }},
		{"member-duplicate", func(c *PVSSCommitment) { c.Members[1] = c.Members[0] }},
		{"missing-coefficient", func(c *PVSSCommitment) { c.Proof.Coefficients = c.Proof.Coefficients[:1] }},
		{"extra-zero-coefficient", func(c *PVSSCommitment) {
			c.Proof.Coefficients = append(c.Proof.Coefficients, scalarHex(suite().Scalar().Zero()))
		}},
		{"coefficient", func(c *PVSSCommitment) {
			c.Proof.Coefficients[0] = scalarHex(suite().Scalar().Add(scalarFromHex(c.Proof.Coefficients[0]), suite().Scalar().One()))
		}},
		{"noncanonical-coefficient", func(c *PVSSCommitment) { c.Proof.Coefficients[0] = hex.EncodeToString(pvssGroupOrder[:]) }},
		{"noncanonical-challenge", func(c *PVSSCommitment) { c.Proof.Challenge = hex.EncodeToString(pvssGroupOrder[:]) }},
		{"legacy-responses", func(c *PVSSCommitment) { c.Proof.Responses = map[p2p.NodeID]string{"n0": c.Proof.Challenge} }},
		{"missing-cipher", func(c *PVSSCommitment) { delete(c.Cipher, "n0") }},
		{"extra-cipher", func(c *PVSSCommitment) { c.Cipher["other"] = c.Cipher["n0"] }},
		{"cipher", func(c *PVSSCommitment) { c.Cipher["n1"] = c.Cipher["n0"] }},
		{"nonce-commitment", func(c *PVSSCommitment) { c.Commit["n1"] = c.Commit["n0"] }},
		{"missing-commitment", func(c *PVSSCommitment) { delete(c.Commit, "n0") }},
		{"malformed-point", func(c *PVSSCommitment) { c.Commit["n0"] = "not a curve point" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := clonePVSS(t, c)
			tc.edit(&bad)
			bad.SecretID = commitmentID(bad)
			if v.Verify(bad) {
				t.Fatal("modified transcript accepted with recomputed object ID")
			}
			if _, err := f.schemes["n0"].PreRecon(bad, "n0"); err == nil {
				t.Fatal("decrypted an invalid sharing")
			}
		})
	}
}

func TestALBATROSSDegreeBound(t *testing.T) {
	f := newALBATROSSFixture(t, 4, 2)
	s := f.schemes["n0"]
	c, _ := f.sharing(t)
	// Construct a genuine accepting Sigma equation for a degree-two witness.
	// It must be rejected by the declared degree-one bound, not accepted merely
	// because all per-holder exponent equations are well formed.
	group := suite()
	witness := []kyber.Scalar{group.Scalar().SetInt64(3), group.Scalar().SetInt64(5), group.Scalar().One()}
	nonces := []kyber.Scalar{group.Scalar().SetInt64(7), group.Scalar().SetInt64(11), group.Scalar().SetInt64(13)}
	for i, id := range s.members {
		c.Cipher[id] = mustPointHex(group.Point().Mul(evaluatePVSSPolynomial(witness, i+1), s.public[id]))
		c.Commit[id] = mustPointHex(group.Point().Mul(evaluatePVSSPolynomial(nonces, i+1), s.public[id]))
	}
	e := albatrossSharingChallenge(c)
	c.Proof = PVSSProof{Challenge: scalarHex(e), Coefficients: make([]string, 3)}
	for i := range witness {
		c.Proof.Coefficients[i] = scalarHex(group.Scalar().Add(nonces[i], group.Scalar().Mul(e, witness[i])))
	}
	c.SecretID = commitmentID(c)
	if s.Verify(c) {
		t.Fatal("valid higher-degree Sigma proof bypassed the threshold")
	}
}

func TestALBATROSSZeroSecretAndSubgroupValidation(t *testing.T) {
	f := newALBATROSSFixture(t, 4, 2)
	s := f.schemes["n0"]
	c, _ := f.sharing(t)
	zero := suite().Scalar().Zero()
	for _, id := range s.members {
		c.Cipher[id] = mustPointHex(suite().Point().Null())
	}
	s.proveALBATROSSSharing(&c, []kyber.Scalar{zero, zero})
	c.SecretID = commitmentID(c)
	v, _ := NewALBATROSSPVSSVerifier(2, f.public)
	if !v.Verify(c) {
		t.Fatal("zero secret/evaluations were rejected")
	}
	var shares []PVSSDecryptedShare
	for _, id := range f.ids[:2] {
		sh, err := f.schemes[id].PreRecon(c, id)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, sh)
	}
	z, err := v.Recon(c, shares, 2)
	if err != nil || !bytes.Equal(z, mustPointBytes(suite().Point().Null())) {
		t.Fatal("zero secret did not reconstruct", err)
	}
	c.Commit["n0"] = "ec" + strings.Repeat("ff", 30) + "7f" // order-two point
	c.Proof.Challenge = scalarHex(albatrossSharingChallenge(c))
	c.SecretID = commitmentID(c)
	if v.Verify(c) {
		t.Fatal("non-subgroup commitment was accepted")
	}
}

func TestALBATROSSProtocolAndSetupIsolation(t *testing.T) {
	f := newALBATROSSFixture(t, 4, 2)
	a, _ := f.sharing(t)
	scrape, err := NewPVSSScheme("n0", 2, f.keys["n0"].Private, f.public)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := scrape.Share("n0", 1, f.ids)
	if err != nil || scrape.Verify(a) || f.schemes["n0"].Verify(c) || a.SetupID == c.SetupID {
		t.Fatal("schemes did not isolate their proofs and setup domains", err)
	}
	// A SCRAPE verifier must reject coefficient fields rather than ignore them.
	c.Proof.Coefficients = append([]string(nil), a.Proof.Coefficients...)
	c.SecretID = commitmentID(c)
	if scrape.Verify(c) {
		t.Fatal("SCRAPE accepted an ALBATROSS proof field")
	}
	keys := make(map[p2p.NodeID]kyber.Point)
	for id, key := range f.public {
		keys[id] = key
	}
	keys["n3"] = PVSSKeyPairFromSeed([]byte("another test key")).Public
	v, _ := NewALBATROSSPVSSVerifier(2, keys)
	if v.Verify(a) {
		t.Fatal("proof survived a shareholder-key change")
	}
	a.SetupID = v.SetupID()
	a.SecretID = commitmentID(a)
	if v.Verify(a) {
		t.Fatal("changing the setup ID repaired an old proof")
	}
	if _, err := NewALBATROSSPVSSScheme("n0", 2, f.keys["n1"].Private, f.public); err == nil {
		t.Fatal("mismatched local key accepted")
	}
}

func TestALBATROSSShareValidationAndConcurrency(t *testing.T) {
	f := newALBATROSSFixture(t, 4, 2)
	c, secret := f.sharing(t)
	v, _ := NewALBATROSSPVSSVerifier(2, f.public)
	sh0, _ := f.schemes["n0"].PreRecon(c, "n0")
	sh1, _ := f.schemes["n1"].PreRecon(c, "n1")
	if sh0.Proof.C != "" || len(sh0.Proof.A) != 64 || len(sh0.Proof.B) != 64 || len(sh0.Proof.R) != 64 {
		t.Fatal("decryption share does not use the paper's (d,a,b,z) encoding")
	}
	if !v.VerifyShare(c, sh0) {
		t.Fatal("valid share rejected")
	}
	for _, edit := range []func(*PVSSDecryptedShare){
		func(s *PVSSDecryptedShare) { s.Proof.A = "" },
		func(s *PVSSDecryptedShare) { s.Proof.B = "" },
		func(s *PVSSDecryptedShare) { s.Proof.C = scalarHex(suite().Scalar().Zero()) },
		func(s *PVSSDecryptedShare) { s.Proof.A = mustPointHex(suite().Point().Null()) },
		func(s *PVSSDecryptedShare) { s.Proof.B = mustPointHex(suite().Point().Null()) },
		func(s *PVSSDecryptedShare) { s.Proof.A = "ec" + strings.Repeat("ff", 30) + "7f" },
	} {
		modified := sh0
		edit(&modified)
		if v.VerifyShare(c, modified) {
			t.Fatal("malformed expanded decryption proof passed, including after cache priming")
		}
	}
	bad := sh0
	bad.Proof.R = scalarHex(suite().Scalar().Add(scalarFromHex(bad.Proof.R), suite().Scalar().One()))
	if v.VerifyShare(c, bad) {
		t.Fatal("cached verification admitted a modified proof")
	}
	if _, err := v.ReconTrusted(c, []PVSSDecryptedShare{sh0, sh0}, 2); err == nil {
		t.Fatal("duplicate holders counted toward threshold")
	}
	z, err := v.ReconTrusted(c, []PVSSDecryptedShare{bad, sh1, sh0}, 2)
	if err != nil || !bytes.Equal(z, secret) {
		t.Fatal("an invalid share hid a later valid share", err)
	}
	other := clonePVSS(t, c)
	other.Seq++
	other.SecretID = commitmentID(other)
	replay := sh0
	replay.CommitmentID = other.SecretID
	if v.VerifyShare(other, replay) {
		t.Fatal("share survived relabelling to another object")
	}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !v.Verify(c) || !v.VerifyShare(c, sh0) {
				t.Error("concurrent verification failed")
			}
		}()
	}
	wg.Wait()
}
