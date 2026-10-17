package crypto

import (
	"Tyche/utils/verification"
	"testing"
)

func TestRuntimeAndHistoryPVSSReuseCompleteChecks(t *testing.T) {
	f := newPVSSFixture(t, 4, 2)
	cache := verification.New()
	runtime, err := NewALBATROSSPVSSScheme("n0", 2, f.keys["n0"].Private, f.public, cache)
	if err != nil {
		t.Fatal(err)
	}
	history, err := NewALBATROSSPVSSVerifier(2, f.public, cache)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := runtime.Share("n0", 1, f.ids)
	if err != nil || !runtime.Verify(c) {
		t.Fatal("honest sharing rejected", err)
	}
	before := cache.Stats().Executions
	if !history.Verify(c) || !runtime.Verify(c) || cache.Stats().Executions != before {
		t.Fatal("sharing reverified across node paths")
	}
	holder, err := NewALBATROSSPVSSScheme("n1", 2, f.keys["n1"].Private, f.public)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := holder.PreRecon(c, "n1")
	if err != nil || !runtime.VerifyShare(c, sh) {
		t.Fatal("honest share rejected", err)
	}
	before = cache.Stats().Executions
	if !history.VerifyShare(c, sh) || cache.Stats().Executions != before {
		t.Fatal("share reverified in history path")
	}
	bad := clonePVSS(t, c)
	bad.Cipher["n1"] = bad.Cipher["n0"]
	if runtime.Verify(bad) || history.VerifyShare(bad, sh) {
		t.Fatal("cached result accepted mutated transcript")
	}
	sh.Proof.R = "00"
	if runtime.VerifyShare(c, sh) {
		t.Fatal("cached result accepted mutated share proof")
	}
}
