package verification

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentSuccessRunsOnceAndOwnersAreIsolated(t *testing.T) {
	c := New()
	key := Digest("proof", []byte("full public statement"))
	var calls atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if !c.Check(key, func() bool { calls.Add(1); return true }) {
				t.Error("success lost")
			}
		}()
	}
	close(start)
	wg.Wait()
	if calls.Load() != 1 || c.Stats().Executions != 1 {
		t.Fatal("concurrent duplicate work", calls.Load(), c.Stats())
	}
	if !New().Check(key, func() bool { calls.Add(1); return true }) || calls.Load() != 2 {
		t.Fatal("results leaked to another owner")
	}
}

func TestEd25519MemoBindsKeyStatementAndSignature(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("decision/context/instance/value")
	sig := ed25519.Sign(private, message)
	c := New()
	for i := 0; i < 10; i++ {
		valid, executed := c.Ed25519Once(pub, message, sig)
		if !valid || executed != (i == 0) {
			t.Fatal("signature was verified again or rejected", i, valid, executed)
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	bad := append([]byte(nil), sig...)
	bad[0] ^= 1
	if c.Ed25519(other, message, sig) || c.Ed25519(pub, []byte("different instance"), sig) || c.Ed25519(pub, message, bad) {
		t.Fatal("cached success accepted altered verification input")
	}
	key := Digest("invalid-proof")
	for i := 0; i < 2; i++ {
		if c.Check(key, func() bool { return false }) {
			t.Fatal("invalid proof accepted")
		}
	}
	if c.Stats().Entries != 1 {
		t.Fatal("failed checks persisted", c.Stats())
	}
}
