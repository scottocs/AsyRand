package verification

import (
	"Tyche/utils/cryptoexec"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetServiceNestedProofsAndCacheOwnership(t *testing.T) {
	if os.Getenv("TYCHE_TEST_CPU_GROUP") != "1" {
		t.Skip("isolated Linux budget fixture")
	}
	c := New()
	var checks atomic.Int32
	var wg sync.WaitGroup
	var failed atomic.Bool
	for k := 0; k < 8; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cryptoexec.WithCPUGroup(func() {
				if !cryptoexec.AllLabeled("pvss-verify", 31, func(i int) bool {
					return c.Check(Digest("nested-budget", []byte(fmt.Sprint(i))), func() bool { checks.Add(1); return true })
				}) {
					failed.Store(true)
				}
			})
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("nested proof/cache budget deadlock")
	}
	if failed.Load() || checks.Load() != 31 {
		t.Fatal("nested cache/proof jobs lost", checks.Load())
	}
	func() {
		defer func() {
			if recover() != "budget-panic" {
				t.Error("panic was not propagated to caller")
			}
		}()
		cryptoexec.WithCPUGroup(func() { panic("budget-panic") })
	}()
	var survived bool
	cryptoexec.WithCPUGroup(func() { survived = true })
	if !survived {
		t.Fatal("budget worker did not survive callback panic")
	}
}

func TestBudgetFastPrimitiveRunsBetweenProofEquations(t *testing.T) {
	if os.Getenv("TYCHE_TEST_CPU_GROUP") != "1" {
		t.Skip("isolated Linux budget fixture")
	}
	started, done := make(chan struct{}), make(chan struct{})
	var first sync.Once
	go func() {
		cryptoexec.WithCPUGroup(func() {
			cryptoexec.All(200, func(int) bool { first.Do(func() { close(started) }); time.Sleep(time.Millisecond); return true })
		})
		close(done)
	}()
	<-started
	cryptoexec.WithCPUGroupFast(func() {})
	select {
	case <-done:
		t.Fatal("short primitive waited for the complete long proof")
	default:
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("proof did not resume after the short primitive")
	}
}

func TestParallelProofPartitionsRejectInvalidInput(t *testing.T) {
	var calls atomic.Int32
	if !cryptoexec.All(31, func(int) bool { calls.Add(1); return true }) || calls.Load() != 31 {
		t.Fatal("proof equations omitted or repeated")
	}
	for _, invalid := range []int{0, 1, 15, 30} {
		if cryptoexec.All(31, func(i int) bool { return i != invalid }) {
			t.Fatal("invalid parallel equation accepted", invalid)
		}
	}
}

// This test is run separately inside the controller's dedicated Linux cgroup.
// It exercises actual TID migration, nesting, quota throttling and restoration.
func TestCPUGroupLinuxIntegration(t *testing.T) {
	if os.Getenv("TYCHE_TEST_CPU_GROUP") != "1" {
		t.Skip("requires the isolated Linux controller fixture")
	}
	var cfg cryptoexec.CPUGroup
	raw, err := os.ReadFile(os.Getenv("TYCHE_CRYPTO_CGROUP_CONFIG"))
	if err != nil || json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("missing group config", err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid, _ := os.Readlink("/proc/thread-self")
	tid = tid[strings.LastIndex(tid, "/")+1:]
	contains := func(path string) bool {
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		return strings.Contains("\n"+string(b), "\n"+tid+"\n")
	}
	release := cryptoexec.EnterCPUGroup()
	nested := cryptoexec.EnterCPUGroup()
	if !contains(cfg.Threads) {
		t.Fatal("thread not in crypto child")
	}
	nested()
	if !contains(cfg.Threads) {
		t.Fatal("nested release moved outer work")
	}
	release()
	if !contains(cfg.ParentThreads) {
		t.Fatal("thread not restored to parent")
	}
	before := cryptoexec.CPUGroupStats()
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cryptoexec.WithCPUGroup(func() {
				for time.Since(start) < 2*time.Second {
					for j := 0; j < 10000; j++ {
						atomic.AddUint64(new(uint64), 1)
					}
				}
			})
		}()
	}
	wg.Wait()
	after := cryptoexec.CPUGroupStats()
	elapsed := time.Since(start).Seconds()
	used := float64(after["usage_usec"]-before["usage_usec"]) / 1e6
	if used < 2 || used > elapsed*1.8+0.15 || after["nr_throttled"] <= before["nr_throttled"] {
		t.Fatalf("CPU cap not enforced: cpu=%.3f elapsed=%.3f before=%v after=%v", used, elapsed, before, after)
	}
	if after["threads"] > uint64(cfg.Workers) && cfg.Workers > 0 {
		t.Fatal("unregistered threads inherited the crypto cgroup", after)
	}
	t.Logf("crypto CPU=%.3fs elapsed=%.3fs cores=%.3f throttled=%d", used, elapsed, used/elapsed, after["nr_throttled"]-before["nr_throttled"])
}

func BenchmarkBudgetDispatch(b *testing.B) {
	if os.Getenv("TYCHE_TEST_CPU_GROUP") != "1" {
		b.Skip("isolated Linux cgroup fixture")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	message := make([]byte, 256)
	sig := ed25519.Sign(priv, message)
	for _, mode := range []string{"per-call-move", "resident-pool"} {
		b.Run(mode, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if mode == "per-call-move" {
						release := cryptoexec.EnterCPUGroup()
						_ = ed25519.Verify(pub, message, sig)
						release()
					} else {
						cryptoexec.WithCPUGroup(func() { _ = ed25519.Verify(pub, message, sig) })
					}
				}
			})
		})
	}
}

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
