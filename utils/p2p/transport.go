package p2p

import (
	"Tyche/utils/cryptoexec"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"
)

type Metrics struct {
	SentMessages uint64
	SentBytes    uint64
	RecvMessages uint64
	RecvBytes    uint64
}

type MessageTypeMetrics struct {
	SentMessages uint64
	SentBytes    uint64
	RecvMessages uint64
	RecvBytes    uint64
}

type Transport interface {
	ID() NodeID
	Inbox() <-chan Message
	Start(context.Context) error
	Send(context.Context, NodeID, Message) error
	Broadcast(context.Context, Message) error
	Metrics() Metrics
	Close() error
}

// AuthenticatedDelivery is an explicit capability, not a deployment setting.
// Unauthenticated transports continue to require application signatures.
func AuthenticatedDelivery(t Transport) bool {
	x, ok := t.(interface{ AuthenticatedDelivery() bool })
	return ok && x.AuthenticatedDelivery()
}

var benchmarkEnabled = os.Getenv("TYCHE_BENCHMARK") == "1"
var benchmarkProfiled = benchmarkEnabled && os.Getenv("TYCHE_PROFILE_NODE") != "" && os.Getenv("TYCHE_PROFILE_NODE") == os.Getenv("TYCHE_BENCHMARK_NODE")

// BenchmarkTask labels only executed work, including its child calls. CPU
// profiling remains off unless the common benchmark probe enables it.
func BenchmarkTask(name string, work func()) {
	original := work
	work = func() {
		if !benchmarkProfiled {
			original()
			return
		}
		pprof.Do(context.Background(), pprof.Labels("task", name), func(context.Context) { original() })
	}
	// ABA/RBC labels cover routing and state work; their actual signature
	// checks enter the CPU group through the verification cache separately.
	if name != "aba-handle" && name != "rbc-handle" {
		original := work
		work = func() { cryptoexec.WithCPUGroup(original) }
	}
	work()
}

// BenchmarkProbe gives every protocol the same output-aligned CPU/traffic
// checkpoints. It is opt-in and intended for single-node Linux containers.
type BenchmarkProbe struct {
	node          string
	dir           string
	total, last   uint64
	file, profile *os.File
	transport     interface {
		NetworkMessageTypeMetrics() map[string]MessageTypeMetrics
	}
}

func OpenBenchmark(node string, transport Transport, total uint64) (*BenchmarkProbe, error) {
	if !benchmarkEnabled {
		return nil, nil
	}
	network, ok := transport.(interface {
		NetworkMessageTypeMetrics() map[string]MessageTypeMetrics
	})
	if !ok || total < 2 {
		return nil, fmt.Errorf("benchmark requires TCP transport and at least two outputs")
	}
	dir := os.Getenv("TYCHE_BENCHMARK_DIR")
	if dir == "" {
		dir = "/results"
	}
	file, err := os.OpenFile(filepath.Join(dir, "measurement.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &BenchmarkProbe{node: node, dir: dir, total: total, file: file, transport: network}, nil
}

func (p *BenchmarkProbe) Output(count uint64, extra func() any) error {
	if p == nil {
		return nil
	}
	if count != 1 && count != p.total && count%100 != 0 {
		return nil
	}
	if count <= p.last || count > p.total || (p.last == 0 && count != 1) {
		return fmt.Errorf("nonmonotonic benchmark checkpoint")
	}
	raw, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return err
	}
	var cpu uint64
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "usage_usec" {
			cpu, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				return err
			}
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("missing cgroup CPU counter")
	}
	at := time.Now().UTC()
	types := p.transport.NetworkMessageTypeMetrics()
	var traffic Metrics
	for _, m := range types {
		traffic.SentMessages += m.SentMessages
		traffic.SentBytes += m.SentBytes
		traffic.RecvMessages += m.RecvMessages
		traffic.RecvBytes += m.RecvBytes
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	current, err := os.ReadFile("/sys/fs/cgroup/memory.current")
	if err != nil {
		return err
	}
	peak, err := os.ReadFile("/sys/fs/cgroup/memory.peak")
	if err != nil {
		return err
	}
	stage := "checkpoint"
	if count == 1 {
		stage = "first_output"
	} else if count == p.total {
		stage = "generation_complete"
	}
	err = json.NewEncoder(p.file).Encode(map[string]any{"stage": stage, "node": p.node, "time": at.Format(time.RFC3339Nano), "outputs": count,
		"crypto_cpu":       cryptoexec.CPUGroupStats(),
		"crypto_scheduler": cryptoexec.BudgetStats(),
		"cpu_usage_usec":   cpu, "traffic": traffic, "message_types": types, "memory_current": strings.TrimSpace(string(current)), "memory_peak": strings.TrimSpace(string(peak)),
		"heap_alloc": memory.HeapAlloc, "total_alloc": memory.TotalAlloc, "num_gc": memory.NumGC, "pause_total_ns": memory.PauseTotalNs, "extra": extra()})
	if err != nil {
		return err
	}
	p.last = count
	if count == 1 && os.Getenv("TYCHE_PROFILE_NODE") == p.node {
		p.profile, err = os.Create(filepath.Join(p.dir, "generation.cpu.pprof"))
		if err != nil {
			return err
		}
		if err = pprof.StartCPUProfile(p.profile); err != nil {
			p.profile.Close()
			p.profile = nil
			return err
		}
	}
	return nil
}

// Finish stops sampling before waiting for the all-node generation barrier.
// Nodes continue helping peers until that barrier; offline verification begins
// only after the caller stops protocol work when Finish returns.
func (p *BenchmarkProbe) Finish(ctx context.Context) error {
	if p == nil {
		return nil
	}
	if p.last != p.total {
		return fmt.Errorf("benchmark finished without requested outputs")
	}
	p.stopProfile()
	if err := os.WriteFile(filepath.Join(p.dir, "generation-complete"), []byte("complete\n"), 0600); err != nil {
		return err
	}
	barrier := os.Getenv("TYCHE_VERIFY_BARRIER")
	if barrier == "" {
		return fmt.Errorf("benchmark verification barrier is required")
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(barrier); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Complete is published only after the command has finished its independent
// verification and durable output. It lets the controller avoid repeatedly
// retrieving growing Docker logs just to discover successful completion.
func (p *BenchmarkProbe) Complete() error {
	if p == nil {
		return nil
	}
	if p.last != p.total {
		return fmt.Errorf("benchmark completion before final output")
	}
	return os.WriteFile(filepath.Join(p.dir, "benchmark-complete"), []byte("complete\n"), 0600)
}

func (p *BenchmarkProbe) stopProfile() {
	if p != nil && p.profile != nil {
		pprof.StopCPUProfile()
		p.profile.Close()
		p.profile = nil
	}
}

func (p *BenchmarkProbe) Close() {
	if p == nil {
		return
	}
	p.stopProfile()
	p.file.Close()
}
