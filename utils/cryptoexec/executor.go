package cryptoexec

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CPUGroup is an optional Linux threaded-cgroup boundary. The controller creates
// this child inside the node's Docker cgroup: RAM and the total node CPU quota
// therefore still apply. Protocol work never changes the configured quotas.
type CPUGroup struct {
	Threads       string `json:"threads"`
	ParentThreads string `json:"parent_threads"`
	Stat          string `json:"stat"`
	Max           string `json:"max"`
	Workers       int    `json:"workers,omitempty"`
}

var cpuGroup = struct {
	sync.Once
	group *CPUGroup
}{}

var cpuThreads = struct {
	sync.Mutex
	depth map[string]int
}{depth: make(map[string]int)}

func configuredCPUGroup() *CPUGroup {
	cpuGroup.Do(func() {
		path := os.Getenv("TYCHE_CRYPTO_CGROUP_CONFIG")
		if path == "" {
			return
		}
		if runtime.GOOS != "linux" {
			panic("crypto CPU cgroups require Linux")
		}
		raw, err := os.ReadFile(path)
		var group CPUGroup
		if err != nil || json.Unmarshal(raw, &group) != nil {
			panic(fmt.Sprintf("invalid crypto CPU group configuration: %v", err))
		}
		dir := filepath.Dir(group.Threads)
		parent := filepath.Dir(dir)
		if !filepath.IsAbs(dir) || filepath.Base(dir) != "crypto" ||
			group.Threads != filepath.Join(dir, "cgroup.threads") || group.ParentThreads != filepath.Join(parent, "cgroup.threads") ||
			group.Stat != filepath.Join(dir, "cpu.stat") || group.Max != filepath.Join(dir, "cpu.max") {
			panic("crypto CPU group paths must describe one child and its parent")
		}
		cpuGroup.group = &group
		if group.Workers == 0 {
			group.Workers = 2
		}
		if group.Workers < 1 || group.Workers > 16 {
			panic("invalid crypto CPU worker count")
		}
	})
	return cpuGroup.group
}

// EnterCPUGroup pins the current goroutine to its OS thread until release.
// Workers call it once for their lifetime; inline protocol cryptography uses
// WithCPUGroup. Nesting stays on the same thread and restores its prior group.
// Without an explicitly configured group this is a no-op on every platform.
func EnterCPUGroup() func() {
	group := configuredCPUGroup()
	if group == nil {
		return func() {}
	}
	runtime.LockOSThread()
	link, err := os.Readlink("/proc/thread-self")
	if err != nil {
		runtime.UnlockOSThread()
		panic(err)
	}
	tid := filepath.Base(link)
	if _, err := strconv.Atoi(tid); err != nil {
		runtime.UnlockOSThread()
		panic("invalid Linux thread identity")
	}
	cpuThreads.Lock()
	if cpuThreads.depth[tid] == 0 {
		if err := os.WriteFile(group.Threads, []byte(tid), 0); err != nil {
			cpuThreads.Unlock()
			runtime.UnlockOSThread()
			panic(fmt.Sprintf("attach crypto CPU thread: %v", err))
		}
	}
	cpuThreads.depth[tid]++
	cpuThreads.Unlock()
	return func() {
		cpuThreads.Lock()
		cpuThreads.depth[tid]--
		if cpuThreads.depth[tid] == 0 {
			delete(cpuThreads.depth, tid)
			if err := os.WriteFile(group.ParentThreads, []byte(tid), 0); err != nil {
				cpuThreads.Unlock()
				panic(fmt.Sprintf("restore protocol CPU thread: %v", err))
			}
		}
		cpuThreads.Unlock()
		runtime.UnlockOSThread()
	}
}

func WithCPUGroup(work func()) {
	withCPUGroup(work, false)
}

// Only short, independent primitives may use this queue. A proof partition
// can service one between equations without re-entering protocol callbacks.
func WithCPUGroupFast(work func()) { withCPUGroup(work, true) }

func withCPUGroup(work func(), fast bool) {
	if configuredCPUGroup() == nil {
		work()
		return
	}
	// Only permanent service workers enter the cgroup. Callers keep their
	// scheduler threads outside it, so a throttled crypto M does not carry an
	// actor/network goroutine (or its Go execution slot) into the child group.
	runtime.LockOSThread()
	link, err := os.Readlink("/proc/thread-self")
	if err != nil {
		runtime.UnlockOSThread()
		panic(err)
	}
	tid := filepath.Base(link)
	cpuThreads.Lock()
	inside := cpuThreads.depth[tid] > 0
	cpuThreads.Unlock()
	if inside {
		defer runtime.UnlockOSThread()
		work()
		return
	}
	runtime.UnlockOSThread()
	p := budgetService()
	job := &budgetJob{fn: work, done: make(chan struct{}), queued: time.Now()}
	if fast {
		p.submitFast(job)
	} else {
		p.submit(job, false)
	}
	<-job.done
	if job.failure != nil {
		panic(job.failure)
	}
}

type budgetJob struct {
	fn      func()
	done    chan struct{}
	failure any
	queued  time.Time
}
type budgetPool struct {
	mu                         sync.Mutex
	normal                     []*budgetJob
	fast                       []*budgetJob
	proofs                     []*budgetJob
	wake                       chan struct{}
	workers                    int
	active                     atomic.Int64
	completed, helpers, waitNS atomic.Uint64
}

var profileBudgetTasks = os.Getenv("TYCHE_PROFILE_NODE") != "" && os.Getenv("TYCHE_PROFILE_NODE") == os.Getenv("TYCHE_BENCHMARK_NODE")

func budgetLabel(label string, fn func()) {
	if !profileBudgetTasks {
		fn()
		return
	}
	pprof.Do(context.Background(), pprof.Labels("task", label), func(context.Context) { fn() })
}

var budgetState struct {
	sync.Once
	pool *budgetPool
}

func budgetService() *budgetPool {
	budgetState.Do(func() {
		p := &budgetPool{wake: make(chan struct{}), workers: configuredCPUGroup().Workers}
		budgetState.pool = p
		for i := 0; i < p.workers; i++ {
			go func() {
				release := EnterCPUGroup()
				defer release()
				for {
					job, wake := p.take(false)
					if job == nil {
						<-wake
						continue
					}
					p.execute(job)
				}
			}()
		}
	})
	return budgetState.pool
}
func (p *budgetPool) submit(job *budgetJob, proof bool) {
	p.mu.Lock()
	if proof {
		p.proofs = append(p.proofs, job)
		p.helpers.Add(1)
	} else {
		p.normal = append(p.normal, job)
	}
	close(p.wake)
	p.wake = make(chan struct{})
	p.mu.Unlock()
}
func (p *budgetPool) submitFast(job *budgetJob) {
	original := job.fn
	job.fn = func() { budgetLabel("native-signature", original) }
	p.mu.Lock()
	p.fast = append(p.fast, job)
	close(p.wake)
	p.wake = make(chan struct{})
	p.mu.Unlock()
}
func (p *budgetPool) takeFast() *budgetJob {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.fast) == 0 {
		return nil
	}
	job := p.fast[0]
	p.fast[0] = nil
	p.fast = p.fast[1:]
	return job
}
func (p *budgetPool) take(proofsOnly bool) (*budgetJob, <-chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var queue *[]*budgetJob
	if len(p.fast) > 0 {
		queue = &p.fast
	} else if len(p.proofs) > 0 {
		queue = &p.proofs
	} else if !proofsOnly && len(p.normal) > 0 {
		queue = &p.normal
	}
	if queue == nil {
		return nil, p.wake
	}
	job := (*queue)[0]
	(*queue)[0] = nil
	*queue = (*queue)[1:]
	return job, p.wake
}
func (p *budgetPool) execute(job *budgetJob) {
	p.active.Add(1)
	p.waitNS.Add(uint64(time.Since(job.queued)))
	defer func() { job.failure = recover(); p.active.Add(-1); p.completed.Add(1); close(job.done) }()
	job.fn()
}

// While waiting for a fork/join proof, execute only independent proof jobs.
// Never re-enter arbitrary protocol callbacks: those can own actor/state locks.
func (p *budgetPool) join(done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
		}
		job, wake := p.take(true)
		if job != nil {
			p.execute(job)
			continue
		}
		select {
		case <-done:
			return
		case <-wake:
		}
	}
}
func BudgetStats() map[string]uint64 {
	if configuredCPUGroup() == nil {
		return nil
	}
	p := budgetService()
	p.mu.Lock()
	queued, proofs, fast := len(p.normal), len(p.proofs), len(p.fast)
	p.mu.Unlock()
	return map[string]uint64{"workers": uint64(p.workers), "active_frames": uint64(p.active.Load()),
		"queued": uint64(queued), "proof_queued": uint64(proofs), "fast_queued": uint64(fast), "completed": p.completed.Load(), "helper_jobs": p.helpers.Load(), "queue_wait_ns": p.waitNS.Load()}
}

// CPUGroupStats counts actual scheduled CPU, including runtime work performed
// on these threads. It is not a sum of overlapping cryptographic wall timers.
func CPUGroupStats() map[string]uint64 {
	group := configuredCPUGroup()
	if group == nil {
		return nil
	}
	raw, err := os.ReadFile(group.Stat)
	if err != nil {
		panic(err)
	}
	stats := make(map[string]uint64)
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			value, err := strconv.ParseUint(parts[1], 10, 64)
			if err == nil {
				stats[parts[0]] = value
			}
		}
	}
	threads, err := os.ReadFile(group.Threads)
	if err != nil {
		panic(err)
	}
	stats["threads"] = uint64(len(strings.Fields(string(threads))))
	return stats
}

var batchWorkers = func() int {
	raw := os.Getenv("TYCHE_CRYPTO_PARALLELISM")
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 16 {
		panic("invalid cryptographic batch parallelism")
	}
	return n
}()

// All parallelizes independent proof equations, with a bounded number of
// partitions and no dependence on an executor worker becoming available. The
// caller executes one partition; every child uses the same CPU cgroup budget.
func All(count int, verify func(int) bool) bool {
	return AllLabeled("proof-equations", count, verify)
}

func AllLabeled(label string, count int, verify func(int) bool) bool {
	if configuredCPUGroup() != nil {
		valid := false
		WithCPUGroup(func() { valid = budgetAll(label, count, verify) })
		return valid
	}
	if batchWorkers == 1 || count < 2 {
		for i := 0; i < count; i++ {
			if !verify(i) {
				return false
			}
		}
		return true
	}
	workers := min(batchWorkers, count)
	var valid atomic.Bool
	valid.Store(true)
	var wg sync.WaitGroup
	part := func(offset int) {
		WithCPUGroup(func() {
			for i := offset; i < count && valid.Load(); i += workers {
				if !verify(i) {
					valid.Store(false)
				}
			}
		})
	}
	for offset := 1; offset < workers; offset++ {
		wg.Add(1)
		go func() { defer wg.Done(); part(offset) }()
	}
	part(0)
	wg.Wait()
	return valid.Load()
}

func budgetAll(label string, count int, verify func(int) bool) bool {
	workers := min(batchWorkers, configuredCPUGroup().Workers, count)
	if workers < 2 || count < 2 {
		for i := 0; i < count; i++ {
			if !verify(i) {
				return false
			}
		}
		return true
	}
	p := budgetService()
	var valid atomic.Bool
	valid.Store(true)
	part := func(offset int) {
		for i := offset; i < count && valid.Load(); i += workers {
			if !verify(i) {
				valid.Store(false)
			}
			if fast := p.takeFast(); fast != nil {
				p.execute(fast)
			}
		}
	}
	var jobs []*budgetJob
	for offset := 1; offset < workers; offset++ {
		job := &budgetJob{done: make(chan struct{}), queued: time.Now(), fn: func() {
			budgetLabel(label, func() { part(offset) })
		}}
		jobs = append(jobs, job)
		p.submit(job, true)
	}
	// Always join before returning or propagating a panic: proof closures can
	// reference arrays owned by this call, and must not outlive it.
	var failure any
	func() { defer func() { failure = recover() }(); part(0) }()
	for _, job := range jobs {
		p.join(job.done)
		if failure == nil {
			failure = job.failure
		}
	}
	if failure != nil {
		panic(failure)
	}
	return valid.Load()
}

type Stats struct {
	Workers int
	Active  int64
	Queued  int64
}

type Executor struct {
	mu         sync.Mutex
	cond       *sync.Cond
	high       []task
	highHead   int
	normal     []task
	normalHead int
	workers    int
	active     atomic.Int64
	queued     atomic.Int64
}

type task struct {
	ctx context.Context
	fn  func()
}

func New(workers int) *Executor {
	if workers <= 0 {
		return nil
	}
	e := &Executor{workers: workers}
	e.cond = sync.NewCond(&e.mu)
	for i := 0; i < workers; i++ {
		go e.worker()
	}
	return e
}

func (e *Executor) Go(ctx context.Context, fn func()) bool {
	if e == nil {
		fn()
		return true
	}
	e.enqueue(ctx, fn, false)
	return true
}

func (e *Executor) GoPriority(ctx context.Context, fn func()) bool {
	if e == nil {
		fn()
		return true
	}
	e.enqueue(ctx, fn, true)
	return true
}

func (e *Executor) enqueue(ctx context.Context, fn func(), priority bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.queued.Add(1)
	e.mu.Lock()
	if priority {
		e.high = append(e.high, task{ctx: ctx, fn: fn})
	} else {
		e.normal = append(e.normal, task{ctx: ctx, fn: fn})
	}
	e.cond.Signal()
	e.mu.Unlock()
}

func (e *Executor) worker() {
	for {
		e.run(e.next())
	}
}

func (e *Executor) run(t task) {
	e.active.Add(1)
	defer e.active.Add(-1)
	select {
	case <-t.ctx.Done():
	default:
		WithCPUGroup(t.fn)
	}
}

func (e *Executor) next() task {
	e.mu.Lock()
	defer e.mu.Unlock()
	for e.highHead >= len(e.high) && e.normalHead >= len(e.normal) {
		e.cond.Wait()
	}
	var t task
	if e.highHead < len(e.high) {
		t = e.high[e.highHead]
		e.high[e.highHead] = task{}
		e.highHead++
		if e.highHead > 1024 && e.highHead*2 >= len(e.high) {
			e.high = append([]task(nil), e.high[e.highHead:]...)
			e.highHead = 0
		}
	} else {
		t = e.normal[e.normalHead]
		e.normal[e.normalHead] = task{}
		e.normalHead++
		if e.normalHead > 1024 && e.normalHead*2 >= len(e.normal) {
			e.normal = append([]task(nil), e.normal[e.normalHead:]...)
			e.normalHead = 0
		}
	}
	e.queued.Add(-1)
	return t
}

func (e *Executor) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return Stats{
		Workers: e.workers,
		Active:  e.active.Load(),
		Queued:  e.queued.Load(),
	}
}
