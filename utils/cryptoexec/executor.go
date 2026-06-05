package cryptoexec

import (
	"context"
	"sync"
	"sync/atomic"
)

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
		t.fn()
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
