package cryptoexec

import (
	"context"
	"sync/atomic"
)

type Stats struct {
	Workers int
	Active  int64
	Queued  int64
}

type Executor struct {
	slots  chan struct{}
	active atomic.Int64
	queued atomic.Int64
}

func New(workers int) *Executor {
	if workers <= 0 {
		return nil
	}
	return &Executor{slots: make(chan struct{}, workers)}
}

func (e *Executor) Go(ctx context.Context, fn func()) bool {
	if e == nil {
		fn()
		return true
	}
	e.queued.Add(1)
	go func() {
		select {
		case e.slots <- struct{}{}:
			e.queued.Add(-1)
			e.active.Add(1)
		case <-ctx.Done():
			e.queued.Add(-1)
			return
		}
		defer func() {
			e.active.Add(-1)
			<-e.slots
		}()
		fn()
	}()
	return true
}

func (e *Executor) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return Stats{
		Workers: cap(e.slots),
		Active:  e.active.Load(),
		Queued:  e.queued.Load(),
	}
}
