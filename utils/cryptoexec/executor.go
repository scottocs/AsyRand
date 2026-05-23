package cryptoexec

import "context"

type Executor struct {
	slots chan struct{}
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
	go func() {
		select {
		case e.slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		defer func() { <-e.slots }()
		fn()
	}()
	return true
}
