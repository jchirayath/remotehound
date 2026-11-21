package jobs

// @feature:debug

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPanicIsRecoveredAndCountedAsFailure(t *testing.T) {
	r := New()
	var runs atomic.Int32
	r.Register(Job{Name: "p", Interval: 10 * time.Millisecond, Run: func(context.Context) error {
		runs.Add(1)
		panic("kaboom")
	}})
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for runs.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	r.Wait()
	st := r.Statuses()[0]
	if st.ConsecutiveFailures < 1 || st.LastError == "" {
		t.Fatalf("panic not recorded: %+v", st)
	}
}

func TestBackoffGrowsAndResets(t *testing.T) {
	r := New()
	r.Register(Job{Name: "b", Interval: time.Second, Run: func(context.Context) error { return errors.New("x") }})
	e := r.entries["b"]
	e.status.ConsecutiveFailures = 3
	if d := r.nextDelay(e); d != 8*time.Second {
		t.Fatalf("backoff = %s", d)
	}
	e.status.ConsecutiveFailures = 20
	if d := r.nextDelay(e); d != 10*time.Second {
		t.Fatalf("cap = %s", d)
	}
	e.status.ConsecutiveFailures = 0
	if d := r.nextDelay(e); d != time.Second {
		t.Fatalf("reset = %s", d)
	}
}

func TestRunNowUnknownJob(t *testing.T) {
	if err := New().RunNow("nope"); !errors.Is(err, ErrUnknown) {
		t.Fatal("unknown job accepted")
	}
}
