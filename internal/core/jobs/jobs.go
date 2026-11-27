// Package jobs is CORE-10: the background job registry and the self-healing
// loop every periodic task runs inside.
//
// Contract: Register a Job (name, interval, timeout, Run). Start runs each job
// on its own schedule with:
//   - single-flight (a run never overlaps the previous one),
//   - panic recovery (a panic is an ERROR and a failed run, never a crash),
//   - exponential backoff after consecutive failures (interval × 2ⁿ, capped
//     at 10 × interval), resetting on success,
//   - status (last run/success/error/duration, next run) for the Debug screen
//     and job freshness metrics (LOG-10),
//   - RunNow for the "Run now" button.
//
// Bare goroutine loops and tickers for periodic work are banned elsewhere.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/logx"
)

// Job describes one periodic task.
type Job struct {
	Name        string
	Description string
	Interval    time.Duration
	Timeout     time.Duration
	// Quiet jobs log success at DEBUG (e.g. the 2-second bundle log tail).
	Quiet bool
	Run   func(ctx context.Context) error
}

// Status is the observable state of a job.
type Status struct {
	Name                string    `json:"name"`
	Description         string    `json:"description"`
	Schedule            string    `json:"schedule"`
	Running             bool      `json:"running"`
	LastRunAt           time.Time `json:"last_run_at"`
	LastSuccessAt       time.Time `json:"last_success_at"`
	LastError           string    `json:"last_error"`
	LastDurationMS      int64     `json:"last_duration_ms"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	NextRunAt           time.Time `json:"next_run_at"`
	Runs                int64     `json:"runs"`
}

type entry struct {
	job    Job
	mu     sync.Mutex
	status Status
	kick   chan struct{}
}

// Registry owns all jobs.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]*entry
	wg      sync.WaitGroup
}

// ErrUnknown is returned by RunNow for an unregistered name.
var ErrUnknown = errors.New("unknown job")

// New returns an empty registry.
func New() *Registry { return &Registry{entries: map[string]*entry{}} }

// Register adds a job. Call before Start.
func (r *Registry) Register(j Job) {
	if j.Timeout == 0 {
		j.Timeout = j.Interval
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[j.Name] = &entry{job: j, kick: make(chan struct{}, 1),
		status: Status{Name: j.Name, Description: j.Description, Schedule: "every " + j.Interval.String()}}
}

// Start launches every job's loop; they stop when ctx is canceled. Wait blocks until they have.
func (r *Registry) Start(ctx context.Context) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		r.wg.Add(1)
		go r.loop(ctx, e)
	}
}

// Wait blocks until all loops exit (graceful shutdown, OPS-1).
func (r *Registry) Wait() { r.wg.Wait() }

func (r *Registry) loop(ctx context.Context, e *entry) {
	defer r.wg.Done()
	// Stagger first runs so a restart doesn't fire everything at once.
	first := time.Duration(rand.Int64N(int64(min(e.job.Interval, 5*time.Second)) + 1)) // #nosec G404 -- scheduling jitter, not a secret
	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		e.mu.Lock()
		e.status.NextRunAt = time.Now().Add(first)
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-e.kick:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		r.runOnce(ctx, e)
		first = r.nextDelay(e)
		timer.Reset(first)
	}
}

func (r *Registry) nextDelay(e *entry) time.Duration {
	e.mu.Lock()
	defer e.mu.Unlock()
	d := e.job.Interval
	for i := 0; i < e.status.ConsecutiveFailures && d < 10*e.job.Interval; i++ {
		d *= 2
	}
	return min(d, 10*e.job.Interval)
}

func (r *Registry) runOnce(parent context.Context, e *entry) {
	e.mu.Lock()
	if e.status.Running {
		e.mu.Unlock()
		return
	}
	e.status.Running = true
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(parent, e.job.Timeout)
	defer cancel()
	ctx = logx.WithScope(ctx, logx.Scope{RequestID: "job-" + e.job.Name})
	start := time.Now()
	err := safeRun(ctx, e.job.Run)
	dur := time.Since(start)

	e.mu.Lock()
	e.status.Running = false
	e.status.Runs++
	e.status.LastRunAt = start
	e.status.LastDurationMS = dur.Milliseconds()
	if err != nil {
		e.status.ConsecutiveFailures++
		e.status.LastError = err.Error()
	} else {
		e.status.ConsecutiveFailures = 0
		e.status.LastError = ""
		e.status.LastSuccessAt = time.Now()
	}
	failures := e.status.ConsecutiveFailures
	e.mu.Unlock()

	log := logx.L()
	attrs := []any{logx.Event("job." + e.job.Name + ".finish"), slog.Int64("app.duration_ms", dur.Milliseconds())}
	switch {
	case err != nil && failures >= 3:
		log.ErrorContext(ctx, "Job failing repeatedly", append(attrs, logx.Err(err), slog.Int("app.job.failures", failures))...)
	case err != nil:
		log.WarnContext(ctx, "Job failed; will back off", append(attrs, logx.Err(err), slog.Int("app.job.failures", failures))...)
	case e.job.Quiet:
		log.DebugContext(ctx, "Job finished", attrs...)
	default:
		log.InfoContext(ctx, "Job finished", attrs...)
	}
}

func safeRun(ctx context.Context, fn func(context.Context) error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			logx.L().ErrorContext(ctx, "Job panicked", logx.Event("job.panic"), slog.String("exception.stacktrace", string(debug.Stack())))
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return fn(ctx)
}

// RunNow triggers a job immediately (no-op if it is already running).
func (r *Registry) RunNow(name string) error {
	r.mu.RLock()
	e, ok := r.entries[name]
	r.mu.RUnlock()
	if !ok {
		return ErrUnknown
	}
	select {
	case e.kick <- struct{}{}:
	default:
	}
	return nil
}

// Statuses returns every job's status sorted by name.
func (r *Registry) Statuses() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Status, 0, len(r.entries))
	for _, e := range r.entries {
		e.mu.Lock()
		out = append(out, e.status)
		e.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Failing counts jobs with consecutive failures.
func (r *Registry) Failing() int {
	n := 0
	for _, s := range r.Statuses() {
		if s.ConsecutiveFailures > 0 {
			n++
		}
	}
	return n
}
