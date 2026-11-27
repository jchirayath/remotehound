package app

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/jobs"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/model"
)

// registerJobs declares every background job (CORE-10). Each one is
// idempotent and safe to "Run now" from the Debug screen.
func (a *App) registerJobs() {
	a.Jobs.Register(jobs.Job{
		Name: "guac-health", Description: "Validates the Guacamole integration (reachability, guacd handshake, JSON auth round-trip, clocks).",
		Interval: 30 * time.Second, Timeout: 20 * time.Second, Quiet: true,
		Run: func(ctx context.Context) error {
			prev := a.Guac.Health()
			rep := a.Guac.RunPeriodic(ctx)
			now := a.Guac.Health()
			if prev != now && prev != "unknown" {
				lvl := slog.LevelWarn
				if now == "ok" {
					lvl = slog.LevelInfo
				}
				logx.L().Log(ctx, lvl, "Guacamole integration changed state", logx.Event("integration.state"),
					slog.String("app.from", prev), slog.String("app.to", now))
			}
			if rep.Overall == "fail" {
				return errors.New("integration check failing (see Integration screen)")
			}
			return nil
		},
	})
	a.Jobs.Register(jobs.Job{
		Name: "session-reconcile", Description: "Closes session records left open by a crash or restart (no live tunnel connection behind them).",
		Interval: 5 * time.Minute, Timeout: time.Minute,
		Run: func(ctx context.Context) error {
			live := map[string]bool{}
			for _, in := range a.Tunnel.Infos() {
				for _, f := range in.Forwards {
					if f.ActiveConns > 0 {
						live[in.DeviceID] = true
					}
				}
			}
			n := 0
			err := a.Store.Update(func(s *model.State) error {
				for _, ss := range s.Sessions {
					if ss.EndedAt.IsZero() && !live[ss.DeviceID] && time.Since(ss.StartedAt) > time.Minute {
						ss.EndedAt = time.Now().UTC()
						ss.Touch(ss.EndedAt)
						n++
					}
				}
				return nil
			})
			if n > 0 {
				logx.L().InfoContext(ctx, "Closed stale session records", logx.Event("session.reconcile"), slog.Int("app.count", n))
			}
			return err
		},
	})
	a.Jobs.Register(jobs.Job{
		Name: "retention", Description: "Applies retention: expired enrollment codes, old sessions, old recordings and audit records.",
		Interval: time.Hour, Timeout: 10 * time.Minute,
		Run: a.retention,
	})
	a.Jobs.Register(jobs.Job{
		Name: "store-snapshot", Description: "Writes a daily snapshot of the state file (7 kept) — the fallback if state.json and its .bak are both unreadable.",
		Interval: 24 * time.Hour, Timeout: time.Minute,
		Run: func(ctx context.Context) error {
			p, err := a.Store.Snapshot()
			if err == nil {
				logx.L().InfoContext(ctx, "State snapshot written", logx.Event("store.snapshot"), slog.String("app.file", filepath.Base(p)))
			}
			return err
		},
	})
	a.Jobs.Register(jobs.Job{
		Name: "audit-verify", Description: "Recomputes the audit hash chain and reports the first edited or missing record.",
		Interval: 6 * time.Hour, Timeout: 5 * time.Minute,
		Run: func(ctx context.Context) error {
			n, err := a.Audit.Verify()
			if err != nil {
				logx.L().ErrorContext(ctx, "Audit chain verification failed", logx.Event("audit.verify"), logx.Err(err))
				return err
			}
			logx.L().InfoContext(ctx, "Audit chain verified", logx.Event("audit.verify"), slog.Int("app.records", n))
			return nil
		},
	})
	if a.Cfg.BundleLog != "" {
		t := &tailer{path: a.Cfg.BundleLog}
		a.Jobs.Register(jobs.Job{
			Name: "bundle-log-tail", Description: "Reads new container log lines (vector profile) into the Logs screen as source=bundle.",
			Interval: 2 * time.Second, Timeout: 2 * time.Second, Quiet: true,
			Run: t.poll,
		})
	}
}

func (a *App) retention(ctx context.Context) error {
	var st model.Settings
	a.Store.View(func(s *model.State) { st = s.Settings })
	now := time.Now().UTC()
	var expired, sessions int
	err := a.Store.Update(func(s *model.State) error {
		for id, e := range s.Enrollments {
			// Keep used/expired codes for a week so the UI can show what happened.
			if e.State(now) != "open" && now.Sub(e.ExpiresAt) > 7*24*time.Hour {
				delete(s.Enrollments, id)
				expired++
			}
		}
		cut := now.AddDate(0, 0, -st.SessionRetentionDays)
		for id, ss := range s.Sessions {
			if !ss.EndedAt.IsZero() && ss.EndedAt.Before(cut) {
				delete(s.Sessions, id)
				sessions++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	recs, err := pruneRecordings(a.Cfg.RecordingsDir, now.AddDate(0, 0, -st.RecordingRetentionDays))
	if err != nil {
		logx.L().WarnContext(ctx, "Recording retention could not run", logx.Event("retention.recordings"), logx.Err(err))
	}
	dropped, err := a.Audit.Prune(now.AddDate(0, 0, -st.AuditRetentionDays))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("audit prune: %w", err)
	}
	if dropped > 0 {
		a.Audit.Record(ctx, "audit.retention", audit.Success, "audit", map[string]any{"dropped": dropped})
	}
	if a.Cfg.BundleLog != "" {
		// vector's file sink does not rotate; cap it so the volume cannot fill.
		if fi, err := os.Stat(a.Cfg.BundleLog); err == nil && fi.Size() > 100<<20 {
			if err := os.Truncate(a.Cfg.BundleLog, 0); err != nil {
				logx.L().WarnContext(ctx, "Could not cap bundle log", logx.Event("retention.bundle_log"), logx.Err(err))
			}
		}
	}
	logx.L().InfoContext(ctx, "Retention applied", logx.Event("retention.run"), slog.Int("app.enrollments", expired),
		slog.Int("app.sessions", sessions), slog.Int("app.recordings", recs), slog.Int("app.audit", dropped))
	return nil
}

// pruneRecordings deletes recordings older than cutoff. The recordings volume
// is mounted read-only into remotehound in the bundle (guacd owns writes), in
// which case this reports a permission error and the guacd-side cron in
// deploy/ handles it.
func pruneRecordings(dir string, cutoff time.Time) (int, error) {
	n := 0
	var firstErr error
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			if rmErr := os.Remove(p); rmErr != nil {
				if firstErr == nil {
					firstErr = rmErr
				}
			} else {
				n++
			}
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return n, err
	}
	return n, firstErr
}

// tailer follows a JSONL file of container logs (vector's file sink).
type tailer struct {
	path   string
	offset int64
	inode  uint64
}

func (t *tailer) poll(ctx context.Context) error {
	f, err := os.Open(t.path) // #nosec G304 -- operator-configured path
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() < t.offset { // rotated or truncated
		t.offset = 0
	}
	if t.offset == 0 && st.Size() > 1<<20 {
		t.offset = st.Size() - 1<<20 // first read: last 1 MB only
	}
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	for i := 0; i < 5000; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			break // partial line: re-read next poll
		}
		t.offset += int64(len(line))
		ingestBundleLine(strings.TrimSpace(line))
	}
	return nil
}

// ingestBundleLine maps a vector docker_logs event to the log ring.
func ingestBundleLine(line string) {
	if line == "" {
		return
	}
	var ev struct {
		Message       string            `json:"message"`
		ContainerName string            `json:"container_name"`
		Stream        string            `json:"stream"`
		Label         map[string]string `json:"label"`
	}
	if json.Unmarshal([]byte(line), &ev) != nil {
		logx.Ingest("bundle", "", "INFO", line, nil)
		return
	}
	sev := "INFO"
	msg := ev.Message
	up := strings.ToUpper(msg)
	switch {
	case strings.Contains(up, "ERROR") || strings.Contains(up, "SEVERE"):
		sev = "ERROR"
	case strings.Contains(up, "WARN"):
		sev = "WARN"
	case strings.Contains(up, "DEBUG"):
		sev = "DEBUG"
	}
	if ev.ContainerName == "remotehound" || strings.HasSuffix(ev.ContainerName, "-remotehound-1") {
		return // our own lines are already in the ring as source=server
	}
	logx.Ingest("bundle", "", sev, msg, map[string]any{"container.name": ev.ContainerName, "log.iostream": ev.Stream})
}
