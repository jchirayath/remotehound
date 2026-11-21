// Package audit is CORE-4: record(ctx, event, outcome, resource, attrs).
//
// Contract (LOG-5): one call emits (a) one structured log record via logx and
// (b) one append-only line in <data>/audit.jsonl, hash-chained (each record
// carries the SHA-256 of the previous one) so truncation or edits are
// detectable by Verify. The actor is identified by internal user ID; email is
// carried for readability in the activity feed. A failed audit write is itself
// logged at ERROR (LOG-9 alert: audit-write failure).
package audit

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/logx"
)

// Outcomes (app.outcome).
const (
	Success = "success"
	Failure = "failure"
	Denied  = "denied"
)

// Event is one audit record.
type Event struct {
	ID            string         `json:"id"`
	Timestamp     time.Time      `json:"timestamp"`
	Event         string         `json:"event"`
	Outcome       string         `json:"outcome"`
	UserID        string         `json:"user_id,omitempty"`
	UserEmail     string         `json:"user_email,omitempty"`
	UserRoles     []string       `json:"user_roles,omitempty"`
	ClientAddress string         `json:"client_address,omitempty"`
	UserAgent     string         `json:"user_agent,omitempty"`
	Resource      string         `json:"resource,omitempty"`
	Attrs         map[string]any `json:"attrs,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	PrevHash      string         `json:"prev_hash"`
	Hash          string         `json:"hash"`
}

// Origin carries request facts audit needs (set by the HTTP middleware).
type Origin struct {
	ClientAddress string
	UserAgent     string
}

type originKey struct{}

// WithOrigin attaches o to ctx.
func WithOrigin(ctx context.Context, o Origin) context.Context {
	return context.WithValue(ctx, originKey{}, o)
}

// Log is the audit sink.
type Log struct {
	mu      sync.Mutex
	path    string
	f       *os.File
	last    string
	recent  []Event // newest last, capped
	maxKeep int
}

// Open opens (or creates) the audit file and loads recent records.
func Open(dataDir string) (*Log, error) {
	p := filepath.Join(dataDir, "audit.jsonl")
	l := &Log{path: p, maxKeep: 20000}
	if err := l.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- fixed path
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) load() error {
	f, err := os.Open(l.path) // #nosec G304 -- fixed path
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // Verify reports corruption; loading stays resilient
		}
		l.keep(e)
		l.last = e.Hash
	}
	return sc.Err()
}

func (l *Log) keep(e Event) {
	l.recent = append(l.recent, e)
	if len(l.recent) > l.maxKeep {
		l.recent = l.recent[len(l.recent)-l.maxKeep:]
	}
}

// Close flushes and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Record is THE audit call. resource is "kind:id" (e.g. "device:dev_x").
func (l *Log) Record(ctx context.Context, event, outcome, resource string, attrs map[string]any) {
	a := authz.ActorFrom(ctx)
	o, _ := ctx.Value(originKey{}).(Origin)
	sc := logx.ScopeFrom(ctx)
	e := Event{
		ID:            ids.New("aud"),
		Timestamp:     time.Now().UTC(),
		Event:         event,
		Outcome:       outcome,
		ClientAddress: o.ClientAddress,
		UserAgent:     o.UserAgent,
		Resource:      resource,
		Attrs:         sanitize(attrs),
		RequestID:     sc.RequestID,
	}
	if a != nil && !a.Anonymous() {
		e.UserID, e.UserEmail, e.UserRoles = a.UserID, a.Email, []string{a.Role}
	}

	lvl := slog.LevelInfo
	if outcome == Denied || outcome == Failure {
		lvl = slog.LevelWarn
	}
	logArgs := []any{logx.Event(event), slog.String("app.outcome", outcome), slog.String("app.resource", resource), slog.Bool("app.audit", true)}
	for k, v := range e.Attrs {
		logArgs = append(logArgs, slog.Any("app."+k, v))
	}
	logx.L().Log(ctx, lvl, "Audit: "+event+" "+outcome, logArgs...)

	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e.PrevHash = l.last
	e.Hash = chainHash(e)
	line, err := json.Marshal(e)
	if err == nil {
		_, err = l.f.Write(append(line, '\n'))
	}
	if err != nil {
		logx.L().ErrorContext(ctx, "Audit write failed", logx.Event("audit.write_failed"), logx.Err(err))
		return
	}
	l.last = e.Hash
	l.keep(e)
}

func sanitize(attrs map[string]any) map[string]any {
	if len(attrs) == 0 {
		return nil
	}
	out := make(map[string]any, len(attrs))
	for k, v := range attrs {
		if s, ok := v.(string); ok {
			v = logx.Redact(s)
		}
		if strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "secret") {
			v = "[REDACTED]"
		}
		out[k] = v
	}
	return out
}

func chainHash(e Event) string {
	e.Hash = ""
	b, _ := json.Marshal(e) // struct of plain types: cannot fail
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Query filters recent events, newest first.
type Query struct {
	Event   string
	Outcome string
	Limit   int
	Before  string // event ID cursor
	Visible func(Event) bool
}

// List returns newest-first events matching q and the next cursor.
func (l *Log) List(q Query) ([]Event, string) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 50
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	started := q.Before == ""
	for i := len(l.recent) - 1; i >= 0; i-- {
		e := l.recent[i]
		if !started {
			if e.ID == q.Before {
				started = true
			}
			continue
		}
		if q.Event != "" && !strings.HasPrefix(e.Event, q.Event) {
			continue
		}
		if q.Outcome != "" && e.Outcome != q.Outcome {
			continue
		}
		if q.Visible != nil && !q.Visible(e) {
			continue
		}
		if len(out) == q.Limit {
			return out, out[len(out)-1].ID
		}
		out = append(out, e)
	}
	return out, ""
}

// Verify recomputes the chain over the whole file and returns the first problem.
func (l *Log) Verify() (records int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path) // #nosec G304 -- fixed path
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	prev := ""
	for sc.Scan() {
		records++
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return records, fmt.Errorf("record %d: unreadable: %w", records, err)
		}
		if records > 1 && e.PrevHash != prev {
			return records, fmt.Errorf("record %d (%s): chain broken (prev_hash mismatch)", records, e.ID)
		}
		if chainHash(e) != e.Hash {
			return records, fmt.Errorf("record %d (%s): hash mismatch (edited)", records, e.ID)
		}
		prev = e.Hash
	}
	return records, sc.Err()
}

// Prune drops records older than cutoff by rewriting the file with the kept
// lines byte-for-byte unchanged, so their hashes still verify. The chain then
// starts at the first kept record (Verify accepts any prev_hash on record 1);
// the caller records an "audit.retention" event noting what was dropped.
func (l *Log) Prune(cutoff time.Time) (dropped int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path) // #nosec G304 -- fixed path
	if err != nil {
		return 0, err
	}
	var kept [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Timestamp.Before(cutoff) {
			dropped++
			continue
		}
		kept = append(kept, append([]byte{}, sc.Bytes()...))
	}
	f.Close()
	if err := sc.Err(); err != nil || dropped == 0 {
		return 0, err
	}
	tmp := l.path + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- fixed path
	if err != nil {
		return 0, err
	}
	w := bufio.NewWriter(out)
	for _, line := range kept {
		_, _ = w.Write(append(line, '\n'))
	}
	if err := w.Flush(); err != nil {
		out.Close()
		return 0, err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return 0, err
	}
	out.Close()
	l.f.Close()
	if err := os.Rename(tmp, l.path); err != nil {
		return 0, err
	}
	if l.f, err = os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o600); err != nil { // #nosec G304 -- fixed path
		return dropped, err
	}
	l.recent = nil
	return dropped, l.load()
}
