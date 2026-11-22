// Package logx is CORE-3: the one logger.
//
// Contract:
//   - Every record is one JSON line on stdout in the OpenTelemetry log data
//     model with OTel semantic-convention keys (LOG-1): timestamp,
//     severity_text, severity_number, body, service.*, event.name, trace_id,
//     span_id, app.request.id, user.id, …
//   - Redaction happens HERE, not at call sites (LOG-4): sensitive keys are
//     replaced and secret-looking values (JWTs, bearer tokens, long hex/base64)
//     are scrubbed. JSON encoding escapes CR/LF (SEC-29).
//   - The level is a runtime switch (LOG-3): SetLevel from the Debug screen.
//   - Every record is also kept in an in-memory Ring (server, client and bundle
//     sources) that backs the Logs screen and its live tail.
//
// Usage:
//
//	log := logx.L()
//	log.InfoContext(ctx, "Tunnel opened", logx.Event("tunnel.open"), slog.String("app.device.id", id))
package logx

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resource attributes set once at Init (LOG-1).
type Resource struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
}

var (
	level    = new(slog.LevelVar)
	global   atomic.Pointer[slog.Logger] // swapped by Init, read by L from any goroutine
	ring     = NewRing(5000)
	initOnce sync.Mutex
)

// Init installs the process-wide logger writing to w (os.Stdout in production).
func Init(w io.Writer, res Resource, lvl string) *slog.Logger {
	initOnce.Lock()
	defer initOnce.Unlock()
	SetLevel(lvl)
	if w == nil {
		w = os.Stdout
	}
	l := slog.New(&handler{w: w, res: res, mu: &sync.Mutex{}})
	global.Store(l)
	return l
}

// L returns the process logger (a discard-safe default before Init).
func L() *slog.Logger {
	if l := global.Load(); l != nil {
		return l
	}
	return Init(io.Discard, Resource{ServiceName: "remotehound"}, "INFO")
}

// GetRing returns the shared in-memory ring.
func GetRing() *Ring { return ring }

// SetLevel changes the minimum level at runtime. Unknown values mean INFO.
func SetLevel(s string) {
	switch strings.ToUpper(s) {
	case "DEBUG":
		level.Set(slog.LevelDebug)
	case "WARN":
		level.Set(slog.LevelWarn)
	case "ERROR":
		level.Set(slog.LevelError)
	default:
		level.Set(slog.LevelInfo)
	}
}

// Level returns the current level name.
func Level() string { return levelName(level.Level()) }

// Event is the attribute every record should carry: a stable dotted name.
func Event(name string) slog.Attr { return slog.String("event.name", name) }

// Err records an error's stable code (error.type) and message (exception.message).
func Err(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	type coded interface{ ErrorCode() string }
	code := "INTERNAL"
	if c, ok := err.(coded); ok {
		code = c.ErrorCode()
	}
	return slog.Group("", slog.String("error.type", code), slog.String("exception.message", err.Error()))
}

// ---- request-scoped context ------------------------------------------------

type ctxKey struct{}

// Scope carries correlation fields that every record in a request inherits.
type Scope struct {
	RequestID string
	TraceID   string
	SpanID    string
	UserID    string
	UserRoles string
	DeviceID  string
	Debug     bool // per-device debug flag: emit DEBUG for this scope regardless of level
}

// WithScope attaches s to ctx.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, ctxKey{}, &s)
}

// ScopeFrom returns the scope on ctx (zero value if none).
func ScopeFrom(ctx context.Context) Scope {
	if ctx == nil {
		return Scope{}
	}
	if s, ok := ctx.Value(ctxKey{}).(*Scope); ok {
		return *s
	}
	return Scope{}
}

// UpdateScope mutates the scope stored on ctx in place (e.g. after auth sets the user).
func UpdateScope(ctx context.Context, f func(*Scope)) {
	if s, ok := ctx.Value(ctxKey{}).(*Scope); ok {
		f(s)
	}
}

// ---- handler ---------------------------------------------------------------

type handler struct {
	w      io.Writer
	res    Resource
	attrs  []slog.Attr
	groups []string
	mu     *sync.Mutex
}

func (h *handler) Enabled(ctx context.Context, l slog.Level) bool {
	if l >= level.Level() {
		return true
	}
	return ScopeFrom(ctx).Debug
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), qualify(h.groups, as)...)
	return &c
}

func (h *handler) WithGroup(name string) slog.Handler {
	c := *h
	c.groups = append(append([]string{}, h.groups...), name)
	return &c
}

func qualify(groups []string, as []slog.Attr) []slog.Attr {
	if len(groups) == 0 {
		return as
	}
	prefix := strings.Join(groups, ".") + "."
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = slog.Attr{Key: prefix + a.Key, Value: a.Value}
	}
	return out
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	rec := map[string]any{
		"timestamp":                   r.Time.UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		"severity_text":               levelName(r.Level),
		"severity_number":             severityNumber(r.Level),
		"body":                        Redact(r.Message),
		"service.name":                h.res.ServiceName,
		"service.version":             h.res.ServiceVersion,
		"deployment.environment.name": h.res.Environment,
	}
	s := ScopeFrom(ctx)
	setIf(rec, "app.request.id", s.RequestID)
	setIf(rec, "trace_id", s.TraceID)
	setIf(rec, "span_id", s.SpanID)
	setIf(rec, "user.id", s.UserID)
	setIf(rec, "user.roles", s.UserRoles)
	setIf(rec, "app.device.id", s.DeviceID)

	add := func(a slog.Attr) { flatten(rec, "", a) }
	for _, a := range h.attrs {
		add(a)
	}
	attrs := qualifyRecord(h.groups, r)
	for _, a := range attrs {
		add(a)
	}
	if _, ok := rec["event.name"]; !ok {
		rec["event.name"] = "app.log"
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	h.mu.Lock()
	_, err = h.w.Write(append(line, '\n'))
	h.mu.Unlock()

	ring.Add(recordFromMap("server", r.Time, rec))
	return err
}

func qualifyRecord(groups []string, r slog.Record) []slog.Attr {
	var as []slog.Attr
	r.Attrs(func(a slog.Attr) bool { as = append(as, a); return true })
	return qualify(groups, as)
}

func flatten(rec map[string]any, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Key == "" && a.Value.Kind() != slog.KindGroup {
		return
	}
	key := a.Key
	if prefix != "" && key != "" {
		key = prefix + "." + key
	} else if prefix != "" {
		key = prefix
	}
	if a.Value.Kind() == slog.KindGroup {
		for _, g := range a.Value.Group() {
			flatten(rec, key, g)
		}
		return
	}
	rec[key] = redactValue(key, a.Value.Any())
}

func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func severityNumber(l slog.Level) int {
	switch {
	case l >= slog.LevelError:
		return 17
	case l >= slog.LevelWarn:
		return 13
	case l >= slog.LevelInfo:
		return 9
	default:
		return 5
	}
}

// ---- redaction (LOG-4) -----------------------------------------------------

var (
	sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|token|authorization|cookie|api[_-]?key|private[_-]?key|credential|ssn|card|sealed)`)
	jwtPattern   = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	bearer       = regexp.MustCompile(`(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	longHex      = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)
	longB64      = regexp.MustCompile(`[A-Za-z0-9+/_-]{40,}={0,2}`)
	privKey      = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)
	guacData     = regexp.MustCompile(`([?&]data=)[^&#\s]+`)
	fingerprint  = regexp.MustCompile(`SHA256:[A-Za-z0-9+/]{43}`)
	// key=value / key: value / "key":"value" pairs in third-party output
	// (container logs on the Services screen, bundle logs).
	secretPair = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|client[_-]?secret|token|access[_-]?token|api[_-]?key)("?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s&,;"']+)`)
)

// Keys that look sensitive by name but carry safe values.
var allowKeys = map[string]bool{"app.device.key_fingerprint": true, "event.name": true, "error.type": true}

const redacted = "[REDACTED]"

func redactValue(key string, v any) any {
	if !allowKeys[key] && sensitiveKey.MatchString(key) {
		return redacted
	}
	if s, ok := v.(string); ok {
		return Redact(s)
	}
	if e, ok := v.(error); ok {
		return Redact(e.Error())
	}
	return v
}

// Redact scrubs secret-looking substrings from free text. Exported for the
// client-log and bundle-log ingesters, which apply the same rules.
func Redact(s string) string {
	if len(s) > 8192 {
		s = s[:8192] + "…[truncated]"
	}
	s = privKey.ReplaceAllString(s, redacted)
	s = secretPair.ReplaceAllString(s, "${1}${2}"+redacted)
	s = guacData.ReplaceAllString(s, "${1}"+redacted)
	s = jwtPattern.ReplaceAllString(s, redacted)
	s = bearer.ReplaceAllString(s, "$1 "+redacted)
	s = longHex.ReplaceAllString(s, redacted)
	// SSH key fingerprints ("SHA256:" + 43 base64 chars) are public and needed
	// for debugging: shield them from the long-base64 rule, then restore.
	fps := fingerprint.FindAllString(s, -1)
	if len(fps) > 0 {
		s = fingerprint.ReplaceAllString(s, "\x00FP\x00")
	}
	s = longB64.ReplaceAllString(s, redacted)
	for _, fp := range fps {
		s = strings.Replace(s, "\x00FP\x00", fp, 1)
	}
	return stripControl(s)
}

// stripControl removes control characters except tab (SEC-29 for raw sinks).
func stripControl(s string) string {
	clean := true
	for _, r := range s {
		if r < 0x20 && r != '\t' || r == 0x7f {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 && r != '\t' || r == 0x7f {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---- external sources -------------------------------------------------------

// Ingest adds a line from another source (client tunnel logs, bundle logs) to
// the ring after redaction. It is not written to stdout: those sources have
// their own sinks, and re-emitting them would double-count in a collector.
func Ingest(source, deviceID, severity, body string, attrs map[string]any) {
	rec := map[string]any{
		"severity_text": strings.ToUpper(severity),
		"body":          Redact(body),
		"event.name":    source + ".log",
	}
	if deviceID != "" {
		rec["app.device.id"] = deviceID
	}
	for k, v := range attrs {
		rec[k] = redactValue(k, v)
	}
	ring.Add(recordFromMap(source, time.Now(), rec))
}
