// Package api is the HTTP layer: routing, middleware and thin handlers over
// the domain services. Handlers decode → validate (CORE-9) → authorize
// (CORE-5) → call a service → respond {data, meta} or problem+json (CORE-7).
package api

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/auth"
	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/metrics"
)

type ctxSession struct{}

func sessionFrom(ctx context.Context) *auth.Session {
	s, _ := ctx.Value(ctxSession{}).(*auth.Session)
	return s
}

var traceparentRe = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$`)
var requestIDRe = regexp.MustCompile(`^[A-Za-z0-9._-]{8,64}$`)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// statusWriter captures the status code and supports hijacking (websockets,
// the Guacamole tunnel) and flushing (SSE).
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijack not supported")
	}
	w.status = http.StatusSwitchingProtocols
	return h.Hijack()
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// clientIP returns the caller's address, honouring X-Forwarded-For only from
// trusted proxies (rightmost untrusted hop).
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !auth.TrustedPeer(r, trusted) {
		return host
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		ip, err := netip.ParseAddr(p)
		if err != nil {
			continue
		}
		inTrusted := false
		for _, t := range trusted {
			if t.Contains(ip.Unmap()) {
				inTrusted = true
				break
			}
		}
		if !inTrusted {
			return ip.String()
		}
	}
	return host
}

// observe is the outermost middleware: request ID + trace context, panic
// recovery, one summary log record per request (LOG-7) and the duration metric.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := r.Header.Get("X-Request-Id")
		if !requestIDRe.MatchString(reqID) {
			reqID = randHex(8)
		}
		traceID, parentSpan := randHex(16), ""
		if m := traceparentRe.FindStringSubmatch(r.Header.Get("traceparent")); m != nil {
			traceID, parentSpan = m[1], m[2]
		}
		_ = parentSpan
		ip := clientIP(r, s.TrustedProxies)
		ctx := logx.WithScope(r.Context(), logx.Scope{RequestID: reqID, TraceID: traceID, SpanID: randHex(8)})
		ctx = audit.WithOrigin(ctx, audit.Origin{ClientAddress: ip, UserAgent: truncate(r.UserAgent(), 256)})
		w.Header().Set("X-Request-Id", reqID)
		sw := &statusWriter{ResponseWriter: w}
		r = r.WithContext(ctx)

		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				logx.L().ErrorContext(ctx, "Handler panicked", logx.Event("http.panic"), slog.String("exception.stacktrace", string(debug.Stack())))
				if sw.status == 0 {
					apierr.Write(sw, r, reqID, apierr.Internal(errors.New("panic")))
				}
			}
			route := r.Pattern
			if route == "" {
				route = "unmatched"
			}
			dur := time.Since(start)
			if sw.status == 0 {
				sw.status = http.StatusOK
			}
			lvl := slog.LevelInfo
			if sw.status >= 500 {
				lvl = slog.LevelError
			} else if strings.HasPrefix(route, "GET /healthz") || strings.HasPrefix(route, "GET /readyz") || strings.Contains(route, "/ui/") {
				lvl = slog.LevelDebug
			}
			logx.L().Log(ctx, lvl, "HTTP request", logx.Event("http.request"),
				slog.String("http.request.method", r.Method), slog.String("http.route", route),
				slog.Int("http.response.status_code", sw.status), slog.String("url.path", r.URL.Path),
				slog.String("client.address", ip), slog.String("user_agent.original", truncate(r.UserAgent(), 256)),
				slog.Int64("app.duration_ms", dur.Milliseconds()))
			metrics.Default.Observe("http_server_request_duration_seconds", "HTTP server request duration.", dur.Seconds(),
				"http_request_method", r.Method, "http_route", route, "http_response_status_code", itoa(sw.status))
		}()
		next.ServeHTTP(sw, r)
	})
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// guacPrefix is set from config at startup (the proxied Guacamole path).
var guacPrefix = "/guacamole/"

// securityHeaders applies BRW-1 headers. /guacamole/* gets a relaxed CSP set
// by the proxy because the Guacamole client needs inline styles and eval-free
// but dynamic scripts of its own.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if !strings.HasPrefix(r.URL.Path, guacPrefix) {
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
			h.Set("X-Frame-Options", "DENY")
		}
		next.ServeHTTP(w, r)
	})
}

// publicPath reports routes that never need an identity. Identity headers or
// cookies on them are not even looked at, so a request to an ungated path can
// never create or modify a user (and costs no store access).
func publicPath(p string) bool {
	switch p {
	case "/healthz", "/readyz", "/signed-out", "/auth/providers", "/api/v1/enroll", "/api/v1/enroll/status", "/favicon.ico":
		return true
	}
	return strings.HasPrefix(p, "/ui/") || strings.HasPrefix(p, "/e/") || strings.HasPrefix(p, "/docs/")
}

// authenticate loads the actor (if any) into the context.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		actor, sess := s.Auth.Authenticate(w, r)
		ctx := r.Context()
		if actor != nil {
			ctx = authz.WithActor(ctx, actor)
			ctx = context.WithValue(ctx, ctxSession{}, sess)
			logx.UpdateScope(ctx, func(sc *logx.Scope) { sc.UserID, sc.UserRoles = actor.UserID, actor.Role })
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAuth rejects anonymous callers and enforces CSRF on mutations.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := authz.ActorFrom(r.Context())
		if a.Anonymous() {
			if s.Auth.Mode == "proxy" {
				// Not "sign in": the proxy already did that. Something between
				// it and us dropped or refused the identity — say so, so the UI
				// shows an explanation instead of bouncing to /auth/login.
				s.fail(w, r, apierr.New(http.StatusUnauthorized, apierr.CodeProxyIdentity,
					"Your sign-in proxy let this request through without identifying you. Sign in again; if it keeps happening, an admin should check the proxy's email header and secret."))
				return
			}
			s.fail(w, r, apierr.Unauthenticated())
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			sess := sessionFrom(r.Context())
			if sess == nil || !auth.CheckCSRF(r, sess) {
				s.Audit.Record(r.Context(), "auth.csrf", audit.Denied, "", map[string]any{"path": r.URL.Path})
				s.fail(w, r, apierr.New(http.StatusForbidden, apierr.CodeCSRF, "Your session token is missing or stale. Reload the page and try again."))
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ---- rate limiting (API-4) ---------------------------------------------------

// limiter is a per-key token bucket.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst int) *limiter {
	return &limiter{rate: float64(perMinute) / 60, burst: float64(burst), buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) > 50000 { // bound memory under a flood: evict idle (full) buckets, never reset active ones
			for k, ob := range l.buckets {
				if now.Sub(ob.last).Seconds()*l.rate >= l.burst {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) > 50000 {
				return false // still saturated: fail closed for new keys
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (s *Server) limit(l *limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := ids.ClientKey(clientIP(r, s.TrustedProxies))
		if a := authz.ActorFrom(r.Context()); !a.Anonymous() {
			key = a.UserID
		}
		if !l.allow(key) {
			w.Header().Set("Retry-After", "30")
			s.fail(w, r, apierr.New(http.StatusTooManyRequests, apierr.CodeRateLimited, "Too many requests. Wait a moment and try again."))
			return
		}
		next.ServeHTTP(w, r)
	})
}
