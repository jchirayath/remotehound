package control

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/logx"
)

// Server is rh-control's HTTP API (internal network only):
//
//	GET  /healthz                         liveness + whether the engine answers (no auth)
//	GET  /v1/services                     every labeled container (allowlisted view)
//	POST /v1/services/{service}/{action}  start | stop | restart
//	GET  /v1/services/{service}/logs      ?tail=N (1..1000)
type Server struct {
	Docker *Docker
	Token  []byte

	mu sync.Mutex // one lifecycle action at a time: no stop/start races
}

// Handler builds the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /v1/services", s.auth(http.HandlerFunc(s.list)))
	mux.Handle("POST /v1/services/{service}/{action}", s.auth(http.HandlerFunc(s.act)))
	mux.Handle("GET /v1/services/{service}/logs", s.auth(http.HandlerFunc(s.logs)))
	return mux
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || len(s.Token) == 0 || subtle.ConstantTimeCompare([]byte(got), s.Token) != 1 {
			logx.L().WarnContext(r.Context(), "Control request refused: bad or missing token", logx.Event("control.unauthorized"),
				slog.String("client.address", r.RemoteAddr), slog.String("url.path", r.URL.Path))
			writeErr(w, http.StatusUnauthorized, "unauthorized", "Missing or wrong control token.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Docker.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "down", "docker": "unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "docker": "ok"})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	ts, err := s.Docker.Targets(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "engine", err.Error())
		return
	}
	out := make([]Container, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.view)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	writeJSON(w, http.StatusOK, out)
}

// resolve finds the labeled container for {service} and checks the action
// against ITS label — the allowlist is enforced here, not only in RemoteHound.
func (s *Server) resolve(w http.ResponseWriter, r *http.Request, action string) *target {
	name := r.PathValue("service")
	if !ValidServiceName(name) {
		writeErr(w, http.StatusNotFound, "unknown_service", "No controllable service with that name.")
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	ts, err := s.Docker.Targets(ctx)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "engine", err.Error())
		return nil
	}
	t, ok := ts[name]
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown_service", "No container is labeled "+LabelService+"="+name+".")
		return nil
	}
	if !slices.Contains(t.actions, action) {
		logx.L().WarnContext(r.Context(), "Control action refused: not in the container's allowlist", logx.Event("control.denied"),
			slog.String("app.service", name), slog.String("app.action", action))
		writeErr(w, http.StatusForbidden, "action_not_allowed", "The "+name+" container does not allow "+action+" (label "+LabelActions+").")
		return nil
	}
	return t
}

func (s *Server) act(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != ActionStart && action != ActionStop && action != ActionRestart {
		writeErr(w, http.StatusNotFound, "unknown_action", "Use start, stop or restart.")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.resolve(w, r, action)
	if t == nil {
		return
	}
	// Detached from the request: if the caller is the container being
	// restarted, its connection dies mid-call and the action must still finish.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 60*time.Second)
	defer cancel()
	start := time.Now()
	err := s.Docker.Act(ctx, t.id, action)
	attrs := []any{logx.Event("control.action"), slog.String("app.service", t.view.Service), slog.String("app.action", action),
		slog.String("app.container", t.view.Name), slog.Int64("app.duration_ms", time.Since(start).Milliseconds())}
	if err != nil {
		logx.L().ErrorContext(r.Context(), "Control action failed", append(attrs, logx.Err(err))...)
		writeErr(w, http.StatusBadGateway, "engine", err.Error())
		return
	}
	logx.L().InfoContext(r.Context(), "Control action done", attrs...)
	if fresh, err := s.Docker.inspect(ctx, t.id); err == nil {
		writeJSON(w, http.StatusOK, fresh.view)
		return
	}
	writeJSON(w, http.StatusOK, t.view)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	tail := DefaultTail
	if v := r.URL.Query().Get("tail"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxTail {
			writeErr(w, http.StatusBadRequest, "bad_tail", "tail must be 1.."+strconv.Itoa(MaxTail)+".")
			return
		}
		tail = n
	}
	t := s.resolve(w, r, ActionLogs)
	if t == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	lines, err := s.Docker.Logs(ctx, t.id, t.tty, tail)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "engine", err.Error())
		return
	}
	if lines == nil {
		lines = []LogLine{}
	}
	writeJSON(w, http.StatusOK, lines)
}

// Wire format: success is the bare JSON value; errors are {"code","detail"}.

// RemoteError is an error answer from the helper.
type RemoteError struct {
	Status int    `json:"-"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

func (e *RemoteError) Error() string { return "rh-control: " + e.Code + ": " + e.Detail }

// IsRemote reports whether err is a RemoteError with the given code.
func IsRemote(err error, code string) bool {
	var re *RemoteError
	return errors.As(err, &re) && re.Code == code
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, RemoteError{Code: code, Detail: detail})
}
