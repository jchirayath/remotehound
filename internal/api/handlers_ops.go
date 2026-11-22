package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/jobs"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/validate"
	"github.com/jchirayath/remotehound/internal/device"
	"github.com/jchirayath/remotehound/internal/model"
)

func encodeJSON(w io.Writer, v any) { _ = json.NewEncoder(w).Encode(v) }

var streams = struct {
	sync.Mutex
	n map[string]int
}{n: map[string]int{}}

func streamCount(uid string, d int) int {
	streams.Lock()
	defer streams.Unlock()
	streams.n[uid] += d
	if streams.n[uid] <= 0 {
		delete(streams.n, uid)
		return 0
	}
	return streams.n[uid]
}

func attrStr(k, v string) slog.Attr       { return slog.String(k, v) }
func attrBool(k string, v bool) slog.Attr { return slog.Bool(k, v) }
func urlEscape(s string) string           { return url.QueryEscape(s) }

func auditQuery(event, outcome string, limit int) audit.Query {
	return audit.Query{Event: event, Outcome: outcome, Limit: limit}
}

// ---- sessions & recordings --------------------------------------------------

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.SessionRead) {
		return
	}
	scope := qparam(r, "scope")
	switch scope {
	case "", "mine", "shared":
	default:
		s.fail(w, r, apierr.Validation([]apierr.FieldError{{Pointer: "/scope", Code: "NOT_ALLOWED", Detail: "Use mine or shared."}}))
		return
	}
	size, token := pageParams(r)
	out, next, total := s.Devices.ListSessions(authz.ActorFrom(r.Context()), device.SessionFilter{
		DeviceID: qparam(r, "device_id"), Active: boolParam(r, "active"), Scope: scope, PageSize: size, PageToken: token})
	writeJSON(w, http.StatusOK, nonNil(out), &meta{NextPageToken: next, Total: total})
}

func (s *Server) terminateSession(w http.ResponseWriter, r *http.Request) {
	if err := s.Devices.Terminate(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) shareSession(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID     string `json:"user_id"`
		Mode       string `json:"mode"`
		TTLMinutes int    `json:"ttl_minutes"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.TTLMinutes == 0 {
		in.TTLMinutes = 60
	}
	var v validate.Collector
	v.Required("/user_id", in.UserID)
	v.ID("/user_id", in.UserID, "usr")
	v.Required("/mode", in.Mode)
	v.OneOf("/mode", in.Mode, model.ShareView, model.ShareControl)
	v.Range("/ttl_minutes", in.TTLMinutes, 5, 480)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Devices.Share(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), in.UserID, in.Mode, time.Duration(in.TTLMinutes)*time.Minute)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) unshareSession(w http.ResponseWriter, r *http.Request) {
	out, err := s.Devices.Unshare(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), r.PathValue("user_id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) joinSession(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.SessionRead) {
		return
	}
	out, err := s.Devices.Join(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

// directory is the minimal user list for share pickers (anyone who may share):
// id, name and email of active users — no roles, groups or identities.
func (s *Server) directory(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.SessionShare) {
		return
	}
	a := authz.ActorFrom(r.Context())
	q := strings.ToLower(qparam(r, "q"))
	type entry struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
		Role        string `json:"role"` // needed to explain "viewers can only watch"
	}
	out := []entry{}
	s.Store.View(func(st *model.State) {
		for _, u := range st.Users {
			if u.Disabled || u.ID == a.UserID {
				continue
			}
			if !a.IsAdmin() && !sharesGroup(a.GroupIDs, u.GroupIDs) && u.Role != model.RoleAdmin {
				continue // operators see colleagues in their groups (and admins), not the whole org
			}
			if q != "" && !strings.Contains(strings.ToLower(u.Email+" "+u.DisplayName), q) {
				continue
			}
			out = append(out, entry{ID: u.ID, DisplayName: u.DisplayName, Email: u.Email, Role: u.Role})
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	if len(out) > 200 {
		out = out[:200]
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func sharesGroup(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// ---- personal credentials --------------------------------------------------------

func (s *Server) myCredentials(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Devices.MyCredentials(authz.ActorFrom(r.Context())), nil)
}

func (s *Server) saveCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		PrivateKey string `json:"private_key"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	v.MaxLen("/username", in.Username, 128)
	v.MaxLen("/password", in.Password, 512)
	v.MaxLen("/private_key", in.PrivateKey, 16<<10)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Devices.SaveCredential(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("device_id"), r.PathValue("service"), in.Username, in.Password, in.PrivateKey)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) deleteCredential(w http.ResponseWriter, r *http.Request) {
	if err := s.Devices.DeleteCredential(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("device_id"), r.PathValue("service")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type recordingView struct {
	Name       string    `json:"name"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

func (s *Server) listRecordings(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.RecordingRead) {
		return
	}
	var out []recordingView
	_ = filepath.WalkDir(s.RecordingsDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || len(out) >= 1000 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(s.RecordingsDir, p)
		out = append(out, recordingView{Name: filepath.ToSlash(rel), SizeBytes: info.Size(), ModifiedAt: info.ModTime().UTC()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ModifiedAt.After(out[j].ModifiedAt) })
	writeJSON(w, http.StatusOK, nonNil(out), nil)
}

// getRecording serves a file confined to the recordings root (SEC-26).
func (s *Server) getRecording(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.RecordingRead) {
		return
	}
	name := r.PathValue("name")
	root, err := filepath.EvalSymlinks(s.RecordingsDir)
	if err != nil {
		s.fail(w, r, apierr.NotFound(apierr.CodeRecordingMissing, "Recording storage is not mounted."))
		return
	}
	clean := filepath.Clean("/" + name)
	full, err := filepath.EvalSymlinks(filepath.Join(root, clean))
	if err != nil || !strings.HasPrefix(full, root+string(os.PathSeparator)) {
		s.fail(w, r, apierr.NotFound(apierr.CodeRecordingMissing, "No recording with that name."))
		return
	}
	f, err := os.Open(full) // #nosec G304 -- confined to the recordings root above
	if err != nil {
		s.fail(w, r, apierr.NotFound(apierr.CodeRecordingMissing, "No recording with that name."))
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		s.fail(w, r, apierr.NotFound(apierr.CodeRecordingMissing, "No recording with that name."))
		return
	}
	s.Audit.Record(r.Context(), "recording.download", audit.Success, "recording:"+filepath.Base(full), nil)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(filepath.Base(full), `"`, "")+`"`)
	http.ServeContent(w, r, filepath.Base(full), st.ModTime(), f)
}

// ---- integration ---------------------------------------------------------------

func (s *Server) getIntegration(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.IntegrationRead) {
		return
	}
	rep := s.Guac.Last()
	if rep.CheckedAt.IsZero() {
		rep.Overall = "unknown"
	}
	writeJSON(w, http.StatusOK, rep, nil)
}

func (s *Server) testIntegration(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.IntegrationTest) {
		return
	}
	rep := s.Guac.Run(r.Context())
	s.Audit.Record(r.Context(), "integration.test", audit.Success, "integration", map[string]any{"overall": rep.Overall})
	writeJSON(w, http.StatusOK, rep, nil)
}

// ---- audit -----------------------------------------------------------------------

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.AuditRead) {
		return
	}
	size, token := pageParams(r)
	evs, next := s.Audit.List(audit.Query{Event: qparam(r, "event"), Outcome: qparam(r, "outcome"), Limit: size, Before: token})
	if evs == nil {
		evs = []audit.Event{}
	}
	if qparam(r, "format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="remotehound-audit.csv"`)
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"timestamp", "event", "outcome", "user_email", "user_roles", "client_address", "resource", "request_id", "id"})
		for _, e := range evs {
			_ = cw.Write([]string{e.Timestamp.Format(time.RFC3339), csvSafe(e.Event), e.Outcome, csvSafe(e.UserEmail), strings.Join(e.UserRoles, " "),
				e.ClientAddress, csvSafe(e.Resource), e.RequestID, e.ID})
		}
		cw.Flush()
		return
	}
	writeJSON(w, http.StatusOK, evs, &meta{NextPageToken: next, Total: len(evs)})
}

// csvSafe neutralises spreadsheet formula injection.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// ---- logs ------------------------------------------------------------------------

func logFilter(r *http.Request) logx.Filter {
	limit, _ := strconv.Atoi(qparam(r, "limit"))
	q := qparam(r, "q")
	if len(q) > 200 {
		q = q[:200]
	}
	return logx.Filter{Source: qparam(r, "source"), MinLevel: qparam(r, "level"), Query: q,
		RequestID: qparam(r, "request_id"), DeviceID: qparam(r, "device_id"), Limit: limit}
}

func (s *Server) queryLogs(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.LogsRead) {
		return
	}
	writeJSON(w, http.StatusOK, nonNil(logx.GetRing().Query(logFilter(r))), nil)
}

// streamLogs is a Server-Sent Events live tail.
func (s *Server) streamLogs(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.LogsRead) {
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		s.fail(w, r, apierr.Internal(fmt.Errorf("streaming unsupported")))
		return
	}
	uid := authz.ActorFrom(r.Context()).UserID
	if n := streamCount(uid, 1); n > 3 {
		streamCount(uid, -1)
		s.fail(w, r, apierr.New(http.StatusTooManyRequests, apierr.CodeRateLimited, "Too many live tails open. Close one and try again."))
		return
	}
	defer streamCount(uid, -1)
	f := logFilter(r)
	ch, cancel := logx.GetRing().Subscribe()
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	fl.Flush()
	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()
	deadline := time.NewTimer(30 * time.Minute) // clients reconnect; bounds abandoned streams
	defer deadline.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case rec := <-ch:
			// The stream's own HTTP summary would echo forever; skip it.
			if !f.Match(rec) || rec.Attributes["http.route"] == "GET /api/v1/logs/stream" {
				continue
			}
			b, _ := json.Marshal(rec)
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

// ---- jobs and debug ----------------------------------------------------------------

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DebugRead) {
		return
	}
	writeJSON(w, http.StatusOK, s.Jobs.Statuses(), nil)
}

func (s *Server) runJob(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.JobRun) {
		return
	}
	name := r.PathValue("name")
	if err := s.Jobs.RunNow(name); err == jobs.ErrUnknown {
		s.fail(w, r, apierr.NotFound(apierr.CodeJobNotFound, "No job with that name."))
		return
	}
	s.Audit.Record(r.Context(), "job.run", audit.Success, "job:"+name, nil)
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) runtimeInfo() map[string]any {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return map[string]any{
		"version": s.Version, "commit": s.Commit, "go_version": runtime.Version(),
		"started_at": s.StartedAt.UTC(), "uptime_seconds": int64(time.Since(s.StartedAt).Seconds()),
		"goroutines": runtime.NumGoroutine(), "heap_bytes": ms.HeapAlloc, "log_level": logx.Level(),
		"auth_mode": s.Auth.Mode, "store_path": s.Store.Path(), "store_recovered_from_backup": s.Store.RecoveredFrom() != "",
		"store_recovered_from": s.Store.RecoveredFrom(), "tunnels_online": s.Tunnel.OnlineCount(), "ssh_listen": s.SSHListen,
	}
}

func (s *Server) runtime(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DebugRead) {
		return
	}
	writeJSON(w, http.StatusOK, s.runtimeInfo(), nil)
}

func (s *Server) tunnels(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DebugRead) {
		return
	}
	infos := s.Tunnel.Infos()
	out := make([]map[string]any, 0, len(infos))
	s.Store.View(func(st *model.State) {
		for _, in := range infos {
			name := ""
			if d := st.Devices[in.DeviceID]; d != nil {
				name = d.Name
			}
			fw := in.Forwards
			out = append(out, map[string]any{"device_id": in.DeviceID, "device_name": name, "remote_address": in.RemoteAddress,
				"connected_since": in.ConnectedSince, "client_version": in.ClientVersion, "last_keepalive_at": in.LastKeepaliveAt,
				"forwards": nonNil(fw)})
		}
	})
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) setLogLevel(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DebugWrite) {
		return
	}
	var in struct {
		Level string `json:"level"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	switch in.Level {
	case "DEBUG", "INFO", "WARN", "ERROR":
	default:
		s.fail(w, r, apierr.Validation([]apierr.FieldError{{Pointer: "/level", Code: "NOT_ALLOWED", Detail: "Use DEBUG, INFO, WARN or ERROR."}}))
		return
	}
	logx.SetLevel(in.Level)
	if s.OnLogLevel != nil {
		s.OnLogLevel(in.Level)
	}
	s.Audit.Record(r.Context(), "debug.log_level", audit.Success, "settings", map[string]any{"level": in.Level})
	writeJSON(w, http.StatusOK, map[string]string{"level": logx.Level()}, nil)
}

// bundle is a redacted diagnostics download: runtime, jobs, integration,
// tunnels, settings (no secrets exist in settings) and the last 500 log records.
func (s *Server) bundle(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.DebugRead) {
		return
	}
	var st model.Settings
	counts := map[string]int{}
	s.Store.View(func(x *model.State) {
		st = x.Settings
		counts["devices"], counts["users"], counts["groups"], counts["sessions"], counts["enrollments"] =
			len(x.Devices), len(x.Users), len(x.Groups), len(x.Sessions), len(x.Enrollments)
	})
	b := map[string]any{
		"generated_at": time.Now().UTC(), "runtime": s.runtimeInfo(), "jobs": s.Jobs.Statuses(),
		"integration": s.Guac.Last(), "tunnels": s.Tunnel.Infos(), "settings": st, "counts": counts,
		"logs": logx.GetRing().Query(logx.Filter{Limit: 500}),
	}
	s.Audit.Record(r.Context(), "debug.bundle", audit.Success, "diagnostics", nil)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="remotehound-diagnostics-`+time.Now().UTC().Format("20060102-150405")+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(b)
}
