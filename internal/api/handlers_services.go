package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/services"
)

// ---- services (admin) -------------------------------------------------------------
//
// GET  /api/v1/services                          status of every component (+ Guacamole config)
// GET  /api/v1/services/{id}/logs?tail=N         container log tail (via rh-control), redacted
// POST /api/v1/services/{id}/actions/{action}    start | stop | restart (via rh-control), audited

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.ServicesRead) {
		return
	}
	writeJSON(w, http.StatusOK, s.Services.Build(r.Context()), nil)
}

func (s *Server) serviceLogs(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.ServicesRead) {
		return
	}
	tail := 200
	if v := qparam(r, "tail"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > control.MaxTail {
			s.fail(w, r, apierr.Validation([]apierr.FieldError{{Pointer: "/tail", Code: "OUT_OF_RANGE", Detail: "Use 1 to 1000."}}))
			return
		}
		tail = n
	}
	if !s.Control.Configured() {
		s.fail(w, r, apierr.New(http.StatusServiceUnavailable, apierr.CodeControlOff,
			"Container logs need the rh-control helper (RH_CONTROL_URL). RemoteHound's own logs are on the Logs screen."))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	lines, err := s.Control.Logs(ctx, r.PathValue("id"), tail)
	if err != nil {
		s.fail(w, r, controlErr(err))
		return
	}
	type line struct {
		control.LogLine
		Severity string `json:"severity,omitempty"`
	}
	out := make([]line, 0, len(lines))
	for _, l := range lines {
		l.Text = logx.Redact(l.Text) // container output may carry tokens or addresses with credentials
		out = append(out, line{LogLine: l, Severity: control.Problem(l.Text)})
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) serviceAction(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.ServicesControl) {
		return
	}
	id, action := r.PathValue("id"), r.PathValue("action")
	if action != control.ActionStart && action != control.ActionStop && action != control.ActionRestart {
		s.fail(w, r, apierr.Validation([]apierr.FieldError{{Pointer: "/action", Code: "NOT_ALLOWED", Detail: "Use start, stop or restart."}}))
		return
	}
	resource := "service:" + id
	if !s.Control.Configured() {
		s.fail(w, r, apierr.New(http.StatusServiceUnavailable, apierr.CodeControlOff,
			"Container control needs the rh-control helper (RH_CONTROL_URL)."))
		return
	}
	// RemoteHound may only restart itself: stopping it would take down the
	// console needed to start it again. Enforced here whatever the label says.
	if id == services.IDRemoteHound && action != control.ActionRestart {
		s.Audit.Record(r.Context(), "service.action", audit.Denied, resource, map[string]any{"action": action, "reason": "self"})
		s.fail(w, r, apierr.New(http.StatusForbidden, apierr.CodeControlDenied,
			"RemoteHound can only restart itself from here. Stopping it would leave no console to start it again; use the host for that."))
		return
	}

	// Check the target and its allowed actions first, for a clear error.
	lctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	list, err := s.Control.List(lctx)
	cancel()
	if err != nil {
		s.fail(w, r, controlErr(err))
		return
	}
	idx := slices.IndexFunc(list, func(c control.Container) bool { return c.Service == id })
	if idx < 0 {
		s.fail(w, r, apierr.NotFound(apierr.CodeControlTarget, "No container is labelled for "+id+"."))
		return
	}
	if !slices.Contains(list[idx].Actions, action) {
		s.Audit.Record(r.Context(), "service.action", audit.Denied, resource, map[string]any{"action": action, "reason": "label"})
		s.fail(w, r, apierr.New(http.StatusForbidden, apierr.CodeControlDenied, "The "+id+" container does not allow "+action+"."))
		return
	}

	if id == services.IDRemoteHound {
		// Restarting ourselves: answer first, then ask the helper, which
		// finishes the restart even though this process is the one going away.
		s.Audit.Record(r.Context(), "service.action", audit.Success, resource, map[string]any{"action": action, "container": list[idx].Name})
		writeJSON(w, http.StatusAccepted, map[string]any{"service": id, "action": action, "state": "restarting",
			"detail": "RemoteHound is restarting. The page reconnects by itself in about 10 seconds."}, nil)
		ctx := context.WithoutCancel(r.Context())
		go func() {
			time.Sleep(300 * time.Millisecond) // let the response reach the browser
			actx, done := context.WithTimeout(ctx, 60*time.Second)
			defer done()
			if _, err := s.Control.Act(actx, id, action); err != nil {
				logx.L().ErrorContext(ctx, "Self-restart through rh-control failed", logx.Event("service.action"), logx.Err(err))
			}
		}()
		return
	}

	// Once asked, the action runs to the end even if the browser goes away (tab
	// closed, network change): cancelling halfway would leave the container in an
	// unknown state and the audit log claiming a failure for an action that ran.
	// The request's values (actor, request ID) are kept; only its cancellation is not.
	actx, done := context.WithTimeout(context.WithoutCancel(r.Context()), 70*time.Second)
	defer done()
	start := time.Now()
	c, err := s.Control.Act(actx, id, action)
	if err != nil {
		s.Audit.Record(actx, "service.action", audit.Failure, resource, map[string]any{"action": action, "error": err.Error()})
		s.fail(w, r, controlErr(err))
		return
	}
	logx.L().InfoContext(actx, "Service action done", logx.Event("service.action"), slog.String("app.service", id),
		slog.String("app.action", action), slog.Int64("app.duration_ms", time.Since(start).Milliseconds()))
	s.Audit.Record(actx, "service.action", audit.Success, resource, map[string]any{"action": action, "container": c.Name, "state": c.State})
	writeJSON(w, http.StatusOK, map[string]any{"service": id, "action": action, "state": c.State, "container": c}, nil)
}

// controlErr maps helper failures onto client-safe errors.
func controlErr(err error) error {
	var re *control.RemoteError
	switch {
	case errors.Is(err, control.ErrNotConfigured):
		return apierr.New(http.StatusServiceUnavailable, apierr.CodeControlOff, "Container control is not configured (RH_CONTROL_URL).")
	case errors.As(err, &re) && re.Code == "unknown_service":
		return apierr.NotFound(apierr.CodeControlTarget, re.Detail).Wrap(err)
	case errors.As(err, &re) && re.Code == "action_not_allowed":
		return apierr.New(http.StatusForbidden, apierr.CodeControlDenied, re.Detail).Wrap(err)
	case errors.As(err, &re) && re.Code == "engine":
		return apierr.New(http.StatusBadGateway, apierr.CodeControlOff, "The Docker engine refused or failed: "+re.Detail).Wrap(err)
	case errors.As(err, &re) && re.Code == "unauthorized":
		return apierr.New(http.StatusBadGateway, apierr.CodeControlOff,
			"rh-control rejected RemoteHound's token: RH_CONTROL_TOKEN differs between the two containers.").Wrap(err)
	}
	return apierr.New(http.StatusBadGateway, apierr.CodeControlOff, "rh-control is not answering. Check that its container is running.").Wrap(err)
}
