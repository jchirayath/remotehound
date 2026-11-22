package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/auth"
	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/enroll"
	"github.com/jchirayath/remotehound/internal/model"
)

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.fail(w, r, apierr.NotFound(apierr.CodeNotFound, "No such endpoint. See api/openapi.yaml."))
}

// healthz is liveness: the process is serving (OPS-1).
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// readyz checks our own critical dependencies. Guacamole being down is
// reported as degraded but does not fail readiness (REL-7): the UI, enrolment
// and tunnels keep working, and restarting RemoteHound would not fix Guacamole.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	status, code := "ok", http.StatusOK
	if err := s.Store.Writable(); err != nil {
		checks["store"], status, code = "down", "down", http.StatusServiceUnavailable
	} else {
		checks["store"] = "ok"
	}
	if s.Tunnel.Addr() == nil {
		checks["ssh"], status, code = "down", "down", http.StatusServiceUnavailable
	} else {
		checks["ssh"] = "ok"
	}
	checks["guacamole"] = s.Guac.Health()
	if status == "ok" && checks["guacamole"] != "ok" && checks["guacamole"] != "unknown" {
		status = "degraded"
	}
	w.Header().Set("Cache-Control", "no-store")
	if code != http.StatusOK {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
	}
	writeBody(w, map[string]any{"status": status, "checks": checks, "version": s.Version})
}

func writeBody(w http.ResponseWriter, v any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	encodeJSON(w, v)
}

// script serves the bootstrap for /e/{code}[.sh|.ps1]. Wrong codes are
// limited per client (and in total) by the enroll service.
func (s *Server) script(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	ps := strings.Contains(r.UserAgent(), "PowerShell")
	switch {
	case strings.HasSuffix(code, ".ps1"):
		code, ps = strings.TrimSuffix(code, ".ps1"), true
	case strings.HasSuffix(code, ".sh"):
		code, ps = strings.TrimSuffix(code, ".sh"), false
	}
	code = strings.ToLower(code)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	body, state := s.Enroll.Script(code, clientIP(r, s.TrustedProxies), ps)
	logx.L().InfoContext(r.Context(), "Bootstrap script requested", logx.Event("enrollment.script"),
		attrStr("app.enrollment.state", state), attrBool("app.powershell", ps))
	_, _ = w.Write([]byte(body))
}

func (s *Server) redeem(w http.ResponseWriter, r *http.Request) {
	var req enroll.RedeemRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.Enroll.Redeem(r.Context(), clientIP(r, s.TrustedProxies), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, res, nil)
}

func (s *Server) enrollStatus(w http.ResponseWriter, r *http.Request) {
	online, fwds, err := s.Enroll.Status(r.URL.Query().Get("device_id"), r.URL.Query().Get("fingerprint"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if fwds == nil {
		fwds = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"online": online, "forwards": fwds}, nil)
}

// ---- auth -------------------------------------------------------------------

// providers lists the sign-in methods for the login page (public).
func (s *Server) providers(w http.ResponseWriter, r *http.Request) {
	list := s.Auth.Providers.List()
	if list == nil {
		list = []auth.ProviderInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": s.Auth.Mode, "providers": list, "idp_logout_url": s.IdPLogoutURL, "project_url": s.ProjectURL}, nil)
}

// login: dev and proxy sign in directly; oauth with one provider goes straight
// to it; with several, the UI's /login page lets the user choose.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	rd := auth.SafeReturn(r.URL.Query().Get("rd"))
	switch s.Auth.Mode {
	case "dev":
		u, err := s.Auth.DevLogin(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		s.Auth.Sessions.Issue(w, u.ID, u.SessionGen)
		http.Redirect(w, r, rd, http.StatusFound)
	case "proxy":
		// The proxy authenticates. If it let this request through WITHOUT an
		// identity we would redirect to rd, get a 401, come back here… a loop
		// the rate limiter ends with a 429. Explain instead.
		if authz.ActorFrom(r.Context()).Anonymous() {
			http.Redirect(w, r, "/signed-out?reason=proxy", http.StatusFound)
			return
		}
		http.Redirect(w, r, rd, http.StatusFound)
	default:
		if p, ok := s.Auth.Providers.Only(); ok {
			s.startProvider(w, r, p, rd, "")
			return
		}
		http.Redirect(w, r, "/login?rd="+urlEscape(rd), http.StatusFound)
	}
}

func (s *Server) loginWith(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Auth.Providers.Get(r.PathValue("provider"))
	if !ok {
		s.fail(w, r, apierr.NotFound(apierr.CodeNotFound, "That sign-in method is not enabled."))
		return
	}
	s.startProvider(w, r, p, auth.SafeReturn(r.URL.Query().Get("rd")), "")
}

// linkWith starts a flow that adds another sign-in method to the signed-in user.
func (s *Server) linkWith(w http.ResponseWriter, r *http.Request) {
	a := authz.ActorFrom(r.Context())
	if a.Anonymous() {
		http.Redirect(w, r, "/auth/login?rd=/profile", http.StatusFound)
		return
	}
	p, ok := s.Auth.Providers.Get(r.PathValue("provider"))
	if !ok {
		s.fail(w, r, apierr.NotFound(apierr.CodeNotFound, "That sign-in method is not enabled."))
		return
	}
	s.startProvider(w, r, p, "/profile", a.UserID)
}

func (s *Server) startProvider(w http.ResponseWriter, r *http.Request, p auth.Provider, rd, linkTo string) {
	var claim string
	s.Store.View(func(st *model.State) { claim = st.Settings.RolesClaim })
	u, err := p.Start(r.Context(), w, s.Auth.Sessions, auth.NewFlow(rd, linkTo, claim))
	if err != nil {
		s.fail(w, r, apierr.New(http.StatusBadGateway, apierr.CodeUnavailable, "The identity provider could not be reached. Try again shortly.").Wrap(err))
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}

// callback finishes any provider's flow (GET, or POST for Apple's form_post).
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.Auth.Providers.Get(r.PathValue("provider"))
	if !ok {
		s.notFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	}
	f, err := s.Auth.Sessions.TakeFlow(w, r)
	if err == nil && auth.FlowProvider(f) != p.ID() {
		err = errors.New("sign-in started with a different provider")
	}
	var id auth.Identity
	if err == nil {
		id, err = p.Finish(r.Context(), w, r, s.Auth.Sessions, f)
	}
	if err != nil {
		s.Audit.Record(r.Context(), "auth.login", audit.Failure, "", map[string]any{"provider": p.ID(), "reason": err.Error()})
		s.fail(w, r, apierr.New(http.StatusUnauthorized, apierr.CodeUnauthenticated, "Sign-in did not complete: "+err.Error()+". Start again.").Wrap(err))
		return
	}
	linkTo := auth.FlowLink(f)
	if linkTo != "" {
		// Linking requires the same signed-in user who started it.
		if a := authz.ActorFrom(r.Context()); a.Anonymous() || a.UserID != linkTo {
			s.fail(w, r, apierr.Forbidden("Sign in first, then link another account from your profile."))
			return
		}
	}
	u, err := s.Auth.Resolve(r.Context(), id, linkTo, true)
	if err != nil {
		s.Audit.Record(r.Context(), "auth.login", audit.Denied, "", map[string]any{"provider": p.ID(), "email": id.Email})
		s.fail(w, r, err)
		return
	}
	ctx := authz.WithActor(r.Context(), &authz.Actor{UserID: u.ID, Email: u.Email, Role: u.Role})
	if linkTo != "" {
		s.Audit.Record(ctx, "auth.identity_link", audit.Success, "user:"+u.ID, map[string]any{"provider": p.ID()})
	} else {
		s.Auth.Sessions.Issue(w, u.ID, u.SessionGen)
		s.Audit.Record(ctx, "auth.login", audit.Success, "user:"+u.ID, map[string]any{"provider": p.ID()})
	}
	http.Redirect(w, r, auth.FlowReturn(f), http.StatusFound)
}

// logout ends EVERY session of the user (bumps the generation), so a copied
// cookie stops working immediately rather than at its idle timeout.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	a := authz.ActorFrom(r.Context())
	_ = s.Store.Update(func(st *model.State) error {
		if u, ok := st.Users[a.UserID]; ok {
			u.SessionGen++
			u.Touch(time.Now().UTC())
		}
		return nil
	})
	// Guacamole keeps its own token in the browser; without this a desktop
	// (or its token) would outlive Sign out.
	revoked := 0
	if s.GuacSessions != nil {
		revoked = s.GuacSessions.Revoke(r.Context(), a.UserID)
	}
	s.Audit.Record(r.Context(), "auth.logout", audit.Success, "", map[string]any{"guacamole_sessions": revoked})
	s.Auth.Sessions.Clear(w)
	// Behind a sign-in proxy our session is the proxy's: ending only ours
	// would sign the user straight back in on the next request. Tell the
	// browser where to go to end the proxy's session as well.
	if s.Auth.Mode == "proxy" && s.ProxyLogoutURL != "" {
		writeJSON(w, http.StatusOK, map[string]string{"redirect": s.ProxyLogoutURL}, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requireGuacSession gates the Guacamole proxy with our own session (any
// role that may connect); guacGate then ties Guacamole's tokens and connect
// blobs to that user.
func (s *Server) requireGuacSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := authz.ActorFrom(r.Context())
		if a.Anonymous() {
			if r.Method == http.MethodGet && !strings.Contains(r.URL.Path, "/api/") && !strings.Contains(r.URL.Path, "tunnel") {
				http.Redirect(w, r, "/auth/login?rd="+urlEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			s.fail(w, r, apierr.Unauthenticated())
			return
		}
		// Any signed-in user may reach the proxy (a viewer joining a session shared
		// with them needs it); what they can open is decided by the connect blob
		// RemoteHound minted for THEM and the Guacamole token bound to them.
		next.ServeHTTP(w, r)
	})
}

// ---- me ---------------------------------------------------------------------

type meView struct {
	ID          string              `json:"id"`
	Email       string              `json:"email"`
	DisplayName string              `json:"display_name"`
	Role        string              `json:"role"`
	GroupIDs    []string            `json:"group_ids"`
	Permissions []string            `json:"permissions"`
	CSRFToken   string              `json:"csrf_token"`
	Theme       string              `json:"theme"`
	AuthMode    string              `json:"auth_mode"`
	Version     string              `json:"version"`
	Identities  []identityView      `json:"identities"`
	Providers   []auth.ProviderInfo `json:"providers"`
}

type identityView struct {
	Provider string    `json:"provider"`
	Email    string    `json:"email"`
	LinkedAt time.Time `json:"linked_at"`
}

func (s *Server) meFor(r *http.Request) meView {
	a := authz.ActorFrom(r.Context())
	sess := sessionFrom(r.Context())
	v := meView{ID: a.UserID, Email: a.Email, DisplayName: a.Name, Role: a.Role, GroupIDs: a.GroupIDs,
		Permissions: authz.Permissions(a), AuthMode: s.Auth.Mode, Version: s.Version, Theme: "system"}
	if v.GroupIDs == nil {
		v.GroupIDs = []string{}
	}
	if sess != nil {
		v.CSRFToken = sess.CSRF
	}
	v.Identities = []identityView{}
	s.Store.View(func(st *model.State) {
		if u, ok := st.Users[a.UserID]; ok {
			if u.Theme != "" {
				v.Theme = u.Theme
			}
			for _, i := range u.Identities {
				v.Identities = append(v.Identities, identityView{Provider: i.Provider, Email: i.Email, LinkedAt: i.LinkedAt})
			}
		}
	})
	v.Providers = s.Auth.Providers.List()
	if v.Providers == nil {
		v.Providers = []auth.ProviderInfo{}
	}
	return v
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.meFor(r), nil)
}

func (s *Server) preferences(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Theme string `json:"theme"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	switch in.Theme {
	case "system", "light", "dark":
	default:
		s.fail(w, r, apierr.Validation([]apierr.FieldError{{Pointer: "/theme", Code: "NOT_ALLOWED", Detail: "Use system, light or dark."}}))
		return
	}
	a := authz.ActorFrom(r.Context())
	err := s.Store.Update(func(st *model.State) error {
		u, ok := st.Users[a.UserID]
		if !ok {
			return apierr.NotFound(apierr.CodeUserNotFound, "User not found.")
		}
		u.Theme = in.Theme
		u.Touch(time.Now().UTC())
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, s.meFor(r), nil)
}

// unlinkIdentity removes one sign-in method; the last one cannot be removed.
func (s *Server) unlinkIdentity(w http.ResponseWriter, r *http.Request) {
	a := authz.ActorFrom(r.Context())
	prov := r.PathValue("provider")
	err := s.Store.Update(func(st *model.State) error {
		u, ok := st.Users[a.UserID]
		if !ok {
			return apierr.NotFound(apierr.CodeUserNotFound, "User not found.")
		}
		kept := u.Identities[:0]
		for _, i := range u.Identities {
			if i.Provider != prov {
				kept = append(kept, i)
			}
		}
		if len(kept) == len(u.Identities) {
			return apierr.NotFound(apierr.CodeNotFound, "That sign-in method is not linked.")
		}
		if len(kept) == 0 {
			return apierr.Conflict(apierr.CodeLastAdmin, "Keep at least one sign-in method, or you could not sign in again.")
		}
		u.Identities = kept
		u.Touch(time.Now().UTC())
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "auth.identity_unlink", audit.Success, "user:"+a.UserID, map[string]any{"provider": prov})
	writeJSON(w, http.StatusOK, s.meFor(r), nil)
}

// ---- overview ----------------------------------------------------------------

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	a := authz.ActorFrom(r.Context())
	now := time.Now().UTC()
	out := map[string]any{}
	total, online, pending, active, day, open, groups := 0, 0, 0, 0, 0, 0, 0
	s.Store.View(func(st *model.State) {
		visible := map[string]bool{}
		for _, d := range st.Devices {
			if !authz.SeesGroup(a, d.GroupID) {
				continue
			}
			visible[d.ID] = true
			total++
			if s.Tunnel.Online(d.ID) {
				online++
			} else if d.LastSeenAt.IsZero() {
				pending++
			}
		}
		for _, ss := range st.Sessions {
			if !visible[ss.DeviceID] {
				continue
			}
			if ss.EndedAt.IsZero() {
				active++
			}
			if now.Sub(ss.StartedAt) < 24*time.Hour {
				day++
			}
		}
		for _, g := range st.Groups {
			if authz.SeesGroup(a, g.ID) {
				groups++
			}
		}
		for _, e := range st.Enrollments {
			if e.State(now) == "open" && (authz.SeesGroup(a, e.GroupID) || e.CreatedBy == a.UserID) {
				open++
			}
		}
	})
	out["devices_total"], out["devices_online"], out["devices_pending"] = total, online, pending
	out["sessions_active"], out["sessions_24h"], out["enrollments_open"] = active, day, open
	out["groups_total"] = groups
	out["guacamole"] = s.Guac.Health()
	out["jobs_failing"] = s.Jobs.Failing()
	recent := []any{}
	if authz.Can(a, authz.AuditRead, authz.Any) {
		evs, _ := s.Audit.List(auditQuery("", "", 10))
		for _, e := range evs {
			recent = append(recent, e)
		}
	}
	out["recent_activity"] = recent
	writeJSON(w, http.StatusOK, out, nil)
}
