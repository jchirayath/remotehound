package api

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/jchirayath/remotehound/internal/auth"
	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/jobs"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/device"
	"github.com/jchirayath/remotehound/internal/enroll"
	"github.com/jchirayath/remotehound/internal/guac"
	"github.com/jchirayath/remotehound/internal/services"
	"github.com/jchirayath/remotehound/internal/tunnel"
)

// Server holds the dependencies every handler needs.
type Server struct {
	Store          store.Store
	Audit          *audit.Log
	Auth           *auth.Authenticator
	Devices        *device.Service
	Enroll         *enroll.Service
	Tunnel         *tunnel.Server
	Guac           *guac.Checker
	Jobs           *jobs.Registry
	TrustedProxies []netip.Prefix
	RecordingsDir  string
	Version        string
	Commit         string
	StartedAt      time.Time
	SSHListen      string
	Static         http.Handler   // the SPA (index.html fallback)
	Docs           http.Handler   // /docs/{page}.md
	GuacProxy      http.Handler   // <GuacPath>/*
	GuacPath       string         // e.g. /guacamole
	GuacSessions   *guac.Sessions // binds Guacamole tokens and connect blobs to users (nil: no binding)
	OnLogLevel     func(level string)
	Services       *services.Sources // the Services screen's report builder
	Control        *control.Client   // nil when rh-control is not configured
	// ProxyLogoutURL (proxy mode): where Sign out sends the browser so the
	// proxy's own session ends too; IdPLogoutURL is offered on /signed-out.
	ProxyLogoutURL string
	IdPLogoutURL   string
	// ProjectURL is where Overview's "Learn more" link goes (RH_PROJECT_URL).
	ProjectURL string
	// AllowHTTPPublicURL permits an http public_url (development only): the
	// bootstrap pins the SSH host key from what it downloads, so production is https.
	AllowHTTPPublicURL bool
}

// Routes builds the HTTP handler. Patterns double as the http.route log
// attribute (LOG-1), so keep them templated.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	if s.GuacPath != "" {
		guacPrefix = s.GuacPath + "/"
	}
	public := newLimiter(30, 10)   // script fetch / redeem / status poll per IP
	login := newLimiter(20, 10)    // login starts and callbacks per IP
	authed := newLimiter(600, 120) // per user
	connect := newLimiter(60, 20)  // connect mints per user

	pub := func(h http.HandlerFunc) http.Handler { return s.limit(public, h) }
	priv := func(h http.HandlerFunc) http.Handler { return s.requireAuth(s.limit(authed, h)) }

	// Public.
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.Handle("GET /e/{code}", pub(s.script))
	mux.Handle("POST /api/v1/enroll", pub(s.redeem))
	mux.Handle("GET /api/v1/enroll/status", s.limit(newLimiter(120, 40), http.HandlerFunc(s.enrollStatus)))

	// Auth.
	mux.HandleFunc("GET /auth/providers", s.providers)
	mux.Handle("GET /auth/login", s.limit(login, http.HandlerFunc(s.login)))
	mux.Handle("GET /auth/login/{provider}", s.limit(login, http.HandlerFunc(s.loginWith)))
	mux.Handle("GET /auth/link/{provider}", s.limit(login, http.HandlerFunc(s.linkWith)))
	mux.Handle("GET /auth/callback/{provider}", s.limit(login, http.HandlerFunc(s.callback)))
	mux.Handle("POST /auth/callback/{provider}", s.limit(login, http.HandlerFunc(s.callback))) // Apple form_post; state-checked, no session needed
	mux.Handle("POST /auth/logout", s.requireAuth(http.HandlerFunc(s.logout)))

	// Me.
	mux.Handle("GET /api/v1/me", priv(s.me))
	mux.Handle("PUT /api/v1/me/preferences", priv(s.preferences))
	mux.Handle("GET /api/v1/overview", priv(s.overview))

	// Devices.
	mux.Handle("GET /api/v1/devices", priv(s.listDevices))
	mux.Handle("POST /api/v1/devices", priv(s.createDevice))
	mux.Handle("GET /api/v1/devices/{id}", priv(s.getDevice))
	mux.Handle("PATCH /api/v1/devices/{id}", priv(s.patchDevice))
	mux.Handle("DELETE /api/v1/devices/{id}", priv(s.deleteDevice))
	mux.Handle("PUT /api/v1/devices/{id}/services/{kind}", priv(s.putService))
	mux.Handle("DELETE /api/v1/devices/{id}/services/{kind}", priv(s.deleteService))
	mux.Handle("POST /api/v1/devices/{id}/connect", s.requireAuth(s.limit(connect, http.HandlerFunc(s.connectDevice))))
	mux.Handle("POST /api/v1/devices/{id}/reconnect", priv(s.reconnectDevice))
	mux.Handle("POST /api/v1/devices/{id}/disable", priv(s.disableDevice))
	mux.Handle("POST /api/v1/devices/{id}/enable", priv(s.enableDevice))
	mux.Handle("POST /api/v1/devices/{id}/probe", priv(s.probeDevice))
	mux.Handle("GET /api/v1/devices/{id}/logs", priv(s.deviceLogs))

	// Enrolments.
	mux.Handle("GET /api/v1/enrollments", priv(s.listEnrollments))
	mux.Handle("POST /api/v1/enrollments", priv(s.createEnrollment))
	mux.Handle("GET /api/v1/enrollments/{id}", priv(s.getEnrollment))
	mux.Handle("DELETE /api/v1/enrollments/{id}", priv(s.revokeEnrollment))
	mux.Handle("PATCH /api/v1/enrollments/{id}", priv(s.updateEnrollment))
	mux.Handle("POST /api/v1/enrollments/cleanup", priv(s.cleanupEnrollments))

	// Groups and users.
	mux.Handle("GET /api/v1/groups", priv(s.listGroups))
	mux.Handle("POST /api/v1/groups", priv(s.createGroup))
	mux.Handle("GET /api/v1/groups/{id}", priv(s.getGroup))
	mux.Handle("PATCH /api/v1/groups/{id}", priv(s.patchGroup))
	mux.Handle("DELETE /api/v1/groups/{id}", priv(s.deleteGroup))
	mux.Handle("GET /api/v1/users", priv(s.listUsers))
	mux.Handle("POST /api/v1/users", priv(s.createUser))
	mux.Handle("GET /api/v1/users/{id}", priv(s.getUser))
	mux.Handle("PATCH /api/v1/users/{id}", priv(s.patchUser))
	mux.Handle("DELETE /api/v1/users/{id}", priv(s.deleteUser))

	// Sessions and recordings.
	mux.Handle("GET /api/v1/sessions", priv(s.listSessions))
	mux.Handle("POST /api/v1/sessions/{id}/terminate", priv(s.terminateSession))
	mux.Handle("POST /api/v1/sessions/{id}/shares", priv(s.shareSession))
	mux.Handle("DELETE /api/v1/sessions/{id}/shares/{user_id}", priv(s.unshareSession))
	mux.Handle("POST /api/v1/sessions/{id}/join", s.requireAuth(s.limit(connect, http.HandlerFunc(s.joinSession))))
	mux.Handle("GET /api/v1/directory", priv(s.directory))
	mux.Handle("GET /api/v1/me/credentials", priv(s.myCredentials))
	mux.Handle("PUT /api/v1/me/credentials/{device_id}/{service}", priv(s.saveCredential))
	mux.Handle("DELETE /api/v1/me/credentials/{device_id}/{service}", priv(s.deleteCredential))
	mux.Handle("DELETE /api/v1/me/identities/{provider}", priv(s.unlinkIdentity))
	mux.Handle("GET /api/v1/recordings", priv(s.listRecordings))
	mux.Handle("GET /api/v1/recordings/{name}", priv(s.getRecording))

	// Settings and integration.
	mux.Handle("GET /api/v1/settings", priv(s.getSettings))
	mux.Handle("PATCH /api/v1/settings", priv(s.patchSettings))
	mux.Handle("GET /api/v1/integration", priv(s.getIntegration))
	mux.Handle("POST /api/v1/integration/test", priv(s.testIntegration))
	mux.Handle("GET /api/v1/services", priv(s.listServices))
	mux.Handle("GET /api/v1/services/{id}/logs", priv(s.serviceLogs))
	mux.Handle("POST /api/v1/services/{id}/actions/{action}", s.requireAuth(s.limit(newLimiter(30, 10), http.HandlerFunc(s.serviceAction))))

	// Observability and debugging.
	mux.Handle("GET /api/v1/audit", priv(s.listAudit))
	mux.Handle("GET /api/v1/logs", priv(s.queryLogs))
	mux.Handle("GET /api/v1/logs/stream", s.requireAuth(http.HandlerFunc(s.streamLogs)))
	mux.Handle("GET /api/v1/jobs", priv(s.listJobs))
	mux.Handle("POST /api/v1/jobs/{name}/run", priv(s.runJob))
	mux.Handle("GET /api/v1/debug/runtime", priv(s.runtime))
	mux.Handle("GET /api/v1/debug/tunnels", priv(s.tunnels))
	mux.Handle("PUT /api/v1/debug/log-level", priv(s.setLogLevel))
	mux.Handle("GET /api/v1/debug/bundle", priv(s.bundle))

	// Unknown API paths are problem+json, not the SPA.
	mux.Handle("/api/", http.HandlerFunc(s.notFound))

	// Guacamole (authenticated: our session is checked before Guacamole's token).
	if s.GuacProxy != nil {
		mux.Handle(s.GuacPath+"/", s.requireGuacSession(s.guacGate(s.GuacProxy)))
	}
	if s.Docs != nil {
		mux.Handle("GET /docs/{page}", s.Docs)
	}
	if s.Static != nil {
		mux.Handle("/", s.Static)
	}
	return s.observe(securityHeaders(s.authenticate(mux)))
}
