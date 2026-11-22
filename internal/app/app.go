// Package app assembles RemoteHound: it loads config and secrets, opens the
// store and audit log, builds the domain services, the tunnel server, the
// HTTP server and the background jobs, and runs them until shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/docs"
	"github.com/jchirayath/remotehound/internal/api"
	"github.com/jchirayath/remotehound/internal/auth"
	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/core/httpx"
	"github.com/jchirayath/remotehound/internal/core/jobs"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/metrics"
	"github.com/jchirayath/remotehound/internal/core/secrets"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/device"
	"github.com/jchirayath/remotehound/internal/enroll"
	"github.com/jchirayath/remotehound/internal/guac"
	"github.com/jchirayath/remotehound/internal/model"
	"github.com/jchirayath/remotehound/internal/services"
	"github.com/jchirayath/remotehound/internal/tunnel"
	"github.com/jchirayath/remotehound/internal/web"
	uiweb "github.com/jchirayath/remotehound/web"
)

// Build metadata, set with -ldflags at release time.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

// App is the assembled process.
type App struct {
	Cfg     *config.Config
	Store   *store.FileStore
	Audit   *audit.Log
	Secrets *secrets.Set
	Tunnel  *tunnel.Server
	Devices *device.Service
	Enroll  *enroll.Service
	Guac    *guac.Checker
	Jobs    *jobs.Registry
	API     *api.Server
	Handler http.Handler
}

// New builds the app from cfg without starting listeners.
func New(cfg *config.Config) (*App, error) {
	version := Version
	if cfg.Version != "" {
		version = cfg.Version
	}
	logx.Init(os.Stdout, logx.Resource{ServiceName: "remotehound", ServiceVersion: version, Environment: cfg.Env}, cfg.LogLevel)

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("data dir: %w", err)
	}
	sec, err := secrets.Load(cfg)
	if err != nil {
		return nil, err
	}
	sshHost := cfg.PublicURL.Hostname()
	st, err := store.Open(cfg.DataDir, func(s *model.State) {
		s.Settings = model.DefaultSettings(cfg.PublicURL.String(), sshHost, cfg.SSHPublicPort)
		s.Settings.LogLevel = cfg.LogLevel
	})
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if from := st.RecoveredFrom(); from != "" {
		logx.L().Error("State recovered from backup", logx.Event("store.recovered"), slog.String("app.file", from))
	}
	var runtimeLevel string
	st.View(func(s *model.State) { runtimeLevel = s.Settings.LogLevel })
	if runtimeLevel != "" {
		logx.SetLevel(runtimeLevel)
	}
	aud, err := audit.Open(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}

	devs := &device.Service{Store: st, Audit: aud, Secrets: sec, PortMin: cfg.TunnelPortMin, PortMax: cfg.TunnelPortMax,
		TunnelHost: cfg.TunnelAdvertiseHost, GuacPublicPath: cfg.GuacPublicPath, GuacRecordingPath: cfg.GuacRecordingPath}
	tun, err := tunnel.New(tunnel.Config{ListenAddr: cfg.SSHAddr, BindHost: cfg.TunnelBind,
		HostKeyPath: filepath.Join(cfg.DataDir, "ssh_host_ed25519_key"), Hooks: devs})
	if err != nil {
		return nil, fmt.Errorf("tunnel: %w", err)
	}
	devs.Tunnel = tun
	enr := &enroll.Service{Store: st, Audit: aud, Secrets: sec, Devices: devs, Tunnel: tun, AllowHTTP: cfg.Development()}
	tun.SetEnroller(enr) // script-free enrolment over SSH (ADR-0005)

	internalHTTP := httpx.New(httpx.Options{Timeout: 8 * time.Second, AllowPrivate: []string{cfg.GuacURL.Hostname()}})
	checker := &guac.Checker{GuacURL: cfg.GuacURL, GuacdAddr: cfg.GuacdAddr, Key: sec.GuacJSONKey.Bytes(), HTTP: internalHTTP,
		TunnelAdvertiseHost: cfg.TunnelAdvertiseHost, RecordingsDir: cfg.RecordingsDir,
		RecordingEnabled: func() bool {
			on := false
			st.View(func(s *model.State) { on = s.Settings.RecordingEnabled })
			return on
		}}

	sessions := &auth.Sessions{Key: sec.SessionKey.Bytes(), Secure: cfg.PublicURL.Scheme == "https"}
	authn := &auth.Authenticator{Mode: cfg.AuthMode, Store: st, Audit: aud, Sessions: sessions, BootstrapAdmin: cfg.BootstrapAdmin,
		TrustedProxies: cfg.TrustedProxies, ProxyEmail: cfg.ProxyEmailHeader, ProxyName: cfg.ProxyNameHeader,
		ProxyGroups: cfg.ProxyGroupsHeader, ProxySubject: cfg.ProxySubjectHeader, ProxySecret: sec.ProxySecret.Bytes()}
	switch cfg.AuthMode {
	case "oauth":
		var ps []auth.Provider
		for _, pc := range cfg.Providers {
			cs, key := sec.Provider(pc.ID)
			p, err := auth.Build(pc, auth.Credentials{ClientSecret: cs, AppleKeyPEM: key}, cfg.PublicURL.String())
			if err != nil {
				return nil, fmt.Errorf("auth provider %s: %w", pc.ID, err)
			}
			ps = append(ps, p)
		}
		if authn.Providers, err = auth.NewRegistry(ps...); err != nil {
			return nil, err
		}
		logx.L().Info("Sign-in providers enabled", logx.Event("auth.providers"), slog.String("app.providers", strings.Join(authn.Providers.IDs(), ",")))
	case "dev":
		authn.BootstrapAdmin = "dev@localhost"
	}

	reg := jobs.New()
	a := &App{Cfg: cfg, Store: st, Audit: aud, Secrets: sec, Tunnel: tun, Devices: devs, Enroll: enr, Guac: checker, Jobs: reg}
	a.registerJobs()

	srv := &api.Server{Store: st, Audit: aud, Auth: authn, Devices: devs, Enroll: enr, Tunnel: tun, Guac: checker, Jobs: reg,
		TrustedProxies: cfg.TrustedProxies, RecordingsDir: cfg.RecordingsDir, Version: version, Commit: Commit,
		StartedAt: time.Now(), SSHListen: cfg.SSHAddr, Static: web.SPA(uiweb.UI()), Docs: web.Docs(docs.User),
		GuacProxy: web.GuacProxy(cfg.GuacURL, cfg.ProxyEmailHeader, cfg.ProxyNameHeader, cfg.ProxyGroupsHeader, cfg.ProxySubjectHeader), GuacPath: cfg.GuacPublicPath,
		GuacSessions: &guac.Sessions{GuacURL: cfg.GuacURL, HTTP: internalHTTP, Key: sec.GuacJSONKey.Bytes()}, AllowHTTPPublicURL: cfg.Development()}
	var ctl *control.Client
	if cfg.ControlURL != "" {
		u, _ := url.Parse(cfg.ControlURL) // validated by config.Load
		ctl = control.NewClient(u, sec.ControlToken.Bytes())
		logx.L().Info("Container control enabled", logx.Event("control.enabled"), slog.String("server.address", u.Host))
	}
	setting := func(f func(model.Settings) any) func() any {
		return func() any {
			var v any
			st.View(func(s *model.State) { v = f(s.Settings) })
			return v
		}
	}
	publicURL, sshPort := setting(func(s model.Settings) any { return s.PublicURL }), setting(func(s model.Settings) any { return s.SSHPublicPort })
	srv.Control = ctl
	srv.ProxyLogoutURL, srv.IdPLogoutURL, srv.ProjectURL = cfg.ProxyLogoutURL, cfg.IdPLogoutURL, cfg.ProjectURL
	srv.Services = &services.Sources{
		Version: version, StartedAt: srv.StartedAt, HTTPAddr: cfg.HTTPAddr, SSHListen: cfg.SSHAddr,
		PublicURL:     func() string { return publicURL().(string) },
		SSHPublicPort: func() int { return sshPort().(int) },
		TunnelOnline:  tun.OnlineCount, TunnelUp: func() bool { return tun.Addr() != nil },
		TunnelPortMin: cfg.TunnelPortMin, TunnelPortMax: cfg.TunnelPortMax, TunnelBind: cfg.TunnelBind,
		StoreWritable: st.Writable, StorePath: st.Path(), StoreRecovered: st.RecoveredFrom,
		Guac: checker.Last, GuacURL: cfg.GuacURL, GuacPublicPath: cfg.GuacPublicPath, GuacdAddr: cfg.GuacdAddr,
		GuacKey: sec.GuacJSONKey.Bytes(), TunnelHost: cfg.TunnelAdvertiseHost, RecordingOn: checker.RecordingEnabled,
		RecordingPath: cfg.GuacRecordingPath, Logs: logx.GetRing().Query, Control: ctl,
	}
	authn.OnAccessChange = srv.EndUserAccess // IdP role-mapping changes end live sessions too
	a.API = srv
	a.Handler = srv.Routes()

	metrics.Default.GaugeFunc("remotehound_tunnels_online", "Devices with a live tunnel.", func() float64 { return float64(tun.OnlineCount()) })
	metrics.Default.GaugeFunc("remotehound_jobs_failing", "Jobs with consecutive failures.", func() float64 { return float64(reg.Failing()) })
	metrics.Default.GaugeFunc("remotehound_guacamole_up", "1 when the last Guacamole integration check passed.", func() float64 {
		if checker.Health() == "ok" {
			return 1
		}
		return 0
	})
	return a, nil
}

// Run starts every listener and job and blocks until ctx is cancelled, then
// drains in-flight requests and jobs (OPS-1).
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 3)
	tunnelDone := make(chan struct{})
	go func() {
		if err := a.Tunnel.Serve(ctx); err != nil {
			errc <- err
		}
		close(tunnelDone)
	}()

	httpSrv := &http.Server{Addr: a.Cfg.HTTPAddr, Handler: a.Handler, ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		logx.L().Info("HTTP server listening", logx.Event("http.listen"), slog.String("server.address", a.Cfg.HTTPAddr))
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	metricsSrv := &http.Server{Addr: a.Cfg.MetricsAddr, Handler: a.metricsHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logx.L().Error("Metrics listener failed", logx.Event("metrics.listen"), logx.Err(err))
		}
	}()

	a.Jobs.Start(ctx)
	a.Audit.Record(ctx, "system.start", audit.Success, "system", map[string]any{"version": a.API.Version})

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
		logx.L().Error("Listener failed; shutting down", logx.Event("system.listener_failed"), logx.Err(runErr))
	}
	cancel()
	shutCtx, done := context.WithTimeout(context.Background(), 20*time.Second)
	defer done()
	_ = httpSrv.Shutdown(shutCtx)
	_ = metricsSrv.Shutdown(shutCtx)
	select { // tunnels close (devices reconnect to the next instance on their own)
	case <-tunnelDone:
	case <-shutCtx.Done():
	}
	a.Jobs.Wait()
	a.Audit.Record(context.Background(), "system.stop", audit.Success, "system", nil)
	_ = a.Audit.Close()
	return runErr
}

func (a *App) metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		metrics.Default.Write(w)
	})
	if a.Cfg.DebugPprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		logx.L().Warn("pprof enabled on the metrics listener", logx.Event("debug.pprof"))
	}
	return mux
}

// Healthcheck probes the local HTTP listener (used by the container
// HEALTHCHECK; the distroless image has no curl).
func Healthcheck(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if _, err := strconv.Atoi(port); err != nil {
		return err
	}
	// Loopback self-probe for the container HEALTHCHECK, not an outbound call.
	c := http.Client{Timeout: 3 * time.Second}                                // nosemgrep: std.go.default-http-client
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz") // #nosec -- loopback self-probe, not outbound
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}
