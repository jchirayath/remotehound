package control

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/secrets"
)

// Run serves the helper until ctx ends (`remotehound control`).
func Run(ctx context.Context, cfg *config.ControlConfig, version string) error {
	logx.Init(os.Stdout, logx.Resource{ServiceName: "rh-control", ServiceVersion: version, Environment: cfg.Env}, cfg.LogLevel)
	tok, err := secrets.ControlToken(cfg.Token, cfg.TokenFile)
	if err != nil {
		return err
	}
	if tok.Empty() {
		return errors.New("RH_CONTROL_TOKEN: required")
	}
	d := NewDocker(cfg.DockerSocket)
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if err := d.Ping(pingCtx); err != nil {
		// Not fatal: the engine may be restarting. /healthz reports it and the
		// Services screen says "Docker engine unreachable".
		logx.L().Error("Docker engine not reachable at startup", logx.Event("control.engine"), slog.String("app.socket", cfg.DockerSocket), logx.Err(err))
	}
	cancel()
	srv := &http.Server{Addr: cfg.Listen, Handler: (&Server{Docker: d, Token: tok.Bytes()}).Handler(),
		ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10}
	errc := make(chan error, 1)
	go func() {
		logx.L().Info("rh-control listening", logx.Event("control.listen"), slog.String("server.address", cfg.Listen))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	return srv.Shutdown(sctx)
}

// Healthcheck probes the helper's own /healthz (container HEALTHCHECK).
func Healthcheck(listen string) error {
	addr := listen
	if len(addr) > 0 && addr[0] == ':' {
		addr = "127.0.0.1" + addr
	}
	c := http.Client{Timeout: 4 * time.Second}        // nosemgrep: std.go.default-http-client
	resp, err := c.Get("http://" + addr + "/healthz") // #nosec -- loopback self-probe
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("rh-control healthz: " + resp.Status)
	}
	return nil
}
