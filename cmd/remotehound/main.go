// Command remotehound runs the RemoteHound server.
//
//	remotehound serve         run the server (default)
//	remotehound healthcheck   exit 0 if the local server answers /healthz (container HEALTHCHECK)
//	remotehound control       run the optional rh-control helper (Docker-socket side; see internal/control)
//	remotehound control-healthcheck   HEALTHCHECK for the helper
//	remotehound gen-secret    print fresh RH_SECRET_KEY, RH_GUAC_JSON_SECRET and RH_CONTROL_TOKEN values
//	remotehound config-doc    print every environment variable as a Markdown table
//	remotehound version       print the version
//
// CLI output under cmd/ is the program's user interface, so fmt is used here
// (the std.go.print lint rule exempts cmd/).
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jchirayath/remotehound/internal/app"
	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/core/secrets"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "serve":
		os.Exit(serve())
	case "healthcheck":
		addr := ":8080"
		if cfg, err := config.Load(nil); err == nil {
			addr = cfg.HTTPAddr
		}
		if err := app.Healthcheck(addr); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
	case "control":
		os.Exit(runControl())
	case "control-healthcheck":
		listen := ":9091"
		if cfg, err := config.LoadControl(nil); err == nil {
			listen = cfg.Listen
		}
		if err := control.Healthcheck(listen); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
	case "gen-secret":
		k, err1 := secrets.GenerateHex(32)
		g, err2 := secrets.GenerateHex(16)
		c, err3 := secrets.GenerateHex(32)
		if err1 != nil || err2 != nil || err3 != nil {
			fmt.Fprintln(os.Stderr, "no entropy available")
			os.Exit(1)
		}
		fmt.Printf("RH_SECRET_KEY=%s\nRH_GUAC_JSON_SECRET=%s\n# give the same value to guacamole as JSON_SECRET_KEY\n"+
			"RH_CONTROL_TOKEN=%s\n# only if you run rh-control: the same value goes to both remotehound and rh-control\n", k, g, c)
	case "config-doc":
		fmt.Print(config.Markdown())
	case "version":
		fmt.Printf("remotehound %s (%s)\n", app.Version, app.Commit)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (serve | healthcheck | control | control-healthcheck | gen-secret | config-doc | version)\n", cmd)
		os.Exit(2)
	}
}

// runControl runs the rh-control helper (see internal/control). Same image,
// different process, different container, different privileges.
func runControl() int {
	cfg, err := config.LoadControl(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := control.Run(ctx, cfg, app.Version); err != nil {
		fmt.Fprintln(os.Stderr, "rh-control:", err)
		return 1
	}
	return 0
}

func serve() int {
	cfg, err := config.Load(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	a, err := app.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "startup failed:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		return 1
	}
	return 0
}
