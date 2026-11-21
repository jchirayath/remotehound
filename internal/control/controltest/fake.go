// Package controltest is a fake Docker Engine on a unix socket, for testing
// rh-control and the Services screen without a real Docker daemon. Its inspect
// answers include an environment with a secret, so tests can prove the helper
// never passes container environments on.
package controltest

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Secret is planted in every fake container's environment.
const Secret = "PLANTED_SECRET_hunter2" // gitleaks:allow -- planted test value; tests assert it never leaks

// Container is one fake container.
type Container struct {
	ID, Name, Image, State, Health string
	Labels                         map[string]string
	Logs                           []string // lines, each written as a stderr frame when it contains "ERROR"
}

// Engine is the fake daemon.
type Engine struct {
	Socket string

	mu         sync.Mutex
	containers map[string]*Container
	Calls      []string // "start c1", "restart c2", …
}

// Start serves a fake engine with the given containers until the test ends.
func Start(t *testing.T, cs ...*Container) *Engine {
	t.Helper()
	// unix socket paths are limited to ~104 bytes on macOS: t.TempDir() is too long.
	dir, err := os.MkdirTemp("/tmp", "rhd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	e := &Engine{Socket: filepath.Join(dir, "d.sock"), containers: map[string]*Container{}}
	for _, c := range cs {
		e.containers[c.ID] = c
	}
	l, err := net.Listen("unix", e.Socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: time.Second}
	go srv.Serve(l) //nolint:errcheck // closed at cleanup
	t.Cleanup(func() { srv.Close() })
	return e
}

// State returns a container's current state.
func (e *Engine) State(id string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.containers[id].State
}

func (e *Engine) serve(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	defer e.mu.Unlock()
	path := r.URL.Path
	switch {
	case path == "/_ping":
		w.Write([]byte("OK")) //nolint:errcheck
	case path == "/containers/json":
		var out []map[string]any
		for _, c := range e.containers {
			if _, ok := c.Labels["io.remotehound.control.service"]; !ok && strings.Contains(r.URL.Query().Get("filters"), "io.remotehound.control.service") {
				continue
			}
			out = append(out, map[string]any{"Id": c.ID, "Names": []string{"/" + c.Name}, "Labels": c.Labels})
		}
		json.NewEncoder(w).Encode(out) //nolint:errcheck
	case strings.HasPrefix(path, "/containers/"):
		parts := strings.Split(strings.TrimPrefix(path, "/containers/"), "/")
		c, ok := e.containers[parts[0]]
		if !ok || len(parts) != 2 {
			http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
			return
		}
		switch parts[1] {
		case "json":
			st := map[string]any{"Status": c.State, "ExitCode": 0, "StartedAt": "2026-11-20T10:00:00.000000000Z", "FinishedAt": "0001-01-01T00:00:00Z"}
			if c.State == "exited" {
				st["ExitCode"] = 137
			}
			if c.Health != "" {
				st["Health"] = map[string]any{"Status": c.Health}
			}
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"Id": c.ID, "Name": "/" + c.Name, "State": st, "RestartCount": 2,
				"Config": map[string]any{"Image": c.Image, "Labels": c.Labels, "Tty": false,
					"Env": []string{"DB_PASSWORD=" + Secret}, "Cmd": []string{"--token", Secret}},
			})
		case "start", "stop", "restart":
			if r.Method != http.MethodPost {
				http.Error(w, "method", http.StatusMethodNotAllowed)
				return
			}
			e.Calls = append(e.Calls, parts[1]+" "+c.ID)
			if parts[1] == "stop" {
				c.State = "exited"
			} else {
				c.State = "running"
			}
			w.WriteHeader(http.StatusNoContent)
		case "logs":
			for _, line := range c.Logs {
				stream := byte(1)
				if strings.Contains(line, "ERROR") {
					stream = 2
				}
				payload := []byte("2026-11-20T10:00:01.000000000Z " + line + "\n")
				hdr := make([]byte, 8)
				hdr[0] = stream
				binary.BigEndian.PutUint32(hdr[4:], uint32(len(payload)))
				w.Write(hdr)     //nolint:errcheck
				w.Write(payload) //nolint:errcheck
			}
		default:
			http.Error(w, "unknown", http.StatusNotFound)
		}
	default:
		http.Error(w, "unknown", http.StatusNotFound)
	}
}

// Bundle returns the three standard containers labelled like deploy/compose.yml,
// plus one UNLABELLED container that must never be visible or controllable.
func Bundle() []*Container {
	return []*Container{
		{ID: "c-rh", Name: "rh-remotehound-1", Image: "remotehound:test", State: "running", Health: "healthy",
			Labels: map[string]string{"io.remotehound.control.service": "remotehound", "io.remotehound.control.actions": "restart,logs"}},
		{ID: "c-guac", Name: "rh-guacamole-1", Image: "guacamole/guacamole:1.6.0", State: "running",
			Labels: map[string]string{"io.remotehound.control.service": "guacamole", "io.remotehound.control.actions": "start,stop,restart,logs"},
			Logs:   []string{"10:00:01.000 [main] INFO  o.a.g.GuacamoleServlet - started", "10:00:02.000 [http-1] ERROR o.a.g.a.json - token rejected data=abc123"}},
		{ID: "c-guacd", Name: "rh-guacd-1", Image: "guacamole/guacd:1.6.0", State: "running",
			Labels: map[string]string{"io.remotehound.control.service": "guacd", "io.remotehound.control.actions": "start,stop,restart,logs"},
			Logs:   []string{"guacd[1]: INFO: Guacamole proxy daemon (guacd) version 1.6.0 started", "guacd[1]: WARNING: Unable to connect"}},
		{ID: "c-db", Name: "podcast-mariadb-1", Image: "mariadb:11.4", State: "running", Labels: map[string]string{"com.docker.compose.service": "mariadb"}},
	}
}
