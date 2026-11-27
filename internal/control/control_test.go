// @feature:services
package control_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/control/controltest"
)

const token = "0123456789abcdef0123456789abcdef0123456789abcdef" // gitleaks:allow -- test fixture

func helper(t *testing.T) (*controltest.Engine, *httptest.Server, *control.Client) {
	t.Helper()
	eng := controltest.Start(t, controltest.Bundle()...)
	srv := httptest.NewServer((&control.Server{Docker: control.NewDocker(eng.Socket), Token: []byte(token)}).Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return eng, srv, control.NewClient(u, []byte(token))
}

func TestListShowsOnlyLabeledContainersAndNoEnvironment(t *testing.T) {
	_, srv, c := helper(t)
	list, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("want the 3 labeled containers, got %d: %+v", len(list), list)
	}
	for _, x := range list {
		if x.Name == "podcast-mariadb-1" {
			t.Fatal("unlabeled container must never be listed")
		}
	}
	// The raw wire answer must not carry the planted secret from Env/Cmd.
	req, _ := http.NewRequest("GET", srv.URL+"/v1/services", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(b, []byte(controltest.Secret)) {
		t.Fatal("container environment leaked through rh-control")
	}
	g := list[slicesIndex(list, "guacamole")]
	if g.State != "running" || g.RestartCount != 2 || strings.Join(g.Actions, ",") != "start,stop,restart,logs" {
		t.Fatalf("guacamole view: %+v", g)
	}
}

func slicesIndex(l []control.Container, svc string) int {
	for i, x := range l {
		if x.Service == svc {
			return i
		}
	}
	return -1
}

func TestTokenRequired(t *testing.T) {
	_, srv, _ := helper(t)
	for _, auth := range []string{"", "Bearer wrong", "Basic " + token, "Bearer " + token + "x"} {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/services/guacamole/restart", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("auth %q: got %d, want 401", auth, resp.StatusCode)
		}
	}
	// healthz is the only unauthenticated route.
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
}

func TestActionsAreLimitedToTheLabel(t *testing.T) {
	eng, _, c := helper(t)
	ctx := context.Background()
	if _, err := c.Act(ctx, "remotehound", "stop"); !control.IsRemote(err, "action_not_allowed") {
		t.Fatalf("stop remotehound: want action_not_allowed, got %v", err)
	}
	if _, err := c.Act(ctx, "mariadb", "restart"); !control.IsRemote(err, "unknown_service") {
		t.Fatalf("unlabeled container: want unknown_service, got %v", err)
	}
	if _, err := c.Act(ctx, "guacamole", "exec"); err == nil {
		t.Fatal("unknown action accepted")
	}
	got, err := c.Act(ctx, "guacd", "stop")
	if err != nil || got.State != "exited" || eng.State("c-guacd") != "exited" {
		t.Fatalf("stop guacd: %v %+v", err, got)
	}
	if _, err := c.Act(ctx, "guacd", "start"); err != nil || eng.State("c-guacd") != "running" {
		t.Fatalf("start guacd: %v", err)
	}
	if _, err := c.Act(ctx, "remotehound", "restart"); err != nil {
		t.Fatalf("restart remotehound: %v", err)
	}
	for _, call := range eng.Calls {
		if strings.Contains(call, "c-db") || strings.HasPrefix(call, "stop c-rh") {
			t.Fatalf("forbidden call reached the engine: %s", call)
		}
	}
}

func TestLogsDemuxAndProblemClassification(t *testing.T) {
	_, _, c := helper(t)
	lines, err := c.Logs(context.Background(), "guacamole", 50)
	if err != nil || len(lines) != 2 {
		t.Fatalf("logs: %v %+v", err, lines)
	}
	if lines[1].Stream != "stderr" || lines[1].Time.IsZero() || !strings.Contains(lines[1].Text, "token rejected") {
		t.Fatalf("line: %+v", lines[1])
	}
	if control.Problem(lines[1].Text) != "error" || control.Problem(lines[0].Text) != "" {
		t.Fatal("classification")
	}
	for text, want := range map[string]string{
		"guacd[1]: WARNING: Unable to connect":           "warn",
		"guacd[1]: ERROR: Connection failed":             "error",
		`{"level":"error","msg":"tls handshake"}`:        "error",
		`{"severity_text":"WARN","body":"slow"}`:         "warn",
		"10:00 [main] INFO  o.a.g.GuacamoleServlet - ok": "",
		"java.lang.NullPointerException at Foo.bar":      "error",
	} {
		if got := control.Problem(text); got != want {
			t.Errorf("Problem(%q) = %q, want %q", text, got, want)
		}
	}
	if _, err := c.Logs(context.Background(), "guacamole", 5000); err == nil {
		t.Fatal("tail above the cap accepted")
	}
}

func TestDemuxRejectsImplausibleFrames(t *testing.T) {
	var b bytes.Buffer
	hdr := make([]byte, 8)
	hdr[0] = 1
	binary.BigEndian.PutUint32(hdr[4:], 1<<30)
	b.Write(hdr)
	if _, err := control.Demux(&b); err == nil {
		t.Fatal("a 1 GiB frame header must be refused")
	}
}

func TestParseActionsAndNames(t *testing.T) {
	if got := strings.Join(control.ParseActions(" Logs, restart,exec,stop,restart "), ","); got != "stop,restart,logs" {
		t.Fatalf("ParseActions = %q", got)
	}
	for name, ok := range map[string]bool{"guacd": true, "rh-guac2": true, "": false, "Guacd": false, "1abc": false, "a/b": false, strings.Repeat("a", 33): false} {
		if control.ValidServiceName(name) != ok {
			t.Errorf("ValidServiceName(%q) != %v", name, ok)
		}
	}
}

func TestErrorBodyShape(t *testing.T) {
	_, srv, _ := helper(t)
	req, _ := http.NewRequest("POST", srv.URL+"/v1/services/nope/restart", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e control.RemoteError
	if json.NewDecoder(resp.Body).Decode(&e) != nil || e.Code != "unknown_service" || resp.StatusCode != 404 {
		t.Fatalf("error body: %d %+v", resp.StatusCode, e)
	}
}
