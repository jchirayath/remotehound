// Services screen, rh-control and proxy sign-out, end to end in-process: the
// real API, a real rh-control server, and a fake Docker engine on a unix socket.
//
// @kind:integration
// @feature:services
package integration

import (
	"context"
	"encoding/json"
	"github.com/jchirayath/remotehound/internal/model"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jchirayath/remotehound/internal/app"
	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/control/controltest"
	"github.com/jchirayath/remotehound/internal/core/config"
)

const ctlToken = "feedfacefeedfacefeedfacefeedfacefeedfacefeedface"

func startWithControl(t *testing.T) (*harness, *controltest.Engine) {
	eng := controltest.Start(t, controltest.Bundle()...)
	ctl := httptest.NewServer((&control.Server{Docker: control.NewDocker(eng.Socket), Token: []byte(ctlToken)}).Handler())
	t.Cleanup(ctl.Close)
	return startWith(t, map[string]string{"RH_CONTROL_URL": ctl.URL, "RH_CONTROL_TOKEN": ctlToken}), eng
}

type svcReport struct {
	Data struct {
		Overall string `json:"overall"`
		Control struct {
			Configured, Reachable bool
		} `json:"control"`
		Services []struct {
			ID, Status string
			Container  *control.Container
			Problems   []struct{ Severity, Text, Source string }
			Endpoints  []struct{ Label, Address, Exposure string }
		} `json:"services"`
		Guacamole struct {
			SecretFingerprint string `json:"secret_fingerprint"`
			UserDatabase      string `json:"user_database"`
		} `json:"guacamole"`
	} `json:"data"`
}

func TestServicesReportWithControl(t *testing.T) {
	h, _ := startWithControl(t)
	var rep svcReport
	h.do("GET", "/api/v1/services", nil, 200, &rep)
	if !rep.Data.Control.Configured || !rep.Data.Control.Reachable {
		t.Fatalf("control: %+v", rep.Data.Control)
	}
	ids := map[string]int{}
	for i, s := range rep.Data.Services {
		ids[s.ID] = i
	}
	for _, id := range []string{"remotehound", "tunnel", "store", "guacamole", "guacd"} {
		if _, ok := ids[id]; !ok {
			t.Fatalf("missing card %s: %+v", id, ids)
		}
	}
	if _, ok := ids["mariadb"]; ok {
		t.Fatal("an unlabelled container got a card")
	}
	g := rep.Data.Services[ids["guacamole"]]
	if g.Container == nil || g.Container.Name != "rh-guacamole-1" {
		t.Fatalf("guacamole container not merged: %+v", g.Container)
	}
	found := false
	for _, p := range g.Problems {
		if p.Source == "container" && p.Severity == "error" && strings.Contains(p.Text, "token rejected") {
			found = true
		}
	}
	if !found {
		t.Fatalf("container error not surfaced as a problem: %+v", g.Problems)
	}
	tun := rep.Data.Services[ids["tunnel"]]
	if tun.Status != "ok" || len(tun.Endpoints) == 0 || tun.Endpoints[0].Exposure != "public" {
		t.Fatalf("tunnel card: %+v", tun)
	}
	if len(rep.Data.Guacamole.SecretFingerprint) != 23 || !strings.Contains(rep.Data.Guacamole.UserDatabase, "None") {
		t.Fatalf("guac config: %+v", rep.Data.Guacamole)
	}
	// Nothing secret in the whole answer: not the planted container env, not the JSON key.
	raw := h.raw("GET", "/api/v1/services")
	key := h.app.Secrets.GuacJSONKey.Bytes()
	for _, bad := range []string{controltest.Secret, string(key), hexOf(key), ctlToken} {
		if strings.Contains(raw, bad) {
			t.Fatalf("services report leaks a secret (%.6s…)", bad)
		}
	}
}

func TestServiceActionsAuditedAndLimited(t *testing.T) {
	h, eng := startWithControl(t)
	var out struct{ Data struct{ State string } }
	h.do("POST", "/api/v1/services/guacamole/actions/restart", nil, 200, &out)
	if out.Data.State != "running" || !contains(eng.Calls, "restart c-guac") {
		t.Fatalf("restart: %+v calls=%v", out, eng.Calls)
	}
	h.do("POST", "/api/v1/services/guacd/actions/stop", nil, 200, &out)
	if eng.State("c-guacd") != "exited" {
		t.Fatal("guacd not stopped")
	}
	// The report now says guacd is down because its container is.
	var rep svcReport
	h.do("GET", "/api/v1/services", nil, 200, &rep)
	for _, s := range rep.Data.Services {
		if s.ID == "guacd" && s.Status != "down" {
			t.Fatalf("stopped guacd reported %s", s.Status)
		}
	}
	if rep.Data.Overall != "down" {
		t.Fatalf("overall %s", rep.Data.Overall)
	}
	h.do("POST", "/api/v1/services/guacd/actions/start", nil, 200, &out)

	// RemoteHound may only restart itself — refused even before rh-control's label check.
	h.do("POST", "/api/v1/services/remotehound/actions/stop", nil, 403, nil)
	// Unknown action / unlabelled target.
	h.do("POST", "/api/v1/services/guacamole/actions/exec", nil, 400, nil)
	h.do("POST", "/api/v1/services/mariadb/actions/restart", nil, 404, nil)
	for _, call := range eng.Calls {
		if strings.Contains(call, "c-db") || strings.HasPrefix(call, "stop c-rh") {
			t.Fatalf("forbidden call reached the engine: %s", call)
		}
	}
	// Every action is in the audit log.
	var aud struct {
		Data []struct{ Event, Outcome, Resource string }
	}
	h.do("GET", "/api/v1/audit?event=service.action", nil, 200, &aud)
	seen := map[string]bool{}
	for _, e := range aud.Data {
		seen[e.Resource+" "+e.Outcome] = true
	}
	for _, want := range []string{"service:guacamole success", "service:guacd success", "service:remotehound denied"} {
		if !seen[want] {
			t.Fatalf("audit missing %q: %+v", want, aud.Data)
		}
	}

	// Operators can neither read nor control services.
	var u struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator"}, 201, &u)
	op := h.as(u.Data.ID)
	op.do("GET", "/api/v1/services", nil, 403, nil)
	op.do("POST", "/api/v1/services/guacamole/actions/restart", nil, 403, nil)
	op.do("GET", "/api/v1/services/guacamole/logs", nil, 403, nil)
}

func TestServiceLogsAreRedacted(t *testing.T) {
	h, _ := startWithControl(t)
	var out struct {
		Data []struct{ Text, Severity, Stream string }
	}
	h.do("GET", "/api/v1/services/guacd/logs?tail=50", nil, 200, &out)
	if len(out.Data) != 2 || out.Data[1].Severity != "warn" {
		t.Fatalf("logs: %+v", out.Data)
	}
	h.do("GET", "/api/v1/services/guacd/logs?tail=0", nil, 400, nil)
	h.do("GET", "/api/v1/services/guacd/logs?tail=99999", nil, 400, nil)
}

func TestServicesWithoutControlAreStatusOnly(t *testing.T) {
	h := start(t)
	var rep svcReport
	h.do("GET", "/api/v1/services", nil, 200, &rep)
	if rep.Data.Control.Configured || len(rep.Data.Services) != 5 {
		t.Fatalf("status-only report: %+v", rep.Data.Control)
	}
	var e struct{ Code string }
	h.do("POST", "/api/v1/services/guacamole/actions/restart", nil, 503, &e)
	if e.Code != "CONTROL_UNAVAILABLE" {
		t.Fatalf("code %s", e.Code)
	}
	h.do("GET", "/api/v1/services/guacamole/logs", nil, 503, nil)
}

// Proxy mode: a request the proxy let through WITHOUT an identity gets an
// explanation (no sign-in loop), and Sign out returns the proxy's logout URL.
func TestProxyModeNoIdentityAndSignOut(t *testing.T) {
	dir := t.TempDir()
	env := map[string]string{
		"RH_ENV": "development", "RH_AUTH_MODE": "proxy", "RH_TRUSTED_PROXIES": "127.0.0.1/32", "RH_PROXY_SECRET": testProxySecret,
		"RH_PROXY_EMAIL_HEADER": "X-Auth-Request-Email", "RH_BOOTSTRAP_ADMIN": "boss@example.com",
		"RH_PROXY_NAME_HEADER": "X-Auth-Request-User",
		"RH_PROXY_LOGOUT_URL":  "https://sso.example.com/oauth2/sign_out?rd=https%3A%2F%2Frh.example.com%2Fsigned-out",
		"RH_IDP_LOGOUT_URL":    "https://login.example.com/logout",
		"RH_HTTP_ADDR":         "127.0.0.1:0", "RH_SSH_ADDR": "127.0.0.1:0", "RH_METRICS_ADDR": "127.0.0.1:0",
		"RH_PUBLIC_URL": "http://127.0.0.1", "RH_DATA_DIR": dir, "RH_RECORDINGS_DIR": filepath.Join(dir, "rec"),
		"RH_TUNNEL_BIND": "127.0.0.1", "RH_TUNNEL_ADVERTISE_HOST": "127.0.0.1",
		"RH_GUAC_URL": "http://127.0.0.1:1/guacamole", "RH_GUACD_ADDR": "127.0.0.1:1", "RH_LOG_LEVEL": "WARN",
	}
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Audit.Close() })
	srv := httptest.NewServer(a.Handler)
	t.Cleanup(srv.Close)
	noFollow := &http.Client{Transport: proxyTransport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(path string, hdr ...string) *http.Response {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", srv.URL+path, nil)
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := noFollow.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// 1. No identity: a specific code, not the generic AUTH_REQUIRED that sends the UI to /auth/login.
	resp := get("/api/v1/me")
	var prob struct{ Code string }
	json.NewDecoder(resp.Body).Decode(&prob) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != 401 || prob.Code != "PROXY_IDENTITY_MISSING" {
		t.Fatalf("no identity: %d %s", resp.StatusCode, prob.Code)
	}
	// 2. /auth/login without identity must NOT bounce back to the app (that was the loop).
	resp = get("/auth/login?rd=/")
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/signed-out?reason=proxy" {
		t.Fatalf("login without identity: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 3. With identity: login goes back to rd.
	resp = get("/auth/login?rd=/devices", "X-Auth-Request-Email", "boss@example.com")
	resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/devices" {
		t.Fatalf("login with identity: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// 3b. oauth2-proxy with Entra puts the opaque subject in the user header:
	// never a display name. A name stored that way earlier is cleared too.
	const sub = "7HFBnaKsHAmdpqMfN6_ip0w2wqFvN0ccPfJPYXhxXYc"
	nameOf := func() string {
		r := get("/api/v1/me", "X-Auth-Request-Email", "boss@example.com", "X-Auth-Request-User", sub)
		defer r.Body.Close()
		var m struct {
			Data struct {
				DisplayName string `json:"display_name"`
			}
		}
		json.NewDecoder(r.Body).Decode(&m) //nolint:errcheck
		return m.Data.DisplayName
	}
	if n := nameOf(); n != "" {
		t.Fatalf("subject used as display name: %q", n)
	}
	a.Store.Update(func(st *model.State) error { //nolint:errcheck
		for _, u := range st.Users {
			u.DisplayName = sub // as stored before this fix
		}
		return nil
	})
	if n := nameOf(); n != "" {
		t.Fatalf("stored subject not cleared: %q", n)
	}
	// 3c. Editing your own name (the form also sends the unchanged groups)
	// must not rotate the session: behind a proxy that would make the page's
	// CSRF token stale, and the next change (sign out) was refused.
	meOf := func() (id, csrf string) {
		r := get("/api/v1/me", "X-Auth-Request-Email", "boss@example.com")
		defer r.Body.Close()
		var m struct {
			Data struct {
				ID   string `json:"id"`
				CSRF string `json:"csrf_token"`
			}
		}
		json.NewDecoder(r.Body).Decode(&m) //nolint:errcheck
		return m.Data.ID, m.Data.CSRF
	}
	uid, csrf1 := meOf()
	ur := get("/api/v1/users/"+uid, "X-Auth-Request-Email", "boss@example.com")
	etag := ur.Header.Get("ETag")
	ur.Body.Close()
	preq, _ := http.NewRequestWithContext(context.Background(), "PATCH", srv.URL+"/api/v1/users/"+uid,
		strings.NewReader(`{"display_name":"Boss Person","group_ids":[]}`))
	preq.Header.Set("Content-Type", "application/merge-patch+json")
	preq.Header.Set("X-Auth-Request-Email", "boss@example.com")
	preq.Header.Set("X-CSRF-Token", csrf1)
	preq.Header.Set("If-Match", etag)
	presp, err := noFollow.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	presp.Body.Close()
	if presp.StatusCode != 200 {
		t.Fatalf("edit own name: %d", presp.StatusCode)
	}
	if _, csrf2 := meOf(); csrf2 != csrf1 {
		t.Fatal("editing your own name rotated the CSRF token")
	}
	// 4. Sign out returns the proxy's logout URL.
	var me struct {
		Data struct {
			CSRF string `json:"csrf_token"`
		}
	}
	resp = get("/api/v1/me", "X-Auth-Request-Email", "boss@example.com")
	json.NewDecoder(resp.Body).Decode(&me) //nolint:errcheck
	resp.Body.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/auth/logout", nil)
	req.Header.Set("X-Auth-Request-Email", "boss@example.com")
	req.Header.Set("X-CSRF-Token", me.Data.CSRF)
	resp, err = noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var lo struct{ Data struct{ Redirect string } }
	json.NewDecoder(resp.Body).Decode(&lo) //nolint:errcheck
	resp.Body.Close()
	if resp.StatusCode != 200 || lo.Data.Redirect != env["RH_PROXY_LOGOUT_URL"] {
		t.Fatalf("logout: %d %+v", resp.StatusCode, lo)
	}
	// 5. The public providers endpoint offers the IdP sign-out for the signed-out page.
	resp = get("/auth/providers")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), env["RH_IDP_LOGOUT_URL"]) {
		t.Fatalf("providers: %s", b)
	}
	// 6. /signed-out is served (SPA) without any identity.
	resp = get("/signed-out")
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/signed-out: %d", resp.StatusCode)
	}
}

func (h *harness) raw(method, path string) string {
	req, _ := http.NewRequest(method, h.srv.URL+path, nil)
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
