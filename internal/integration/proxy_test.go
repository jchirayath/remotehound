package integration

// @kind:integration
// @feature:users

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/app"
	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/model"
)

const testProxySecret = "test-proxy-secret-not-a-real-one" // gitleaks:allow -- test value

// proxyTransport adds the shared proxy header, as the sign-in proxy would.
type proxyTransport struct{}

func (proxyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-RemoteHound-Proxy-Secret", testProxySecret)
	return http.DefaultTransport.RoundTrip(r)
}

// proxyApp starts RemoteHound in proxy mode (trusting 127.0.0.1) without the
// dev login; requests carry identity headers like a sign-in proxy would.
func proxyApp(t *testing.T, extra map[string]string) (*app.App, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	env := map[string]string{
		"RH_ENV": "development", "RH_AUTH_MODE": "proxy", "RH_TRUSTED_PROXIES": "127.0.0.1/32",
		"RH_PROXY_SECRET": testProxySecret, "RH_BOOTSTRAP_ADMIN": "boss@example.com",
		"RH_HTTP_ADDR": "127.0.0.1:0", "RH_SSH_ADDR": "127.0.0.1:0", "RH_METRICS_ADDR": "127.0.0.1:0",
		"RH_PUBLIC_URL": "http://127.0.0.1", "RH_DATA_DIR": dir, "RH_RECORDINGS_DIR": filepath.Join(dir, "rec"),
		"RH_TUNNEL_BIND": "127.0.0.1", "RH_TUNNEL_ADVERTISE_HOST": "127.0.0.1",
		"RH_GUAC_URL": "http://127.0.0.1:1/guacamole", "RH_GUACD_ADDR": "127.0.0.1:1", "RH_LOG_LEVEL": "WARN",
	}
	for k, v := range extra {
		env[k] = v
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
	return a, srv
}

func proxyGet(t *testing.T, srv *httptest.Server, path string, hdr ...string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	req.Header.Set("X-RemoteHound-Proxy-Secret", testProxySecret)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

type fileState struct {
	b   []byte
	mod time.Time
}

func stateFile(t *testing.T, a *app.App) fileState {
	t.Helper()
	b, err := os.ReadFile(a.Store.Path())
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(a.Store.Path())
	return fileState{b, st.ModTime()}
}

// S3: once the user exists and nothing about them changed, authenticated
// requests (every API call and every Guacamole asset) must not rewrite the store.
func TestProxyRequestsDoNotWriteTheStore(t *testing.T) {
	a, srv := proxyApp(t, nil)
	id := []string{"X-Forwarded-Email", "boss@example.com", "X-Forwarded-User", "Boss Person"}
	if c := proxyGet(t, srv, "/api/v1/me", id...); c != 200 {
		t.Fatalf("first request: %d", c)
	}
	before := stateFile(t, a)
	time.Sleep(20 * time.Millisecond) // a write would move the mtime visibly
	for i := 0; i < 25; i++ {
		if c := proxyGet(t, srv, "/api/v1/me", id...); c != 200 {
			t.Fatalf("request %d: %d", i, c)
		}
	}
	after := stateFile(t, a)
	if !bytes.Equal(before.b, after.b) || !before.mod.Equal(after.mod) {
		t.Fatal("authenticated requests rewrote state.json")
	}
	// A real change (the IdP now maps the user's group to a lower role) is still written.
	a.Store.Update(func(st *model.State) error { //nolint:errcheck
		st.Settings.RolesMap = map[string]string{"helpdesk": "operator"}
		u := &model.User{Meta: model.Meta{ID: "usr_second"}, Email: "two@example.com", Role: "admin", GroupIDs: []string{}}
		st.Users[u.ID] = u // a second admin, so the bootstrap admin may be demoted
		return nil
	})
	proxyGet(t, srv, "/api/v1/me", append(id, "X-Forwarded-Groups", "helpdesk")...)
	var role string
	a.Store.View(func(st *model.State) {
		for _, u := range st.Users {
			if u.Email == "boss@example.com" {
				role = u.Role
			}
		}
	})
	if role != "operator" {
		t.Fatalf("role mapping change not applied: %q", role)
	}
}

// S3: identity headers on public routes are never acted on: no user is created
// or modified by a request to /ui/*, /e/*, /healthz, enrollment, etc.
func TestProxyIdentityIgnoredOnPublicRoutes(t *testing.T) {
	a, srv := proxyApp(t, nil)
	before := stateFile(t, a)
	for _, p := range []string{"/ui/app.js", "/e/abcdef", "/healthz", "/readyz", "/signed-out", "/auth/providers",
		"/api/v1/enroll/status?device_id=dev_x&fingerprint=y", "/docs/login"} {
		proxyGet(t, srv, p, "X-Forwarded-Email", "boss@example.com", "X-Forwarded-User", "Boss")
	}
	n := 0
	a.Store.View(func(st *model.State) { n = len(st.Users) })
	if n != 0 {
		t.Fatalf("public routes created %d user(s) from identity headers", n)
	}
	if !bytes.Equal(before.b, stateFile(t, a).b) {
		t.Fatal("public routes modified the store")
	}
}

// S4: proxy mode without the shared header value is anonymous, even from a
// trusted address.
func TestProxyIdentityNeedsSharedHeader(t *testing.T) {
	_, srv := proxyApp(t, nil)
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/me", nil)
	req.Header.Set("X-Forwarded-Email", "boss@example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("identity accepted without the proxy header: %d", resp.StatusCode)
	}
}

// S4: with RH_PROXY_SUBJECT_HEADER the IdP subject is the identity key: the
// same email arriving with another subject is not that user, and an existing
// email-keyed user is converted on their first request with a subject.
func TestProxySubjectHeaderIsTheIdentityKey(t *testing.T) {
	a, srv := proxyApp(t, nil)
	if c := proxyGet(t, srv, "/api/v1/me", "X-Forwarded-Email", "boss@example.com"); c != 200 {
		t.Fatalf("email-keyed sign-in: %d", c)
	}
	a.API.Auth.ProxySubject = "X-Auth-Request-Sub" // as after enabling RH_PROXY_SUBJECT_HEADER
	if c := proxyGet(t, srv, "/api/v1/me", "X-Forwarded-Email", "boss@example.com", "X-Auth-Request-Sub", "sub-ONE"); c != 200 {
		t.Fatalf("migration to subject: %d", c)
	}
	var ids []model.UserIdentity
	a.Store.View(func(st *model.State) {
		for _, u := range st.Users {
			ids = append(ids, u.Identities...)
		}
	})
	if len(ids) != 1 || ids[0].Subject != "sub-ONE" || ids[0].Provider != "proxy-sub" {
		t.Fatalf("identity not converted to the subject: %+v", ids)
	}
	if c := proxyGet(t, srv, "/api/v1/me", "X-Forwarded-Email", "boss@example.com", "X-Auth-Request-Sub", "sub-TWO"); c != 401 {
		t.Fatalf("same email with another subject got in: %d", c)
	}
	if c := proxyGet(t, srv, "/api/v1/me", "X-Forwarded-Email", "boss@example.com"); c != 401 {
		t.Fatalf("no subject header got in: %d", c)
	}
}

// S4 (namespace): a subject value equal to another user's email, or to their
// legacy email-keyed identity, never resolves to that user.
func TestProxySubjectCannotNameAnotherUser(t *testing.T) {
	a, srv := proxyApp(t, nil)
	// The victim signs in before the subject header is enabled: legacy proxy:victim identity.
	if c := proxyGet(t, srv, "/api/v1/me", "X-Forwarded-Email", "boss@example.com"); c != 200 {
		t.Fatalf("victim sign-in: %d", c)
	}
	a.Store.Update(func(st *model.State) error { //nolint:errcheck
		st.Settings.RolesMap = map[string]string{"staff": "viewer"} // the attacker is a legitimate (JIT) user
		return nil
	})
	a.API.Auth.ProxySubject = "X-Auth-Request-Sub"
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/me", nil)
	req.Header.Set("X-RemoteHound-Proxy-Secret", testProxySecret)
	req.Header.Set("X-Forwarded-Email", "mallory@example.com")
	req.Header.Set("X-Forwarded-Groups", "staff")
	req.Header.Set("X-Auth-Request-Sub", "boss@example.com") // the victim's legacy subject
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var me struct {
		Data struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		}
	}
	json.NewDecoder(resp.Body).Decode(&me) //nolint:errcheck
	resp.Body.Close()
	if me.Data.Email == "boss@example.com" || me.Data.Role == "admin" {
		t.Fatalf("subject equal to the victim's email signed in as the victim: %+v", me.Data)
	}
	var victimIDs []model.UserIdentity
	a.Store.View(func(st *model.State) {
		for _, u := range st.Users {
			if u.Email == "boss@example.com" {
				victimIDs = u.Identities
			}
		}
	})
	if len(victimIDs) != 1 || victimIDs[0].Provider != "proxy" || victimIDs[0].Subject != "boss@example.com" {
		t.Fatalf("victim's identity was touched: %+v", victimIDs)
	}
}
