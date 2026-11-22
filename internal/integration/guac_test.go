package integration

// @kind:integration
// @feature:sessions

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/guac"
)

// fakeGuac stands in for the Guacamole web app behind the proxy: it issues a
// new token per data= login, echoes a token refresh, and records revocations.
type fakeGuac struct {
	mu        sync.Mutex
	srv       *httptest.Server
	redeemed  int
	revoked   []string
	lastToken string
	loginSeen string // token / content type the last data= login reached Guacamole with
}

func newFakeGuac(t *testing.T) *fakeGuac {
	f := &fakeGuac{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.Method == "POST" && r.URL.Path == "/guacamole/api/tokens":
			b, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(b))
			tok := form.Get("token")
			if form.Get("data") != "" {
				f.loginSeen = "header=" + r.Header.Get("Guacamole-Token") + " query=" + r.URL.Query().Get("token") +
					" form=" + form.Get("token") + " ct=" + r.Header.Get("Content-Type")
				f.redeemed++
				tok = fmt.Sprintf("GUACTOKEN%d", f.redeemed)
			} else if tok == "" {
				tok = "PASSWORD-LOGIN-TOKEN" // another auth provider answering
			}
			f.lastToken = tok
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"authToken":%q,"username":"u","dataSource":"json","availableDataSources":["json"]}`, tok)
		case r.Method == "DELETE" && r.URL.Path == "/guacamole/api/session":
			f.revoked = append(f.revoked, r.Header.Get("Guacamole-Token"))
			w.WriteHeader(204)
		default:
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, "{}")
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGuac) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.redeemed }

// waitRevoked waits up to 3 s for Guacamole to be asked to end token's session.
func (f *fakeGuac) waitRevoked(tok string) bool {
	for i := 0; i < 300; i++ {
		f.mu.Lock()
		for _, r := range f.revoked {
			if r == tok {
				f.mu.Unlock()
				return true
			}
		}
		f.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// guacDo sends a request through RemoteHound's /guacamole proxy as h.
func guacDo(t *testing.T, h *harness, method, path string, form url.Values, hdr ...string) (int, string) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func redeem(t *testing.T, h *harness, blob string) (int, string) {
	t.Helper()
	code, body := guacDo(t, h, "POST", "/guacamole/api/tokens", url.Values{"data": {blob}})
	var v struct {
		AuthToken string `json:"authToken"`
	}
	json.Unmarshal([]byte(body), &v) //nolint:errcheck
	return code, v.AuthToken
}

func sealFor(t *testing.T, h *harness, email string) string {
	t.Helper()
	s, err := guac.Seal(guacKey(t, h), guac.AuthData{Username: email, Expires: guac.Expiry(time.Now(), time.Minute),
		Connections: map[string]guac.Connection{"x": {Protocol: "ssh"}}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func myID(h *harness) string {
	var me struct{ Data struct{ ID string } }
	h.do("GET", "/api/v1/me", nil, 200, &me)
	return me.Data.ID
}

// S2: a connect blob is redeemed once, by its own user; Guacamole tokens work
// only for the user they were issued to; Sign out revokes them.
func TestGuacamoleTokensAreBoundToTheUser(t *testing.T) {
	fg := newFakeGuac(t)
	h := startWith(t, map[string]string{"RH_GUAC_URL": fg.srv.URL + "/guacamole"})
	adminID := myID(h)
	var u struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator"}, 201, &u)
	op := h.as(u.Data.ID)

	blob := sealFor(t, h, "dev@localhost")
	code, tok := redeem(t, h, blob)
	if code != 200 || tok == "" {
		t.Fatalf("first redemption: %d %q", code, tok)
	}
	// The same user again (a reload): the same Guacamole session, no new one.
	if code, again := redeem(t, h, blob); code != 200 || again != tok || fg.count() != 1 {
		t.Fatalf("repeat redemption: %d %q (guacamole saw %d logins)", code, again, fg.count())
	}
	// Someone else with the URL: refused, Guacamole never sees it.
	if code, _ := redeem(t, op, blob); code != 403 {
		t.Fatalf("other user replayed the blob: %d", code)
	}
	if code, _ := redeem(t, op, sealFor(t, h, "dev@localhost")); code != 403 || fg.count() != 1 {
		t.Fatalf("other user redeemed a fresh blob minted for someone else: %d", code)
	}

	// data= is honoured only once, in the body: in the query (where Guacamole
	// would also read it) or twice, the request is refused before Guacamole.
	other := sealFor(t, h, "dev@localhost")
	if c, _ := guacDo(t, h, "POST", "/guacamole/api/tokens?data="+url.QueryEscape(other), url.Values{"token": {tok}}); c != 403 {
		t.Fatalf("data= in the query passed: %d", c)
	}
	if c, _ := guacDo(t, h, "POST", "/guacamole/api/tokens", url.Values{"data": {other, blob}}); c != 403 {
		t.Fatalf("two data= values passed: %d", c)
	}
	// The connect link itself is GET /guacamole/?data=… (guac.ConnectURL): the
	// page load must reach Guacamole, whose web client then posts the blob to
	// /api/tokens in a form body. Found by the live test against Guacamole 1.6.0.
	if c, _ := guacDo(t, h, "GET", "/guacamole/?data="+url.QueryEscape(other), nil); c == 403 || c == 415 {
		t.Fatalf("the connect link page was refused: %d", c)
	}
	if fg.count() != 1 {
		t.Fatalf("guacamole saw %d logins", fg.count())
	}

	// Token use: only by its owner, in any of Guacamole's three carriers.
	api := "/guacamole/api/session/data/json/self/effectivePermissions"
	if c, _ := guacDo(t, h, "GET", api, nil, "Guacamole-Token", tok); c != 200 {
		t.Fatalf("owner's token refused: %d", c)
	}
	if c, _ := guacDo(t, op, "GET", api, nil, "Guacamole-Token", tok); c != 403 {
		t.Fatalf("cross-user token (header): %d", c)
	}
	if c, _ := guacDo(t, op, "GET", api+"?token="+tok, nil); c != 403 {
		t.Fatalf("cross-user token (query): %d", c)
	}
	if c, _ := guacDo(t, op, "POST", "/guacamole/tunnel?connect", url.Values{"token": {tok}}); c != 403 {
		t.Fatalf("cross-user token (form): %d", c)
	}
	// However the body type is spelled, a token= field is found; bodies the
	// proxy cannot read for one are refused, not forwarded (fail closed).
	for _, ct := range []string{"Application/X-WWW-Form-Urlencoded", "application/x-www-form-urlencoded;charset=US-ASCII"} {
		if c, _ := guacDo(t, op, "PUT", "/guacamole/tunnel?connect", url.Values{"token": {tok}}, "Content-Type", ct); c != 403 {
			t.Fatalf("cross-user token in %q body: %d", ct, c)
		}
	}
	// A charset Tomcat might decode differently is refused outright (stricter than 403).
	if c, _ := guacDo(t, op, "PUT", "/guacamole/tunnel?connect", url.Values{"token": {tok}}, "Content-Type", "application/x-www-form-urlencoded;charset=ISO-8859-1"); c != 415 {
		t.Fatalf("cross-user token in an ISO-8859-1 body: %d", c)
	}
	for _, ct := range []string{"multipart/form-data; boundary=x", "text/plain", ""} {
		req, _ := http.NewRequest("POST", h.srv.URL+"/guacamole/tunnel?connect", strings.NewReader("token="+tok))
		req.Header.Set("Content-Type", ct)
		resp, err := op.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 415 {
			t.Fatalf("unparsed body type %q forwarded: %d", ct, resp.StatusCode)
		}
	}
	if c, _ := guacDo(t, h, "POST", "/guacamole/tunnel?write:abc", nil, "Content-Type", "application/octet-stream"); c != 200 {
		t.Fatalf("tunnel write (octet-stream) refused: %d", c)
	}
	// A login without data or token (e.g. username/password) yields a token
	// nobody may use: it is not handed out.
	if c, _ := guacDo(t, h, "POST", "/guacamole/api/tokens", url.Values{"username": {"guacadmin"}, "password": {"x"}}); c != 403 {
		t.Fatalf("unbound login answer handed out: %d", c)
	}
	if c, _ := guacDo(t, h, "GET", api, nil, "Guacamole-Token", "NOT-ISSUED-HERE"); c != 403 {
		t.Fatalf("unknown token accepted: %d", c)
	}
	if !auditHas(t, h, "session.guacamole_denied", "denied") {
		t.Error("audit lacks session.guacamole_denied denied")
	}

	// Sign out revokes the Guacamole session and the token stops working.
	h.do("POST", "/auth/logout", nil, 204, nil)
	if !fg.waitRevoked(tok) {
		t.Fatal("logout did not revoke the Guacamole session")
	}
	h2 := h.asGen(adminID, 1)
	if c, _ := guacDo(t, h2, "GET", api, nil, "Guacamole-Token", tok); c != 403 {
		t.Fatalf("token survived sign out: %d", c)
	}
	if code, _ := redeem(t, h2, blob); code != 403 {
		t.Fatalf("blob redeemable again after sign out: %d", code)
	}
	// A fresh Connect after signing in again works: the stale token Guacamole's
	// app sends along (header, query and body) is removed by the gate itself,
	// and the body reaches Guacamole as canonical UTF-8 form data.
	if c, _ := guacDo(t, h2, "POST", "/guacamole/api/tokens?token="+tok, url.Values{"data": {sealFor(t, h, "dev@localhost")}, "token": {tok}},
		"Guacamole-Token", tok, "Content-Type", "application/x-www-form-urlencoded;charset=utf-8"); c != 200 {
		t.Fatalf("fresh connect after sign out: %d", c)
	}
	fg.mu.Lock()
	seen := fg.loginSeen
	fg.mu.Unlock()
	if seen != "header= query= form= ct=application/x-www-form-urlencoded; charset=UTF-8" {
		t.Fatalf("data= login reached Guacamole as %q", seen)
	}
	// A form charset Tomcat could decode differently, and the login path with a
	// trailing slash, are refused before Guacamole.
	if c, _ := guacDo(t, h2, "POST", "/guacamole/tunnel?connect", url.Values{"token": {"x"}}, "Content-Type", "application/x-www-form-urlencoded; charset=UTF-16"); c != 415 {
		t.Fatalf("UTF-16 form body: %d", c)
	}
	if c, _ := guacDo(t, h2, "POST", "/guacamole/api/tokens/", url.Values{"data": {sealFor(t, h, "dev@localhost")}}); c != 403 {
		t.Fatalf("/api/tokens/ (trailing slash): %d", c)
	}
}

// S1 (grantee side): B joined A's session through a share; disabling B
// revokes B's Guacamole session and B's share, while A's session keeps running.
func TestDisabledGranteeLosesJoinedSession(t *testing.T) {
	fg := newFakeGuac(t)
	h := startWith(t, map[string]string{"RH_GUAC_URL": fg.srv.URL + "/guacamole"})
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Shared"}, 201, &grp)
	devID := enrolOnline(t, h, grp.Data.ID)
	var u struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "b@example.com", "role": "operator", "group_ids": []string{grp.Data.ID}}, 201, &u)
	b := h.as(u.Data.ID)

	sid, g := liveSessionAs(t, h, devID)
	h.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": u.Data.ID, "mode": "control"}, 200, nil)
	var join struct{ Data struct{ URL string } }
	b.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 200, &join)
	jurl, _ := url.Parse("http://x" + join.Data.URL)
	code, btok := redeem(t, b, jurl.Query().Get("data"))
	if code != 200 || btok == "" {
		t.Fatalf("grantee redemption: %d", code)
	}

	var cur struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/users/"+u.Data.ID, nil, 200, &cur)
	h.do("PATCH", "/api/v1/users/"+u.Data.ID, map[string]any{"disabled": true}, 200, nil, "If-Match", cur.Data.ETag)
	if !fg.waitRevoked(btok) {
		t.Fatal("disabled grantee's Guacamole session was not revoked")
	}
	// A's own session is untouched.
	g.SetReadDeadline(time.Now().Add(300 * time.Millisecond)) //nolint:errcheck
	if _, err := io.ReadAll(g); err == nil || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("owner's session was closed: %v", err) // nil = EOF
	}
	// The share is gone: even re-enabled, B cannot rejoin.
	h.do("GET", "/api/v1/users/"+u.Data.ID, nil, 200, &cur)
	h.do("PATCH", "/api/v1/users/"+u.Data.ID, map[string]any{"disabled": false}, 200, nil, "If-Match", cur.Data.ETag)
	h.asGen(u.Data.ID, 2).do("POST", "/api/v1/sessions/"+sid+"/join", nil, 404, nil)
}
