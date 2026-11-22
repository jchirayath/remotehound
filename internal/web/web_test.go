// @feature:sessions
package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
)

// UI assets revalidate (no-cache + content ETag, 304 when unchanged), so a release
// can never mix a new screen module with a stale cached lib module.
func TestUIAssetsRevalidateWithETag(t *testing.T) {
	ui := fstest.MapFS{"index.html": {Data: []byte("<html>")}, "lib/ui.js": {Data: []byte("export const a = 1")}}
	h := SPA(ui)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/lib/ui.js", nil))
	tag := rec.Header().Get("ETag")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-cache" || len(tag) < 10 {
		t.Fatalf("first fetch: %d cc=%q etag=%q", rec.Code, rec.Header().Get("Cache-Control"), tag)
	}
	req := httptest.NewRequest("GET", "/ui/lib/ui.js", nil)
	req.Header.Set("If-None-Match", tag)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("revalidation: %d, want 304", rec.Code)
	}
	ui["lib/ui.js"] = &fstest.MapFile{Data: []byte("export const a = 2")}
	if assetETags(ui)["lib/ui.js"] == tag {
		t.Fatal("ETag did not change with the content")
	}
}

// A second Connect in the same browser must get its own Guacamole session:
// the stale token Guacamole's app sends with a data= login is dropped.
func TestGuacLoginWithDataDropsStaleToken(t *testing.T) {
	var got url.Values
	var gotHeader string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(b))
		gotHeader = r.Header.Get("Guacamole-Token")
		if int64(len(b)) != r.ContentLength {
			t.Errorf("content length %d for %d bytes", r.ContentLength, len(b))
		}
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL + "/guacamole")
	h := GuacProxy(u)

	post := func(body string) {
		req := httptest.NewRequest("POST", "/guacamole/api/tokens", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		req.Header.Set("Guacamole-Token", "OLD")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	post("token=OLDTOKEN&data=BLOB%2B1")
	if got.Get("token") != "" || got.Get("data") != "BLOB+1" || gotHeader != "" {
		t.Fatalf("data login kept the stale token: form=%v header=%q", got, gotHeader)
	}
	// A plain token refresh (no data) is passed through untouched.
	post("token=OLDTOKEN")
	if got.Get("token") != "OLDTOKEN" || gotHeader != "OLD" {
		t.Fatalf("token refresh altered: form=%v header=%q", got, gotHeader)
	}
}

// The proxy forwards no identity, proxy-secret or sign-in-proxy material to
// Guacamole: X-Auth-Request-*, the configured identity headers, and every
// cookie except the allow-listed Tomcat one.
func TestGuacProxyStripsIdentityHeadersAndCookies(t *testing.T) {
	var got *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Clone(r.Context()) }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL + "/guacamole")
	h := GuacProxy(u, "X-Custom-Email", "X-Custom-Sub")
	req := httptest.NewRequest("GET", "/guacamole/api/languages", nil)
	for _, k := range []string{"X-Auth-Request-Email", "X-Auth-Request-User", "X-Auth-Request-Groups", "X-Auth-Request-Access-Token",
		"X-Forwarded-Email", "X-Forwarded-User", "X-Forwarded-Groups", "X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token",
		"X-Custom-Email", "X-Custom-Sub", "X-RemoteHound-Proxy-Secret", "Authorization", "X-CSRF-Token"} {
		req.Header.Set(k, "secret-value")
	}
	req.Header.Set("Guacamole-Token", "TOK")
	req.Header.Set("Cookie", "_oauth2_proxy=abc; __Host-rh_session=x; rh_flow=y; other=z; JSESSIONID=keep")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got == nil {
		t.Fatal("request not forwarded")
	}
	for k, v := range got.Header {
		if strings.Contains(strings.Join(v, ","), "secret-value") {
			t.Errorf("forwarded %s", k)
		}
	}
	if got.Header.Get("Guacamole-Token") != "TOK" {
		t.Error("Guacamole's own token header was dropped")
	}
	if c := got.Header.Get("Cookie"); c != "JSESSIONID=keep" {
		t.Errorf("cookies forwarded: %q", c)
	}
}

// Tomcat treats ";" as a path parameter, so "..;" walks out of the context
// path. The proxy refuses any path containing ";" (raw or encoded).
func TestGuacProxyRejectsPathParameters(t *testing.T) {
	hit := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer backend.Close()
	u, _ := url.Parse(backend.URL + "/guacamole")
	h := GuacProxy(u)
	for _, p := range []string{"/guacamole/..;/manager/html", "/guacamole/api;x=1/tokens", "/guacamole/%2e%2e%3b/manager"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", p, rec.Code)
		}
	}
	if hit {
		t.Fatal("a path with ';' reached Guacamole")
	}
}

// The proxy recognises a form body exactly as the gate does (guac.BodyKind):
// an unusual spelling of the media type still drops the stale token.
func TestGuacLoginFormDetectionMatchesGate(t *testing.T) {
	var got url.Values
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(b))
	}))
	defer backend.Close()
	u, _ := url.Parse(backend.URL + "/guacamole")
	req := httptest.NewRequest("POST", "/guacamole/api/tokens", strings.NewReader("token=OLD&data=BLOB"))
	req.Header.Set("Content-Type", "Application/X-WWW-Form-Urlencoded;Charset=UTF-8")
	GuacProxy(u).ServeHTTP(httptest.NewRecorder(), req)
	if got.Get("token") != "" || got.Get("data") != "BLOB" {
		t.Fatalf("stale token kept for an odd media-type spelling: %v", got)
	}
}
