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
