// Package web serves the embedded single-page UI, the user docs, and the
// reverse proxy to Guacamole.
package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/jchirayath/remotehound/internal/guac"
)

// SPA serves files from ui (rooted at web/ui) under /ui/ and index.html for
// every other GET path (client-side routing). Index is never cached so a new
// release is picked up. Assets are "no-cache" with a content-hash ETag: the
// browser revalidates each one (a 304 when unchanged), so after a release it can
// never pair a new screen module with a stale cached lib module, which made the
// screen fail to load ("This screen failed to load", INTERNAL) until max-age ran out.
func SPA(ui fs.FS) http.Handler {
	files := http.FileServerFS(ui)
	etags := assetETags(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/ui/"); ok {
			if rest == "" || strings.HasSuffix(rest, "/") {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Cache-Control", "no-cache")
			if tag, ok := etags[rest]; ok {
				w.Header().Set("ETag", tag) // http.FileServer answers If-None-Match with 304
			}
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/" + rest
			files.ServeHTTP(w, r2)
			return
		}
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		b, err := fs.ReadFile(ui, "index.html")
		if err != nil {
			http.Error(w, "UI not built into this binary", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
}

// assetETags hashes every embedded UI file once at start-up (the files are
// immutable for the life of the binary).
func assetETags(ui fs.FS) map[string]string {
	out := map[string]string{}
	_ = fs.WalkDir(ui, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(ui, p)
		if err != nil {
			return nil
		}
		sum := sha256.Sum256(b)
		out[p] = `"` + hex.EncodeToString(sum[:12]) + `"`
		return nil
	})
	return out
}

var docPage = regexp.MustCompile(`^[a-z0-9-]{1,40}(\.md)?$`)

// Docs serves docs/user/<page>.md as text/markdown (rendered by the help panel).
func Docs(docs fs.FS) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.PathValue("page")
		if !docPage.MatchString(p) {
			http.NotFound(w, r)
			return
		}
		p = strings.TrimSuffix(p, ".md") + ".md"
		b, err := fs.ReadFile(docs, path.Join("user", p))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(b)
	})
}

// GuacProxy forwards /guacamole/* (HTTP and WebSocket) to the internal
// Guacamole app. Guacamole never sees the operator's session or the sign-in
// proxy's: every cookie except Tomcat's JSESSIONID, every X-Auth-Request-*
// header, the usual X-Forwarded-* identity headers and identityHeaders (the
// configured RH_PROXY_*_HEADER names) are dropped. Paths containing ";" are
// refused (Tomcat path parameters: "..;" escapes the context path). The
// relaxed CSP Guacamole's client needs is scoped to this path only.
func GuacProxy(target *url.URL, identityHeaders ...string) http.Handler {
	strip := []string{"X-RemoteHound-Proxy-Secret", "X-Forwarded-Email", "X-Forwarded-User", "X-Forwarded-Groups",
		"X-Forwarded-Preferred-Username", "X-Forwarded-Access-Token", "X-CSRF-Token", "Authorization"}
	for _, h := range identityHeaders {
		if h != "" {
			strip = append(strip, h)
		}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: target.Scheme, Host: target.Host})
			pr.Out.URL.Path = pr.In.URL.Path // same context path on both sides (validated in config)
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.Out.Host = target.Host
			pr.SetXForwarded()
			stripCookies(pr.Out)
			for _, h := range strip {
				pr.Out.Header.Del(h)
			}
			for k := range pr.Out.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Auth-Request-") {
					pr.Out.Header.Del(k)
				}
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Server")
			// Guacamole's Tomcat serves some static files as application/octet-stream;
			// with our nosniff header the browser would refuse them. Correct by extension.
			if ct := resp.Header.Get("Content-Type"); ct == "" || strings.HasPrefix(ct, "application/octet-stream") {
				if m := mimeByExt[path.Ext(resp.Request.URL.Path)]; m != "" {
					resp.Header.Set("Content-Type", m)
				}
			}
			// object-src 'self': the client measures its display with an <object> of blank.html.
			resp.Header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'self'; object-src 'self'; base-uri 'self'")
			resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
			return nil
		},
		FlushInterval: -1, // stream (the HTTP tunnel fallback is long-polling)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ";") || strings.Contains(strings.ToLower(r.URL.RawPath), "%3b") {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if err := freshGuacLogin(r); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

// freshGuacLogin makes every Connect start its OWN Guacamole session.
//
// Guacamole's web app keeps its auth token in the browser and sends it back
// with every POST /api/tokens, including the one that redeems a new sealed
// connect blob (data=…). guacamole-auth-json then updates the EXISTING session,
// which only knows the first connection, and the second Connect in the same
// browser fails with "The requested connection does not exist" (found testing
// SSH then RDP from one browser, 2026-11-21). When a login carries data, drop
// the stale token so Guacamole creates a fresh session for exactly that blob.
// Earlier sessions keep running on their own tunnels and tokens.
func freshGuacLogin(r *http.Request) error {
	if !guac.IsTokensLogin(r) { // the same test as api.guacGate
		return nil
	}
	if guac.BodyKind(r) != guac.BodyForm { // the same classification as api.guacGate
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return err
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return err
	}
	if form.Get("data") != "" {
		form.Del("token")
		r.Header.Del("Guacamole-Token")
		if q := r.URL.Query(); q.Has("token") {
			q.Del("token")
			r.URL.RawQuery = q.Encode()
		}
		body = []byte(form.Encode())
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

var mimeByExt = map[string]string{
	".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".html": "text/html; charset=utf-8",
	".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2", ".woff": "font/woff",
	".ico": "image/x-icon", ".map": "application/json", ".txt": "text/plain; charset=utf-8",
}

// guacCookies are the only cookies Guacamole may receive (it keeps its own
// auth token in the page, not in a cookie).
var guacCookies = map[string]bool{"JSESSIONID": true}

func stripCookies(r *http.Request) {
	cs := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cs {
		if guacCookies[c.Name] {
			r.AddCookie(c)
		}
	}
}
