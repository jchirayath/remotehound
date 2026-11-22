package guac

// @feature:sessions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/core/httpx"
)

type revokeRecorder struct {
	mu   sync.Mutex
	toks []string
}

func (r *revokeRecorder) has(tok string) bool {
	for i := 0; i < 300; i++ {
		r.mu.Lock()
		for _, t := range r.toks {
			if t == tok {
				r.mu.Unlock()
				return true
			}
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func newRegistry(t *testing.T) (*Sessions, *revokeRecorder, []byte) {
	rec := &revokeRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/guacamole/api/session" {
			rec.mu.Lock()
			rec.toks = append(rec.toks, r.Header.Get("Guacamole-Token"))
			rec.mu.Unlock()
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL + "/guacamole")
	key := []byte("0123456789abcdef")
	return &Sessions{GuacURL: u, Key: key, HTTP: httpx.New(httpx.Options{AllowPrivate: []string{u.Hostname()}})}, rec, key
}

// A revocation (sign out, access change) while a redemption is in flight
// wins: the token Guacamole issued is not bound, the blob stays used, and
// Guacamole is told to end that session.
func TestRevokeDuringRedemptionFailsClosed(t *testing.T) {
	s, rec, key := newRegistry(t)
	now := time.Now()
	blob, _ := Seal(key, AuthData{Username: "a@example.com", Expires: Expiry(now, time.Minute)})
	if cached, err := s.Redeem("usr_a", "a@example.com", blob, now); err != nil || cached != nil {
		t.Fatalf("first redemption: %v %v", cached, err)
	}
	s.Revoke(context.Background(), "usr_a") // e.g. logout lands here
	if s.Redeemed(context.Background(), "usr_a", blob, "LATE", []byte(`{"authToken":"LATE"}`), now) {
		t.Fatal("token issued across a revocation was bound")
	}
	if _, err := s.Allow("usr_a", []string{"LATE"}, now); err == nil {
		t.Fatal("late token usable")
	}
	if !rec.has("LATE") {
		t.Fatal("Guacamole was not told to end the late session")
	}
	if _, err := s.Redeem("usr_a", "a@example.com", blob, now); err != ErrBlobUsed {
		t.Fatalf("blob redeemable again after the race: %v", err)
	}

	// Same for a re-authentication answer forwarded before a revocation.
	if !s.Redeemed(context.Background(), "usr_b", "", "", nil, now) && s.Bind(context.Background(), "TOK_B", "usr_b", s.Gen("usr_b"), nil, now) {
		gen := s.Gen("usr_b")
		s.Revoke(context.Background(), "usr_b")
		if s.Bind(context.Background(), "TOK_B2", "usr_b", gen, nil, now) {
			t.Fatal("re-auth token bound across a revocation")
		}
		if !rec.has("TOK_B2") {
			t.Fatal("Guacamole was not told to end the re-auth session")
		}
	} else {
		t.Fatal("setup: bind failed")
	}
}

// Tokens are per user; blobs only for the user named in them.
func TestTokenAndBlobBinding(t *testing.T) {
	s, _, key := newRegistry(t)
	now := time.Now()
	blob, _ := Seal(key, AuthData{Username: "a@example.com", Expires: Expiry(now, time.Minute)})
	if _, err := s.Redeem("usr_b", "b@example.com", blob, now); err != ErrForeignBlob {
		t.Fatalf("foreign blob: %v", err)
	}
	expired, _ := Seal(key, AuthData{Username: "a@example.com", Expires: Expiry(now, -time.Second)})
	if _, err := s.Redeem("usr_a", "a@example.com", expired, now); err != ErrBadBlob {
		t.Fatalf("expired blob: %v", err)
	}
	s.Redeem("usr_a", "a@example.com", blob, now) //nolint:errcheck
	s.Redeemed(context.Background(), "usr_a", blob, "TA", []byte(`{"authToken":"TA"}`), now)
	if _, err := s.Allow("usr_b", []string{"TA"}, now); err != ErrForeignToken {
		t.Fatalf("cross-user token: %v", err)
	}
	if cached, err := s.Redeem("usr_a", "a@example.com", blob, now); err != nil || string(cached) != `{"authToken":"TA"}` {
		t.Fatalf("same-user repeat: %s %v", cached, err)
	}
}

// TOCTOU: a re-auth answer is bound only if the presented token is still the
// user's at the generation Allow returned; a revocation in between (even one
// that only dropped that token) ends the new session instead.
func TestBindRechecksPresentedTokens(t *testing.T) {
	s, rec, _ := newRegistry(t)
	now := time.Now()
	s.Bind(context.Background(), "OLD", "usr_c", s.Gen("usr_c"), nil, now)
	gen, err := s.Allow("usr_c", []string{"OLD"}, now)
	if err != nil {
		t.Fatal(err)
	}
	s.Revoke(context.Background(), "usr_c") // lands between Allow and the answer
	if s.Bind(context.Background(), "NEW", "usr_c", gen, []string{"OLD"}, now) {
		t.Fatal("re-auth answer bound after the presented token was revoked")
	}
	if !rec.has("NEW") {
		t.Fatal("Guacamole was not told to end the new session")
	}
	// Still current: binds.
	s.Bind(context.Background(), "T1", "usr_d", s.Gen("usr_d"), nil, now)
	gen, _ = s.Allow("usr_d", []string{"T1"}, now)
	if !s.Bind(context.Background(), "T1", "usr_d", gen, []string{"T1"}, now) {
		t.Fatal("current re-auth refused")
	}
}

// The gate and the proxy classify bodies the same way.
func TestBodyKind(t *testing.T) {
	mk := func(method, ct, body string) *http.Request {
		r := httptest.NewRequest(method, "/guacamole/api/tokens", strings.NewReader(body))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		return r
	}
	for _, c := range []struct {
		r    *http.Request
		want int
	}{
		{mk("POST", "Application/X-WWW-Form-Urlencoded; Charset=UTF-8", "a=1"), BodyForm},
		{mk("PUT", "application/x-www-form-urlencoded", "a=1"), BodyForm},
		{mk("POST", "application/json", "{}"), BodyOpaque},
		{mk("POST", "application/octet-stream", "x"), BodyOpaque},
		{mk("POST", "multipart/form-data; boundary=z", "x"), BodyRefused},
		{mk("POST", "", "token=x"), BodyRefused},
		{mk("POST", "form;;", "x"), BodyRefused},
		{mk("GET", "", ""), BodyNone},
	} {
		if got := BodyKind(c.r); got != c.want {
			t.Errorf("%s %q: %d, want %d", c.r.Method, c.r.Header.Get("Content-Type"), got, c.want)
		}
	}
}

// Form bodies only in a charset both sides decode identically, and the
// login path spelled exactly.
func TestBodyKindCharsetAndTokensPath(t *testing.T) {
	for ct, want := range map[string]int{
		"application/x-www-form-urlencoded; charset=utf-8":    BodyForm,
		"application/x-www-form-urlencoded; charset=US-ASCII": BodyForm,
		"application/x-www-form-urlencoded; charset=UTF-16":   BodyRefused,
		"application/x-www-form-urlencoded; charset=utf-7":    BodyRefused,
		"application/x-www-form-urlencoded; boundary=x":       BodyRefused,
	} {
		r := httptest.NewRequest("POST", "/guacamole/api/tokens", strings.NewReader("a=1"))
		r.Header.Set("Content-Type", ct)
		if got := BodyKind(r); got != want {
			t.Errorf("%q: %d, want %d", ct, got, want)
		}
	}
	for p, ambiguous := range map[string]bool{
		"/guacamole/api/tokens": false, "/guacamole/api/tokens/": true, "/guacamole/api/Tokens": true,
		"/guacamole/api/tokens;x=1": true, "/guacamole/api/tokens/TOK": false,
	} {
		r := httptest.NewRequest("POST", p, nil)
		if AmbiguousTokensPath(r) != ambiguous {
			t.Errorf("%s: ambiguous=%v", p, !ambiguous)
		}
		if IsTokensLogin(r) != (p == "/guacamole/api/tokens") {
			t.Errorf("%s: IsTokensLogin wrong", p)
		}
	}
}
