package httpx

// @feature:integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestSSRFGuardBlocksPrivateDestinations(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c := New(Options{Retries: 1})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if _, err := c.Do(req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback not blocked: %v", err)
	}
}

func TestAllowPrivateHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "RemoteHound" {
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	c := New(Options{AllowPrivate: []string{"127.0.0.1"}})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("allowed host failed: %v %v", err, resp)
	}
	resp.Body.Close()
}

func TestPublicAddr(t *testing.T) {
	for addr, want := range map[string]bool{"8.8.8.8": true, "10.0.0.1": false, "169.254.169.254": false, "::1": false, "100.64.1.1": false, "::ffff:127.0.0.1": false} {
		if got := PublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: got %v", addr, got)
		}
	}
}

func TestBreakerOpensAfterFailures(t *testing.T) {
	c := New(Options{})
	b := c.breaker("h")
	for i := 0; i < 5; i++ {
		b.record(false)
	}
	if b.allow() || c.BreakerState("h") != "open" {
		t.Fatal("breaker did not open")
	}
}
