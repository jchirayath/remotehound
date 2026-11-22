package integration

// Enrolment hardening: public_url is a strict ASCII allow-list everywhere it
// can enter a bootstrap script or a one-liner, and wrong-code limiting is per
// client with a distinct "busy" answer.
//
// @kind:integration
// @feature:enroll @feature:settings

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jchirayath/remotehound/internal/enroll"
	"github.com/jchirayath/remotehound/internal/model"
)

// Unicode quotes PowerShell honours, plus other characters that must never
// reach a script.
var badURLs = []string{
	"https://rh.example.com/‘", "https://rh.example.com/’", "https://rh.example.com/‚", "https://rh.example.com/‛",
	"https://rh.example.com/“", "https://rh.example.com/”", "https://rh.example.com/„",
	"https://rh.exämple.com", "https://rh.example.com/a b", "https://rh.example.com/'x'", `https://rh.example.com/"`,
	"https://rh.example.com/$(id)", "https://rh.example.com/‮",
}

func TestPublicURLSettingIsStrict(t *testing.T) {
	h := start(t)
	var st struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/settings", nil, 200, &st)
	for _, u := range badURLs {
		var prob struct {
			Code   string `json:"code"`
			Fields []struct {
				Pointer string `json:"pointer"`
			} `json:"errors"`
		}
		h.do("PATCH", "/api/v1/settings", map[string]any{"public_url": u}, 400, &prob, "If-Match", st.Data.ETag)
		if prob.Code != "VALIDATION_FAILED" {
			t.Errorf("%q: %+v", u, prob)
		}
	}
}

// setPublicURL writes a value straight into the store, as an older release
// (with a weaker validator) or a hand-edited state file could have.
func setPublicURL(t *testing.T, h *harness, u string) {
	t.Helper()
	if err := h.app.Store.Update(func(x *model.State) error { x.Settings.PublicURL = u; return nil }); err != nil {
		t.Fatal(err)
	}
}

func getScript(t *testing.T, url, ua string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestBadStoredPublicURLFailsClosed(t *testing.T) {
	h := start(t)
	var st struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/settings", nil, 200, &st)
	h.do("PATCH", "/api/v1/settings", map[string]any{"public_url": h.srv.URL, "ssh_public_host": "127.0.0.1",
		"ssh_public_port": h.app.Tunnel.Addr().(*net.TCPAddr).Port}, 200, nil, "If-Match", st.Data.ETag)
	var enr struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "pc"}, 201, &enr)

	check := func(bad, s, how string) {
		t.Helper()
		if strings.Contains(s, bad) || strings.Contains(s, "__RH_") || !strings.Contains(s, "public address") {
			t.Fatalf("%q (%s): script not refused: %.300s", bad, how, s)
		}
	}
	// Over HTTP for one value (the per-IP HTTP limiter caps how many requests a test may send)…
	setPublicURL(t, h, badURLs[1])
	check(badURLs[1], getScript(t, h.srv.URL+"/e/"+enr.Data.Code, "curl/8.6.0"), "sh over HTTP")
	check(badURLs[1], getScript(t, h.srv.URL+"/e/"+enr.Data.Code, "WindowsPowerShell/5.1"), "ps1 over HTTP")
	// …and through the service for every value.
	for _, bad := range badURLs {
		setPublicURL(t, h, bad)
		for _, ps := range []bool{false, true} {
			s, _ := h.app.Enroll.Script(enr.Data.Code, "203.0.113.9", ps)
			check(bad, s, "service")
		}
		if u, w := enroll.Commands(bad, enr.Data.Code, true); u != "" || w != "" {
			t.Fatalf("%q: Commands built %q / %q", bad, u, w)
		}
		// A new code cannot be created with commands built from a bad URL.
		var prob struct {
			Code string `json:"code"`
		}
		h.do("POST", "/api/v1/enrollments", map[string]any{"name": "pc2"}, 409, &prob)
		if prob.Code != "SETTINGS_PUBLIC_URL_INVALID" {
			t.Fatalf("%q: create: %+v", bad, prob)
		}
	}
	// The code is re-checked at render too.
	setPublicURL(t, h, h.srv.URL)
	if u, _ := enroll.Commands(h.srv.URL, "ab'cd;", true); u != "" {
		t.Fatalf("Commands accepted a bad code: %q", u)
	}
	// Restored: the same code renders normally again (it was not consumed).
	setPublicURL(t, h, h.srv.URL)
	if s := getScript(t, h.srv.URL+"/e/"+enr.Data.Code, "curl/8.6.0"); !strings.Contains(s, h.srv.URL) || !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatalf("good URL did not render: %.200s", s)
	}
}

func newCode(t *testing.T, h *harness) string {
	t.Helper()
	var enr struct {
		Data struct {
			Code string `json:"code"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "pc"}, 201, &enr)
	return enr.Data.Code
}

func TestEnrolScriptCountsOneMissPerRequest(t *testing.T) {
	h := start(t)
	const n = 6 // under the HTTP limiter's burst; > MissesPerClient/2, so double counting shows
	for i := 0; i < n; i++ {
		if s := getScript(t, h.srv.URL+"/e/zzzzzz", "curl/8.6.0"); !strings.Contains(s, "not valid or has expired") {
			t.Fatalf("request %d: %s", i+1, s)
		}
	}
	// The test client is 127.0.0.1: exactly n misses were recorded.
	for i := n; i < enroll.MissesPerClient; i++ {
		if _, st := h.app.Enroll.Lookup("zzzzzz", "127.0.0.1"); st != "invalid" {
			t.Fatalf("miss %d: state %q (a request counted more than once)", i+1, st)
		}
	}
	if _, st := h.app.Enroll.Lookup("zzzzzz", "127.0.0.1"); st != "throttled" {
		t.Fatalf("after %d misses: state %q, want throttled", enroll.MissesPerClient, st)
	}
}

func TestEnrolBrakeIsPerClientWithDistinctBusyMessage(t *testing.T) {
	h := start(t)
	code := newCode(t, h)
	// More wrong codes than the old global brake allowed (120/min), from many clients.
	for i := 0; i < 130; i++ {
		ip := "198.51.100." + strconv.Itoa(i)
		if _, st := h.app.Enroll.Lookup("zzzzzz", ip); st != "invalid" {
			t.Fatalf("client %s: %q", ip, st)
		}
	}
	if s, st := h.app.Enroll.Script(code, "203.0.113.1", false); st != "open" || !strings.HasPrefix(s, "#!/bin/sh") {
		t.Fatalf("a real code stopped working after 130 spread-out misses: %q", st)
	}
	// One client (an IPv6 /64, whatever address it rotates to) that guesses too often is throttled…
	for i := 0; i < enroll.MissesPerClient; i++ {
		h.app.Enroll.Lookup("zzzzzz", "2001:db8:7:7::"+strconv.Itoa(i+1))
	}
	for _, ps := range []bool{false, true} {
		s, st := h.app.Enroll.Script(code, "2001:db8:7:7:dead::1", ps)
		if st != "throttled" || strings.Contains(s, "not valid") || !strings.Contains(s, "try again in a minute") {
			t.Fatalf("throttled client (ps=%v): %q %s", ps, st, s)
		}
	}
	if _, err := h.app.Enroll.Redeem(context.Background(), "2001:db8:7:7::99", enroll.RedeemRequest{Code: code}); err == nil ||
		!strings.Contains(err.Error(), "try again in a minute") {
		t.Fatalf("throttled redeem: %v", err)
	}
	// …while everyone else still enrols.
	if _, st := h.app.Enroll.Script(code, "2001:db8:8::1", false); st != "open" {
		t.Fatalf("another client: %q", st)
	}
}

func TestEnrolAbsoluteCeiling(t *testing.T) {
	h := start(t)
	code := newCode(t, h)
	for i := 0; i < enroll.MissCeiling; i++ {
		h.app.Enroll.Lookup("zzzzzz", "10."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250)+".1")
	}
	if _, st := h.app.Enroll.Lookup(code, "203.0.113.50"); st != "throttled" {
		t.Fatalf("after %d misses from everyone: %q, want throttled", enroll.MissCeiling, st)
	}
}

func TestEnrolMissLimitIsAtomicUnderConcurrency(t *testing.T) {
	h := start(t)
	const n = 64
	states := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, st := h.app.Enroll.Lookup("zzzzzz", "192.0.2.77")
			states <- st
		}()
	}
	wg.Wait()
	close(states)
	invalid := 0
	for st := range states {
		if st == "invalid" {
			invalid++
		}
	}
	if invalid != enroll.MissesPerClient {
		t.Fatalf("%d concurrent wrong codes were checked, want exactly %d", invalid, enroll.MissesPerClient)
	}
}

func TestEnrolGlobalCeilingRefusesCorrectRedeemAsBusy(t *testing.T) {
	if enroll.MissCeiling > 300 {
		t.Fatalf("MissCeiling = %d, want ≤ 300 (see THREAT_MODEL S5)", enroll.MissCeiling)
	}
	h := start(t)
	code := newCode(t, h)
	for i := 0; i < enroll.MissCeiling; i++ {
		h.app.Enroll.Lookup("zzzzzz", "10."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250)+".1")
	}
	_, err := h.app.Enroll.Redeem(context.Background(), "203.0.113.60", enroll.RedeemRequest{Code: code})
	if err == nil || !strings.Contains(err.Error(), "try again in a minute") || strings.Contains(err.Error(), "not valid") {
		t.Fatalf("correct code during a global pause: %v", err)
	}
}

// An untrusted peer cannot pick its own limiter key with X-Forwarded-For.
func TestEnrolMissKeyIgnoresUntrustedForwardedFor(t *testing.T) {
	h := start(t)
	code := newCode(t, h)
	// The test client is 127.0.0.1 and not a trusted proxy. Leave it one miss short.
	for i := 0; i < enroll.MissesPerClient-1; i++ {
		h.app.Enroll.Lookup("zzzzzz", "127.0.0.1")
	}
	get := func(xff string) string {
		req, _ := http.NewRequest("GET", h.srv.URL+"/e/zzzzzz", nil)
		req.Header.Set("User-Agent", "curl/8.6.0")
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if s := get("198.51.100.1"); !strings.Contains(s, "not valid") {
		t.Fatalf("last allowed miss: %s", s)
	}
	if s := get("198.51.100.2"); !strings.Contains(s, "try again in a minute") {
		t.Fatalf("a forged X-Forwarded-For reset the per-client budget on /e/: %s", s)
	}
	body, _ := json.Marshal(map[string]any{"code": code})
	req, _ := http.NewRequest("POST", h.srv.URL+"/api/v1/enroll", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "198.51.100.3")
	req.Header.Set("X-Real-IP", "198.51.100.3")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(b), "try again in a minute") {
		t.Fatalf("a forged X-Forwarded-For reset the per-client budget on redeem: %d %s", resp.StatusCode, b)
	}
}
