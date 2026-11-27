package logx

// @feature:logs

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactScrubsSecretsAndKeepsFingerprints(t *testing.T) {
	cases := map[string]string{
		"Authorization: Bearer abcdefghijklmnop.qrstuvwx":                              "abcdefghijklmnop",
		"jwt eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlc2lnbmF0dXJl here":  "eyJhbGciOiJSUzI1NiJ9", // gitleaks:allow (redaction fixture)
		"key 4c0b569e4c96df157eee1b65dd0e4d41ffff":                                     "4c0b569e4c96df157eee1b65dd0e4d41",
		"/guacamole/?data=QUJDREVGR0g%3D#/client/x":                                    "QUJDREVGR0g",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----": "AAAA",
	}
	for in, secret := range cases {
		if out := Redact(in); strings.Contains(out, secret) {
			t.Errorf("Redact(%q) = %q still contains %q", in, out, secret)
		}
	}
	fp := "fingerprint SHA256:2fGkWq3vO0aN1Zr7yq9g0u6E1lCq3mDh5ZtQ7xYcVbA"
	if out := Redact(fp); out != fp {
		t.Errorf("fingerprint mangled: %q", out)
	}
}

// An enrollment code in a request path (/e/<code>) is a live credential until
// it is used or expires: it must never reach a log line (THREAT_MODEL S5).
func TestRedactEnrollmentCodesInPaths(t *testing.T) {
	for _, in := range []string{"/e/k7q2mx", "GET /e/k7q2mx HTTP/1.1", "https://rh.example.com/e/K7Q2MX?x=1"} {
		if out := Redact(in); strings.Contains(strings.ToLower(out), "k7q2mx") {
			t.Errorf("Redact(%q) = %q still contains the code", in, out)
		}
	}
	if out := Redact("/ui/e/app.js"); out != "/ui/e/app.js" {
		t.Errorf("an asset path was mangled: %q", out)
	}
}

func TestRedactStripsControlCharacters(t *testing.T) {
	if out := Redact("line1\r\nfake INFO entry\x1b[31m"); strings.ContainsAny(out, "\r\n\x1b") {
		t.Fatalf("control chars survived: %q", out)
	}
}

func TestHandlerEmitsOTelShapeAndRedactsSensitiveKeys(t *testing.T) {
	var buf bytes.Buffer
	log := Init(&buf, Resource{ServiceName: "remotehound", ServiceVersion: "test", Environment: "test"}, "INFO")
	ctx := WithScope(context.Background(), Scope{RequestID: "req-12345678", TraceID: strings.Repeat("a", 32)})
	log.InfoContext(ctx, "Thing happened", Event("thing.happen"), slog.String("password", "hunter2"), slog.String("app.device.id", "dev_abc"))
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %v: %s", err, buf.String())
	}
	for k, want := range map[string]any{"severity_text": "INFO", "severity_number": float64(9), "event.name": "thing.happen",
		"service.name": "remotehound", "app.request.id": "req-12345678", "password": "[REDACTED]", "app.device.id": "dev_abc"} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %v", k, rec[k], want)
		}
	}
}

func TestLevelIsSwitchableAtRuntimeAndScopeDebugOverrides(t *testing.T) {
	var buf bytes.Buffer
	log := Init(&buf, Resource{}, "INFO")
	log.Debug("hidden")
	if buf.Len() != 0 {
		t.Fatal("debug emitted at INFO")
	}
	log.DebugContext(WithScope(context.Background(), Scope{Debug: true}), "per-device debug")
	if !strings.Contains(buf.String(), "per-device debug") {
		t.Fatal("scope debug flag ignored")
	}
	buf.Reset()
	SetLevel("DEBUG")
	log.Debug("now visible")
	if !strings.Contains(buf.String(), "now visible") || Level() != "DEBUG" {
		t.Fatal("runtime level change ignored")
	}
	SetLevel("INFO")
}

func TestRingFiltersAndKeepsNewest(t *testing.T) {
	r := NewRing(3)
	for i, sev := range []string{"INFO", "WARN", "ERROR", "INFO"} {
		r.Add(&Record{Severity: sev, Body: "m" + string(rune('0'+i)), Source: "server", Attributes: map[string]any{}})
	}
	all := r.Query(Filter{})
	if len(all) != 3 || all[0].Body != "m1" || all[2].Body != "m3" {
		t.Fatalf("ring order wrong: %+v", all)
	}
	if got := r.Query(Filter{MinLevel: "WARN"}); len(got) != 2 {
		t.Fatalf("level filter: got %d", len(got))
	}
}

// @feature:services
func TestRedactSecretPairsInFreeText(t *testing.T) {
	for in, leak := range map[string]string{
		"upstream said password=hunter2":         "hunter2",
		`{"client_secret":"s3cr3t-value","x":1}`: "s3cr3t-value",
		"connect token: abcdefg123 failed":       "abcdefg123",
		"API_KEY='k-123' rejected":               "k-123",
		"guacd: pwd=topsecret&user=admin":        "topsecret",
	} {
		if out := Redact(in); strings.Contains(out, leak) {
			t.Errorf("Redact(%q) = %q still leaks %q", in, out, leak)
		}
	}
	if out := Redact("token rejected for user admin"); out != "token rejected for user admin" {
		t.Errorf("plain prose changed: %q", out)
	}
}
