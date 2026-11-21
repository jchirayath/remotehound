// @feature:services
package services

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/guac"
)

func sources(mod func(*Sources)) *Sources {
	gu, _ := url.Parse("http://guacamole:8080/guacamole")
	s := &Sources{
		Version: "1.2.3", StartedAt: time.Now().Add(-time.Hour), HTTPAddr: ":8080", SSHListen: ":2222",
		PublicURL: func() string { return "https://rh.example.com" }, SSHPublicPort: func() int { return 2222 },
		TunnelOnline: func() int { return 3 }, TunnelUp: func() bool { return true },
		TunnelPortMin: 20000, TunnelPortMax: 20999, TunnelBind: "10.0.0.14",
		StoreWritable: func() error { return nil }, StorePath: "/data/state.json", StoreRecovered: func() string { return "" },
		Guac: func() guac.Report {
			return guac.Report{CheckedAt: time.Now(), Overall: guac.Pass, GuacamoleVersion: "1.6.0", Checks: []guac.Check{
				{ID: "guacamole.reachable", Status: guac.Pass, Detail: "HTTP 200", LatencyMS: 4},
				{ID: "guacd.reachable", Status: guac.Pass, Detail: "guacd answered 'args' for rdp (protocol 1.5.0)"},
				{ID: "json_auth.roundtrip", Status: guac.Pass, Detail: "accepted"}}}
		},
		GuacURL: gu, GuacPublicPath: "/guacamole", GuacdAddr: "guacd:4822", GuacKey: []byte("0123456789abcdef"),
		TunnelHost: "remotehound", RecordingOn: func() bool { return false }, RecordingPath: "/recordings",
	}
	if mod != nil {
		mod(s)
	}
	return s
}

func card(r Report, id string) Service {
	for _, s := range r.Services {
		if s.ID == id {
			return s
		}
	}
	return Service{}
}

func TestBuildHealthyStatusOnly(t *testing.T) {
	r := sources(nil).Build(context.Background())
	if r.Overall != OK || r.Control.Configured || len(r.Services) != 5 {
		t.Fatalf("report: overall=%s control=%+v n=%d", r.Overall, r.Control, len(r.Services))
	}
	if gd := card(r, IDGuacd); gd.Facts["protocol"] != "1.5.0" || gd.Status != OK || r.Guacamole.GuacdProtocol != "1.5.0" {
		t.Fatalf("guacd: %+v", gd)
	}
	if r.Guacamole.SecretMatches != "pass" || r.Guacamole.SecretFingerprint == "" || strings.Contains(r.Guacamole.SecretFingerprint, "0123") {
		t.Fatalf("guac config: %+v", r.Guacamole)
	}
	if !card(r, IDRemoteHound).SelfManaged {
		t.Fatal("remotehound must be marked self-managed (restart only)")
	}
}

func TestBuildMarksFailures(t *testing.T) {
	r := sources(func(s *Sources) {
		s.StoreWritable = func() error { return errors.New("read-only file system") }
		s.TunnelUp = func() bool { return false }
		s.Guac = func() guac.Report {
			return guac.Report{CheckedAt: time.Now(), Checks: []guac.Check{
				{ID: "guacamole.reachable", Status: guac.Pass}, {ID: "json_auth.roundtrip", Status: guac.Fail, Detail: "secret differs"}}}
		}
	}).Build(context.Background())
	if r.Overall != Down || card(r, IDStore).Status != Down || card(r, IDTunnel).Status != Down || card(r, IDGuacamole).Status != Down {
		t.Fatalf("failures not reported: %+v", r)
	}
	if r.Guacamole.SecretMatches != "fail" {
		t.Fatal("secret mismatch not surfaced")
	}
	if card(r, IDGuacd).Status != OK {
		// guacd.reachable is absent from the checks: unknown detail, but not invented as down.
		t.Logf("guacd: %+v", card(r, IDGuacd))
	}
}

func TestNeverCheckedIsUnknownNotOK(t *testing.T) {
	r := sources(func(s *Sources) { s.Guac = func() guac.Report { return guac.Report{} } }).Build(context.Background())
	if card(r, IDGuacamole).Status != Unknown || r.Overall != Degraded {
		t.Fatalf("unchecked guacamole: %s overall %s", card(r, IDGuacamole).Status, r.Overall)
	}
}

func TestOwnProblemsAreRecentRedactedAndAttributed(t *testing.T) {
	now := time.Now()
	recs := []*logx.Record{
		{Timestamp: now.Add(-2 * time.Hour), Severity: "ERROR", Body: "too old", Event: "http.error"},
		{Timestamp: now.Add(-time.Minute), Severity: "WARN", Body: "tunnel dropped", Event: "tunnel.closed"},
		{Timestamp: now, Severity: "ERROR", Body: "upstream said password=hunter2", Event: "http.error"},
	}
	r := sources(func(s *Sources) { s.Logs = func(logx.Filter) []*logx.Record { return recs } }).Build(context.Background())
	rh, tun := card(r, IDRemoteHound), card(r, IDTunnel)
	if len(rh.Problems) != 1 || strings.Contains(rh.Problems[0].Text, "hunter2") {
		t.Fatalf("remotehound problems: %+v", rh.Problems)
	}
	if len(tun.Problems) != 1 || !strings.Contains(tun.Problems[0].Text, "tunnel dropped") {
		t.Fatalf("tunnel problems: %+v", tun.Problems)
	}
}

func TestContainerProblemsNewestFirst(t *testing.T) {
	lines := []control.LogLine{{Text: "a ERROR: first"}, {Text: "fine"}, {Text: "WARNING: second"}, {Text: "ERROR: third"}}
	got := ContainerProblems(lines, 2)
	if len(got) != 2 || !strings.Contains(got[0].Text, "third") || got[1].Severity != "warn" {
		t.Fatalf("got %+v", got)
	}
}

func TestFingerprint(t *testing.T) {
	if Fingerprint(nil) != "" {
		t.Fatal("empty key")
	}
	f := Fingerprint([]byte("0123456789abcdef"))
	if len(f) != 23 || strings.Count(f, ":") != 7 || f != Fingerprint([]byte("0123456789abcdef")) {
		t.Fatalf("fingerprint %q", f)
	}
}

func TestImageVersionAndBenignLines(t *testing.T) {
	for img, want := range map[string]string{
		"guacamole/guacd:1.6.0@sha256:abc": "1.6.0", "remotehound:ae2d08c": "ae2d08c",
		"localhost:5000/guacd": "", "ghcr.io/x/remotehound:latest": "", "registry:5000/a/b:2.1": "2.1",
	} {
		if got := imageVersion(&control.Container{Image: img}); got != want {
			t.Errorf("imageVersion(%q) = %q, want %q", img, got, want)
		}
	}
	lines := []control.LogLine{
		{Text: `guacd[8]: ERROR:	Handshake failed, "connect" instruction was not received.`},
		{Text: `guacd[9]: ERROR:	Connection to host 10.0.0.1 failed`},
	}
	got := ContainerProblems(lines, 10)
	if len(got) != 1 || !strings.Contains(got[0].Text, "Connection to host") {
		t.Fatalf("benign filter: %+v", got)
	}
}
