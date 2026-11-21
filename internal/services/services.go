// Package services builds the Services screen: one card per component of the
// bundle (RemoteHound, its tunnel server and data store, Guacamole, guacd) with
// status, version, ports, recent problems and — when the optional rh-control
// helper is configured — the container's state and the actions it allows.
//
// Status comes from RemoteHound's own probes and the Guacamole integration
// checker, so it works with no Docker access at all. Container state, container
// logs and start/stop/restart come from rh-control (internal/control).
package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/url"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/control"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/guac"
)

// Service statuses.
const (
	OK       = "ok"
	Degraded = "degraded"
	Down     = "down"
	Unknown  = "unknown"
)

// Well-known service IDs. They double as the rh-control label names, so a
// container labelled io.remotehound.control.service=guacamole merges into the
// Guacamole card. Any other labelled container gets a card of its own.
const (
	IDRemoteHound = "remotehound"
	IDTunnel      = "tunnel"
	IDStore       = "store"
	IDGuacamole   = "guacamole"
	IDGuacd       = "guacd"
)

// Endpoint is a port or URL the service answers on.
type Endpoint struct {
	Label    string `json:"label"`
	Address  string `json:"address"`
	Exposure string `json:"exposure"` // public | internal
	Protocol string `json:"protocol"`
}

// Problem is a recent warning or error attributed to a service.
type Problem struct {
	Time     time.Time `json:"time,omitzero"`
	Severity string    `json:"severity"` // warn | error
	Text     string    `json:"text"`
	Source   string    `json:"source"` // remotehound | container
}

// Service is one card.
type Service struct {
	ID         string             `json:"id"`
	Name       string             `json:"name"`
	Role       string             `json:"role"`
	Status     string             `json:"status"`
	Detail     string             `json:"detail"`
	Version    string             `json:"version,omitempty"`
	LatencyMS  *int64             `json:"latency_ms,omitempty"`
	Endpoints  []Endpoint         `json:"endpoints"`
	Facts      map[string]string  `json:"facts,omitempty"`
	Container  *control.Container `json:"container,omitempty"`
	Problems   []Problem          `json:"problems"`
	Controlled bool               `json:"controlled"` // has a container rh-control can act on
	// SelfManaged: actions on this service end the request that asked for
	// them (restarting RemoteHound restarts the API) — the UI warns first.
	SelfManaged bool `json:"self_managed,omitempty"`
}

// ControlStatus reports whether container control is available.
type ControlStatus struct {
	Configured bool   `json:"configured"`
	Reachable  bool   `json:"reachable"`
	Address    string `json:"address,omitempty"`
	Detail     string `json:"detail"`
}

// GuacConfig is the read-only Guacamole configuration card. No secret is ever
// included: the JSON key appears only as a short fingerprint so an operator
// can compare it with the value given to the guacamole container.
type GuacConfig struct {
	InternalURL         string `json:"internal_url"`
	PublicPath          string `json:"public_path"`
	Version             string `json:"version,omitempty"`
	GuacdAddress        string `json:"guacd_address"`
	GuacdProtocol       string `json:"guacd_protocol,omitempty"`
	AuthExtension       string `json:"auth_extension"`
	UserDatabase        string `json:"user_database"`
	SecretFingerprint   string `json:"secret_fingerprint"`
	SecretMatches       string `json:"secret_matches"` // pass | fail | unknown — from the JSON round-trip check
	TunnelAdvertiseHost string `json:"tunnel_advertise_host"`
	RecordingEnabled    bool   `json:"recording_enabled"`
	RecordingPath       string `json:"recording_path"`
	CheckedAt           string `json:"checked_at,omitempty"`
}

// Report is GET /api/v1/services.
type Report struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Overall     string        `json:"overall"`
	Control     ControlStatus `json:"control"`
	Services    []Service     `json:"services"`
	Guacamole   GuacConfig    `json:"guacamole"`
}

// Sources are the read-only views the report needs (small interfaces so the
// builder is unit-testable without a real tunnel server or store).
type Sources struct {
	Version        string
	StartedAt      time.Time
	HTTPAddr       string
	PublicURL      func() string
	SSHListen      string
	SSHPublicPort  func() int
	TunnelOnline   func() int
	TunnelUp       func() bool
	TunnelPortMin  int
	TunnelPortMax  int
	TunnelBind     string
	StoreWritable  func() error
	StorePath      string
	StoreRecovered func() string
	Guac           func() guac.Report
	GuacURL        *url.URL
	GuacPublicPath string
	GuacdAddr      string
	GuacKey        []byte
	TunnelHost     string
	RecordingOn    func() bool
	RecordingPath  string
	Logs           func(f logx.Filter) []*logx.Record
	Control        *control.Client
}

// Build assembles the report. It never fails: a broken dependency is a
// status on its card, not an error page.
func (src *Sources) Build(ctx context.Context) Report {
	rep := Report{GeneratedAt: time.Now().UTC()}
	g := src.Guac()
	byID := map[string]guac.Check{}
	for _, c := range g.Checks {
		byID[c.ID] = c
	}

	// Container view first, so it can be merged into the built-in cards.
	var containers []control.Container
	rep.Control.Configured = src.Control.Configured()
	rep.Control.Address = src.Control.Address()
	if !rep.Control.Configured {
		rep.Control.Detail = "Status only. Set RH_CONTROL_URL and run the rh-control helper to start, stop and restart containers and read their logs here."
	} else {
		cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
		list, err := src.Control.List(cctx)
		cancel()
		if err != nil {
			rep.Control.Detail = "rh-control did not answer: " + err.Error()
		} else {
			rep.Control.Reachable, containers = true, list
			rep.Control.Detail = strconv.Itoa(len(list)) + " controllable container(s)."
		}
	}
	take := func(id string) *control.Container {
		for i := range containers {
			if containers[i].Service == id {
				c := containers[i]
				containers = slices.Delete(containers, i, i+1)
				return &c
			}
		}
		return nil
	}
	// RemoteHound's own WARN/ERROR records from the last hour (newest first).
	ownProblems := func(match func(logx.Record) bool) []Problem {
		var out []Problem
		if src.Logs == nil {
			return []Problem{}
		}
		cutoff := time.Now().Add(-time.Hour)
		recs := src.Logs(logx.Filter{MinLevel: "WARN", Limit: 500}) // oldest first
		for i := len(recs) - 1; i >= 0; i-- {
			r := *recs[i]
			if r.Timestamp.Before(cutoff) || !match(r) {
				continue
			}
			out = append(out, Problem{Time: r.Timestamp, Severity: strings.ToLower(r.Severity), Text: logx.Redact(r.Body + eventSuffix(r)), Source: "remotehound"})
			if len(out) == 10 {
				break
			}
		}
		if out == nil {
			out = []Problem{}
		}
		return out
	}
	eventIs := func(prefixes ...string) func(logx.Record) bool {
		return func(r logx.Record) bool {
			for _, p := range prefixes {
				if strings.HasPrefix(r.Event, p) {
					return true
				}
			}
			return false
		}
	}

	// RemoteHound (this process).
	rh := Service{ID: IDRemoteHound, Name: "RemoteHound", Role: "Web console, API, sign-in and the Guacamole proxy", Status: OK,
		Version: src.Version, Detail: "Serving since " + src.StartedAt.UTC().Format(time.RFC3339),
		Endpoints: []Endpoint{{Label: "Console and API", Address: src.PublicURL(), Exposure: "public", Protocol: "https"},
			{Label: "HTTP listener", Address: src.HTTPAddr, Exposure: "internal", Protocol: "http"}},
		Facts: map[string]string{"uptime": time.Since(src.StartedAt).Round(time.Second).String(), "go": runtime.Version(),
			"goroutines": strconv.Itoa(runtime.NumGoroutine())},
		SelfManaged: true,
		Problems: ownProblems(func(r logx.Record) bool {
			return !eventIs("tunnel.", "device.", "store.", "integration.", "guac")(r)
		})}
	rh.Container = take(IDRemoteHound)

	// Tunnel server.
	tun := Service{ID: IDTunnel, Name: "Tunnel server", Role: "Embedded SSH server devices hold their ssh -R tunnel to", Status: OK,
		Endpoints: []Endpoint{{Label: "Device tunnels (SSH)", Address: hostPort(src.PublicURL(), src.SSHPublicPort()), Exposure: "public", Protocol: "ssh"},
			{Label: "SSH listener", Address: src.SSHListen, Exposure: "internal", Protocol: "ssh"},
			{Label: "Tunnel listeners for guacd", Address: src.TunnelBind + ":" + strconv.Itoa(src.TunnelPortMin) + "-" + strconv.Itoa(src.TunnelPortMax), Exposure: "internal", Protocol: "tcp"}},
		Facts:    map[string]string{"devices_online": strconv.Itoa(src.TunnelOnline())},
		Problems: ownProblems(eventIs("tunnel.", "device."))}
	if !src.TunnelUp() {
		tun.Status, tun.Detail = Down, "The SSH listener is not running: devices cannot connect. RemoteHound's readiness check fails too, so the container will be restarted."
	} else {
		tun.Detail = strconv.Itoa(src.TunnelOnline()) + " device(s) connected."
	}

	// Data store.
	sto := Service{ID: IDStore, Name: "Data store", Role: "Users, devices, groups, sessions and sealed logins (JSON file, atomic writes)", Status: OK,
		Endpoints: []Endpoint{}, Facts: map[string]string{"path": src.StorePath}, Problems: ownProblems(eventIs("store."))}
	if err := src.StoreWritable(); err != nil {
		sto.Status, sto.Detail = Down, "Not writable: "+err.Error()+". Changes cannot be saved."
	} else {
		sto.Detail = "Writable."
	}
	if from := src.StoreRecovered(); from != "" {
		if sto.Status == OK {
			sto.Status = Degraded
		}
		sto.Detail += " Loaded from backup " + from + " at startup because the main file was unreadable — check the audit log for missing recent changes."
	}

	// Guacamole.
	gc := Service{ID: IDGuacamole, Name: "Guacamole", Role: "HTML5 remote-desktop client; redeems RemoteHound's sealed connect tokens",
		Version: g.GuacamoleVersion, Endpoints: []Endpoint{{Label: "Web app (proxied at " + src.GuacPublicPath + ")", Address: src.GuacURL.Host, Exposure: "internal", Protocol: "http"}},
		Problems: ownProblems(eventIs("integration.", "guac"))}
	gc.Status, gc.Detail, gc.LatencyMS = fromChecks(g, byID, "guacamole.reachable", "json_auth.roundtrip")
	gc.Container = take(IDGuacamole)
	if gc.Version == "" || gc.Version == "unknown" {
		// Stock Guacamole does not report its version over HTTP; the image tag
		// (guacamole/guacamole:1.6.0@sha256:…) is the reliable source.
		gc.Version = imageVersion(gc.Container)
	}

	// guacd.
	gd := Service{ID: IDGuacd, Name: "guacd", Role: "Protocol engine: speaks RDP, VNC and SSH to devices through their tunnels",
		Endpoints: []Endpoint{{Label: "Guacamole protocol", Address: src.GuacdAddr, Exposure: "internal", Protocol: "guac"}}, Problems: []Problem{}}
	gd.Status, gd.Detail, gd.LatencyMS = fromChecks(g, byID, "guacd.reachable")
	proto := ""
	if c, ok := byID["guacd.reachable"]; ok {
		proto = protocolOf(c.Detail) // the Guacamole PROTOCOL version (1.5.0 for guacd 1.6.0), not the release
	}
	gd.Container = take(IDGuacd)
	gd.Version = imageVersion(gd.Container)
	if proto != "" {
		gd.Facts = map[string]string{"protocol": proto}
	}

	rep.Services = []Service{rh, tun, sto, gc, gd}
	// Any other labelled container (e.g. the operator labelled caddy).
	sort.Slice(containers, func(i, j int) bool { return containers[i].Service < containers[j].Service })
	for i := range containers {
		c := containers[i]
		rep.Services = append(rep.Services, Service{ID: c.Service, Name: c.Service, Role: "Container labelled for RemoteHound control",
			Status: containerStatus(&c), Detail: "Known only through rh-control.", Endpoints: []Endpoint{}, Container: &c, Problems: []Problem{}})
	}

	// Container state overrides: a stopped container is down whatever the
	// last probe said; an unhealthy one is at least degraded.
	for i := range rep.Services {
		s := &rep.Services[i]
		if s.Container == nil {
			continue
		}
		s.Controlled = len(s.Container.Actions) > 0
		switch cs := containerStatus(s.Container); {
		case cs == Down:
			s.Status, s.Detail = Down, "Container is "+s.Container.State+exitNote(s.Container)+". "+s.Detail
		case cs == Degraded && s.Status == OK:
			s.Status = Degraded
			s.Detail = "Container health is " + s.Container.Health + ". " + s.Detail
		}
	}

	// Recent problems from container output (Guacamole, guacd, any extra
	// labelled container). RemoteHound's own come from its log ring above,
	// which is richer than its stdout, so its container log is not re-read.
	if rep.Control.Reachable {
		for i := range rep.Services {
			s := &rep.Services[i]
			if s.Container == nil || s.ID == IDRemoteHound || !slices.Contains(s.Container.Actions, control.ActionLogs) {
				continue
			}
			lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			lines, err := src.Control.Logs(lctx, s.Container.Service, 300)
			cancel()
			if err != nil {
				continue
			}
			s.Problems = append(s.Problems, ContainerProblems(lines, 10)...)
			sort.SliceStable(s.Problems, func(a, b int) bool { return s.Problems[a].Time.After(s.Problems[b].Time) })
			if len(s.Problems) > 10 {
				s.Problems = s.Problems[:10]
			}
		}
	}

	rep.Guacamole = GuacConfig{InternalURL: src.GuacURL.String(), PublicPath: src.GuacPublicPath, Version: gc.Version,
		GuacdAddress: src.GuacdAddr, GuacdProtocol: proto, AuthExtension: "guacamole-auth-json (encrypted JSON)",
		UserDatabase:      "None. Guacamole keeps no users or connections: RemoteHound holds them and hands Guacamole a 60-second sealed token per session.",
		SecretFingerprint: Fingerprint(src.GuacKey), SecretMatches: Unknown, TunnelAdvertiseHost: src.TunnelHost,
		RecordingEnabled: src.RecordingOn(), RecordingPath: src.RecordingPath}
	if !g.CheckedAt.IsZero() {
		rep.Guacamole.CheckedAt = g.CheckedAt.Format(time.RFC3339)
	}
	if c, ok := byID["json_auth.roundtrip"]; ok {
		switch c.Status {
		case guac.Pass:
			rep.Guacamole.SecretMatches = "pass"
		case guac.Fail:
			rep.Guacamole.SecretMatches = "fail"
		}
	}

	rep.Overall = OK
	for _, s := range rep.Services {
		switch s.Status {
		case Down:
			rep.Overall = Down
		case Degraded, Unknown:
			if rep.Overall == OK {
				rep.Overall = Degraded
			}
		}
	}
	return rep
}

// benign are container log lines that look like problems but are not, each
// with the reason. Keep this list short and specific: hiding a real error is
// worse than showing a harmless one.
var benign = []string{
	// RemoteHound's own guacd probe (guac.checkGuacd) sends "select", reads
	// "args" and hangs up; guacd logs that at ERROR. A real client always
	// sends "connect", so this line is the probe (or a port scan).
	`Handshake failed, "connect" instruction was not received`,
	// Guacamole 1.6.0 start-up notice from Jersey; WADL is unused.
	`JAXBContext implementation could not be found. WADL feature is disabled`,
}

func isBenign(text string) bool {
	for _, b := range benign {
		if strings.Contains(text, b) {
			return true
		}
	}
	return false
}

// ContainerProblems turns container log lines into problems (newest first, max n).
func ContainerProblems(lines []control.LogLine, n int) []Problem {
	out := []Problem{}
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		if isBenign(lines[i].Text) {
			continue
		}
		if sev := control.Problem(lines[i].Text); sev != "" {
			out = append(out, Problem{Time: lines[i].Time, Severity: sev, Text: logx.Redact(lines[i].Text), Source: "container"})
		}
	}
	return out
}

// Fingerprint is the first 8 bytes of SHA-256 of a key, as hex pairs. It
// identifies a 128-bit random key without revealing anything usable.
func Fingerprint(key []byte) string {
	if len(key) == 0 {
		return ""
	}
	sum := sha256.Sum256(key)
	h := hex.EncodeToString(sum[:8])
	var b strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(h[i : i+2])
	}
	return b.String()
}

func fromChecks(g guac.Report, byID map[string]guac.Check, ids ...string) (string, string, *int64) {
	if g.CheckedAt.IsZero() {
		return Unknown, "Not checked yet. Run the integration checks.", nil
	}
	status, detail := OK, ""
	var lat *int64
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			continue
		}
		if lat == nil && c.LatencyMS > 0 {
			l := c.LatencyMS
			lat = &l
		}
		switch c.Status {
		case guac.Fail:
			status = Down
		case guac.Warn:
			if status == OK {
				status = Degraded
			}
		}
		if detail == "" || c.Status == guac.Fail {
			detail = c.Detail
		}
	}
	return status, detail + " (checked " + g.CheckedAt.Format("15:04:05 MST") + ")", lat
}

func containerStatus(c *control.Container) string {
	switch {
	case c.State != "running":
		return Down
	case c.Health == "unhealthy":
		return Degraded
	case c.Health == "starting":
		return Degraded
	}
	return OK
}

func exitNote(c *control.Container) string {
	if c.State != "exited" && c.State != "dead" {
		return ""
	}
	s := " (exit code " + strconv.Itoa(c.ExitCode)
	if c.OOMKilled {
		s += ", killed for using too much memory"
	}
	return s + ")"
}

func eventSuffix(r logx.Record) string {
	if r.Event == "" {
		return ""
	}
	return " [" + r.Event + "]"
}

// imageVersion is the tag of an image reference: "guacamole/guacd:1.6.0@sha256:…"
// → "1.6.0". Empty for untagged/latest references or no container.
func imageVersion(c *control.Container) string {
	if c == nil {
		return ""
	}
	ref, _, _ := strings.Cut(c.Image, "@")
	i := strings.LastIndex(ref, ":")
	if i < 0 || strings.Contains(ref[i:], "/") {
		return ""
	}
	if v := ref[i+1:]; v != "latest" {
		return v
	}
	return ""
}

func protocolOf(detail string) string {
	_, v, ok := strings.Cut(detail, "(protocol ")
	if !ok {
		return ""
	}
	return strings.TrimSuffix(v, ")")
}

func hostPort(publicURL string, port int) string {
	u, err := url.Parse(publicURL)
	if err != nil || u.Hostname() == "" {
		return ":" + strconv.Itoa(port)
	}
	return net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
}
