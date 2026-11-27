package guac

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/httpx"
)

// Check statuses.
const (
	Pass = "pass"
	Warn = "warn"
	Fail = "fail"
	Skip = "skip"
)

// Check is one integration validation result shown on the Integration screen.
type Check struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Hint      string `json:"hint,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
}

// Report is the full result.
type Report struct {
	CheckedAt        time.Time `json:"checked_at"`
	Overall          string    `json:"overall"`
	GuacamoleVersion string    `json:"guacamole_version"`
	Checks           []Check   `json:"checks"`
}

// Checker validates the RemoteHound ⇄ Guacamole ⇄ guacd wiring.
type Checker struct {
	GuacURL             *url.URL // internal, e.g. http://guacamole:8080/guacamole
	GuacdAddr           string
	Key                 []byte
	HTTP                *httpx.Client
	TunnelAdvertiseHost string
	RecordingsDir       string
	RecordingEnabled    func() bool

	mu       sync.RWMutex
	last     Report
	lastDeep time.Time
	guacd    Check
}

// Last returns the most recent report (zero value before the first run).
func (c *Checker) Last() Report {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last
}

// Health summarizes the last report as ok | degraded | down | unknown.
func (c *Checker) Health() string {
	r := c.Last()
	switch r.Overall {
	case Pass:
		return "ok"
	case Warn:
		return "degraded"
	case Fail:
		return "down"
	}
	return "unknown"
}

// Run executes every check (on demand: the Integration screen's button).
func (c *Checker) Run(ctx context.Context) Report { return c.run(ctx, true) }

// RunPeriodic is the background job's variant: the guacd protocol handshake
// makes guacd log an ERROR ("connect instruction was not received") every
// time, so it runs at most every 10 minutes; in between, the last result is reused.
func (c *Checker) RunPeriodic(ctx context.Context) Report {
	c.mu.RLock()
	deep := time.Since(c.lastDeep) > 10*time.Minute
	c.mu.RUnlock()
	return c.run(ctx, deep)
}

func (c *Checker) run(ctx context.Context, deep bool) Report {
	r := Report{CheckedAt: time.Now().UTC()}
	add := func(ch Check) { r.Checks = append(r.Checks, ch) }

	reach := c.checkReachable(ctx)
	add(reach)
	if deep {
		g := c.checkGuacd(ctx)
		c.mu.Lock()
		c.guacd, c.lastDeep = g, time.Now()
		c.mu.Unlock()
		add(g)
	} else {
		c.mu.RLock()
		add(c.guacd)
		c.mu.RUnlock()
	}
	rt, version, skew := c.checkRoundtrip(ctx, reach.Status != Fail)
	add(rt)
	r.GuacamoleVersion = version
	add(c.checkClock(skew, rt.Status == Pass))
	add(c.checkAdvertise(ctx))
	add(c.checkRecording())

	r.Overall = Pass
	for _, ch := range r.Checks {
		if ch.Status == Fail {
			r.Overall = Fail
			break
		}
		if ch.Status == Warn {
			r.Overall = Warn
		}
	}
	c.mu.Lock()
	c.last = r
	c.mu.Unlock()
	return r
}

func timed(f func() Check) Check {
	start := time.Now()
	ch := f()
	ch.LatencyMS = time.Since(start).Milliseconds()
	return ch
}

func (c *Checker) checkReachable(ctx context.Context) Check {
	return timed(func() Check {
		ch := Check{ID: "guacamole.reachable", Title: "Guacamole web app answers"}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.GuacURL.String()+"/api/languages", nil)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			ch.Status, ch.Detail = Fail, "No answer from "+c.GuacURL.Host+": "+err.Error()
			ch.Hint = "Is the guacamole container running and on the guac network? Check RH_GUAC_URL and `docker compose ps`."
			return ch
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) //nolint:errcheck // body not needed
		if resp.StatusCode != http.StatusOK {
			ch.Status, ch.Detail = Fail, fmt.Sprintf("GET /api/languages returned %d", resp.StatusCode)
			ch.Hint = "RH_GUAC_URL must include Guacamole's context path (default /guacamole) and match WEBAPP_CONTEXT."
			return ch
		}
		ch.Status, ch.Detail = Pass, "HTTP 200 from "+c.GuacURL.Host
		return ch
	})
}

// checkGuacd speaks the Guacamole protocol: "select" a protocol and expect "args".
func (c *Checker) checkGuacd(ctx context.Context) Check {
	return timed(func() Check {
		ch := Check{ID: "guacd.reachable", Title: "guacd protocol handshake"}
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", c.GuacdAddr)
		if err != nil {
			ch.Status, ch.Detail = Fail, "Cannot connect to guacd at "+c.GuacdAddr+": "+err.Error()
			ch.Hint = "Check the guacd container and RH_GUACD_ADDR / GUACD_HOSTNAME."
			return ch
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte("6.select,3.rdp;")); err != nil {
			ch.Status, ch.Detail = Fail, "Write failed: "+err.Error()
			return ch
		}
		line, err := bufio.NewReader(conn).ReadString(';')
		if err != nil || !strings.Contains(line, ".args,") {
			ch.Status, ch.Detail = Fail, "guacd did not answer the select instruction"
			ch.Hint = "Something other than guacd is listening on " + c.GuacdAddr + "."
			return ch
		}
		ch.Status, ch.Detail = Pass, "guacd answered 'args' for rdp"
		if v := guacdVersion(line); v != "" {
			ch.Detail += " (protocol " + v + ")"
		}
		return ch
	})
}

func guacdVersion(argsInstr string) string {
	// 4.args,13.VERSION_1_5_0,8.hostname,… — first arg is the protocol version.
	parts := strings.SplitN(argsInstr, ",", 3)
	if len(parts) < 2 {
		return ""
	}
	_, v, ok := strings.Cut(parts[1], ".")
	if !ok || !strings.HasPrefix(v, "VERSION_") {
		return ""
	}
	return strings.ReplaceAll(strings.TrimPrefix(v, "VERSION_"), "_", ".")
}

// checkRoundtrip proves the shared JSON key matches by redeeming a sealed blob.
func (c *Checker) checkRoundtrip(ctx context.Context, reachable bool) (Check, string, time.Duration) {
	var version string
	var skew time.Duration
	ch := timed(func() Check {
		ch := Check{ID: "json_auth.roundtrip", Title: "Signed connect token accepted"}
		if !reachable {
			ch.Status, ch.Detail = Skip, "Skipped: Guacamole is not reachable."
			return ch
		}
		sealed, err := Seal(c.Key, AuthData{Username: "remotehound-selfcheck", Expires: Expiry(time.Now(), 30*time.Second), Connections: map[string]Connection{}})
		if err != nil {
			ch.Status, ch.Detail = Fail, err.Error()
			return ch
		}
		form := url.Values{"data": {sealed}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.GuacURL.String()+"/api/tokens", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			ch.Status, ch.Detail = Fail, "POST /api/tokens failed: "+err.Error()
			return ch
		}
		defer resp.Body.Close()
		if d, err := http.ParseTime(resp.Header.Get("Date")); err == nil {
			skew = time.Since(d)
		}
		var tok struct {
			AuthToken  string `json:"authToken"`
			DataSource string `json:"dataSource"`
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &tok) != nil || tok.AuthToken == "" {
			ch.Status = Fail
			ch.Detail = fmt.Sprintf("Guacamole rejected the token (HTTP %d).", resp.StatusCode)
			ch.Hint = "RH_GUAC_JSON_SECRET must equal JSON_SECRET_KEY on the guacamole container, and JSON_ENABLED must be true. Guacamole logs the exact reason."
			return ch
		}
		if tok.DataSource != DataSource {
			ch.Status = Warn
			ch.Detail = "Token accepted but by data source '" + tok.DataSource + "', expected 'json'."
			ch.Hint = "Another auth extension answered first. Disable other auth extensions on the guacamole container."
		} else {
			ch.Status, ch.Detail = Pass, "Guacamole redeemed a sealed token with the json data source."
		}
		// Clean up the session we just created.
		del, _ := http.NewRequestWithContext(ctx, http.MethodDelete, c.GuacURL.String()+"/api/session", nil)
		del.Header.Set("Guacamole-Token", tok.AuthToken)
		if r2, err := c.HTTP.Do(del); err == nil {
			r2.Body.Close()
		}
		version = resp.Header.Get("X-Guacamole-Version") // not sent by stock builds; kept if a proxy adds it
		return ch
	})
	if version == "" {
		version = "unknown"
	}
	return ch, version, skew
}

func (c *Checker) checkClock(skew time.Duration, haveDate bool) Check {
	ch := Check{ID: "json_auth.clock", Title: "Clocks agree (tokens live 60 s)"}
	if !haveDate {
		ch.Status, ch.Detail = Skip, "Skipped: no response to compare against."
		return ch
	}
	if skew < 0 {
		skew = -skew
	}
	switch {
	case skew > 30*time.Second:
		ch.Status = Fail
		ch.Hint = "Connect tokens will be rejected as expired. Enable NTP on the host."
	case skew > 5*time.Second:
		ch.Status = Warn
		ch.Hint = "Enable NTP on the host."
	default:
		ch.Status = Pass
	}
	ch.Detail = fmt.Sprintf("Skew %s", skew.Round(time.Second))
	return ch
}

func (c *Checker) checkAdvertise(ctx context.Context) Check {
	return timed(func() Check {
		ch := Check{ID: "tunnel.listener", Title: "guacd can find the tunnel host"}
		addrs, err := net.DefaultResolver.LookupHost(ctx, c.TunnelAdvertiseHost)
		if err != nil || len(addrs) == 0 {
			ch.Status = Warn
			ch.Detail = "'" + c.TunnelAdvertiseHost + "' does not resolve from RemoteHound."
			ch.Hint = "RH_TUNNEL_ADVERTISE_HOST must be the name guacd uses to reach RemoteHound (the service name in compose)."
			return ch
		}
		ch.Status, ch.Detail = Pass, c.TunnelAdvertiseHost+" → "+strings.Join(addrs, ", ")
		return ch
	})
}

func (c *Checker) checkRecording() Check {
	ch := Check{ID: "recording.path", Title: "Session recording storage"}
	if c.RecordingEnabled == nil || !c.RecordingEnabled() {
		ch.Status, ch.Detail = Skip, "Recording is off (Settings → Recording)."
		return ch
	}
	st, err := os.Stat(c.RecordingsDir)
	if err != nil || !st.IsDir() {
		ch.Status = Fail
		ch.Detail = c.RecordingsDir + " is not mounted."
		ch.Hint = "Mount the recordings volume into remotehound (read-only) and guacd (read-write)."
		return ch
	}
	ch.Status, ch.Detail = Pass, c.RecordingsDir+" is mounted."
	return ch
}
