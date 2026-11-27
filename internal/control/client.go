package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/httpx"
)

// Client is RemoteHound's side of the helper API. A nil *Client means control
// is not configured; every method then reports ErrNotConfigured.
type Client struct {
	base  *url.URL
	token []byte
	http  *httpx.Client
}

// ErrNotConfigured: RH_CONTROL_URL is empty.
var ErrNotConfigured = fmt.Errorf("rh-control is not configured (RH_CONTROL_URL is empty)")

// NewClient builds a client for base (e.g. http://rh-control:9091). The SSRF
// guard is opened for that one hostname only.
func NewClient(base *url.URL, token []byte) *Client {
	return &Client{base: base, token: token,
		http: httpx.New(httpx.Options{Timeout: 70 * time.Second, Retries: 1, AllowPrivate: []string{base.Hostname()}})}
}

// Configured reports whether a helper URL is set.
func (c *Client) Configured() bool { return c != nil && c.base != nil }

// Address is the helper's host:port, for display.
func (c *Client) Address() string {
	if !c.Configured() {
		return ""
	}
	return c.base.Host
}

func (c *Client) call(ctx context.Context, method, path string, q url.Values, out any) error {
	if !c.Configured() {
		return ErrNotConfigured
	}
	u := *c.base
	u.Path = path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+string(c.token))
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rh-control unreachable at %s: %w", c.base.Host, err)
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 8<<20)
	if resp.StatusCode >= 300 {
		re := &RemoteError{Status: resp.StatusCode}
		if json.NewDecoder(body).Decode(re) != nil || re.Code == "" {
			re.Code, re.Detail = "http_"+strconv.Itoa(resp.StatusCode), "unexpected answer from rh-control"
		}
		return re
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(body).Decode(out)
}

// Healthy pings the helper (no token needed); "" means ok.
func (c *Client) Healthy(ctx context.Context) error {
	var v map[string]string
	return c.call(ctx, http.MethodGet, "/healthz", nil, &v)
}

// List returns every labeled container.
func (c *Client) List(ctx context.Context) ([]Container, error) {
	var out []Container
	err := c.call(ctx, http.MethodGet, "/v1/services", nil, &out)
	return out, err
}

// Act runs start|stop|restart on service and returns its fresh state.
func (c *Client) Act(ctx context.Context, service, action string) (Container, error) {
	var out Container
	err := c.call(ctx, http.MethodPost, "/v1/services/"+url.PathEscape(service)+"/"+url.PathEscape(action), nil, &out)
	return out, err
}

// Logs returns the last tail lines of service.
func (c *Client) Logs(ctx context.Context, service string, tail int) ([]LogLine, error) {
	var out []LogLine
	err := c.call(ctx, http.MethodGet, "/v1/services/"+url.PathEscape(service)+"/logs", url.Values{"tail": {strconv.Itoa(tail)}}, &out)
	return out, err
}

// Problem classifies a log line as "error", "warn" or "" (informational), by
// the conventions of the bundle's images: Guacamole (logback "… ERROR o.a.g…"),
// guacd ("guacd[1]: ERROR: …"), Caddy/RemoteHound JSON ("level":"error",
// "severity_text":"ERROR").
func Problem(text string) string {
	t := strings.ToUpper(text)
	switch {
	case strings.Contains(t, " ERROR ") || strings.Contains(t, "ERROR:") || strings.Contains(t, `"LEVEL":"ERROR"`) ||
		strings.Contains(t, `"SEVERITY_TEXT":"ERROR"`) || strings.Contains(t, " SEVERE ") || strings.Contains(t, "FATAL") ||
		strings.Contains(t, "PANIC:") || strings.Contains(t, "EXCEPTION"):
		return "error"
	case strings.Contains(t, " WARN ") || strings.Contains(t, "WARNING:") || strings.Contains(t, `"LEVEL":"WARN`) ||
		strings.Contains(t, `"SEVERITY_TEXT":"WARN"`) || strings.Contains(t, " WARNING "):
		return "warn"
	}
	return ""
}
