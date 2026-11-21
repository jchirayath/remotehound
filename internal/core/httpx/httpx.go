// Package httpx is CORE-6: the only outbound HTTP client.
//
// Contract: every outbound call goes through a Client built here. It has
//   - connect/total timeouts (PERF-2),
//   - retries with exponential backoff + full jitter for idempotent methods
//     and connection errors / 502-504 / 429 (never for POST unless asked),
//   - a per-host circuit breaker (5 consecutive failures → open 30 s →
//     half-open probe), so a dead Guacamole fails fast instead of piling up,
//   - an SSRF guard (SEC-5): after DNS resolution, private, loopback,
//     link-local and metadata addresses are refused unless the host is on the
//     client's AllowPrivate list (Guacamole is a private container by design),
//   - W3C traceparent propagation from the request scope (LOG-1),
//   - a redacted DEBUG log per call (method, host, path, status, duration).
package httpx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jchirayath/remotehound/internal/core/logx"
)

// Options configures a Client.
type Options struct {
	Timeout      time.Duration  // total per attempt (default 10 s)
	Retries      int            // extra attempts for retryable failures (default 2)
	AllowPrivate []string       // hostnames allowed to resolve to private addresses
	RetryPOST    bool           // POST is retried only when the caller knows it is idempotent
	RootCAs      *x509.CertPool // tests only: trust a local test CA (nil = system roots)
}

// Client is a hardened HTTP client.
type Client struct {
	hc       *http.Client
	opts     Options
	breakers sync.Map // host -> *breaker
}

// ErrBlocked is returned when the SSRF guard refuses a destination.
var ErrBlocked = errors.New("destination address not allowed")

// ErrCircuitOpen is returned while a host's breaker is open.
var ErrCircuitOpen = errors.New("circuit open: upstream recently failing")

// New builds a client.
func New(o Options) *Client {
	if o.Timeout == 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Retries == 0 {
		o.Retries = 2
	}
	allow := map[string]bool{}
	for _, h := range o.AllowPrivate {
		allow[strings.ToLower(h)] = true
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil, // never route through an env proxy implicitly
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		MaxIdleConns:          32,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: o.Timeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := *dialer
			if !allow[strings.ToLower(host)] {
				d.Control = guard
			}
			return d.DialContext(ctx, network, addr)
		},
	}
	// This IS the shared outbound client (CORE-6): the one place a raw
	// http.Client is allowed.
	return &Client{opts: o, hc: &http.Client{ // nosemgrep: std.go.default-http-client
		Transport: tr,
		Timeout:   o.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}}
}

// guard runs after DNS resolution on the actual IP being dialled.
func guard(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return ErrBlocked
	}
	if !PublicAddr(ip) {
		return fmt.Errorf("%w: %s", ErrBlocked, ip)
	}
	return nil
}

// PublicAddr reports whether ip is a routable public address.
func PublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("169.254.0.0/16"), // link-local / cloud metadata
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking
	netip.MustParsePrefix("fd00:ec2::/32"),  // AWS IMDS v6
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 can reach v4 private space
}

// Do sends req with retries, breaker and tracing. The caller closes the body.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	br := c.breaker(host)
	if !br.allow() {
		return nil, fmt.Errorf("%s: %w", host, ErrCircuitOpen)
	}
	sc := logx.ScopeFrom(req.Context())
	if sc.TraceID != "" && req.Header.Get("traceparent") == "" {
		req.Header.Set("traceparent", "00-"+sc.TraceID+"-"+newSpanID()+"-01")
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "RemoteHound")
	}
	retryable := req.Method == http.MethodGet || req.Method == http.MethodHead || req.Method == http.MethodDelete ||
		(req.Method == http.MethodPost && c.opts.RetryPOST)
	attempts := 1
	if retryable {
		attempts += c.opts.Retries
	}

	var body []byte
	if req.Body != nil && attempts > 1 {
		b, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}

	var resp *http.Response
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			backoff := time.Duration(rand.Int64N(int64(200*time.Millisecond) << i)) // #nosec G404 -- jitter
			select {
			case <-req.Context().Done():
				return nil, req.Context().Err()
			case <-time.After(backoff):
			}
		}
		if body != nil {
			req.Body = io.NopCloser(strings.NewReader(string(body)))
		}
		start := time.Now()
		resp, err = c.hc.Do(req)
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		logx.L().DebugContext(req.Context(), "Outbound HTTP", logx.Event("http.client.request"),
			slog.String("http.request.method", req.Method), slog.String("server.address", host),
			slog.String("url.path", req.URL.Path), slog.Int("http.response.status_code", status),
			slog.Int64("app.duration_ms", time.Since(start).Milliseconds()), slog.Int("app.attempt", i+1))
		if err == nil && !retryStatus(status) {
			br.record(status < 500)
			return resp, nil
		}
		if errors.Is(err, ErrBlocked) {
			return nil, err
		}
		if resp != nil && i < attempts-1 {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) //nolint:errcheck // draining before retry
			resp.Body.Close()
		}
	}
	br.record(false)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func retryStatus(s int) bool { return s == 429 || s == 502 || s == 503 || s == 504 }

func newSpanID() string {
	const hex = "0123456789abcdef"
	b := make([]byte, 16)
	for i := range b {
		b[i] = hex[rand.IntN(16)] // #nosec G404 -- span ids are correlation ids, not secrets
	}
	return string(b)
}

// ---- circuit breaker --------------------------------------------------------

type breaker struct {
	mu       sync.Mutex
	failures int
	openTill time.Time
}

func (c *Client) breaker(host string) *breaker {
	b, _ := c.breakers.LoadOrStore(host, &breaker{})
	return b.(*breaker)
}

func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().After(b.openTill) // half-open after the window: one call decides
}

func (b *breaker) record(ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		b.failures = 0
		b.openTill = time.Time{}
		return
	}
	b.failures++
	if b.failures >= 5 {
		b.openTill = time.Now().Add(30 * time.Second)
	}
}

// BreakerState reports "closed" or "open" for host (Debug screen).
func (c *Client) BreakerState(host string) string {
	b := c.breaker(host)
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Now().Before(b.openTill) {
		return "open"
	}
	return "closed"
}
