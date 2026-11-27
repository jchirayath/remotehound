package control

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Docker is a minimal Docker Engine API client over the unix socket: list,
// inspect, start/stop/restart and logs. Hand-written (≈150 lines) instead of
// the Docker SDK so the helper keeps RemoteHound's single-dependency footprint.
type Docker struct {
	hc *http.Client
}

// NewDocker returns a client for the socket at path.
func NewDocker(socket string) *Docker {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	// Local unix-socket client, not an outbound HTTP call: core/httpx's SSRF
	// guard does not apply to a socket path.
	return &Docker{hc: &http.Client{Transport: tr, Timeout: 75 * time.Second}} // nosemgrep: std.go.default-http-client
}

// ErrNotFound is returned when a container disappeared between list and act.
var ErrNotFound = errors.New("container not found")

func (d *Docker) do(ctx context.Context, method, path string, q url.Values) (*http.Response, error) {
	u := "http://docker" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker engine unreachable: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		var e struct {
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&e)
		return nil, fmt.Errorf("docker engine: %s %s: %d %s", method, path, resp.StatusCode, e.Message)
	}
	return resp, nil
}

// Ping reports whether the engine answers.
func (d *Docker) Ping(ctx context.Context) error {
	resp, err := d.do(ctx, http.MethodGet, "/_ping", nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

type listEntry struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

type inspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status     string `json:"Status"`
		OOMKilled  bool   `json:"OOMKilled"`
		ExitCode   int    `json:"ExitCode"`
		Error      string `json:"Error"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
		Health     *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	RestartCount int `json:"RestartCount"`
	Config       struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
		Tty    bool              `json:"Tty"`
		// Env, Cmd, Entrypoint are deliberately NOT decoded: they never leave
		// this process (secrets live there).
	} `json:"Config"`
}

// target is a labeled container the helper may act on.
type target struct {
	id      string
	tty     bool
	view    Container
	actions []string
}

// Targets lists every labeled container, keyed by service name. A service
// name claimed by two containers is reported as an error rather than letting
// "restart guacamole" pick one at random.
func (d *Docker) Targets(ctx context.Context) (map[string]*target, error) {
	f, _ := json.Marshal(map[string][]string{"label": {LabelService}})
	resp, err := d.do(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"true"}, "filters": {string(f)}})
	if err != nil {
		return nil, err
	}
	var list []listEntry
	err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("docker engine: decoding container list: %w", err)
	}
	out := map[string]*target{}
	for _, e := range list {
		name := e.Labels[LabelService]
		if !ValidServiceName(name) {
			continue
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("two containers carry %s=%s; give each a unique name", LabelService, name)
		}
		t, err := d.inspect(ctx, e.ID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue
			}
			return nil, err
		}
		out[name] = t
	}
	return out, nil
}

func (d *Docker) inspect(ctx context.Context, id string) (*target, error) {
	resp, err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return nil, err
	}
	var in inspect
	err = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&in)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("docker engine: decoding inspect: %w", err)
	}
	acts := ParseActions(in.Config.Labels[LabelActions])
	v := Container{
		Service: in.Config.Labels[LabelService], Name: strings.TrimPrefix(in.Name, "/"), Image: in.Config.Image,
		State: in.State.Status, OOMKilled: in.State.OOMKilled, ExitCode: in.State.ExitCode, Error: truncate(in.State.Error, 300),
		RestartCount: in.RestartCount, StartedAt: dockerTime(in.State.StartedAt), FinishedAt: dockerTime(in.State.FinishedAt),
		Actions: acts,
	}
	if in.State.Health != nil {
		v.Health = in.State.Health.Status
	}
	return &target{id: in.ID, tty: in.Config.Tty, view: v, actions: acts}, nil
}

// Act runs start|stop|restart. Docker answers 304 for "already in that state",
// which is success from the operator's point of view.
func (d *Docker) Act(ctx context.Context, id, action string) error {
	q := url.Values{}
	if action == ActionStop || action == ActionRestart {
		q.Set("t", "10") // grace period before SIGKILL
	}
	resp, err := d.do(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/"+action, q)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Logs returns the last tail lines (stdout+stderr, timestamped).
func (d *Docker) Logs(ctx context.Context, id string, tty bool, tail int) ([]LogLine, error) {
	resp, err := d.do(ctx, http.MethodGet, "/containers/"+url.PathEscape(id)+"/logs",
		url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.Itoa(tail)}})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, 8<<20)
	if tty {
		return splitLines(body, "stdout"), nil
	}
	return Demux(body)
}

// Demux decodes Docker's multiplexed log stream: frames of
// [stream byte][3 zero bytes][uint32 big-endian length][payload].
func Demux(r io.Reader) ([]LogLine, error) {
	var out []LogLine
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, nil
			}
			return out, err
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if n > 1<<20 {
			return out, fmt.Errorf("log frame of %d bytes is not plausible", n)
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(r, payload); err != nil {
			return out, nil
		}
		out = append(out, splitLines(bytes.NewReader(payload), stream)...)
	}
}

func splitLines(r io.Reader, stream string) []LogLine {
	var out []LogLine
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		ll := LogLine{Stream: stream}
		// timestamps=1 prefixes RFC3339Nano and a space.
		if ts, rest, ok := strings.Cut(line, " "); ok {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ll.Time, line = t.UTC(), rest
			}
		}
		ll.Text = truncate(line, maxLineLen)
		out = append(out, ll)
	}
	return out
}

// ParseActions keeps only known actions, de-duplicated, in canonical order.
func ParseActions(label string) []string {
	var out []string
	for _, a := range strings.Split(label, ",") {
		a = strings.ToLower(strings.TrimSpace(a))
		if slices.Contains(AllActions, a) && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return slices.Index(AllActions, out[i]) < slices.Index(AllActions, out[j])
	})
	if out == nil {
		out = []string{}
	}
	return out
}

// ValidServiceName: 1–32 of [a-z0-9-], starting with a letter.
func ValidServiceName(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func dockerTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || t.Year() < 2000 { // Docker reports 0001-01-01 for "never"
		return time.Time{}
	}
	return t.UTC()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
