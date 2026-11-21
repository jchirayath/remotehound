// Package integration runs RemoteHound end to end in-process: real HTTP API,
// real embedded SSH tunnel server, a simulated device using the same SSH
// protocol the bootstrap scripts use, and the JSON store on a temp dir.
//
// @kind:integration
// @feature:enroll @feature:devices @feature:sessions @feature:groups @feature:users
// @feature:settings @feature:audit @feature:integration @feature:logs @feature:debug @feature:overview
package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/app"
	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/guac"
)

type harness struct {
	t      *testing.T
	app    *app.App
	srv    *httptest.Server
	client *http.Client
	csrf   string
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func start(t *testing.T) *harness { t.Helper(); return startWith(t, nil) }

// startWith is start with extra/overridden environment (e.g. RH_CONTROL_URL).
func startWith(t *testing.T, extra map[string]string) *harness {
	t.Helper()
	dir := t.TempDir()
	portMin := 20000 + int(time.Now().UnixNano()%30000) // a range unlikely to collide between parallel test binaries
	env := map[string]string{
		"RH_ENV": "development", "RH_AUTH_MODE": "dev", "RH_HTTP_ADDR": "127.0.0.1:0",
		"RH_SSH_ADDR": "127.0.0.1:0", "RH_METRICS_ADDR": "127.0.0.1:0", "RH_PUBLIC_URL": "http://127.0.0.1",
		"RH_DATA_DIR": dir, "RH_RECORDINGS_DIR": filepath.Join(dir, "rec"), "RH_TUNNEL_BIND": "127.0.0.1",
		"RH_TUNNEL_ADVERTISE_HOST": "127.0.0.1", "RH_TUNNEL_PORT_MIN": strconv.Itoa(portMin),
		"RH_TUNNEL_PORT_MAX": strconv.Itoa(portMin + 50), "RH_GUAC_URL": "http://127.0.0.1:1/guacamole",
		"RH_GUACD_ADDR": "127.0.0.1:1", "RH_LOG_LEVEL": "WARN",
	}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	a, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan struct{})
	go func() { a.Tunnel.Serve(ctx); close(served) }() //nolint:errcheck // stops on cancel
	// Registered after TempDir, so it runs BEFORE the temp dir is removed:
	// stop tunnels and let their final presence/session writes land.
	t.Cleanup(func() {
		cancel()
		<-served
		for i := 0; i < 100 && a.Tunnel.OnlineCount() > 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		a.Audit.Close()
	})
	for a.Tunnel.Addr() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	srv := httptest.NewServer(a.Handler)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	h := &harness{t: t, app: a, srv: srv, client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	// Settings point the public URL at the test server so scripts render correctly.
	h.login()
	return h
}

func (h *harness) login() {
	resp, err := h.client.Get(h.srv.URL + "/auth/login?rd=/devices")
	if err != nil {
		h.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/devices" {
		h.t.Fatalf("dev login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	var me struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
			Role      string `json:"role"`
		} `json:"data"`
	}
	h.do("GET", "/api/v1/me", nil, 200, &me)
	if me.Data.Role != "admin" || me.Data.CSRFToken == "" {
		h.t.Fatalf("me: %+v", me)
	}
	h.csrf = me.Data.CSRFToken
}

// do sends a request with the session + CSRF token and checks the status.
func (h *harness) do(method, path string, body any, want int, out any, hdr ...string) http.Header {
	h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if method != "GET" {
		req.Header.Set("X-CSRF-Token", h.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		h.t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, b)
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			h.t.Fatalf("%s %s: decode: %v: %s", method, path, err, b)
		}
	}
	if resp.StatusCode >= 400 && !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") {
		h.t.Fatalf("%s %s: error is not problem+json", method, path)
	}
	return resp.Header
}

type device struct {
	signer   ssh.Signer
	client   *ssh.Client
	control  io.Reader
	deviceID string
}

func TestFullJourney(t *testing.T) {
	h := start(t)

	// --- groups + settings ------------------------------------------------------
	var grp struct{ Data struct{ ID, ETag string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Family", "color": "violet"}, 201, &grp)
	var settings struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/settings", nil, 200, &settings)
	h.do("PATCH", "/api/v1/settings", map[string]any{"public_url": h.srv.URL, "ssh_public_host": "127.0.0.1",
		"ssh_public_port": h.app.Tunnel.Addr().(*net.TCPAddr).Port}, 200, nil, "If-Match", settings.Data.ETag)
	h.do("PATCH", "/api/v1/settings", map[string]any{"log_level": "DEBUG"}, 412, nil, "If-Match", settings.Data.ETag)

	// --- enrolment code ----------------------------------------------------------
	var enr struct {
		Data struct {
			ID             string `json:"id"`
			Code           string `json:"code"`
			CommandUnix    string `json:"command_unix"`
			CommandUnixSys string `json:"command_unix_system"`
			CommandWindows string `json:"command_windows"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "laptop1", "group_id": grp.Data.ID}, 201, &enr)
	if !strings.Contains(enr.Data.CommandUnix, "/e/"+enr.Data.Code+" | sh") || !strings.HasPrefix(enr.Data.CommandWindows, "irm ") ||
		enr.Data.CommandUnixSys != strings.TrimSuffix(enr.Data.CommandUnix, "| sh")+"| sudo sh" {
		t.Fatalf("commands: %+v", enr.Data)
	}

	// --- script delivery (does not consume the code) ------------------------------
	for ua, marker := range map[string]string{"curl/8.6.0": "#!/bin/sh", "Mozilla/5.0 (Windows NT; Windows NT 10.0) WindowsPowerShell/5.1": "RemoteHound"} {
		req, _ := http.NewRequest("GET", h.srv.URL+"/e/"+enr.Data.Code, nil)
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		s := string(b)
		if !strings.Contains(s, marker) || !strings.Contains(s, enr.Data.Code) || !strings.Contains(s, h.srv.URL) || strings.Contains(s, "__RH_BASE_URL__") || strings.Contains(s, "__RH_CODE__") {
			t.Fatalf("script for %q not rendered (len %d)", ua, len(s))
		}
	}
	resp, _ := http.Get(h.srv.URL + "/e/zzzzzz")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "not valid or has expired") {
		t.Fatalf("bad code script: %s", b)
	}

	// --- redeem ---------------------------------------------------------------------
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	sshPub, _ := ssh.NewPublicKey(pub)
	redeem := map[string]any{"code": enr.Data.Code, "public_key": string(ssh.MarshalAuthorizedKey(sshPub)), "hostname": "laptop1.local",
		"os": "linux", "os_version": "Ubuntu 24.04", "client_version": "1", "services": []map[string]any{{"kind": "ssh", "remote_port": 22}, {"kind": "vnc", "remote_port": 5900}}}
	var res struct {
		Data struct {
			DeviceID       string   `json:"device_id"`
			SSHHost        string   `json:"ssh_host"`
			SSHPort        int      `json:"ssh_port"`
			KnownHostsLine string   `json:"known_hosts_line"`
			Forwards       []string `json:"forwards"`
			Fingerprint    string   `json:"fingerprint"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enroll", redeem, 201, &res)
	if len(res.Data.Forwards) != 2 || res.Data.Forwards[0] != "22:localhost:22" {
		t.Fatalf("forwards %v", res.Data.Forwards)
	}
	var prob struct {
		Code string `json:"code"`
	}
	h.do("POST", "/api/v1/enroll", redeem, 410, &prob)
	if prob.Code != "ENROLL_CODE_USED" {
		t.Fatalf("reuse code: %s", prob.Code)
	}

	// --- the device connects exactly as the bootstrap's watchdog does ----------------
	_, _, _, _, rest, err := ssh.ParseKnownHosts([]byte(res.Data.KnownHostsLine))
	_ = rest
	if err != nil {
		t.Fatalf("known_hosts line unparsable: %v", err)
	}
	hostKeyFields := strings.Fields(res.Data.KnownHostsLine)
	pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyFields[1] + " " + hostKeyFields[2]))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := ssh.Dial("tcp", net.JoinHostPort(res.Data.SSHHost, strconv.Itoa(res.Data.SSHPort)), &ssh.ClientConfig{
		User: res.Data.DeviceID, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(pinned), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("device ssh: %v", err)
	}
	defer cl.Close()
	sess, _ := cl.NewSession()
	stdin, _ := sess.StdinPipe()
	control, _ := sess.StdoutPipe()
	if err := sess.Start("agent v1 os=linux ver=1 host=laptop1 services=ssh:22,vnc:5900"); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "2026-11-20T00:00:00Z WARN previous tunnel dropped token=abcdef0123456789abcdef0123456789\n") // gitleaks:allow (redaction fixture)
	stdin.Close()
	ln, err := cl.Listen("tcp", "localhost:22")
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n")
			time.Sleep(50 * time.Millisecond)
			c.Close()
		}
	}()

	var st struct{ Data struct{ Online bool } }
	for i := 0; i < 100; i++ {
		h.do("GET", "/api/v1/enroll/status?device_id="+res.Data.DeviceID+"&fingerprint="+url.QueryEscape(res.Data.Fingerprint), nil, 200, &st)
		if st.Data.Online {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !st.Data.Online {
		t.Fatal("device never reported online")
	}
	h.do("GET", "/api/v1/enroll/status?device_id="+res.Data.DeviceID+"&fingerprint=SHA256:wrong", nil, 404, nil)

	// --- list + detail ------------------------------------------------------------------
	var list struct {
		Data []struct {
			ID       string
			Online   bool
			Services []struct {
				Kind      string
				Forwarded bool
			}
		}
		Meta struct{ Total int }
	}
	h.do("GET", "/api/v1/devices?online=true&q=laptop", nil, 200, &list)
	if len(list.Data) != 1 || !list.Data[0].Online || list.Meta.Total != 1 {
		t.Fatalf("list: %+v", list)
	}
	var dev struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/devices/"+res.Data.DeviceID, nil, 200, &dev)

	// --- connect: mint a Guacamole connection and follow it to the device ------------------
	var conn struct{ Data struct{ URL string } }
	h.do("POST", "/api/v1/devices/"+res.Data.DeviceID+"/connect", map[string]any{"service": "ssh"}, 200, &conn)
	u, _ := url.Parse("http://x" + conn.Data.URL)
	keyHex, _ := os.ReadFile(filepath.Join(h.app.Cfg.DataDir, "dev-guac-json-secret"))
	key, _ := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	ad, err := guac.Open(key, u.Query().Get("data"))
	if err != nil {
		t.Fatalf("connect blob does not open with the shared key: %v", err)
	}
	var params map[string]string
	for _, c := range ad.Connections {
		params = c.Parameters
		if c.Protocol != "ssh" {
			t.Fatalf("protocol %s", c.Protocol)
		}
	}
	if ad.Username != "dev@localhost" || ad.Expires < time.Now().UnixMilli() {
		t.Fatalf("blob identity/expiry: %+v", ad)
	}
	g, err := net.Dial("tcp", net.JoinHostPort(params["hostname"], params["port"])) // what guacd does
	if err != nil {
		t.Fatal(err)
	}
	banner := make([]byte, 7)
	io.ReadFull(g, banner)
	g.Close()
	if string(banner) != "SSH-2.0" {
		t.Fatalf("guacd would have seen %q", banner)
	}
	h.do("POST", "/api/v1/devices/"+res.Data.DeviceID+"/connect", map[string]any{"service": "vnc"}, 409, &prob)
	if prob.Code != "SERVICE_NOT_FORWARDED" {
		t.Fatalf("vnc connect: %s", prob.Code)
	}

	// --- sessions are attributed to the user who clicked ---------------------------------
	var sessions struct {
		Data []struct {
			UserEmail string `json:"user_email"`
			Service   string `json:"service"`
		}
	}
	for i := 0; i < 50; i++ {
		h.do("GET", "/api/v1/sessions?device_id="+res.Data.DeviceID, nil, 200, &sessions)
		if len(sessions.Data) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(sessions.Data) != 1 || sessions.Data[0].UserEmail != "dev@localhost" {
		t.Fatalf("sessions: %+v", sessions.Data)
	}

	// --- probe, client logs (redacted) ---------------------------------------------------
	var probes struct {
		Data []struct {
			Service string
			OK      bool
		}
	}
	h.do("POST", "/api/v1/devices/"+res.Data.DeviceID+"/probe", nil, 200, &probes)
	okSSH := false
	for _, p := range probes.Data {
		okSSH = okSSH || (p.Service == "ssh" && p.OK)
	}
	if !okSSH {
		t.Fatalf("probe: %+v", probes.Data)
	}
	var logs struct{ Data []struct{ Line string } }
	for i := 0; i < 50 && len(logs.Data) == 0; i++ {
		h.do("GET", "/api/v1/devices/"+res.Data.DeviceID+"/logs", nil, 200, &logs)
		time.Sleep(10 * time.Millisecond)
	}
	if len(logs.Data) != 1 || strings.Contains(logs.Data[0].Line, "abcdef0123456789") {
		t.Fatalf("client log missing or unredacted: %+v", logs.Data)
	}

	// --- optimistic concurrency + CSRF ----------------------------------------------------
	h.do("PATCH", "/api/v1/devices/"+res.Data.DeviceID, map[string]any{"notes": "x"}, 428, nil)
	h.do("PATCH", "/api/v1/devices/"+res.Data.DeviceID, map[string]any{"notes": "x"}, 412, nil, "If-Match", `"999"`)
	h.do("PATCH", "/api/v1/devices/"+res.Data.DeviceID, map[string]any{"notes": "Ada's laptop", "tags": []string{"home"}}, 200, nil, "If-Match", dev.Data.ETag)
	h.do("PATCH", "/api/v1/devices/"+res.Data.DeviceID, map[string]any{"status": "active"}, 400, nil, "If-Match", dev.Data.ETag) // unknown field (SEC-10)
	saved := h.csrf
	h.csrf = "wrong"
	h.do("POST", "/api/v1/groups", map[string]any{"name": "X"}, 403, &prob)
	h.csrf = saved
	if prob.Code != "AUTH_CSRF_FAILED" {
		t.Fatalf("csrf: %s", prob.Code)
	}

	// --- denied paths: operator outside the group, viewer cannot connect (TEST-2) -----------
	var other struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Office"}, 201, &other)
	var op struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator", "group_ids": []string{other.Data.ID}}, 201, &op)
	var viewer struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "view@example.com", "role": "viewer", "group_ids": []string{grp.Data.ID}}, 201, &viewer)
	opH := h.as(op.Data.ID)
	opH.do("GET", "/api/v1/devices/"+res.Data.DeviceID, nil, 404, nil)
	opH.do("POST", "/api/v1/devices/"+res.Data.DeviceID+"/connect", map[string]any{"service": "ssh"}, 404, nil)
	opH.do("GET", "/api/v1/settings", nil, 403, nil)
	var opList struct{ Data []any }
	opH.do("GET", "/api/v1/devices", nil, 200, &opList)
	if len(opList.Data) != 0 {
		t.Fatal("operator sees another group's devices")
	}
	vH := h.as(viewer.Data.ID)
	vH.do("GET", "/api/v1/devices/"+res.Data.DeviceID, nil, 200, nil)
	vH.do("POST", "/api/v1/devices/"+res.Data.DeviceID+"/connect", map[string]any{"service": "ssh"}, 403, nil)
	h.do("DELETE", "/api/v1/users/"+meID(h), nil, 409, nil) // cannot delete yourself

	// --- disabling revokes the live tunnel and tells the device ------------------------------
	h.do("POST", "/api/v1/devices/"+res.Data.DeviceID+"/disable", nil, 200, nil)
	all, _ := io.ReadAll(io.LimitReader(control, 4096))
	if !strings.Contains(string(all), "ok "+res.Data.DeviceID) || !strings.Contains(string(all), "revoked") {
		t.Fatalf("control stream: %q", all)
	}
	if _, err := ssh.Dial("tcp", net.JoinHostPort(res.Data.SSHHost, strconv.Itoa(res.Data.SSHPort)), &ssh.ClientConfig{
		User: res.Data.DeviceID, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(pinned), Timeout: 3 * time.Second}); err == nil {
		t.Fatal("disabled device reconnected")
	}

	// --- group with devices cannot be deleted --------------------------------------------
	h.do("DELETE", "/api/v1/groups/"+grp.Data.ID, nil, 409, &prob)
	if prob.Code != "GROUP_NOT_EMPTY" {
		t.Fatal(prob.Code)
	}

	// --- observability ------------------------------------------------------------------------
	var aud struct {
		Data []struct{ Event, Outcome string }
	}
	h.do("GET", "/api/v1/audit?page_size=200", nil, 200, &aud)
	want := map[string]bool{"enrollment.create": false, "enrollment.redeem": false, "session.open": false, "device.disable": false, "auth.csrf": false, "settings.update": false}
	for _, e := range aud.Data {
		if _, ok := want[e.Event]; ok {
			want[e.Event] = true
		}
	}
	for ev, seen := range want {
		if !seen {
			t.Errorf("audit event %s missing", ev)
		}
	}
	var integ struct {
		Data struct {
			Overall string
			Checks  []struct{ ID, Status, Hint string }
		}
	}
	h.do("POST", "/api/v1/integration/test", nil, 200, &integ)
	if integ.Data.Overall != "fail" || integ.Data.Checks[0].Hint == "" {
		t.Fatalf("integration with no Guacamole should fail with hints: %+v", integ.Data)
	}
	h.do("GET", "/api/v1/jobs", nil, 200, nil)
	h.do("GET", "/api/v1/debug/runtime", nil, 200, nil)
	h.do("GET", "/api/v1/debug/bundle", nil, 200, nil)
	h.do("GET", "/api/v1/logs?level=WARN", nil, 200, nil)
	h.do("GET", "/api/v1/overview", nil, 200, nil)
	h.do("GET", "/api/v1/nope", nil, 404, nil)
	var ready struct{ Status string }
	resp, _ = http.Get(h.srv.URL + "/readyz")
	json.NewDecoder(resp.Body).Decode(&ready)
	resp.Body.Close()
	if ready.Status != "degraded" {
		t.Fatalf("readyz with Guacamole down = %q, want degraded", ready.Status)
	}
}

func meID(h *harness) string {
	var me struct{ Data struct{ ID string } }
	h.do("GET", "/api/v1/me", nil, 200, &me)
	return me.Data.ID
}

// as returns a harness signed in as userID (a session cookie minted the way login does).
func (h *harness) as(userID string) *harness { return h.asGen(userID, 0) }

// asGen is as() for a user whose session generation is gen.
func (h *harness) asGen(userID string, gen int) *harness {
	rec := httptest.NewRecorder()
	h.app.API.Auth.Sessions.Issue(rec, userID, gen)
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(h.srv.URL)
	jar.SetCookies(u, rec.Result().Cookies())
	o := &harness{t: h.t, app: h.app, srv: h.srv, client: &http.Client{Jar: jar}}
	var me struct {
		Data struct {
			CSRFToken string `json:"csrf_token"`
		}
	}
	o.do("GET", "/api/v1/me", nil, 200, &me)
	o.csrf = me.Data.CSRFToken
	return o
}

func TestUnauthenticatedAPIIsRefused(t *testing.T) {
	h := start(t)
	resp, err := http.Get(h.srv.URL + "/api/v1/devices")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || resp.Header.Get("X-Request-Id") == "" {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	resp, _ = http.Get(h.srv.URL + "/guacamole/")
	resp.Body.Close()
	if resp.StatusCode != 200 && resp.Request.URL.Path != "/auth/login" && !strings.Contains(resp.Request.URL.String(), "/devices") {
		// default client follows the redirect to /auth/login → dev login → "/" (SPA)
		t.Fatalf("guacamole proxy not gated: %d %s", resp.StatusCode, resp.Request.URL)
	}
}

func TestOpenRedirectIsBlocked(t *testing.T) {
	h := start(t)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, rd := range []string{"https://evil.example", "//evil.example", "/\\evil.example"} {
		resp, err := c.Get(h.srv.URL + "/auth/login?rd=" + url.QueryEscape(rd))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Errorf("rd=%q redirected to %q", rd, loc)
		}
	}
}
