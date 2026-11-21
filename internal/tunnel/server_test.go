package tunnel

// @feature:devices

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/model"
)

type fakeHooks struct {
	mu       sync.Mutex
	dev      *model.Device
	port     int
	sessions int
	closed   int
	logs     []string
	facts    Facts
}

func (f *fakeHooks) Device(id string) *model.Device {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dev == nil || f.dev.ID != id {
		return nil
	}
	cp := *f.dev
	return &cp
}
func (f *fakeHooks) AllocatePort(string, string, []int) (int, error) { return f.port, nil }
func (f *fakeHooks) Connected(id, ip string, fa Facts)               { f.mu.Lock(); f.facts = fa; f.mu.Unlock() }
func (f *fakeHooks) Disconnected(string)                             {}
func (f *fakeHooks) SessionOpened(string, string, string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sessions++
	return "ses_" + strconv.Itoa(f.sessions)
}
func (f *fakeHooks) SessionClosed(string, int64, int64) { f.mu.Lock(); f.closed++; f.mu.Unlock() }
func (f *fakeHooks) ClientLog(_ string, l []string) {
	f.mu.Lock()
	f.logs = append(f.logs, l...)
	f.mu.Unlock()
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// setup starts a tunnel server and returns it, the device signer and the hooks.
func setup(t *testing.T) (*Server, ssh.Signer, *fakeHooks) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	sshPub, _ := ssh.NewPublicKey(pub)
	h := &fakeHooks{port: freePort(t), dev: &model.Device{Meta: model.Meta{ID: "dev_test01"}, Status: model.DeviceActive,
		PublicKey: string(ssh.MarshalAuthorizedKey(sshPub)), Services: []model.Service{{Kind: "ssh", RemotePort: 22}}}}
	srv, err := New(Config{ListenAddr: "127.0.0.1:0", BindHost: "127.0.0.1", HostKeyPath: filepath.Join(t.TempDir(), "hk"), Hooks: h, Keepalive: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx) //nolint:errcheck // stops on cancel
	for srv.Addr() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	return srv, signer, h
}

func dial(t *testing.T, srv *Server, user string, signer ssh.Signer) (*ssh.Client, error) {
	return ssh.Dial("tcp", srv.Addr().String(), &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey()), Timeout: 3 * time.Second})
}

func TestUnknownDeviceAndWrongKeyAreRefused(t *testing.T) {
	srv, signer, _ := setup(t)
	if _, err := dial(t, srv, "dev_nosuch", signer); err == nil {
		t.Fatal("unknown device accepted")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	if _, err := dial(t, srv, "dev_test01", otherSigner); err == nil {
		t.Fatal("wrong key accepted")
	}
}

func TestDisabledDeviceIsRefused(t *testing.T) {
	srv, signer, h := setup(t)
	h.dev.Status = model.DeviceDisabled
	if _, err := dial(t, srv, "dev_test01", signer); err == nil {
		t.Fatal("disabled device accepted")
	}
}

// The full path: device forwards its "SSH" service; a client (guacd's role)
// connects to the internal port and reaches the device's local service.
func TestRemoteForwardCarriesTrafficAndRecordsSession(t *testing.T) {
	srv, signer, h := setup(t)
	c, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Device-side "service": the agent session, then the forward.
	sess, _ := c.NewSession()
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Start("agent v1 os=linux ver=1 host=box services=ssh:22"); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "2026-11-20T00:00:00Z INFO hello from the device\n")
	stdin.Close()
	line := make([]byte, 64)
	n, _ := stdout.Read(line)
	if !strings.HasPrefix(string(line[:n]), "ok dev_test01") {
		t.Fatalf("control line %q", line[:n])
	}

	ln, err := c.Listen("tcp", "localhost:22")
	if err != nil {
		t.Fatalf("forward refused: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(conn, "SSH-2.0-FakeDevice\r\n")
			conn.Close()
		}
	}()

	for !srv.Online("dev_test01") || len(srv.Forwarded("dev_test01")) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(h.port)))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(conn)
	conn.Close()
	if !strings.HasPrefix(string(b), "SSH-2.0-FakeDevice") {
		t.Fatalf("got %q through the tunnel", b)
	}

	res := srv.Probe(context.Background(), "dev_test01", "ssh", 22)
	if !res.OK {
		t.Fatalf("probe failed: %+v", res)
	}
	time.Sleep(100 * time.Millisecond)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions != 1 {
		t.Fatalf("sessions recorded = %d (probe must not count)", h.sessions)
	}
	if h.facts.OS != "linux" || len(h.logs) != 1 || !strings.Contains(h.logs[0], "hello from the device") {
		t.Fatalf("facts/logs not received: %+v %v", h.facts, h.logs)
	}
}

func TestUndeclaredForwardAndLocalForwardAreRefused(t *testing.T) {
	srv, signer, _ := setup(t)
	c, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Listen("tcp", "localhost:3389"); err == nil {
		t.Fatal("forward for an undeclared service accepted")
	}
	if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("local forward (direct-tcpip) accepted")
	}
	sess, _ := c.NewSession()
	if err := sess.Run("cat /etc/passwd"); err == nil {
		t.Fatal("arbitrary exec accepted")
	}
	c2, err := dial(t, srv, "dev_test01", signer) // fresh tunnel: one session channel each
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	sess2, err := c2.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess2.Shell(); err == nil {
		t.Fatal("shell accepted")
	}
}

func TestNewLoginReplacesOldAndKickRevokes(t *testing.T) {
	srv, signer, _ := setup(t)
	c1, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { c1.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("old connection was not replaced")
	}
	if !srv.Kick("dev_test01", "revoked") {
		t.Fatal("kick found no tunnel")
	}
	done2 := make(chan struct{})
	go func() { c2.Wait(); close(done2) }()
	select {
	case <-done2:
	case <-time.After(3 * time.Second):
		t.Fatal("kick did not close the tunnel")
	}
}

func TestParseAgentCommand(t *testing.T) {
	f, err := ParseAgentCommand("agent v1 os=macos ver=1.2 host=ada-mbp services=ssh:22,vnc:5900,bogus:1,rdp:99999")
	if err != nil || f.OS != "macos" || len(f.Services) != 2 {
		t.Fatalf("%+v %v", f, err)
	}
	for _, bad := range []string{"", "agent", "agent v2", "rm -rf /", "bash -c x"} {
		if _, err := ParseAgentCommand(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if f, _ := ParseAgentCommand("agent v1 host=$(reboot)"); f.Hostname != "" {
		t.Fatal("unsafe value accepted")
	}
}

func FuzzParseAgentCommand(f *testing.F) {
	f.Add("agent v1 os=linux services=ssh:22")
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseAgentCommand(s) })
}

func TestKnownHostsLine(t *testing.T) {
	srv, _, _ := setup(t)
	if l := srv.KnownHostsLine("rh.example.com", 2222); !strings.HasPrefix(l, "[rh.example.com]:2222 ssh-ed25519 ") {
		t.Fatal(l)
	}
	if l := srv.KnownHostsLine("rh.example.com", 22); !strings.HasPrefix(l, "rh.example.com ssh-ed25519 ") {
		t.Fatal(l)
	}
}

// Regression (security review P2): one agent command and one session channel
// per tunnel — repeated execs used to force a state write + audit line each.
func TestOneExecAndOneSessionChannelPerTunnel(t *testing.T) {
	srv, signer, h := setup(t)
	c, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s1, _ := c.NewSession()
	if err := s1.Start("agent v1 os=linux"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.NewSession(); err == nil {
		t.Fatal("second session channel accepted")
	}
	_ = h
}

// Probes run over a direct channel and are never recorded as sessions.
func TestProbeDoesNotCreateSessions(t *testing.T) {
	srv, signer, h := setup(t)
	c, _ := dial(t, srv, "dev_test01", signer)
	defer c.Close()
	ln, err := c.Listen("tcp", "localhost:22")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			x, err := ln.Accept()
			if err != nil {
				return
			}
			io.WriteString(x, "SSH-2.0-T\r\n")
			x.Close()
		}
	}()
	for len(srv.Forwarded("dev_test01")) == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		if r := srv.Probe(context.Background(), "dev_test01", "ssh", 22); !r.OK {
			t.Fatalf("probe: %+v", r)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.sessions != 0 {
		t.Fatalf("probes recorded %d sessions", h.sessions)
	}
}
