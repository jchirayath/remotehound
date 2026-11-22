package tunnel

// @feature:devices

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

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
func (f *fakeHooks) AddService(id, kind string, port int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dev != nil && f.dev.ID == id {
		f.dev.Services = append(f.dev.Services, model.Service{Kind: kind, RemotePort: port})
	}
	return nil
}
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

// pipeConn is one end of a net.Pipe; closed reports whether the server side
// closed it (a read on the peer returns EOF).
func pipeConn(t *testing.T) (server net.Conn, closed func() bool) {
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, func() bool {
		_ = b.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := b.Read(make([]byte, 1))
		return err == io.EOF || errors.Is(err, io.ErrClosedPipe)
	}
}

func TestPreauthLimitKeysIPv6By64And48(t *testing.T) {
	p := newPending(maxHandshakesPerClient, maxHandshakesPerIPv6Net, maxHandshakesTotal)
	for i := 1; i <= maxHandshakesPerClient; i++ {
		c, _ := pipeConn(t)
		if _, ok := p.admit("2001:db8:1:2::"+strconv.FormatInt(int64(i), 16), c); !ok {
			t.Fatalf("handshake %d refused", i)
		}
	}
	// Another address in the same /64 is the same client: refused.
	c, _ := pipeConn(t)
	if _, ok := p.admit("2001:db8:1:2:abcd::99", c); ok {
		t.Fatal("rotating addresses inside one /64 multiplied the per-client budget")
	}
	// A different /64 and an IPv4 address (also written IPv4-mapped) are different clients.
	for _, ip := range []string{"2001:db8:1:3::1", "203.0.113.7", "::ffff:203.0.113.7"} {
		c, _ := pipeConn(t)
		if _, ok := p.admit(ip, c); !ok {
			t.Fatalf("%s refused", ip)
		}
	}
	// ::ffff:203.0.113.7 and 203.0.113.7 are one client: 2 of 8 used.
	if n := p.byClient["203.0.113.7"]; n != 2 {
		t.Fatalf("IPv4-mapped address keyed separately: %d", n)
	}
	// One /48 holds at most maxHandshakesPerIPv6Net, however many /64s it rotates through.
	q := newPending(maxHandshakesPerClient, maxHandshakesPerIPv6Net, maxHandshakesTotal)
	for i := 0; i < maxHandshakesPerIPv6Net; i++ {
		c, _ := pipeConn(t)
		if _, ok := q.admit("2001:db8:9:"+strconv.FormatInt(int64(i), 16)+"::1", c); !ok {
			t.Fatalf("/48 handshake %d refused", i)
		}
	}
	c, _ = pipeConn(t)
	if _, ok := q.admit("2001:db8:9:ffff::1", c); ok {
		t.Fatal("a /48 exceeded its cap by rotating /64s")
	}
	c, _ = pipeConn(t)
	if _, ok := q.admit("2001:db8:a::1", c); !ok {
		t.Fatal("another /48 refused")
	}
}

func TestPreauthFullEvictsFromTheBusiestClient(t *testing.T) {
	const total = 4
	p := newPending(3, 64, total)
	adm := func(ip string) (*pendingConn, func() bool) {
		t.Helper()
		c, cl := pipeConn(t)
		pc, ok := p.admit(ip, c)
		if !ok {
			t.Fatalf("%s refused", ip)
		}
		return pc, cl
	}
	// The victim's single handshake is the globally oldest.
	victim, victimClosed := adm("192.0.2.1")
	a1, a1Closed := adm("198.51.100.1")
	_, a2Closed := adm("198.51.100.1")
	_, a3Closed := adm("198.51.100.1") // table full: victim 1, attacker 3
	// New clients evict the attacker's handshakes (oldest first), never the victim's.
	_, n1Closed := adm("203.0.113.1")
	if !a1Closed() || a2Closed() || a3Closed() || victimClosed() {
		t.Fatal("did not evict the busiest client's oldest handshake")
	}
	_, n2Closed := adm("203.0.113.2")
	if !a2Closed() || victimClosed() || n1Closed() {
		t.Fatal("did not evict the busiest client again")
	}
	if victimClosed() {
		t.Fatal("victim evicted while another client held more than one")
	}
	// Now every key holds one: the oldest overall (the victim) goes next.
	adm("203.0.113.3")
	if !victimClosed() || a3Closed() || n2Closed() {
		t.Fatal("with one each, the oldest handshake should be evicted")
	}
	// An evicted handshake learns it was evicted, and releasing it twice is harmless.
	if p.done(a1) || p.done(victim) {
		t.Fatal("done reported an evicted entry as still owned")
	}
	if n := p.count(); n != total {
		t.Fatalf("pending = %d, want %d", n, total)
	}
	// Its client slots were freed too.
	adm("192.0.2.1")
}

func TestPreauthDoneReportsOwnership(t *testing.T) {
	p := newPending(8, 64, 16)
	c, _ := pipeConn(t)
	pc, _ := p.admit("192.0.2.9", c)
	if !p.done(pc) {
		t.Fatal("a live entry was reported as evicted")
	}
	if p.done(pc) {
		t.Fatal("a second release was reported as owned")
	}
}

func TestSilentClientIsDroppedAtPreauthDeadline(t *testing.T) {
	if preauthTimeout > 5*time.Second {
		t.Fatalf("pre-auth deadline %v, want ≤ 5s", preauthTimeout)
	}
	srv, err := New(Config{ListenAddr: "127.0.0.1:0", BindHost: "127.0.0.1", HostKeyPath: filepath.Join(t.TempDir(), "hk"), Hooks: &fakeHooks{}})
	if err != nil {
		t.Fatal(err)
	}
	srv.preauthTimeout = 300 * time.Millisecond // before Serve
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx) //nolint:errcheck // stops on cancel
	for srv.Addr() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(c); err != nil { // banner, then EOF when the deadline closes it
		t.Fatalf("silent pre-auth client was not dropped: %v", err)
	}
	for i := 0; i < 100 && srv.pending.count() != 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := srv.pending.count(); n != 0 {
		t.Fatalf("pending = %d after drop", n)
	}
}

// readerChannel is an ssh.Channel whose stdin is a fixed string.
type readerChannel struct {
	ssh.Channel
	r io.Reader
}

func (c readerChannel) Read(p []byte) (int, error) { return c.r.Read(p) }

func TestClientLogStripsControlAndBidiCharacters(t *testing.T) {
	h := &fakeHooks{}
	dc := &deviceConn{srv: &Server{cfg: Config{Hooks: h}}, id: "dev_test01"}
	in := "ok\ttab\x1b[2J\x1b]0;pwned\x07 bell\x00nul\x7fdel\u0085c1\r\n" +
		"admin\u202egnp.exe\u2066x\u2069\u200f\u200b\u200c\u200d\ufeff\ufff9\ufffa\ufffb\U000E0041\U000E007F\u2028\u2029\u00ad\n" +
		"a" + strings.Repeat("é", 300) + "\n" // the 500-byte cut lands inside a rune
	dc.readClientLog(readerChannel{r: strings.NewReader(in)})
	if len(h.logs) != 3 {
		t.Fatalf("lines: %q", h.logs)
	}
	if h.logs[0] != "ok\ttab[2J]0;pwned bellnuldelc1" {
		t.Errorf("control characters kept: %q", h.logs[0])
	}
	if h.logs[1] != "admingnp.exex" {
		t.Errorf("bidi/format/separator characters kept: %q", h.logs[1])
	}
	if !utf8.ValidString(h.logs[2]) || len(h.logs[2]) > 500 {
		t.Errorf("truncation broke UTF-8 or the cap: %d bytes", len(h.logs[2]))
	}
}

// dialWith dials with a restricted client algorithm set.
func dialWith(srv *Server, signer ssh.Signer, cfg ssh.Config) error {
	c, err := ssh.Dial("tcp", srv.Addr().String(), &ssh.ClientConfig{Config: cfg, User: "dev_test01", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey()), Timeout: 3 * time.Second})
	if err == nil {
		c.Close()
	}
	return err
}

func TestSHA1KexAndMACsAreNotOffered(t *testing.T) {
	srv, signer, _ := setup(t)
	for name, cfg := range map[string]ssh.Config{
		"dh-group14-sha1": {KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1}},
		"hmac-sha1":       {Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.HMACSHA1}},
		"hmac-sha1-96":    {Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.InsecureHMACSHA196}},
	} {
		if err := dialWith(srv, signer, cfg); err == nil || !strings.Contains(err.Error(), "no common algorithm") {
			t.Errorf("%s negotiated: %v", name, err)
		}
	}
	// What every supported client (OpenSSH ≥ 7.4 incl. Windows 10's 7.7) offers still works.
	for name, cfg := range map[string]ssh.Config{
		"curve25519+gcm":           {KeyExchanges: []string{ssh.KeyExchangeCurve25519}, Ciphers: []string{ssh.CipherAES128GCM}},
		"curve25519+ctr+sha256etm": {KeyExchanges: []string{ssh.KeyExchangeCurve25519}, Ciphers: []string{ssh.CipherAES128CTR}, MACs: []string{ssh.HMACSHA256ETM}},
		"ecdh-p256+chacha":         {KeyExchanges: []string{ssh.KeyExchangeECDHP256}, Ciphers: []string{ssh.CipherChaCha20Poly1305}},
		"dh-group14-sha256+ctr":    {KeyExchanges: []string{ssh.KeyExchangeDH14SHA256}, Ciphers: []string{ssh.CipherAES256CTR}, MACs: []string{ssh.HMACSHA512}},
	} {
		if err := dialWith(srv, signer, cfg); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
}

// TestServerKexInitOffersNoSHA1AndKeepsStrictKex reads the server's raw
// KEXINIT (RFC 4253 §7.1) and checks the offered name-lists.
func TestServerKexInitOffersNoSHA1AndKeepsStrictKex(t *testing.T) {
	srv, _, _ := setup(t)
	c, err := net.Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte("SSH-2.0-test\r\n")); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(c)
	if line, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "SSH-2.0-") {
		t.Fatalf("banner %q: %v", line, err)
	}
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, binary.BigEndian.Uint32(hdr[:4])-1)
	if _, err := io.ReadFull(r, pkt); err != nil || pkt[0] != 20 { // SSH_MSG_KEXINIT
		t.Fatalf("no KEXINIT: %v", err)
	}
	p := pkt[17:] // msg type + 16-byte cookie
	var lists []string
	for i := 0; i < 10; i++ { // kex, hostkey, enc c2s, enc s2c, mac c2s, mac s2c, comp ×2, lang ×2
		n := binary.BigEndian.Uint32(p)
		lists, p = append(lists, string(p[4:4+n])), p[4+n:]
	}
	kex, macs := lists[0], lists[4]+","+lists[5]
	if strings.Contains(kex, "sha1") || strings.Contains(macs, "sha1") {
		t.Fatalf("SHA-1 offered: kex=%s macs=%s", kex, macs)
	}
	if !strings.Contains(kex, "kex-strict-s-v00@openssh.com") || !strings.Contains(kex, "curve25519-sha256") {
		t.Fatalf("kex list %s", kex)
	}
}
