package tunnel

// Script-free enrollment over SSH (ADR-0005): the SSH username is an
// enrollment code. Allowed and denied paths of the tunnel policy.
//
// @feature:enroll @feature:devices

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/model"
)

type fakeEnroller struct {
	mu      sync.Mutex
	h       *fakeHooks
	codes   map[string]CodeInfo // code -> info
	logins  int                 // CodeLogin calls
	redeems []SSHEnrollment
	fail    error         // RedeemSSH returns this when set
	delay   time.Duration // RedeemSSH takes this long (a slow store write)
}

func (e *fakeEnroller) CodeLogin(code, _ string) (CodeInfo, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logins++
	ci, ok := e.codes[code]
	return ci, ok
}

func (e *fakeEnroller) RedeemSSH(enrolID string, r SSHEnrollment) (Redeemed, error) {
	e.mu.Lock()
	d := e.delay
	e.mu.Unlock()
	time.Sleep(d)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fail != nil {
		return Redeemed{}, e.fail
	}
	e.redeems = append(e.redeems, r)
	transport := model.TransportAttended
	if r.PublicKey != "" {
		transport = model.TransportManual
	}
	e.h.mu.Lock()
	e.h.dev = &model.Device{Meta: model.Meta{ID: "dev_new001"}, Name: "Alice laptop", Status: model.DeviceActive,
		Transport: transport, PublicKey: r.PublicKey, Services: r.Facts.Services}
	e.h.mu.Unlock()
	out := Redeemed{DeviceID: "dev_new001", DeviceName: "Alice laptop"}
	if r.PublicKey != "" {
		out.Reconnect = "ssh -i ~/.remotehound/id_ed25519 -p 2222 dev_new001@rh.example.com hello v1"
	}
	return out, nil
}

func setupEnrol(t *testing.T) (*Server, *fakeHooks, *fakeEnroller) {
	t.Helper()
	srv, _, h := setup(t)
	e := &fakeEnroller{h: h, codes: map[string]CodeInfo{
		"k7q2mx": {EnrollmentID: "enr_a", Mode: model.EnrollModeAttended},
		"p3rsst": {EnrollmentID: "enr_p", Mode: model.EnrollModePersistent},
	}}
	srv.SetEnroller(e)
	return srv, h, e
}

// dialNone logs in with no key: x/crypto tries the "none" method.
func dialNone(srv *Server, user string) (*ssh.Client, error) {
	return ssh.Dial("tcp", srv.Addr().String(), &ssh.ClientConfig{User: user,
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey()), Timeout: 3 * time.Second})
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return s
}

// hello starts the session the way the portal's command does and returns the
// first lines the server writes.
func hello(t *testing.T, c *ssh.Client, cmd string) []string {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.StdoutPipe()
	if err := sess.Start(cmd); err != nil {
		t.Fatalf("hello refused: %v", err)
	}
	sc := bufio.NewScanner(out)
	var lines []string
	deadline := time.After(3 * time.Second)
	got := make(chan string)
	go func() {
		for sc.Scan() {
			got <- sc.Text()
		}
		close(got)
	}()
	for {
		select {
		case l, ok := <-got:
			if !ok {
				return lines
			}
			lines = append(lines, l)
			if strings.Contains(l, "Keep this window open") || strings.Contains(l, "could not") {
				return lines
			}
		case <-deadline:
			return lines
		}
	}
}

func TestAttendedCodeEnrolsOnHelloAndBindsHeldForwards(t *testing.T) {
	srv, h, e := setupEnrol(t)
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatalf("attended code refused: %v", err)
	}
	defer c.Close()
	// The forward is requested before hello (as OpenSSH does) and answered after it.
	type res struct {
		ln  net.Listener
		err error
	}
	fwd := make(chan res, 1)
	go func() { ln, err := c.Listen("tcp", "localhost:22"); fwd <- res{ln, err} }()
	time.Sleep(50 * time.Millisecond)
	if srv.Online("dev_new001") {
		t.Fatal("device online before hello")
	}
	lines := hello(t, c, "hello v1 os=windows host=PC-ALICE")
	r := <-fwd
	if r.err != nil {
		t.Fatalf("held forward refused: %v", r.err)
	}
	r.ln.Close()
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, `connected as "Alice laptop"`) || !strings.Contains(text, "Connection code: ") {
		t.Fatalf("status lines: %q", text)
	}
	code := srv.ConnectionCode("dev_new001")
	if len(code) != 4 || !strings.Contains(text, code) {
		t.Fatalf("connection code %q not shown in %q", code, text)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.redeems) != 1 {
		t.Fatalf("redeems = %d", len(e.redeems))
	}
	got := e.redeems[0]
	if got.PublicKey != "" || got.Facts.OS != "windows" || got.Facts.Hostname != "PC-ALICE" ||
		len(got.Facts.Services) != 1 || got.Facts.Services[0].Kind != "ssh" || !strings.HasPrefix(got.Banner, "SSH-2.0-Go") {
		t.Fatalf("redeem = %+v", got)
	}
	if !srv.Online("dev_new001") {
		t.Fatal("device not online after hello")
	}
	_ = h
}

func TestAttendedDeviceCannotLogInAgain(t *testing.T) {
	srv, h, _ := setupEnrol(t)
	h.dev = &model.Device{Meta: model.Meta{ID: "dev_att001"}, Status: model.DeviceActive, Transport: model.TransportAttended}
	if c, err := dialNone(srv, "dev_att001"); err == nil {
		c.Close()
		t.Fatal("attended device logged in with none")
	}
	if c, err := dial(t, srv, "dev_att001", newSigner(t)); err == nil {
		c.Close()
		t.Fatal("attended device logged in with a key")
	}
}

func TestNoneIsRefusedForDevicesAndPersistentCodes(t *testing.T) {
	srv, _, e := setupEnrol(t)
	if c, err := dialNone(srv, "dev_test01"); err == nil {
		c.Close()
		t.Fatal("device logged in with none")
	}
	if c, err := dialNone(srv, "p3rsst"); err == nil {
		c.Close()
		t.Fatal("persistent code logged in without a key")
	}
	if c, err := dialNone(srv, "zzzzzz"); err == nil {
		c.Close()
		t.Fatal("unknown code accepted")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.logins == 0 {
		t.Fatal("code logins were not checked through the enroller (shared wrong-code limiter)")
	}
}

func TestPersistentCodeBindsTheProvenKey(t *testing.T) {
	srv, _, e := setupEnrol(t)
	signer := newSigner(t)
	c, err := dial(t, srv, "p3rsst", signer)
	if err != nil {
		t.Fatalf("persistent code with ed25519 key refused: %v", err)
	}
	defer c.Close()
	lines := hello(t, c, "hello v1 os=Darwin host=ada-mbp")
	text := strings.Join(lines, "\n")
	if !strings.Contains(text, "dev_new001@") || !strings.Contains(text, "reconnect") {
		t.Fatalf("reconnect command not shown: %q", text)
	}
	e.mu.Lock()
	got := e.redeems[0]
	e.mu.Unlock()
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	if got.PublicKey != want || got.Facts.OS != "macos" {
		t.Fatalf("redeem = %+v", got)
	}
}

func TestPersistentCodeRefusesNonEd25519Keys(t *testing.T) {
	srv, _, _ := setupEnrol(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := ssh.NewSignerFromKey(k)
	if c, err := dial(t, srv, "p3rsst", s); err == nil {
		c.Close()
		t.Fatal("ecdsa key accepted for a persistent code")
	}
}

// fakeMeta is the ssh.ConnMetadata an auth callback sees.
type fakeMeta struct{ user, addr string }

func (m fakeMeta) User() string          { return m.user }
func (m fakeMeta) SessionID() []byte     { return []byte("s") }
func (m fakeMeta) ClientVersion() []byte { return []byte("SSH-2.0-test") }
func (m fakeMeta) ServerVersion() []byte { return []byte("SSH-2.0-RemoteHound") }
func (m fakeMeta) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", m.addr)
	return a
}
func (m fakeMeta) LocalAddr() net.Addr { return m.RemoteAddr() }

func TestAttendedCodeIgnoresOfferedKey(t *testing.T) {
	srv, _, e := setupEnrol(t)
	// A client offering a key still tries none first, which an attended code
	// accepts: the key is never bound.
	c, err := dial(t, srv, "k7q2mx", newSigner(t))
	if err != nil {
		t.Fatalf("attended code with a key offered: %v", err)
	}
	hello(t, c, "hello v1 os=linux")
	c.Close()
	e.mu.Lock()
	if len(e.redeems) != 1 || e.redeems[0].PublicKey != "" {
		e.mu.Unlock()
		t.Fatalf("redeems: %+v", e.redeems)
	}
	e.mu.Unlock()
	// publickey alone is refused for an attended code.
	if _, err := srv.authenticate(fakeMeta{"k7q2mx", "192.0.2.1:5000"}, newSigner(t).PublicKey()); err == nil {
		t.Fatal("publickey accepted for an attended code")
	}
}

// A connection gets at most maxCodeChecksPerConn code lookups (none +
// publickey queries), whatever keys it offers.
func TestCodeChecksPerConnectionAreCapped(t *testing.T) {
	srv, _, e := setupEnrol(t)
	m := fakeMeta{"p3rsst", "192.0.2.2:5000"}
	for i := 0; i < maxCodeChecksPerConn+3; i++ {
		_, _ = srv.authenticate(m, newSigner(t).PublicKey())
	}
	e.mu.Lock()
	n := e.logins
	e.mu.Unlock()
	if n != maxCodeChecksPerConn {
		t.Fatalf("code lookups on one connection = %d, want %d", n, maxCodeChecksPerConn)
	}
	srv.forgetCodeChecks(m.addr)
	if _, err := srv.authenticate(m, newSigner(t).PublicKey()); err != nil {
		t.Fatal("a new connection from the same address was refused")
	}
}

func TestLoginsPerCodeAreCapped(t *testing.T) {
	srv, _, _ := setupEnrol(t)
	var open []*ssh.Client
	for i := 0; i < maxCodeLoginsPerCode; i++ {
		c, err := dialNone(srv, "k7q2mx")
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, c)
	}
	defer func() {
		for _, c := range open {
			c.Close()
		}
	}()
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		return // refused outright: fine
	}
	done := make(chan struct{})
	go func() { c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("a third concurrent login with one code was kept")
	}
}

// The hello budget must not cut off a redeem in progress (the code would be
// used up with nothing shown to the person).
func TestHelloTimerLeavesARedeemAlone(t *testing.T) {
	srv, _, e := setupEnrol(t)
	srv.helloTimeout = 150 * time.Millisecond
	e.delay = 400 * time.Millisecond
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	time.Sleep(100 * time.Millisecond) // hello lands before the budget, redeem outlasts it
	if text := strings.Join(hello(t, c, "hello v1 os=linux"), "\n"); !strings.Contains(text, "Keep this window open") {
		t.Fatalf("redeem cut off by the hello timer: %q", text)
	}
	if !srv.Online("dev_new001") {
		t.Fatal("device not online")
	}
}

// A client that drops during the redeem must not stay registered as online.
func TestClientGoneDuringRedeemIsNotLeftOnline(t *testing.T) {
	srv, _, e := setupEnrol(t)
	e.delay = 300 * time.Millisecond
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := c.NewSession()
	if err := s.Start("hello v1 os=linux"); err != nil {
		t.Fatal(err)
	}
	c.Close() // gone while the device is being made
	time.Sleep(600 * time.Millisecond)
	if srv.Online("dev_new001") || srv.OnlineCount() != 0 {
		t.Fatal("closed connection left registered as online")
	}
}

func TestCodeLoginRefusesLocalForwardAndAgent(t *testing.T) {
	srv, _, _ := setupEnrol(t)
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("direct-tcpip accepted on a code login")
	}
	s, _ := c.NewSession()
	if err := s.Start("agent v1 os=linux services=ssh:22"); err == nil {
		t.Fatal("agent v1 accepted on a code login")
	}
}

func TestManualDeviceRefusesLocalForward(t *testing.T) {
	srv, signer, h := setup(t)
	h.dev.Transport = model.TransportManual
	c, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("direct-tcpip accepted from a manual device")
	}
}

func TestCodeLoginWithoutHelloIsDropped(t *testing.T) {
	srv, _, e := setupEnrol(t)
	srv.helloTimeout = 200 * time.Millisecond
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { c.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("code login without hello kept open")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.redeems) != 0 {
		t.Fatal("device created without hello")
	}
}

func TestCodeLoginRefusesUndeclaredKindsAndTooManyForwards(t *testing.T) {
	srv, _, e := setupEnrol(t)
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	errs := make(chan error, 1)
	go func() { _, err := c.Listen("tcp", "localhost:8080"); errs <- err }()
	time.Sleep(50 * time.Millisecond)
	hello(t, c, "hello v1 os=linux")
	if err := <-errs; err == nil {
		t.Fatal("forward of port 8080 accepted")
	}
	e.mu.Lock()
	n := len(e.redeems[0].Facts.Services)
	e.mu.Unlock()
	if n != 0 {
		t.Fatalf("services from a refused forward: %d", n)
	}

	c2, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	done := make(chan struct{})
	go func() { c2.Wait(); close(done) }()
	// x/crypto's client waits for each reply; OpenSSH pipelines. Send without
	// waiting so the server sees what a pipelining client sends.
	payload := ssh.Marshal(tcpipForwardMsg{Addr: "localhost", Port: 22})
	for i := 0; i < maxHeldForwards+1; i++ {
		_, _, _ = c2.SendRequest("tcpip-forward", false, payload)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("more than maxHeldForwards held requests did not close the login")
	}
}

func TestCodeLoginShellAndPtyAndOtherExec(t *testing.T) {
	srv, _, _ := setupEnrol(t)
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("pty accepted")
	}
	if err := sess.Run("cat /etc/passwd"); err == nil {
		t.Fatal("arbitrary exec accepted on a code login")
	}

	c2, _ := dialNone(srv, "k7q2mx")
	defer c2.Close()
	s2, _ := c2.NewSession()
	out, _ := s2.StdoutPipe()
	if err := s2.Shell(); err != nil {
		t.Fatalf("shell (hello with no facts) refused: %v", err)
	}
	line, _ := bufio.NewReader(out).ReadString('\n')
	if !strings.Contains(line, "RemoteHound") {
		t.Fatalf("no status line after shell: %q", line)
	}
}

func TestRedeemFailureIsShownAndNothingIsCreated(t *testing.T) {
	srv, _, e := setupEnrol(t)
	e.fail = errors.New("This code is for a macOS machine, but this one reports Windows.")
	c, err := dialNone(srv, "k7q2mx")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	text := strings.Join(hello(t, c, "hello v1 os=windows"), "\n")
	if !strings.Contains(text, "macOS machine") {
		t.Fatalf("reason not shown: %q", text)
	}
	if srv.Online("dev_new001") {
		t.Fatal("device online after a failed redeem")
	}
}

// Each command only on its own transport.
func TestHelloAndAgentAreTransportBound(t *testing.T) {
	srv, signer, h := setup(t)
	h.dev.Transport = model.TransportScript
	c, _ := dial(t, srv, "dev_test01", signer)
	s, _ := c.NewSession()
	if err := s.Start("hello v1 os=linux"); err == nil {
		t.Fatal("hello accepted from a script device")
	}
	c.Close()

	h.mu.Lock()
	h.dev.Transport = model.TransportManual
	h.mu.Unlock()
	c2, _ := dial(t, srv, "dev_test01", signer)
	defer c2.Close()
	s2, _ := c2.NewSession()
	if err := s2.Start("agent v1 os=linux"); err == nil {
		t.Fatal("agent v1 accepted from a manual device")
	}
	c3, _ := dial(t, srv, "dev_test01", signer)
	defer c3.Close()
	text := strings.Join(hello(t, c3, "hello v1 os=linux host=box"), "\n")
	if !strings.Contains(text, "Keep this window open") {
		t.Fatalf("manual reconnect status: %q", text)
	}
}

// A typed device may forward a conventional port after hello (declared on the
// fly); never another port. (A script device never declares by forwarding:
// TestUndeclaredForwardAndLocalForwardAreRefused, port 3389.)
func TestManualDeviceDeclaresOnlyConventionalPortsByForwarding(t *testing.T) {
	srv, signer, h := setup(t)
	h.dev.Transport = model.TransportManual
	c, err := dial(t, srv, "dev_test01", signer)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	hello(t, c, "hello v1")
	ln, err := c.Listen("tcp", "localhost:3389")
	if err != nil {
		t.Fatalf("conventional port refused on a manual device: %v", err)
	}
	ln.Close()
	if _, err := c.Listen("tcp", "localhost:8080"); err == nil {
		t.Fatal("port 8080 declared by forwarding")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.dev.Services) != 2 {
		t.Fatalf("services: %+v", h.dev.Services)
	}
}

func TestParseHello(t *testing.T) {
	for in, want := range map[string]string{"hello v1 os=Darwin": "macos", "hello v1 os=Linux": "linux", "hello v1 os=windows": "windows", "hello v1 os=plan9": "", "hello v1": ""} {
		f, err := ParseHello(in)
		if err != nil || f.OS != want {
			t.Errorf("%q: %+v %v", in, f, err)
		}
	}
	for _, bad := range []string{"", "hello", "hello v2", "agent v1", "sh -c id"} {
		if _, err := ParseHello(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if f, _ := ParseHello("hello v1 host=%COMPUTERNAME%"); f.Hostname != "" {
		t.Fatal("unexpanded variable accepted as hostname")
	}
}

func FuzzParseHello(f *testing.F) {
	f.Add("hello v1 os=windows host=PC1")
	f.Fuzz(func(t *testing.T, s string) { _, _ = ParseHello(s) })
}
