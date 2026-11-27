package integration

// Script-free enrollment over SSH (ADR-0005), end to end through the real app:
// the code is the SSH username, attended codes make keyless one-session
// devices, persistent codes bind the key the client proves.
//
// @kind:integration
// @feature:enroll @feature:devices

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/enroll"
	"github.com/jchirayath/remotehound/internal/model"
)

type sshEnrol struct {
	ID     string `json:"id"`
	Code   string `json:"code"`
	Mode   string `json:"mode"`
	State  string `json:"state"`
	Device string `json:"device_id"`
	Unix   string `json:"command_unix"`
	Win    string `json:"command_windows"`
	SSH    struct {
		Unix        string `json:"unix"`
		Windows     string `json:"windows"`
		Fingerprint string `json:"host_key_fingerprint"`
	} `json:"ssh"`
}

// sshReady points the public SSH host/port at the test tunnel listener.
func sshReady(t *testing.T, h *harness) {
	t.Helper()
	var st struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/settings", nil, 200, &st)
	h.do("PATCH", "/api/v1/settings", map[string]any{"ssh_public_host": "127.0.0.1",
		"ssh_public_port": h.app.Tunnel.Addr().(*net.TCPAddr).Port}, 200, nil, "If-Match", st.Data.ETag)
}

func createCode(t *testing.T, h *harness, body map[string]any) sshEnrol {
	t.Helper()
	var r struct{ Data sshEnrol }
	h.do("POST", "/api/v1/enrollments", body, 201, &r)
	return r.Data
}

func getCode(t *testing.T, h *harness, id string) sshEnrol {
	t.Helper()
	var r struct{ Data sshEnrol }
	h.do("GET", "/api/v1/enrollments/"+id, nil, 200, &r)
	return r.Data
}

func sshDial(h *harness, user string, signer ssh.Signer) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{User: user, HostKeyCallback: ssh.FixedHostKey(h.app.Tunnel.HostKey()), Timeout: 3 * time.Second}
	if signer != nil {
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	}
	return ssh.Dial("tcp", h.app.Tunnel.Addr().String(), cfg)
}

// sayHello requests forwards (held until hello), runs hello and returns the
// server's status text.
func sayHello(t *testing.T, c *ssh.Client, cmd string, ports ...string) string {
	t.Helper()
	for _, p := range ports {
		go func() {
			if ln, err := c.Listen("tcp", "localhost:"+p); err == nil {
				go func() {
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						conn.Close()
					}
				}()
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.StdoutPipe()
	if err := sess.Start(cmd); err != nil {
		t.Fatalf("hello refused: %v", err)
	}
	var b strings.Builder
	sc := bufio.NewScanner(out)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sc.Scan() {
			b.WriteString(sc.Text() + "\n")
			if strings.Contains(sc.Text(), "Keep this window open") || strings.Contains(sc.Text(), "could not") {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return b.String()
}

func deviceOf(t *testing.T, h *harness, id string) *model.Device {
	t.Helper()
	d := h.app.Devices.Device(id)
	if d == nil {
		t.Fatalf("device %s not created", id)
	}
	return d
}

func TestAttendedCodeOverSSH(t *testing.T) {
	h := start(t)
	sshReady(t, h)
	enr := createCode(t, h, map[string]any{"name": "Alice laptop", "mode": "attended"})
	if enr.Mode != "attended" || enr.Unix != "" || enr.Win != "" {
		t.Fatalf("attended code carries script commands: %+v", enr)
	}
	for _, c := range []string{enr.SSH.Unix, enr.SSH.Windows} {
		if !strings.Contains(c, enr.Code+"@127.0.0.1") || !strings.Contains(c, "StrictHostKeyChecking=yes") ||
			!strings.Contains(c, "ssh-ed25519 ") || strings.Contains(c, "ssh-keygen") {
			t.Fatalf("attended command: %s", c)
		}
	}
	if !strings.HasPrefix(enr.SSH.Fingerprint, "SHA256:") {
		t.Fatalf("fingerprint %q", enr.SSH.Fingerprint)
	}

	// The scripts refuse an attended code, and do not consume it.
	if s := getScript(t, h.srv.URL+"/e/"+enr.Code, "curl/8.6.0"); !strings.Contains(s, "without installing anything") || strings.Contains(s, "__RH_") {
		t.Fatalf("script for an attended code: %.200s", s)
	}
	var prob struct{ Code string }
	h.do("POST", "/api/v1/enroll", map[string]any{"code": enr.Code, "public_key": "ssh-ed25519 AAAA", "os": "linux"}, 400, &prob)
	if prob.Code != "ENROLL_WRONG_METHOD" || getCode(t, h, enr.ID).State != "open" {
		t.Fatalf("redeem of an attended code: %+v", prob)
	}

	c, err := sshDial(h, enr.Code, nil)
	if err != nil {
		t.Fatalf("attended code refused over SSH: %v", err)
	}
	defer c.Close()
	text := sayHello(t, c, "hello v1 os=Linux host=alice-pc", "22")
	if !strings.Contains(text, `connected as "Alice laptop"`) {
		t.Fatalf("status: %q", text)
	}
	got := getCode(t, h, enr.ID)
	if got.State != "used" || got.Device == "" {
		t.Fatalf("code after hello: %+v", got)
	}
	d := deviceOf(t, h, got.Device)
	if d.Transport != model.TransportAttended || d.PublicKey != "" || d.OS != "linux" || d.Hostname != "alice-pc" ||
		len(d.Services) != 1 || d.Services[0].RemotePort != 22 || !strings.HasPrefix(d.ClientVersion, "Go") {
		t.Fatalf("device: %+v", d)
	}
	for i := 0; i < 100 && h.app.Tunnel.ConnectionCode(d.ID) == ""; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	var view struct {
		Data struct {
			ConnectionCode string `json:"connection_code"`
			Online         bool   `json:"online"`
		}
	}
	h.do("GET", "/api/v1/devices/"+d.ID, nil, 200, &view)
	if !view.Data.Online || view.Data.ConnectionCode == "" || !strings.Contains(text, view.Data.ConnectionCode) {
		t.Fatalf("device view %+v, terminal %q", view.Data, text)
	}
	if !auditHas(t, h, "enrollment.redeem", "success") {
		t.Fatal("redeem not audited")
	}

	// Denied: the attended device never logs in again, with or without a key.
	if c2, err := sshDial(h, d.ID, nil); err == nil {
		c2.Close()
		t.Fatal("attended device logged in again (none)")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	if c2, err := sshDial(h, d.ID, s); err == nil {
		c2.Close()
		t.Fatal("attended device logged in again (key)")
	}
	// Denied: the used code does not work a second time.
	if c3, err := sshDial(h, enr.Code, nil); err == nil {
		c3.Close()
		t.Fatal("used code accepted again")
	}
	// Denied: the keyless device's empty fingerprint is no key to the status endpoint.
	h.do("GET", "/api/v1/enroll/status?device_id="+d.ID+"&fingerprint=", nil, 404, nil)
}

func TestPersistentCodeOverSSHBindsKeyAndReconnects(t *testing.T) {
	h := start(t)
	sshReady(t, h)
	enr := createCode(t, h, map[string]any{"name": "ada-mbp", "expected_os": "macos"})
	if enr.Mode != "persistent" || enr.Unix == "" || !strings.Contains(enr.SSH.Unix, "ssh-keygen -q -t ed25519") ||
		!strings.Contains(enr.SSH.Unix, "-R 5900:localhost:5900") || !strings.Contains(enr.SSH.Windows, "%COMPUTERNAME%") {
		t.Fatalf("persistent code commands: %+v", enr)
	}
	// Denied: a persistent code without a key.
	if c, err := sshDial(h, enr.Code, nil); err == nil {
		c.Close()
		t.Fatal("persistent code accepted without a key")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	c, err := sshDial(h, enr.Code, signer)
	if err != nil {
		t.Fatalf("persistent code with key refused: %v", err)
	}
	text := sayHello(t, c, "hello v1 os=Darwin host=ada-mbp", "22", "5900")
	c.Close()
	devID := getCode(t, h, enr.ID).Device
	d := deviceOf(t, h, devID)
	if d.Transport != model.TransportManual || d.KeyFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) || len(d.Services) != 2 {
		t.Fatalf("device: %+v", d)
	}
	if !strings.Contains(text, "-i ~/.remotehound/127.0.0.1-") || !strings.Contains(text, devID+"@127.0.0.1 hello v1") ||
		!strings.Contains(text, "-R 22:localhost:22 -R 5900:localhost:5900") {
		t.Fatalf("reconnect command not shown: %q", text)
	}
	// The device logs in again with its key; agent v1 (the watchdog's command) is refused.
	for i := 0; i < 100 && h.app.Tunnel.Online(devID); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	c2, err := sshDial(h, devID, signer)
	if err != nil {
		t.Fatalf("manual device reconnect refused: %v", err)
	}
	defer c2.Close()
	s, _ := c2.NewSession()
	if err := s.Start("agent v1 os=macos"); err == nil {
		t.Fatal("agent v1 accepted from a manual device")
	}
	c3, err := sshDial(h, devID, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer c3.Close()
	if text := sayHello(t, c3, "hello v1", "22"); !strings.Contains(text, "Keep this window open") {
		t.Fatalf("reconnect status: %q", text)
	}
}

func TestSSHEnrolWrongOSDoesNotConsumeTheCode(t *testing.T) {
	h := start(t)
	sshReady(t, h)
	enr := createCode(t, h, map[string]any{"mode": "attended", "expected_os": "windows"})
	c, err := sshDial(h, enr.Code, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := sayHello(t, c, "hello v1 os=Linux host=wrong-box")
	c.Close()
	if !strings.Contains(text, "Windows machine") {
		t.Fatalf("reason not shown: %q", text)
	}
	if got := getCode(t, h, enr.ID); got.State != "open" || got.Device != "" {
		t.Fatalf("wrong OS consumed the code: %+v", got)
	}
	if !auditHas(t, h, "enrollment.redeem", "failure") {
		t.Fatal("refusal not audited")
	}
}

// Two logins with one code saying hello at once: exactly one device.
func TestConcurrentHelloWithOneCodeMakesOneDevice(t *testing.T) {
	h := start(t)
	sshReady(t, h)
	enr := createCode(t, h, map[string]any{"mode": "attended"})
	var cs []*ssh.Client
	for i := 0; i < 2; i++ {
		c, err := sshDial(h, enr.Code, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		cs = append(cs, c)
	}
	results := make(chan string, 2)
	for _, c := range cs {
		go func() { results <- sayHello(t, c, "hello v1 os=Linux") }()
	}
	ok := 0
	for i := 0; i < 2; i++ {
		if strings.Contains(<-results, "Keep this window open") {
			ok++
		}
	}
	n := 0
	h.app.Store.View(func(x *model.State) {
		for _, d := range x.Devices {
			if d.EnrollmentID == enr.ID {
				n++
			}
		}
	})
	if ok != 1 || n != 1 {
		t.Fatalf("successful hellos = %d, devices = %d; want 1 and 1", ok, n)
	}
}

// SSH code logins spend the same wrong-code budget as /e/{code}.
func TestSSHCodeLoginsShareTheWrongCodeLimit(t *testing.T) {
	h := start(t)
	for i := 0; i < enroll.MissesPerClient; i++ {
		if c, err := sshDial(h, "zzzzzz", nil); err == nil {
			c.Close()
			t.Fatal("wrong code accepted")
		}
	}
	if _, st := h.app.Enroll.Lookup("zzzzzz", "127.0.0.1"); st != "throttled" {
		t.Fatalf("after %d wrong SSH codes: state %q, want throttled", enroll.MissesPerClient, st)
	}
}

func TestEnrollmentModeIsValidated(t *testing.T) {
	h := start(t)
	var prob struct{ Code string }
	h.do("POST", "/api/v1/enrollments", map[string]any{"mode": "forever"}, 400, &prob)
	if prob.Code != "VALIDATION_FAILED" {
		t.Fatalf("%+v", prob)
	}
}
