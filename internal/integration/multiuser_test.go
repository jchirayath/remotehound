package integration

// @kind:integration
// @feature:sessions @feature:users

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/guac"
)

// enrolOnline enrols a device into group and brings its SSH forward online.
func enrolOnline(t *testing.T, h *harness, groupID string) string {
	t.Helper()
	return enrolOnlineAs(t, h, groupID, "shared-box", "linux", "ssh", 22)
}

// enrolOnlineAs enrols a device reporting os with one service forwarded.
func enrolOnlineAs(t *testing.T, h *harness, groupID, name, osName, kind string, port int) string {
	t.Helper()
	var settings struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/settings", nil, 200, &settings)
	h.do("PATCH", "/api/v1/settings", map[string]any{"public_url": h.srv.URL, "ssh_public_host": "127.0.0.1",
		"ssh_public_port": h.app.Tunnel.Addr().(*net.TCPAddr).Port}, 200, nil, "If-Match", settings.Data.ETag)
	var enr struct {
		Data struct {
			Code string `json:"code"`
		}
	}
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": name, "group_id": groupID}, 201, &enr)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	sp, _ := ssh.NewPublicKey(pub)
	var res struct {
		Data struct {
			DeviceID string `json:"device_id"`
			SSHPort  int    `json:"ssh_port"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enroll", map[string]any{"code": enr.Data.Code, "public_key": string(ssh.MarshalAuthorizedKey(sp)), "hostname": name, "os": osName,
		"services": []map[string]any{{"kind": kind, "remote_port": port}}}, 201, &res)
	cl, err := ssh.Dial("tcp", "127.0.0.1:"+strconv.Itoa(res.Data.SSHPort), &ssh.ClientConfig{User: res.Data.DeviceID,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(h.app.Tunnel.HostKey()), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	sess, _ := cl.NewSession()
	sess.Stdin = strings.NewReader("")
	if err := sess.Start("agent v1 os=" + osName + " services=" + kind + ":" + strconv.Itoa(port)); err != nil {
		t.Fatal(err)
	}
	ln, err := cl.Listen("tcp", "localhost:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.WriteString(c, "SSH-2.0-Box\r\n"); io.Copy(io.Discard, c); c.Close() }()
		}
	}()
	for i := 0; i < 200 && len(h.app.Tunnel.Forwarded(res.Data.DeviceID)) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	return res.Data.DeviceID
}

func guacKey(t *testing.T, h *harness) []byte {
	b, _ := os.ReadFile(filepath.Join(h.app.Cfg.DataDir, "dev-guac-json-secret"))
	k, _ := hex.DecodeString(strings.TrimSpace(string(b)))
	return k
}

func openBlob(t *testing.T, h *harness, rawURL string) guac.AuthData {
	t.Helper()
	u, _ := url.Parse("http://x" + rawURL)
	ad, err := guac.Open(guacKey(t, h), u.Query().Get("data"))
	if err != nil {
		t.Fatal(err)
	}
	return ad
}

// TestMultiUserSessions: personal credentials, owner-only sharing, invite-only
// joining (view = read-only), admins see and end sessions but cannot join.
func TestMultiUserSessions(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Lab"}, 201, &grp)
	devID := enrolOnline(t, h, grp.Data.ID)

	mk := func(email, role string) *harness {
		var u struct{ Data struct{ ID string } }
		h.do("POST", "/api/v1/users", map[string]any{"email": email, "role": role, "group_ids": []string{grp.Data.ID}}, 201, &u)
		return h.as(u.Data.ID)
	}
	alice := mk("alice@example.com", "operator")
	bob := mk("bob@example.com", "operator")
	carol := mk("carol@example.com", "operator")
	var bobMe struct{ Data struct{ ID string } }
	bob.do("GET", "/api/v1/me", nil, 200, &bobMe)

	// Alice saves her OWN login; Connect uses it, and nobody can read it back.
	alice.do("PUT", "/api/v1/me/credentials/"+devID+"/ssh", map[string]any{"username": "alice", "password": "alice-secret"}, 200, nil)
	var creds struct{ Data []map[string]any }
	alice.do("GET", "/api/v1/me/credentials", nil, 200, &creds)
	if len(creds.Data) != 1 || creds.Data[0]["password"] != nil || creds.Data[0]["sealed"] != nil {
		t.Fatalf("credential listing leaks or is wrong: %+v", creds.Data)
	}
	bob.do("GET", "/api/v1/me/credentials", nil, 200, &creds)
	if len(creds.Data) != 0 {
		t.Fatal("bob sees alice's credentials")
	}

	var conn struct{ Data struct{ URL string } }
	alice.do("POST", "/api/v1/devices/"+devID+"/connect", map[string]any{"service": "ssh"}, 200, &conn)
	ad := openBlob(t, h, conn.Data.URL)
	var params map[string]string
	var connID string
	for _, c := range ad.Connections {
		params, connID = c.Parameters, c.ID
	}
	if params["username"] != "alice" || params["password"] != "alice-secret" || connID == "" {
		t.Fatalf("connect did not use alice's personal login or lacks a joinable id: %+v id=%q", params, connID)
	}
	// guacd connects through the tunnel → the session is recorded as Alice's.
	g, err := net.Dial("tcp", net.JoinHostPort(params["hostname"], params["port"]))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	io.ReadFull(g, make([]byte, 7))

	var list struct {
		Data []struct {
			ID           string `json:"id"`
			Mine         bool   `json:"mine"`
			CanJoin      bool   `json:"can_join"`
			CanShare     bool   `json:"can_share"`
			CanTerminate bool   `json:"can_terminate"`
			UserEmail    string `json:"user_email"`
		}
	}
	for i := 0; i < 100; i++ {
		alice.do("GET", "/api/v1/sessions?active=true", nil, 200, &list)
		if len(list.Data) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(list.Data) != 1 || !list.Data[0].Mine || !list.Data[0].CanShare || list.Data[0].UserEmail != "alice@example.com" {
		t.Fatalf("alice's session list: %+v", list.Data)
	}
	sid := list.Data[0].ID

	// Before sharing: Bob and Carol cannot see it; the admin sees it but cannot join.
	bob.do("GET", "/api/v1/sessions?active=true", nil, 200, &list)
	if len(list.Data) != 0 {
		t.Fatal("bob sees alice's session before it was shared")
	}
	bob.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 404, nil)
	h.do("GET", "/api/v1/sessions?active=true", nil, 200, &list)
	if len(list.Data) != 1 || list.Data[0].CanJoin || !list.Data[0].CanTerminate {
		t.Fatalf("admin view: %+v", list.Data)
	}
	h.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 403, nil)
	h.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": bobMe.Data.ID, "mode": "control"}, 403, nil) // admin cannot share someone else's session

	// Alice shares view-only with Bob → Bob joins read-only; Carol still cannot.
	alice.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": bobMe.Data.ID, "mode": "view", "ttl_minutes": 30}, 200, nil)
	bob.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 200, &conn)
	jad := openBlob(t, h, conn.Data.URL)
	for _, c := range jad.Connections {
		if c.Join != connID || c.Parameters["read-only"] != "true" || c.Protocol != "" || c.Parameters["password"] != "" {
			t.Fatalf("join token wrong (must join alice's connection read-only and carry no credentials): %+v", c)
		}
	}
	if jad.Username != "bob@example.com" {
		t.Fatalf("join token user %q", jad.Username)
	}
	carol.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 404, nil)
	bob.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": bobMe.Data.ID, "mode": "control"}, 403, nil) // grantee cannot re-share
	bob.do("POST", "/api/v1/sessions/"+sid+"/terminate", nil, 403, nil)                                                      // grantee cannot end it

	// Alice revokes → Bob is out.
	alice.do("DELETE", "/api/v1/sessions/"+sid+"/shares/"+bobMe.Data.ID, nil, 200, nil)
	bob.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 404, nil)

	// The admin ends Alice's session at the tunnel (incident response).
	h.do("POST", "/api/v1/sessions/"+sid+"/terminate", nil, 202, nil)
	g.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(g); err != nil { // returns nil at EOF; a timeout means it stayed open
		t.Fatalf("connection still open after the admin ended the session: %v", err)
	}

	var aud struct {
		Data []struct{ Event, Outcome string }
	}
	h.do("GET", "/api/v1/audit?page_size=200", nil, 200, &aud)
	seen := map[string]bool{}
	for _, e := range aud.Data {
		seen[e.Event+":"+e.Outcome] = true
	}
	for _, want := range []string{"credential.save:success", "session.share:success", "session.join:success", "session.join:denied", "session.unshare:success", "session.terminate:success"} {
		if !seen[want] {
			t.Errorf("audit lacks %s", want)
		}
	}
}

func TestProvidersEndpointIsPublic(t *testing.T) {
	h := start(t)
	var out struct {
		Data struct {
			Mode       string `json:"mode"`
			Providers  []any  `json:"providers"`
			ProjectURL string `json:"project_url"`
		}
	}
	(&harness{t: t, app: h.app, srv: h.srv, client: h.srv.Client()}).do("GET", "/auth/providers", nil, 200, &out)
	if out.Data.Mode != "dev" || out.Data.Providers == nil || out.Data.ProjectURL != "https://github.com/jchirayath/remotehound" {
		t.Fatalf("%+v", out.Data)
	}
}

// Regressions from the security review: operators cannot read the
// cross-device log ring, and viewers do not see enrolment code hints.
func TestOperatorsCannotReadOtherGroupsLogsOrCodeHints(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "G"}, 201, &grp)
	h.do("POST", "/api/v1/enrollments", map[string]any{"group_id": grp.Data.ID}, 201, nil)
	mk := func(email, role string) *harness {
		var u struct{ Data struct{ ID string } }
		h.do("POST", "/api/v1/users", map[string]any{"email": email, "role": role, "group_ids": []string{grp.Data.ID}}, 201, &u)
		return h.as(u.Data.ID)
	}
	op := mk("op2@example.com", "operator")
	op.do("GET", "/api/v1/logs", nil, 403, nil)
	v := mk("v2@example.com", "viewer")
	var list struct {
		Data []struct {
			CodeHint string `json:"code_hint"`
		}
	}
	v.do("GET", "/api/v1/enrollments", nil, 200, &list)
	if len(list.Data) == 0 || list.Data[0].CodeHint != "" {
		t.Fatalf("viewer sees code hint: %+v", list.Data)
	}
	h.do("GET", "/api/v1/enrollments", nil, 200, &list)
	if list.Data[0].CodeHint == "" {
		t.Fatal("creator lost the code hint")
	}
}

// Regression (automated review): a control share is downgraded to view-only
// when the grantee's current role is viewer.
func TestControlShareDowngradedForViewer(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "D"}, 201, &grp)
	devID := enrolOnline(t, h, grp.Data.ID)
	var u struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "demoted@example.com", "role": "operator", "group_ids": []string{grp.Data.ID}}, 201, &u)
	var conn struct{ Data struct{ URL string } }
	h.do("POST", "/api/v1/devices/"+devID+"/connect", map[string]any{"service": "ssh"}, 200, &conn)
	var params map[string]string
	for _, c := range openBlob(t, h, conn.Data.URL).Connections {
		params = c.Parameters
	}
	g, err := net.Dial("tcp", net.JoinHostPort(params["hostname"], params["port"]))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	io.ReadFull(g, make([]byte, 7))
	var list struct {
		Data []struct {
			ID string `json:"id"`
		}
	}
	for i := 0; i < 100 && len(list.Data) == 0; i++ {
		h.do("GET", "/api/v1/sessions?scope=mine&active=true", nil, 200, &list)
		time.Sleep(10 * time.Millisecond)
	}
	sid := list.Data[0].ID
	h.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": u.Data.ID, "mode": "control"}, 200, nil)
	var cur struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	h.do("GET", "/api/v1/users/"+u.Data.ID, nil, 200, &cur)
	h.do("PATCH", "/api/v1/users/"+u.Data.ID, map[string]any{"role": "viewer"}, 200, nil, "If-Match", cur.Data.ETag)
	// The demotion bumped the user's session generation to 1; sign in again as them.
	v := h.asGen(u.Data.ID, 1)
	v.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 200, &conn)
	for _, c := range openBlob(t, h, conn.Data.URL).Connections {
		if c.Parameters["read-only"] != "true" {
			t.Fatalf("demoted viewer joined with control: %+v", c.Parameters)
		}
	}
}

// TestSSHKeyLogin: a personal SSH login can be a private key (+ passphrase).
// It is sealed, never returned, and reaches Guacamole as private-key/passphrase
// — never as "password". Keys are refused for RDP/VNC and when malformed.
func TestSSHKeyLogin(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Keys"}, 201, &grp)
	devID := enrolOnline(t, h, grp.Data.ID)
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA-test-only\n-----END OPENSSH PRIVATE KEY-----" // gitleaks:allow -- not a key

	h.do("PUT", "/api/v1/me/credentials/"+devID+"/ssh", map[string]any{"username": "ops", "private_key": "not a key"}, 400, nil)
	h.do("PUT", "/api/v1/me/credentials/"+devID+"/rdp", map[string]any{"username": "ops", "private_key": key}, 400, nil)
	h.do("PUT", "/api/v1/me/credentials/"+devID+"/ssh", map[string]any{"username": "ops"}, 400, nil) // neither password nor key
	h.do("PUT", "/api/v1/me/credentials/"+devID+"/ssh", map[string]any{"username": "ops", "private_key": key, "password": "pass-phrase"}, 200, nil)

	var creds struct{ Data []map[string]any }
	h.do("GET", "/api/v1/me/credentials", nil, 200, &creds)
	if len(creds.Data) != 1 || creds.Data[0]["auth"] != "key" || creds.Data[0]["private_key"] != nil || creds.Data[0]["sealed_key"] != nil {
		t.Fatalf("credential listing: %+v", creds.Data)
	}
	raw := h.raw("GET", "/api/v1/me/credentials")
	if strings.Contains(raw, "b3BlbnNzaC1rZXkt") || strings.Contains(raw, "pass-phrase") {
		t.Fatal("key material or passphrase returned by the API")
	}

	var conn struct{ Data struct{ URL string } }
	h.do("POST", "/api/v1/devices/"+devID+"/connect", map[string]any{"service": "ssh"}, 200, &conn)
	ad := openBlob(t, h, conn.Data.URL)
	for _, c := range ad.Connections {
		p := c.Parameters
		if p["private-key"] != key+"\n" || p["passphrase"] != "pass-phrase" || p["password"] != "" || p["username"] != "ops" {
			t.Fatalf("guacamole params: user=%q pw=%q pass=%q keylen=%d", p["username"], p["password"], p["passphrase"], len(p["private-key"]))
		}
	}
}

// After a device is deleted, its used enrolment code says so (device_deleted), so
// the UI shows "removed" instead of a link that 404s. (Sessions: device package test.)
func TestDeletedDeviceIsFlaggedNotLinked(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Gone"}, 201, &grp)
	devID := enrolOnline(t, h, grp.Data.ID)
	h.do("POST", "/api/v1/devices/"+devID+"/connect", map[string]any{"service": "ssh"}, 200, nil)

	type row struct {
		DeviceID      string `json:"device_id"`
		DeviceDeleted bool   `json:"device_deleted"`
	}
	var sess, enr struct{ Data []row }
	h.do("GET", "/api/v1/sessions", nil, 200, &sess)
	h.do("GET", "/api/v1/enrollments", nil, 200, &enr)
	for _, r := range append(sess.Data, enr.Data...) {
		if r.DeviceID == devID && r.DeviceDeleted {
			t.Fatalf("live device flagged as deleted: %+v", r)
		}
	}

	h.do("DELETE", "/api/v1/devices/"+devID, nil, 204, nil)
	h.do("GET", "/api/v1/devices/"+devID, nil, 404, nil)
	h.do("GET", "/api/v1/sessions", nil, 200, &sess)
	h.do("GET", "/api/v1/enrollments", nil, 200, &enr)
	n := 0
	for _, r := range append(sess.Data, enr.Data...) {
		if r.DeviceID == devID {
			n++
			if !r.DeviceDeleted {
				t.Fatalf("row for deleted device not flagged: %+v", r)
			}
		}
	}
	if n < 1 {
		t.Fatalf("expected the used enrolment code to remain, got %d rows", n)
	}
}

// A code made for one OS refuses a machine reporting another (and stays usable);
// a name that contradicts the reported OS, and one machine enrolled twice, are
// flagged on the device.
func TestEnrolmentIdentityChecks(t *testing.T) {
	h := start(t)
	key := func() string {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		sp, _ := ssh.NewPublicKey(pub)
		return string(ssh.MarshalAuthorizedKey(sp))
	}
	type created struct {
		Data struct {
			Code       string `json:"code"`
			ExpectedOS string `json:"expected_os"`
		}
	}
	type redeemed struct {
		Data struct {
			DeviceID string `json:"device_id"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "x", "expected_os": "beos"}, 400, nil)

	var linux created
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "office-linux", "expected_os": "linux"}, 201, &linux)
	if linux.Data.ExpectedOS != "linux" {
		t.Fatalf("expected_os not echoed: %+v", linux.Data)
	}
	var prob struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do("POST", "/api/v1/enroll", map[string]any{"code": linux.Data.Code, "public_key": key(), "hostname": "Adas-Mac-Studio", "os": "macos"}, 400, &prob)
	if prob.Code != "ENROLL_WRONG_OS" || !strings.Contains(prob.Detail, "Linux") || !strings.Contains(prob.Detail, "Adas-Mac-Studio") {
		t.Fatalf("wrong-OS refusal: %+v", prob)
	}
	var ok redeemed // the code was not consumed: the right machine can still use it
	h.do("POST", "/api/v1/enroll", map[string]any{"code": linux.Data.Code, "public_key": key(), "hostname": "srv1", "os": "linux"}, 201, &ok)

	// No expected OS: accepted, but the name contradicts the machine.
	var anyOS created
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "lab-linux"}, 201, &anyOS)
	var mac redeemed
	h.do("POST", "/api/v1/enroll", map[string]any{"code": anyOS.Data.Code, "public_key": key(), "hostname": "Adas-Mac-Studio", "os": "macos"}, 201, &mac)
	// The same Mac enrolled again under a neutral name.
	var again created
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "studio"}, 201, &again)
	var mac2 redeemed
	h.do("POST", "/api/v1/enroll", map[string]any{"code": again.Data.Code, "public_key": key(), "hostname": "Adas-Mac-Studio", "os": "macos"}, 201, &mac2)

	type warn struct {
		Code          string `json:"code"`
		OtherDeviceID string `json:"other_device_id"`
	}
	var d struct {
		Data struct {
			IdentityWarnings []warn `json:"identity_warnings"`
		}
	}
	h.do("GET", "/api/v1/devices/"+mac.Data.DeviceID, nil, 200, &d)
	codes := map[string]string{}
	for _, w := range d.Data.IdentityWarnings {
		codes[w.Code] = w.OtherDeviceID
	}
	if _, ok := codes["NAME_OS_MISMATCH"]; !ok || codes["DUPLICATE_HOST"] != mac2.Data.DeviceID {
		t.Fatalf("warnings on the mis-named Mac: %+v", d.Data.IdentityWarnings)
	}
	h.do("GET", "/api/v1/devices/"+ok.Data.DeviceID, nil, 200, &d)
	if len(d.Data.IdentityWarnings) != 0 {
		t.Fatalf("correct enrolment flagged: %+v", d.Data.IdentityWarnings)
	}
	// The list carries the same warnings.
	var list struct {
		Data []struct {
			ID               string `json:"id"`
			IdentityWarnings []warn `json:"identity_warnings"`
		}
	}
	h.do("GET", "/api/v1/devices", nil, 200, &list)
	for _, x := range list.Data {
		if x.ID == mac2.Data.DeviceID && (len(x.IdentityWarnings) != 1 || x.IdentityWarnings[0].Code != "DUPLICATE_HOST") {
			t.Fatalf("list warnings for the second Mac: %+v", x.IdentityWarnings)
		}
	}
}

// Screen Sharing on a Mac and RDP with NLA cannot start without a username and
// password (Guacamole never shows guacd's login prompt), so Connect says so
// instead of opening a tab that waits forever.
func TestConnectNeedsLoginWhereGuacamoleCannotAsk(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Macs"}, 201, &grp)
	mac := enrolOnlineAs(t, h, grp.Data.ID, "studio", "macos", "vnc", 5900)
	var prob struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	h.do("POST", "/api/v1/devices/"+mac+"/connect", map[string]any{"service": "vnc"}, 409, &prob)
	if prob.Code != "CREDENTIALS_REQUIRED" || !strings.Contains(prob.Detail, "macOS username and password") {
		t.Fatalf("no login: %+v", prob)
	}
	h.do("PUT", "/api/v1/me/credentials/"+mac+"/vnc", map[string]any{"password": "only-a-password"}, 200, nil)
	h.do("POST", "/api/v1/devices/"+mac+"/connect", map[string]any{"service": "vnc"}, 409, &prob) // ARD needs the username too
	h.do("PUT", "/api/v1/me/credentials/"+mac+"/vnc", map[string]any{"username": "ada", "password": "pw"}, 200, nil)
	var conn struct{ Data struct{ URL string } }
	h.do("POST", "/api/v1/devices/"+mac+"/connect", map[string]any{"service": "vnc"}, 200, &conn)
	for _, c := range openBlob(t, h, conn.Data.URL).Connections {
		if c.Parameters["username"] != "ada" || c.Parameters["password"] != "pw" {
			t.Fatalf("guacamole params: %+v", c.Parameters)
		}
	}

	pc := enrolOnlineAs(t, h, grp.Data.ID, "desk", "windows", "rdp", 3389)
	h.do("POST", "/api/v1/devices/"+pc+"/connect", map[string]any{"service": "rdp"}, 409, &prob)
	if prob.Code != "CREDENTIALS_REQUIRED" || !strings.Contains(prob.Detail, "Network Level Authentication") {
		t.Fatalf("rdp without login: %+v", prob)
	}
	// Plain RDP security shows the Windows sign-in screen itself: no login needed.
	h.do("PUT", "/api/v1/devices/"+pc+"/services/rdp", map[string]any{"remote_port": 3389, "options": map[string]string{"security": "rdp"}}, 200, nil)
	h.do("POST", "/api/v1/devices/"+pc+"/connect", map[string]any{"service": "rdp"}, 200, nil)
}

// The enrolment script says how it installed (sudo/Administrator or one user's
// logins); the device view carries it for the dashboard. Junk is dropped.
func TestInstallScopeIsReported(t *testing.T) {
	h := start(t)
	key := func() string {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		sp, _ := ssh.NewPublicKey(pub)
		return string(ssh.MarshalAuthorizedKey(sp))
	}
	enrol := func(name string, extra map[string]any) string {
		var c struct {
			Data struct {
				Code string `json:"code"`
			}
		}
		h.do("POST", "/api/v1/enrollments", map[string]any{"name": name}, 201, &c)
		body := map[string]any{"code": c.Data.Code, "public_key": key(), "hostname": name, "os": "linux"}
		for k, v := range extra {
			body[k] = v
		}
		var r struct {
			Data struct {
				DeviceID string `json:"device_id"`
			} `json:"data"`
		}
		h.do("POST", "/api/v1/enroll", body, 201, &r)
		return r.Data.DeviceID
	}
	type view struct {
		Data struct {
			InstallScope string `json:"install_scope"`
			InstallUser  string `json:"install_user"`
		}
	}
	for _, tc := range []struct {
		name        string
		extra       map[string]any
		scope, user string
	}{
		{"sys1", map[string]any{"install_scope": "system", "install_user": "root"}, "system", ""},
		{"usr1", map[string]any{"install_scope": "user", "install_user": "alice"}, "user", "alice"},
		{"usr2", map[string]any{"install_scope": "user", "install_user": "bad;name$(x)"}, "user", ""},
		{"old1", nil, "", ""},
		{"junk1", map[string]any{"install_scope": "root", "install_user": "alice"}, "", ""},
	} {
		id := enrol(tc.name, tc.extra)
		var v view
		h.do("GET", "/api/v1/devices/"+id, nil, 200, &v)
		if v.Data.InstallScope != tc.scope || v.Data.InstallUser != tc.user {
			t.Errorf("%s: got scope %q user %q, want %q %q", tc.name, v.Data.InstallScope, v.Data.InstallUser, tc.scope, tc.user)
		}
	}
}

// Enrolment codes can be tidied: an open code can be edited, a used one
// cannot, removing a used code leaves its device alone, and cleanup removes
// used and expired codes but keeps open ones.
func TestEnrolmentCodesEditAndCleanup(t *testing.T) {
	h := start(t)
	key := func() string {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		sp, _ := ssh.NewPublicKey(pub)
		return string(ssh.MarshalAuthorizedKey(sp))
	}
	type one struct {
		Data struct {
			ID            string `json:"id"`
			Code          string `json:"code"`
			Name          string `json:"name"`
			ExpectedOS    string `json:"expected_os"`
			State         string `json:"state"`
			CreatedByName string `json:"created_by_name"`
		}
	}
	var open, used one
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "typo-nmae"}, 201, &open)
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "box1"}, 201, &used)
	var dev struct {
		Data struct {
			DeviceID string `json:"device_id"`
		} `json:"data"`
	}
	h.do("POST", "/api/v1/enroll", map[string]any{"code": used.Data.Code, "public_key": key(), "hostname": "box1", "os": "linux"}, 201, &dev)

	var edited one
	h.do("PATCH", "/api/v1/enrollments/"+open.Data.ID, map[string]any{"name": "fixed-name", "expected_os": "macos"}, 200, &edited)
	if edited.Data.Name != "fixed-name" || edited.Data.ExpectedOS != "macos" || edited.Data.State != "open" || edited.Data.CreatedByName == "" {
		t.Fatalf("edit open code: %+v", edited.Data)
	}
	h.do("PATCH", "/api/v1/enrollments/"+open.Data.ID, map[string]any{"expected_os": "beos"}, 400, nil)
	h.do("PATCH", "/api/v1/enrollments/"+used.Data.ID, map[string]any{"name": "x"}, 409, nil)

	var cleaned struct {
		Data struct {
			Removed int `json:"removed"`
		}
	}
	h.do("POST", "/api/v1/enrollments/cleanup", nil, 200, &cleaned)
	if cleaned.Data.Removed != 1 {
		t.Fatalf("cleanup removed %d, want 1 (the used code)", cleaned.Data.Removed)
	}
	h.do("GET", "/api/v1/enrollments/"+used.Data.ID, nil, 404, nil)
	h.do("GET", "/api/v1/enrollments/"+open.Data.ID, nil, 200, nil)
	h.do("GET", "/api/v1/devices/"+dev.Data.DeviceID, nil, 200, nil) // the device stays
	h.do("DELETE", "/api/v1/enrollments/"+open.Data.ID, nil, 204, nil)
}

// created_by_name follows the directory's rules: a viewer (no directory
// access) must not learn who made a code; an operator in the group may.
func TestEnrolmentCreatorNameIsNotLeaked(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Lab"}, 201, &grp)
	var code struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/enrollments", map[string]any{"name": "lab-box", "group_id": grp.Data.ID}, 201, &code)
	mk := func(email, role string) *harness {
		var u struct{ Data struct{ ID string } }
		h.do("POST", "/api/v1/users", map[string]any{"email": email, "role": role, "group_ids": []string{grp.Data.ID}}, 201, &u)
		return h.as(u.Data.ID)
	}
	name := func(as *harness) string {
		var v struct {
			Data struct {
				CreatedByName string `json:"created_by_name"`
			}
		}
		as.do("GET", "/api/v1/enrollments/"+code.Data.ID, nil, 200, &v)
		return v.Data.CreatedByName
	}
	if n := name(mk("view@example.com", "viewer")); n != "" {
		t.Fatalf("viewer learned the creator: %q", n)
	}
	if n := name(mk("op@example.com", "operator")); n == "" {
		t.Fatal("operator in the group should see the (admin) creator, as in the directory")
	}
	if n := name(h); n == "" {
		t.Fatal("the creator should see themselves")
	}
}
