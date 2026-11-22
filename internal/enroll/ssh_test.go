package enroll

// @feature:enroll

import (
	"strings"
	"testing"

	"github.com/jchirayath/remotehound/internal/model"
)

const kh = "[rh.example.com]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE5Z6XZ4Y29FxwVcImb/o6NP1H9yqtvlEwxwnO0GQ2ec"

// The commands are pasted into a shell: every value is allow-listed, and the
// builder fails closed rather than escaping.
func TestBuildSSHCommandsFailsClosed(t *testing.T) {
	for name, c := range map[string]struct {
		host, known, code string
		port              int
	}{
		"host with $":       {"rh.example.com$(id)", kh, "k7q2mx", 2222},
		"host with space":   {"rh example.com", kh, "k7q2mx", 2222},
		"empty host":        {"", kh, "k7q2mx", 2222},
		"port 0":            {"rh.example.com", kh, "k7q2mx", 0},
		"bad code":          {"rh.example.com", kh, "K7Q2M'", 2222},
		"quote in key line": {"rh.example.com", kh + "'", "k7q2mx", 2222},
		"rsa host key":      {"rh.example.com", "[rh.example.com]:2222 ssh-rsa AAAAB3", "k7q2mx", 2222},
		"key not base64":    {"rh.example.com", "[rh.example.com]:2222 ssh-ed25519 AAAA&calc", "k7q2mx", 2222},
	} {
		if _, ok := BuildSSHCommands(c.host, c.port, c.known, c.code, "", ""); ok {
			t.Errorf("%s: built a command", name)
		}
	}
}

func TestBuildSSHCommandsShape(t *testing.T) {
	att, ok := BuildSSHCommands("rh.example.com", 2222, kh, "k7q2mx", model.EnrollModeAttended, "")
	if !ok {
		t.Fatal("valid input refused")
	}
	// cmd: the key line is echoed inside parentheses, so a trailing digit is
	// never read as a redirection handle ("…c1>file").
	if !strings.Contains(att.Windows, "(echo "+kh+")>") || !strings.Contains(att.Windows, "-R 3389:localhost:3389") ||
		!strings.Contains(att.Windows, "host=%COMPUTERNAME%") || strings.Contains(att.Windows, "ssh-keygen") {
		t.Fatalf("windows attended: %s", att.Windows)
	}
	if !strings.Contains(att.Unix, "echo '"+kh+"'") || !strings.Contains(att.Unix, "os=$(uname -s)") ||
		!strings.Contains(att.Unix, " k7q2mx@rh.example.com hello v1") || strings.Contains(att.Unix, "-i ~") {
		t.Fatalf("unix attended: %s", att.Unix)
	}
	if !strings.HasPrefix(att.HostKeyFingerprint, "SHA256:") {
		t.Fatal(att.HostKeyFingerprint)
	}
	per, _ := BuildSSHCommands("rh.example.com", 2222, kh, "k7q2mx", model.EnrollModePersistent, "linux")
	// One folder per server, so a second RemoteHound server cannot overwrite this one's key or pin.
	if !strings.Contains(per.Unix, "ssh-keygen -q -t ed25519 -N ''") || !strings.Contains(per.Unix, "-i ~/.remotehound/rh.example.com-2222/id_ed25519 -o IdentitiesOnly=yes") ||
		!strings.Contains(per.Unix, "UserKnownHostsFile=~/.remotehound/rh.example.com-2222/known_hosts") ||
		!strings.Contains(per.Unix, "-R 22:localhost:22 -R 3389:localhost:3389 k7q2mx") || !strings.Contains(per.Unix, `host="$(hostname)"`) ||
		!strings.Contains(per.Windows, `ssh-keygen -q -t ed25519 -N "" -C remotehound -f "%USERPROFILE%\.remotehound\rh.example.com-2222\id_ed25519"`) {
		t.Fatalf("persistent: %s\n%s", per.Unix, per.Windows)
	}
	if r := reconnectCommand("rh.example.com", 2222, "dev_abc123", "windows", nil); !strings.Contains(r, "-i ~/.remotehound/rh.example.com-2222/id_ed25519") ||
		!strings.Contains(r, "-R 3389:localhost:3389 -R 22:localhost:22 dev_abc123@rh.example.com hello v1") {
		t.Fatalf("reconnect: %s", r)
	}
	if r := reconnectCommand("rh.example.com;id", 2222, "dev_abc123", "", nil); r != "" {
		t.Fatalf("reconnect built from a bad host: %s", r)
	}
}

func TestClientBannerIsCleaned(t *testing.T) {
	if got := clientBanner("SSH-2.0-OpenSSH_for_Windows_9.5"); got != "OpenSSH_for_Windows_9.5" {
		t.Fatal(got)
	}
	if got := clientBanner("SSH-2.0-x\x1b[31m<script>" + strings.Repeat("a", 100)); strings.ContainsAny(got, "\x1b<>[") || len(got) > 64 {
		t.Fatalf("%q", got)
	}
}
