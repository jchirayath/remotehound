package enroll

// Script-free enrollment over SSH (ADR-0005, docs/specs/CLIENT_PROTOCOL.md §9):
// the commands a person types, and the tunnel.Enroller the SSH server calls
// when the username is an enrollment code.

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/validate"
	"github.com/jchirayath/remotehound/internal/device"
	"github.com/jchirayath/remotehound/internal/model"
	"github.com/jchirayath/remotehound/internal/tunnel"
)

// SSHCommands are the script-free commands for one code. Each first pins the
// server's host key in ~/.remotehound/known_hosts, then runs ssh with
// StrictHostKeyChecking=yes (no trust-on-first-use prompt).
type SSHCommands struct {
	Unix    string `json:"unix"`    // sh/bash/zsh on macOS and Linux
	Windows string `json:"windows"` // Command Prompt (cmd.exe) syntax
	// HostKeyFingerprint lets the operator read the pinned key out loud.
	HostKeyFingerprint string `json:"host_key_fingerprint"`
}

// knownHostsRe: the only shape the pinned line may have before it is put in a
// command: [host]:port or host, then an ed25519 key in base64.
var knownHostsRe = regexp.MustCompile(`^(\[[A-Za-z0-9.-]+\]:[0-9]{1,5}|[A-Za-z0-9.-]+) ssh-ed25519 [A-Za-z0-9+/]+=*$`)

// forwardsFor lists the services a typed command forwards, by machine type.
// A forward with nothing listening behind it is harmless: a connection to it
// is refused on the device.
func forwardsFor(osName string) []int {
	switch osName {
	case "windows":
		return []int{3389, 22}
	case "macos":
		return []int{22, 5900}
	case "linux":
		return []int{22, 3389}
	}
	return []int{22, 3389, 5900}
}

func rFlags(ports []int) string {
	var b strings.Builder
	for _, p := range ports {
		s := strconv.Itoa(p)
		b.WriteString(" -R " + s + ":localhost:" + s)
	}
	return b.String()
}

// serverDir is this server's folder under ~/.remotehound: one per host and
// port, so enrolling one machine on two RemoteHound servers keeps both keys
// and pins. host passed HostnameOK and port is an int: safe in a path and in
// both shells.
func serverDir(host string, port int) string { return host + "-" + strconv.Itoa(port) }

// sshOpts are the options every typed command shares. ssh expands ~ itself
// (also on Windows), so the paths need no quoting.
func sshOpts(dir string) string {
	return "-o StrictHostKeyChecking=yes -o UserKnownHostsFile=~/.remotehound/" + dir + "/known_hosts -o ServerAliveInterval=15"
}

func keyOpts(dir string) string {
	return "-i ~/.remotehound/" + dir + "/id_ed25519 -o IdentitiesOnly=yes "
}

// BuildSSHCommands returns the commands for code, or ok=false when any value
// fails its allow-list: they are pasted into a shell, so this fails closed.
func BuildSSHCommands(host string, port int, knownHosts, code, mode, expectedOS string) (SSHCommands, bool) {
	if !validate.HostnameOK(host) || port < 1 || port > 65535 || !ids.ValidCode(code) || !knownHostsRe.MatchString(knownHosts) {
		return SSHCommands{}, false
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(knownHosts[strings.IndexByte(knownHosts, ' ')+1:]))
	if err != nil {
		return SSHCommands{}, false
	}
	keyed := mode != model.EnrollModeAttended
	dir := serverDir(host, port)
	ud := "~/.remotehound/" + dir             // sh
	wd := `%USERPROFILE%\.remotehound\` + dir // cmd
	target := " -p " + strconv.Itoa(port)
	dest := " " + code + "@" + host + " hello v1"

	// cmd: mkdir fails when the folder exists, hence "&" before the rest;
	// (echo …) keeps a trailing digit of the key from being read as a
	// redirection handle.
	unix := "mkdir -p " + ud + " && echo '" + knownHosts + "' > " + ud + "/known_hosts && "
	win := `mkdir "` + wd + `" 2>nul & (echo ` + knownHosts + `)>"` + wd + `\known_hosts" && `
	ko := ""
	if keyed { // a fresh key each time: re-enrolling replaces the old device's key here
		unix += "rm -f " + ud + "/id_ed25519 " + ud + "/id_ed25519.pub && ssh-keygen -q -t ed25519 -N '' -C remotehound -f " + ud + "/id_ed25519 && "
		win += `del /q "` + wd + `\id_ed25519*" 2>nul & ssh-keygen -q -t ed25519 -N "" -C remotehound -f "` + wd + `\id_ed25519" && `
		ko = keyOpts(dir)
	}
	unixOS := expectedOS
	if unixOS == "windows" {
		unixOS = ""
	}
	// host="$(hostname)" is quoted so the person's own hostname cannot split
	// the command; %COMPUTERNAME% (a NetBIOS name) has no cmd operators.
	unix += "ssh " + ko + sshOpts(dir) + target + rFlags(forwardsFor(unixOS)) + dest + ` os=$(uname -s) host="$(hostname)"`
	win += "ssh " + ko + sshOpts(dir) + target + rFlags(forwardsFor("windows")) + dest + " os=windows host=%COMPUTERNAME%"
	return SSHCommands{Unix: unix, Windows: win, HostKeyFingerprint: ssh.FingerprintSHA256(key)}, true
}

// reconnectCommand is the login a keyed (ssh-manual) device uses next time:
// no variables, so the same text works in cmd and in sh. It forwards what the
// first command forwarded for that OS, plus any service already declared (a
// client may send its -R requests after hello, so the declared list alone can
// be short).
func reconnectCommand(host string, port int, deviceID, osName string, services []model.Service) string {
	if !validate.HostnameOK(host) || port < 1 || port > 65535 {
		return ""
	}
	ports := forwardsFor(osName)
	for _, s := range services {
		if !slices.Contains(ports, s.RemotePort) {
			ports = append(ports, s.RemotePort)
		}
	}
	dir := serverDir(host, port)
	return "ssh " + keyOpts(dir) + sshOpts(dir) + " -p " + strconv.Itoa(port) + rFlags(ports) + " " + deviceID + "@" + host + " hello v1"
}

// ---- tunnel.Enroller ------------------------------------------------------------

// CodeLogin implements tunnel.Enroller: one Lookup, so the same wrong-code
// limiter (and refund) as /e/{code}.
func (s *Service) CodeLogin(code, ip string) (tunnel.CodeInfo, bool) {
	e, state := s.Lookup(code, ip)
	if state != "open" {
		return tunnel.CodeInfo{}, false
	}
	mode := e.Mode
	if mode == "" {
		mode = model.EnrollModePersistent
	}
	return tunnel.CodeInfo{EnrollmentID: e.ID, Mode: mode}, true
}

// bannerRe keeps a client banner displayable: it is client-controlled.
var bannerRe = regexp.MustCompile(`[^A-Za-z0-9._ -]`)

// clientBanner turns "SSH-2.0-OpenSSH_for_Windows_9.5" into
// "OpenSSH_for_Windows_9.5", charset- and length-limited.
func clientBanner(b string) string {
	b = bannerRe.ReplaceAllString(strings.TrimPrefix(b, "SSH-2.0-"), "")
	if len(b) > 64 {
		b = b[:64]
	}
	return b
}

// RedeemSSH implements tunnel.Enroller: it consumes the code and creates the
// device in one store transaction, as Redeem does for the scripts. The
// error's detail is shown in the person's terminal.
func (s *Service) RedeemSSH(enrollmentID string, r tunnel.SSHEnrollment) (tunnel.Redeemed, error) {
	ctx := context.Background()
	method := "ssh-attended"
	if r.PublicKey != "" {
		method = "ssh-key"
	}
	hostname := r.Facts.Hostname
	if !hostRe.MatchString(hostname) {
		hostname = "device"
	}
	osName := r.Facts.OS
	if osName == "" {
		osName = "unknown"
	}
	now := time.Now().UTC()
	var out tunnel.Redeemed
	var dev *model.Device
	var warnings []string
	err := s.Store.Update(func(x *model.State) error {
		e := x.Enrollments[enrollmentID]
		if e == nil {
			return apierr.NotFound(apierr.CodeEnrollInvalid, "This code was revoked. Ask for a new one.")
		}
		switch e.State(now) {
		case "used":
			return apierr.New(410, apierr.CodeEnrollUsed, "This code was already used. Ask for a new one.")
		case "expired":
			return apierr.New(410, apierr.CodeEnrollExpired, "This code has expired. Ask for a new one.")
		}
		if e.Attended() != (r.PublicKey == "") { // the tunnel enforces this at login; re-checked here
			return apierr.BadRequest(apierr.CodeEnrollWrongMethod, "This code cannot be used this way. Ask for a new one.")
		}
		if e.ExpectedOS != "" && osName != e.ExpectedOS {
			// Not consumed: the right machine can still use this code.
			return apierr.BadRequest(apierr.CodeEnrollWrongOS, "This code is for a "+osLabel(e.ExpectedOS)+" machine, but this one reports "+
				osLabel(osName)+". Run the command on the machine it was made for.")
		}
		name := e.Name
		if name == "" {
			name = hostname
		}
		d, err := s.Devices.CreateTyped(ctx, name, e.GroupID, r.PublicKey, osName, e.ID)
		if err != nil {
			return err
		}
		if d.KeyFingerprint != "" {
			for _, o := range x.Devices {
				if o.KeyFingerprint == d.KeyFingerprint {
					return apierr.BadRequest(apierr.CodeEnrollKeyInvalid, "This key already belongs to another device. Run the full command again: it makes a fresh key.")
				}
			}
		}
		d.Hostname, d.ClientVersion, d.Services = hostname, clientBanner(r.Banner), r.Facts.Services
		x.Devices[d.ID] = d
		warnings = device.RedeemWarnings(d, x.Devices)
		e.UsedAt, e.DeviceID = now, d.ID
		e.Touch(now)
		dev = d
		out = tunnel.Redeemed{DeviceID: d.ID, DeviceName: d.Name}
		if d.Transport == model.TransportManual {
			out.Reconnect = reconnectCommand(x.Settings.SSHPublicHost, x.Settings.SSHPublicPort, d.ID, d.OS, d.Services)
		}
		return nil
	})
	if err != nil {
		s.Audit.Record(ctx, "enrollment.redeem", audit.Failure, "enrollment:"+enrollmentID,
			map[string]any{"reason": apierr.As(err).Code, "method": method, "reported_os": osName, "client_ip": r.IP})
		return tunnel.Redeemed{}, errDetail(err)
	}
	detail := map[string]any{"method": method, "os": dev.OS, "hostname": dev.Hostname, "services": len(dev.Services),
		"client_ip": r.IP, "client": dev.ClientVersion}
	if len(warnings) > 0 {
		detail["identity_warnings"] = warnings
	}
	s.Audit.Record(ctx, "enrollment.redeem", audit.Success, "device:"+dev.ID, detail)
	return out, nil
}

// detailError carries only an API error's person-facing detail.
type detailError struct{ msg string }

func (e detailError) Error() string { return e.msg }

func errDetail(err error) error {
	if p := apierr.As(err); p.Detail != "" {
		return detailError{p.Detail}
	}
	return detailError{"Something went wrong on the server. Try again, or ask for a new code."}
}
