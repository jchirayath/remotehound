// Package enroll owns enrolment codes and the bootstrap scripts
// (docs/specs/CLIENT_PROTOCOL.md §1–2).
//
// Codes are 6 characters from an unambiguous alphabet, made with crypto/rand,
// shown once, stored only as HMAC-SHA256(enroll key, code) — so a stolen state
// file does not reveal open codes and cannot be brute-forced offline — single
// use, and short-lived. GET /e/{code} renders a script without consuming the
// code; POST /api/v1/enroll consumes it.
package enroll

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/client"
	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/metrics"
	"github.com/jchirayath/remotehound/internal/core/secrets"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/core/validate"
	"github.com/jchirayath/remotehound/internal/device"
	"github.com/jchirayath/remotehound/internal/model"
	"github.com/jchirayath/remotehound/internal/tunnel"
)

// Service implements enrolment.
type Service struct {
	Store   store.Store
	Audit   *audit.Log
	Secrets *secrets.Set
	Devices *device.Service
	Tunnel  *tunnel.Server
	// AllowHTTP permits an http public_url (development only), as the
	// settings validator does.
	AllowHTTP bool

	misses missLimiter
}

func (s *Service) hash(code string) string {
	m := hmac.New(sha256.New, s.Secrets.EnrollKey.Bytes())
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

// View is the API shape of an enrolment (the code is never included after creation).
type View struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	GroupID   string     `json:"group_id"`
	CodeHint  string     `json:"code_hint"`
	State     string     `json:"state"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	DeviceID  string     `json:"device_id"`
	// ExpectedOS: the machine type the code is for (macos | linux | windows), "" = any.
	ExpectedOS string `json:"expected_os"`
	// DeviceDeleted: the code was used, but that device has since been deleted.
	DeviceDeleted bool   `json:"device_deleted,omitempty"`
	CreatedBy     string `json:"created_by"`
	// CreatedByName: the creator's display name or email, only when the viewer
	// may see that user (as in the directory); "" otherwise or if deleted.
	CreatedByName string    `json:"created_by_name"`
	CreatedAt     time.Time `json:"created_at"`
}

// Created adds the one-time code and commands.
type Created struct {
	View
	Code        string `json:"code"`
	CommandUnix string `json:"command_unix"`
	// CommandUnixSystem is the same command through sudo: a system-wide install
	// that starts at boot and may turn on SSH / Screen Sharing (recommended).
	CommandUnixSystem string `json:"command_unix_system"`
	CommandWindows    string `json:"command_windows"`
}

// creatorName is who made a code, as the viewer a may see it: the same people
// the user directory (GET /api/v1/directory) shows them, plus themselves.
// Anyone else, e.g. a viewer, gets "": the list must not leak emails.
func creatorName(a *authz.Actor, users map[string]*model.User, id string) string {
	u := users[id]
	if u == nil {
		return ""
	}
	visible := id == a.UserID || a.IsAdmin() ||
		(authz.Can(a, authz.SessionShare, authz.Resource{Global: true}) && !u.Disabled &&
			(u.Role == model.RoleAdmin || slices.ContainsFunc(u.GroupIDs, func(g string) bool { return slices.Contains(a.GroupIDs, g) })))
	if !visible {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func toView(e *model.Enrollment, now time.Time, viewer string, devices map[string]*model.Device) View {
	hint := ""
	if viewer == e.CreatedBy { // the hint narrows a brute force: only the creator sees it
		hint = e.CodeHint
	}
	v := View{ID: e.ID, Name: e.Name, GroupID: e.GroupID, CodeHint: hint, State: e.State(now), ExpiresAt: e.ExpiresAt,
		DeviceID: e.DeviceID, CreatedBy: e.CreatedBy, CreatedAt: e.CreatedAt, ExpectedOS: e.ExpectedOS}
	if e.DeviceID != "" && devices != nil && devices[e.DeviceID] == nil {
		v.DeviceDeleted = true
	}
	if !e.UsedAt.IsZero() {
		t := e.UsedAt
		v.UsedAt = &t
	}
	return v
}

// Commands returns the two one-liners for a code, or "", "" when publicURL or
// code fails its allow-list: both are pasted into a shell, so this fails closed.
func Commands(publicURL, code string, allowHTTP bool) (unix, windows string) {
	if !validate.PublicURL(publicURL, allowHTTP) || !ids.ValidCode(code) {
		return "", ""
	}
	// The scheme is always spelled out (curl's default is http).
	host := strings.TrimRight(publicURL, "/")
	return "curl -fsSL " + host + "/e/" + code + " | sh", "irm " + host + "/e/" + code + " | iex"
}

// errPublicURL: settings.public_url fails the allow-list (e.g. stored by an
// older release); nothing that embeds it may be produced until it is fixed.
var errPublicURL = apierr.Conflict(apierr.CodePublicURLInvalid,
	"The public address in Settings is not valid, so no enrolment command can be made. An admin fixes it under Settings → Public URL.")

// Create issues a new code.
func (s *Service) Create(ctx context.Context, a *authz.Actor, name, groupID, expectedOS string, ttlMinutes int) (Created, error) {
	now := time.Now().UTC()
	code := ids.Code()
	var st model.Settings
	var out *model.Enrollment
	err := s.Store.Update(func(x *model.State) error {
		st = x.Settings
		if !validate.PublicURL(st.PublicURL, s.AllowHTTP) {
			return errPublicURL
		}
		if groupID == "" {
			groupID = st.DefaultGroupID
		}
		if groupID != "" {
			if _, ok := x.Groups[groupID]; !ok {
				return apierr.BadRequest(apierr.CodeGroupNotFound, "That group does not exist.")
			}
		}
		if !authz.Can(a, authz.EnrollmentCreate, authz.Resource{GroupID: groupID, Global: a.IsAdmin()}) {
			return apierr.Forbidden("You can only enrol devices into your own groups. Pick one of your groups.")
		}
		if ttlMinutes == 0 {
			ttlMinutes = st.EnrollmentTTLMinutes
		}
		e := &model.Enrollment{Meta: model.Meta{ID: ids.New("enr"), CreatedAt: now, UpdatedAt: now, Version: 1},
			CodeHash: s.hash(code), CodeHint: code[len(code)-2:], Name: name, GroupID: groupID,
			ExpiresAt: now.Add(time.Duration(ttlMinutes) * time.Minute), CreatedBy: a.UserID, ExpectedOS: expectedOS}
		x.Enrollments[e.ID] = e
		out = e
		return nil
	})
	if err != nil {
		s.Audit.Record(ctx, "enrollment.create", audit.Denied, "", nil)
		return Created{}, err
	}
	s.Audit.Record(ctx, "enrollment.create", audit.Success, "enrollment:"+out.ID, map[string]any{"group_id": groupID, "ttl_minutes": ttlMinutes})
	unix, win := Commands(st.PublicURL, code, s.AllowHTTP)
	return Created{View: toView(out, now, a.UserID, nil), Code: code, CommandUnix: unix,
		CommandUnixSystem: strings.TrimSuffix(unix, "| sh") + "| sudo sh", CommandWindows: win}, nil
}

// List returns enrolments visible to the actor, newest first.
func (s *Service) List(a *authz.Actor, state string, pageSize int, token string) ([]View, string) {
	now := time.Now().UTC()
	var all []*model.Enrollment
	present := map[string]*model.Device{} // devices that still exist, for DeviceDeleted
	names := map[string]string{}
	s.Store.View(func(x *model.State) {
		for id, d := range x.Devices {
			present[id] = d
		}
		for id := range x.Users {
			names[id] = creatorName(a, x.Users, id)
		}
		for _, e := range x.Enrollments {
			if !authz.SeesGroup(a, e.GroupID) && e.CreatedBy != a.UserID {
				continue
			}
			if state != "" && e.State(now) != state {
				continue
			}
			cp := *e
			all = append(all, &cp)
		}
	})
	sort.Slice(all, func(i, j int) bool { return all[i].CreatedAt.After(all[j].CreatedAt) })
	byID := map[string]*model.Enrollment{}
	order := make([]string, len(all))
	for i, e := range all {
		order[i], byID[e.ID] = e.ID, e
	}
	page, next := store.Page(order, pageSize, token)
	out := make([]View, len(page))
	for i, id := range page {
		out[i] = toView(byID[id], now, a.UserID, present)
		out[i].CreatedByName = names[out[i].CreatedBy]
	}
	return out, next
}

// Get returns one enrolment the actor may see.
func (s *Service) Get(a *authz.Actor, id string) (View, error) {
	var out *View
	s.Store.View(func(x *model.State) {
		if e, ok := x.Enrollments[id]; ok && (authz.SeesGroup(a, e.GroupID) || e.CreatedBy == a.UserID) {
			v := toView(e, time.Now().UTC(), a.UserID, x.Devices)
			v.CreatedByName = creatorName(a, x.Users, e.CreatedBy)
			out = &v
		}
	})
	if out == nil {
		return View{}, apierr.NotFound(apierr.CodeNotFound, "No enrolment code with that ID.")
	}
	return *out, nil
}

// canDelete: the actor may revoke or remove e.
func canDelete(a *authz.Actor, e *model.Enrollment) bool {
	return authz.Can(a, authz.EnrollmentDelete, authz.Resource{GroupID: e.GroupID}) || e.CreatedBy == a.UserID
}

// Revoke deletes a code: an open one stops working, a used or expired one is
// removed from the list (its device, if any, is not affected).
func (s *Service) Revoke(ctx context.Context, a *authz.Actor, id string) error {
	var state string
	err := s.Store.Update(func(x *model.State) error {
		e, ok := x.Enrollments[id]
		if !ok || !canDelete(a, e) {
			return apierr.NotFound(apierr.CodeNotFound, "No enrolment code with that ID.")
		}
		state = e.State(time.Now().UTC())
		delete(x.Enrollments, id)
		return nil
	})
	if err == nil {
		s.Audit.Record(ctx, "enrollment.revoke", audit.Success, "enrollment:"+id, map[string]any{"state": state})
	}
	return err
}

// Cleanup removes every used and expired code the actor may delete, and
// returns how many. Open codes stay. Devices are not affected.
func (s *Service) Cleanup(ctx context.Context, a *authz.Actor) (int, error) {
	now := time.Now().UTC()
	n := 0
	err := s.Store.Update(func(x *model.State) error {
		for id, e := range x.Enrollments {
			if e.State(now) != "open" && canDelete(a, e) {
				delete(x.Enrollments, id)
				n++
			}
		}
		return nil
	})
	if err == nil {
		s.Audit.Record(ctx, "enrollment.cleanup", audit.Success, "", map[string]any{"removed": n})
	}
	return n, err
}

// Update changes an open code's device name, group or machine type. Used and
// expired codes cannot change: create a new one.
func (s *Service) Update(ctx context.Context, a *authz.Actor, id string, name, groupID, expectedOS *string) (View, error) {
	now := time.Now().UTC()
	var out View
	err := s.Store.Update(func(x *model.State) error {
		e, ok := x.Enrollments[id]
		if !ok || !(authz.SeesGroup(a, e.GroupID) || e.CreatedBy == a.UserID) {
			return apierr.NotFound(apierr.CodeNotFound, "No enrolment code with that ID.")
		}
		if !canDelete(a, e) {
			return apierr.Forbidden("You cannot change this code.")
		}
		if e.State(now) != "open" {
			return apierr.Conflict(apierr.CodeEnrollUsed, "Only an open code can be changed. Create a new code instead.")
		}
		if groupID != nil && *groupID != e.GroupID {
			g := *groupID
			if g == "" {
				g = x.Settings.DefaultGroupID
			}
			if g != "" {
				if _, ok := x.Groups[g]; !ok {
					return apierr.BadRequest(apierr.CodeGroupNotFound, "That group does not exist.")
				}
			}
			if !authz.Can(a, authz.EnrollmentCreate, authz.Resource{GroupID: g, Global: a.IsAdmin()}) {
				return apierr.Forbidden("You can only enrol devices into your own groups. Pick one of your groups.")
			}
			e.GroupID = g
		}
		if name != nil {
			e.Name = *name
		}
		if expectedOS != nil {
			e.ExpectedOS = *expectedOS
		}
		e.Touch(now)
		out = toView(e, now, a.UserID, x.Devices)
		out.CreatedByName = creatorName(a, x.Users, e.CreatedBy)
		return nil
	})
	if err == nil {
		s.Audit.Record(ctx, "enrollment.update", audit.Success, "enrollment:"+id, map[string]any{"group_id": out.GroupID, "expected_os": out.ExpectedOS})
	}
	return out, err
}

// Wrong-code limits, per fixed one-minute window. A client (ids.ClientKey:
// IPv4 address, IPv6 /64) that misses MissesPerClient times is paused — every
// lookup and redeem, so it gets no oracle. MissCeiling misses from everyone
// together pause all lookups: the backstop against a botnet guessing from
// many prefixes (docs/THREAT_MODEL.md S5 has the arithmetic).
// Paused callers are told the server is busy, never that their code is wrong.
const (
	MissesPerClient = 10
	MissCeiling     = 300
)

type missLimiter struct {
	mu     sync.Mutex
	window time.Time
	total  int
	// byClient holds only non-zero counts (a refund to zero deletes), so at
	// most MissCeiling entries: nothing is added once the ceiling is reached.
	byClient map[string]int
}

// missToken is a reserved miss, refunded if the code turns out to exist.
type missToken struct {
	key    string
	window time.Time
}

func (m *missLimiter) rollLocked() {
	if now := time.Now(); now.Sub(m.window) >= time.Minute {
		m.window, m.total, m.byClient = now, 0, map[string]int{}
	}
}

// reserve atomically checks the limits for ip and, if not paused, counts a
// miss in advance (so concurrent wrong codes cannot overshoot the limit). The
// caller refunds it when the code matches an enrolment.
func (m *missLimiter) reserve(ip string) (missToken, bool) {
	key := ids.ClientKey(ip)
	m.mu.Lock()
	m.rollLocked()
	scope := ""
	switch {
	case m.total >= MissCeiling:
		scope = "global"
	case m.byClient[key] >= MissesPerClient:
		scope = "client"
	default:
		m.total++
		m.byClient[key]++
	}
	tok := missToken{key: key, window: m.window}
	m.mu.Unlock()
	if scope != "" {
		metrics.Default.Inc("remotehound_enroll_throttled_total", "Enrolment lookups and redeems paused by the wrong-code limits.", "scope", scope)
		return missToken{}, false
	}
	return tok, true
}

// refund returns a reserved miss (no-op if the window has rolled since).
func (m *missLimiter) refund(t missToken) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.window.Equal(t.window) {
		return
	}
	m.total--
	if m.byClient[t.key]--; m.byClient[t.key] <= 0 {
		delete(m.byClient, t.key)
	}
}

const busyDetail = "RemoteHound is busy: too many wrong codes were tried recently. Your code was not checked; try again in a minute."

// Lookup finds the enrolment for code (for script rendering) on behalf of the
// client at ip, counting a miss against it. It does not consume the code.
// The state is open | used | expired | invalid | throttled.
func (s *Service) Lookup(code, ip string) (*model.Enrollment, string) {
	tok, ok := s.misses.reserve(ip)
	if !ok {
		return nil, "throttled"
	}
	if !ids.ValidCode(code) {
		return nil, "invalid" // the reserved miss stands
	}
	h := s.hash(code)
	now := time.Now().UTC()
	var found *model.Enrollment
	s.Store.View(func(x *model.State) {
		for _, e := range x.Enrollments {
			if hmac.Equal([]byte(e.CodeHash), []byte(h)) {
				cp := *e
				found = &cp
				return
			}
		}
	})
	if found == nil {
		return nil, "invalid"
	}
	s.misses.refund(tok)
	return found, found.State(now)
}

// failScript is a script that prints msg (a constant without quotes) and exits.
func failScript(msg string, ps bool) string {
	if ps {
		return "Write-Host '" + msg + "' -ForegroundColor Red\n"
	}
	return "#!/bin/sh\necho '" + msg + "' >&2\nexit 1\n"
}

// Script renders the bootstrap for code for the client at ip (one Lookup, so
// one miss at most); ps selects PowerShell. It also returns the lookup state.
// Wrong codes and a paused client get a script that explains and exits non-zero.
func (s *Service) Script(code, ip string, ps bool) (string, string) {
	_, state := s.Lookup(code, ip)
	switch state {
	case "open":
	case "throttled":
		return failScript(busyDetail, ps), state
	default:
		return failScript("RemoteHound: this code is not valid or has expired. Ask for a new one.", ps), state
	}
	var base string
	s.Store.View(func(x *model.State) { base = x.Settings.PublicURL })
	// Re-checked here, failing closed: these are the only two values substituted
	// into the script, inside string literals, and a stored value may predate
	// the current validator.
	if !validate.PublicURL(base, s.AllowHTTP) || !ids.ValidCode(code) {
		return failScript("RemoteHound: the server's public address is not set up correctly, so this command cannot run. Ask your admin to fix the Public URL in Settings.", ps), state
	}
	base = strings.TrimRight(base, "/")
	tpl := client.BootstrapSH
	if ps {
		tpl = client.BootstrapPS1
	}
	return strings.NewReplacer("__RH_BASE_URL__", base, "__RH_CODE__", code).Replace(tpl), state
}

// RedeemRequest is the POST /api/v1/enroll body.
type RedeemRequest struct {
	Code          string `json:"code"`
	PublicKey     string `json:"public_key"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	ClientVersion string `json:"client_version"`
	InstallScope  string `json:"install_scope"` // "system" | "user"; other values are dropped
	InstallUser   string `json:"install_user"`
	Services      []struct {
		Kind       string `json:"kind"`
		RemotePort int    `json:"remote_port"`
	} `json:"services"`
}

// RedeemResult is returned to the script.
type RedeemResult struct {
	DeviceID       string   `json:"device_id"`
	DeviceName     string   `json:"device_name"`
	SSHHost        string   `json:"ssh_host"`
	SSHPort        int      `json:"ssh_port"`
	KnownHostsLine string   `json:"known_hosts_line"`
	Forwards       []string `json:"forwards"`
	Fingerprint    string   `json:"fingerprint"`
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// userRe: an account name as the script reports it (Windows names may hold
// spaces, DOMAIN\ is stripped by the script).
var userRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._ -]{0,63}$`)

// Redeem consumes code and creates the device, for the client at ip.
func (s *Service) Redeem(ctx context.Context, ip string, req RedeemRequest) (RedeemResult, error) {
	tok, ok := s.misses.reserve(ip)
	if !ok {
		return RedeemResult{}, apierr.New(429, apierr.CodeRateLimited, busyDetail)
	}
	code := strings.ToLower(strings.TrimSpace(req.Code))
	if !ids.ValidCode(code) {
		return RedeemResult{}, apierr.NotFound(apierr.CodeEnrollInvalid, "This enrolment code is not valid. Ask for a new one.")
	}
	if !hostRe.MatchString(req.Hostname) {
		req.Hostname = "device"
	}
	switch req.OS {
	case "linux", "macos", "windows":
	default:
		req.OS = "unknown"
	}
	if len(req.OSVersion) > 128 {
		req.OSVersion = req.OSVersion[:128]
	}
	if len(req.ClientVersion) > 32 {
		req.ClientVersion = req.ClientVersion[:32]
	}
	switch req.InstallScope {
	case "system":
		req.InstallUser = ""
	case "user":
		if !userRe.MatchString(req.InstallUser) {
			req.InstallUser = ""
		}
	default:
		req.InstallScope, req.InstallUser = "", ""
	}
	var services []model.Service
	seen := map[string]bool{}
	for _, rs := range req.Services {
		if _, ok := model.DefaultRemotePort[rs.Kind]; !ok || seen[rs.Kind] || rs.RemotePort < 1 || rs.RemotePort > 65535 || len(services) >= 8 {
			continue
		}
		seen[rs.Kind] = true
		services = append(services, model.Service{Kind: rs.Kind, RemotePort: rs.RemotePort})
	}
	if len(services) == 0 {
		services = []model.Service{{Kind: model.ServiceSSH, RemotePort: 22}}
	}

	h := s.hash(code)
	now := time.Now().UTC()
	var res RedeemResult
	var dev *model.Device
	var wrongOS bool
	var warnings []string
	var hit bool // the code exists: refund the reserved miss
	err := s.Store.Update(func(x *model.State) error {
		var e *model.Enrollment
		for _, cand := range x.Enrollments {
			if hmac.Equal([]byte(cand.CodeHash), []byte(h)) {
				e = cand
				break
			}
		}
		if e == nil {
			return apierr.NotFound(apierr.CodeEnrollInvalid, "This enrolment code is not valid. Ask for a new one.")
		}
		hit = true
		switch e.State(now) {
		case "used":
			return apierr.New(410, apierr.CodeEnrollUsed, "This code was already used. Ask for a new one.")
		case "expired":
			return apierr.New(410, apierr.CodeEnrollExpired, "This code has expired. Ask for a new one.")
		}
		if e.ExpectedOS != "" && req.OS != e.ExpectedOS {
			// Not consumed: the right machine can still use this code.
			wrongOS = true
			return apierr.BadRequest(apierr.CodeEnrollWrongOS, "This code is for a "+osLabel(e.ExpectedOS)+" machine, but this one reports "+
				osLabel(req.OS)+" (hostname "+req.Hostname+"). Run the command on the machine it was made for, or create a code for "+osLabel(req.OS)+".")
		}
		name := e.Name
		if name == "" {
			name = req.Hostname
		}
		d, err := s.Devices.Create(ctx, name, e.GroupID, req.PublicKey, req.OS, "", e.ID)
		if err != nil {
			return err
		}
		for _, o := range x.Devices {
			if o.KeyFingerprint == d.KeyFingerprint {
				return apierr.BadRequest(apierr.CodeEnrollKeyInvalid, "This key already belongs to another device. Re-run the command: it generates a fresh key.")
			}
		}
		d.Hostname, d.OSVersion, d.ClientVersion, d.Services = req.Hostname, req.OSVersion, req.ClientVersion, services
		d.InstallScope, d.InstallUser = req.InstallScope, req.InstallUser
		x.Devices[d.ID] = d
		warnings = device.RedeemWarnings(d, x.Devices)
		e.UsedAt, e.DeviceID = now, d.ID
		e.Touch(now)
		dev = d

		st := x.Settings
		res = RedeemResult{DeviceID: d.ID, DeviceName: d.Name, SSHHost: st.SSHPublicHost, SSHPort: st.SSHPublicPort,
			KnownHostsLine: s.Tunnel.KnownHostsLine(st.SSHPublicHost, st.SSHPublicPort), Fingerprint: d.KeyFingerprint}
		for _, sv := range services {
			res.Forwards = append(res.Forwards, itoa(sv.RemotePort)+":localhost:"+itoa(sv.RemotePort))
		}
		return nil
	})
	if hit {
		s.misses.refund(tok)
	}
	if err != nil {
		detail := map[string]any{"reason": apierr.As(err).Code}
		if wrongOS {
			detail["reported_os"], detail["hostname"] = req.OS, req.Hostname
		}
		s.Audit.Record(ctx, "enrollment.redeem", audit.Failure, "", detail)
		return RedeemResult{}, err
	}
	detail := map[string]any{"os": dev.OS, "hostname": dev.Hostname, "services": len(services), "install_scope": dev.InstallScope}
	if len(warnings) > 0 {
		detail["identity_warnings"] = warnings // e.g. NAME_OS_MISMATCH: run on the wrong machine?
	}
	s.Audit.Record(ctx, "enrollment.redeem", audit.Success, "device:"+dev.ID, detail)
	return res, nil
}

// Status reports whether the device's tunnel is up (stage 6 poll). The
// fingerprint must match so this cannot be used to enumerate device IDs.
func (s *Service) Status(deviceID, fingerprint string) (online bool, forwards []string, err error) {
	d := s.Devices.Device(deviceID)
	if d == nil || !hmac.Equal([]byte(d.KeyFingerprint), []byte(fingerprint)) {
		return false, nil, apierr.NotFound(apierr.CodeDeviceNotFound, "Unknown device.")
	}
	for rp := range s.Tunnel.Forwarded(deviceID) {
		forwards = append(forwards, itoa(rp)+":localhost:"+itoa(rp))
	}
	sort.Strings(forwards)
	return s.Tunnel.Online(deviceID), forwards, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func osLabel(os string) string {
	switch os {
	case "macos":
		return "macOS"
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	}
	return "an unknown OS"
}
