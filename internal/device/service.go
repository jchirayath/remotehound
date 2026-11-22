// Package device is the device domain: registry CRUD, services and sealed
// credentials, live presence (it implements tunnel.Hooks), session records,
// probes, and minting Guacamole connections.
//
// Every exported method that acts for a user takes the request context; the
// caller (internal/api) has already checked authz.Can for the action, and the
// methods re-check group scoping where they load a specific device (SEC-7).
package device

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/secrets"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/guac"
	"github.com/jchirayath/remotehound/internal/model"
	"github.com/jchirayath/remotehound/internal/tunnel"
)

// Service is the device domain service.
type Service struct {
	Store             store.Store
	Audit             *audit.Log
	Secrets           *secrets.Set
	Tunnel            *tunnel.Server // set after construction (the tunnel needs the hooks first)
	PortMin           int
	PortMax           int
	TunnelHost        string // RH_TUNNEL_ADVERTISE_HOST
	GuacPublicPath    string
	GuacRecordingPath string

	logMu      sync.Mutex
	clientLogs map[string][]LogLine

	pendMu  sync.Mutex
	pending []pendingConnect
}

// LogLine is one client log line kept in memory.
type LogLine struct {
	ReceivedAt time.Time `json:"received_at"`
	Line       string    `json:"line"`
}

// pendingConnect attributes the next tunnel connection to the user who clicked.
type pendingConnect struct {
	deviceID, kind, userID, connID string
	until                          time.Time
}

// AllowedOptions are the Guacamole parameters an admin may set per service.
var AllowedOptions = map[string]map[string]bool{
	model.ServiceRDP: {"security": true, "ignore-cert": true, "color-depth": true, "enable-sftp": true, "read-only": true, "resize-method": true, "domain": true},
	model.ServiceVNC: {"color-depth": true, "read-only": true, "enable-sftp": true},
	model.ServiceSSH: {"enable-sftp": true, "color-scheme": true, "font-size": true, "read-only": true},
}

// ---- tunnel.Hooks -----------------------------------------------------------------

// Device implements tunnel.Hooks.
func (s *Service) Device(id string) *model.Device {
	var out *model.Device
	s.Store.View(func(st *model.State) {
		if d, ok := st.Devices[id]; ok {
			cp := *d
			cp.Services = append([]model.Service{}, d.Services...)
			out = &cp
		}
	})
	return out
}

// AllocatePort implements tunnel.Hooks: stable per (device, kind).
func (s *Service) AllocatePort(deviceID, kind string, avoid []int) (int, error) {
	var port int
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[deviceID]
		if !ok {
			return errors.New("device gone")
		}
		svc := d.Service(kind)
		if svc == nil {
			return errors.New("service gone")
		}
		if svc.InternalPort != 0 && !slices.Contains(avoid, svc.InternalPort) {
			port = svc.InternalPort
			return nil
		}
		used := map[int]bool{}
		for _, o := range st.Devices {
			for _, os := range o.Services {
				if os.InternalPort != 0 {
					used[os.InternalPort] = true
				}
			}
		}
		for _, a := range avoid {
			used[a] = true
		}
		for p := s.PortMin; p <= s.PortMax; p++ {
			if !used[p] {
				svc.InternalPort = p
				d.Touch(time.Now().UTC())
				port = p
				return nil
			}
		}
		return errors.New("tunnel port range exhausted; widen RH_TUNNEL_PORT_MIN/MAX")
	})
	return port, err
}

// Connected implements tunnel.Hooks.
func (s *Service) Connected(deviceID, remoteIP string, f tunnel.Facts) {
	now := time.Now().UTC()
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[deviceID]
		if !ok {
			return errors.New("device gone")
		}
		d.LastSeenAt, d.LastIP = now, remoteIP
		if f.ClientVersion != "" {
			d.ClientVersion = f.ClientVersion
		}
		if f.OS != "" {
			d.OS = f.OS
		}
		if f.Hostname != "" {
			d.Hostname = f.Hostname
		}
		// Services the device reports but the registry lacks are added
		// (e.g. Screen Sharing turned on after enrolment). Existing ones keep
		// their settings. Nothing is removed automatically.
		for _, rs := range f.Services {
			if d.Service(rs.Kind) == nil && d.ServiceByRemotePort(rs.RemotePort) == nil {
				d.Services = append(d.Services, model.Service{Kind: rs.Kind, RemotePort: rs.RemotePort})
			}
		}
		return nil
	})
	if err != nil {
		logx.L().Warn("Could not update presence", logx.Event("device.presence"), logx.Err(err))
	}
	ctx := logx.WithScope(context.Background(), logx.Scope{DeviceID: deviceID})
	s.Audit.Record(ctx, "device.connect_tunnel", audit.Success, "device:"+deviceID, map[string]any{"client_ip": remoteIP, "client_version": f.ClientVersion})
}

// Disconnected implements tunnel.Hooks.
func (s *Service) Disconnected(deviceID string) {
	_ = s.Store.Update(func(st *model.State) error {
		if d, ok := st.Devices[deviceID]; ok {
			d.LastSeenAt = time.Now().UTC()
		}
		return nil
	})
}

// SessionOpened implements tunnel.Hooks.
func (s *Service) SessionOpened(deviceID, kind, clientAddr string) string {
	userID, connID := s.claimPending(deviceID, kind)
	sess := &model.Session{Meta: model.Meta{ID: ids.New("ses"), CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(), Version: 1},
		DeviceID: deviceID, Service: kind, UserID: userID, GuacConnID: connID, StartedAt: time.Now().UTC(), ClientAddress: clientAddr, Shares: []model.Share{}}
	if err := s.Store.Update(func(st *model.State) error { st.Sessions[sess.ID] = sess; return nil }); err != nil {
		logx.L().Error("Could not record session", logx.Event("session.record_failed"), logx.Err(err))
		return ""
	}
	logx.L().Info("Session started", logx.Event("session.start"), slog.String("app.session.id", sess.ID),
		slog.String("app.device.id", deviceID), slog.String("app.service", kind), slog.String("user.id", userID))
	return sess.ID
}

// SessionClosed implements tunnel.Hooks.
func (s *Service) SessionClosed(sessionID string, in, out int64) {
	_ = s.Store.Update(func(st *model.State) error {
		if ss, ok := st.Sessions[sessionID]; ok {
			ss.EndedAt, ss.BytesIn, ss.BytesOut = time.Now().UTC(), in, out
			ss.Touch(time.Now().UTC())
		}
		return nil
	})
	logx.L().Info("Session ended", logx.Event("session.end"), slog.String("app.session.id", sessionID),
		slog.Int64("app.bytes_in", in), slog.Int64("app.bytes_out", out))
}

// ClientLog implements tunnel.Hooks.
func (s *Service) ClientLog(deviceID string, lines []string) {
	enabled := true
	s.Store.View(func(st *model.State) { enabled = st.Settings.ClientLogsEnabled })
	if !enabled {
		return
	}
	now := time.Now().UTC()
	s.logMu.Lock()
	if s.clientLogs == nil {
		s.clientLogs = map[string][]LogLine{}
	}
	buf := s.clientLogs[deviceID]
	for _, l := range lines {
		red := logx.Redact(l)
		buf = append(buf, LogLine{ReceivedAt: now, Line: red})
		logx.Ingest("client", deviceID, clientSeverity(red), red, nil)
	}
	if len(buf) > 200 {
		buf = buf[len(buf)-200:]
	}
	s.clientLogs[deviceID] = buf
	s.logMu.Unlock()
}

func clientSeverity(line string) string {
	for _, lvl := range []string{"ERROR", "WARN", "DEBUG"} {
		if strings.Contains(line, " "+lvl+" ") {
			return lvl
		}
	}
	return "INFO"
}

// ClientLogs returns the device's log tail.
func (s *Service) ClientLogs(deviceID string) []LogLine {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	return append([]LogLine{}, s.clientLogs[deviceID]...)
}

func (s *Service) addPending(deviceID, kind, userID, connID string, ttl time.Duration) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	now := time.Now()
	kept := s.pending[:0]
	for _, p := range s.pending {
		if p.until.After(now) {
			kept = append(kept, p)
		}
	}
	s.pending = append(kept, pendingConnect{deviceID: deviceID, kind: kind, userID: userID, connID: connID, until: now.Add(ttl + 30*time.Second)})
}

// claimPending attributes a new tunnel connection to the click that minted
// it. The tunnel cannot see which token guacd is serving, so attribution is
// only made when it is unambiguous: if clicks from DIFFERENT users are pending
// for the same device+service, the session is recorded unattributed (owner "")
// — nobody can share/join it and only an admin can end it — rather than
// credited to the wrong person. (A per-token listener would remove this limit.)
func (s *Service) claimPending(deviceID, kind string) (userID, connID string) {
	s.pendMu.Lock()
	defer s.pendMu.Unlock()
	now := time.Now()
	idx := -1
	users := map[string]bool{}
	for i, p := range s.pending {
		if p.deviceID == deviceID && p.kind == kind && p.until.After(now) {
			users[p.userID] = true
			if idx < 0 {
				idx = i
			}
		}
	}
	if idx < 0 {
		return "", ""
	}
	p := s.pending[idx]
	s.pending = append(s.pending[:idx], s.pending[idx+1:]...)
	if len(users) > 1 {
		logx.L().Warn("Session attribution ambiguous; recording unattributed", logx.Event("session.unattributed"),
			slog.String("app.device.id", deviceID), slog.String("app.service", kind))
		return "", ""
	}
	return p.userID, p.connID
}

// ---- views -------------------------------------------------------------------------

// View is the API representation of a device (explicit DTO, API-12).
type View struct {
	ID             string        `json:"id"`
	Name           string        `json:"name"`
	GroupID        string        `json:"group_id"`
	OS             string        `json:"os"`
	OSVersion      string        `json:"os_version"`
	Hostname       string        `json:"hostname"`
	Status         string        `json:"status"`
	Online         bool          `json:"online"`
	Transport      string        `json:"transport"`
	KeyFingerprint string        `json:"key_fingerprint"`
	Services       []ServiceView `json:"services"`
	ClientVersion  string        `json:"client_version"`
	// InstallScope: "system" (permanent, starts at boot), "user" (runs while
	// InstallUser is logged in) or "" (not reported by an older script).
	InstallScope   string     `json:"install_scope"`
	InstallUser    string     `json:"install_user"`
	LastSeenAt     *time.Time `json:"last_seen_at"`
	LastIP         string     `json:"last_ip"`
	ConnectedSince *time.Time `json:"connected_since"`
	Notes          string     `json:"notes"`
	Tags           []string   `json:"tags"`
	Debug          bool       `json:"debug"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ETag           string     `json:"etag"`
	// IdentityWarnings: signs this device is not the machine its name says
	// (wrong machine enrolled, or one machine enrolled twice). Advisory.
	IdentityWarnings []IdentityWarning `json:"identity_warnings"`
}

// ServiceView never exposes the sealed credential.
type ServiceView struct {
	Kind          string            `json:"kind"`
	RemotePort    int               `json:"remote_port"`
	InternalPort  int               `json:"internal_port"`
	Forwarded     bool              `json:"forwarded"`
	Username      string            `json:"username"`
	HasCredential bool              `json:"has_credential"`
	Options       map[string]string `json:"options"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ToView maps a device to its DTO with live presence. Call it outside a Store
// lock: it reads the device's group peers for duplicate detection.
func (s *Service) ToView(d *model.Device) View {
	var peers []*model.Device
	if s.Store != nil {
		s.Store.View(func(st *model.State) { peers = groupPeers(st, d.GroupID) })
	}
	return s.toView(d, peers)
}

// groupPeers: devices in the same group. Duplicates are only looked for there,
// because the group is the unit of visibility (no other group's names leak).
func groupPeers(st *model.State, groupID string) []*model.Device {
	var out []*model.Device
	for _, o := range st.Devices {
		if o.GroupID == groupID {
			out = append(out, o)
		}
	}
	return out
}

func (s *Service) toView(d *model.Device, peers []*model.Device) View {
	fwd := map[int]int{}
	online := false
	var since time.Time
	if s.Tunnel != nil {
		online = s.Tunnel.Online(d.ID)
		fwd = s.Tunnel.Forwarded(d.ID)
		since = s.Tunnel.ConnectedSince(d.ID)
	}
	v := View{ID: d.ID, Name: d.Name, GroupID: d.GroupID, OS: d.OS, OSVersion: d.OSVersion, Hostname: d.Hostname,
		Status: d.Status, Online: online, Transport: d.Transport, KeyFingerprint: d.KeyFingerprint,
		ClientVersion: d.ClientVersion, InstallScope: d.InstallScope, InstallUser: d.InstallUser, LastSeenAt: timePtr(d.LastSeenAt), LastIP: d.LastIP, ConnectedSince: timePtr(since),
		Notes: d.Notes, Tags: append([]string{}, d.Tags...), Debug: d.Debug, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt, ETag: d.ETag()}
	if v.Tags == nil {
		v.Tags = []string{}
	}
	for _, sv := range d.Services {
		_, isFwd := fwd[sv.RemotePort]
		opts := map[string]string{}
		for k, val := range sv.Options {
			opts[k] = val
		}
		v.Services = append(v.Services, ServiceView{Kind: sv.Kind, RemotePort: sv.RemotePort, InternalPort: sv.InternalPort,
			Forwarded: isFwd, Username: sv.Username, HasCredential: sv.CredentialSealed != "", Options: opts})
	}
	if v.Services == nil {
		v.Services = []ServiceView{}
	}
	v.IdentityWarnings = identityWarnings(d, peers)
	return v
}

// Filter for List.
type Filter struct {
	Q, Status, GroupID, OS, OrderBy string
	Online                          *bool
	PageSize                        int
	PageToken                       string
}

// List returns the devices the actor may see, filtered, sorted and paged.
func (s *Service) List(a *authz.Actor, f Filter) ([]View, string, int) {
	var all []View
	s.Store.View(func(st *model.State) {
		byGroup := map[string][]*model.Device{}
		for _, d := range st.Devices {
			byGroup[d.GroupID] = append(byGroup[d.GroupID], d)
		}
		for _, d := range st.Devices {
			if !authz.SeesGroup(a, d.GroupID) {
				continue
			}
			if f.Status != "" && d.Status != f.Status || f.GroupID != "" && d.GroupID != f.GroupID || f.OS != "" && d.OS != f.OS {
				continue
			}
			if !store.Contains(f.Q, d.Name, d.Hostname, d.LastIP, strings.Join(d.Tags, " ")) {
				continue
			}
			all = append(all, s.toView(d, byGroup[d.GroupID]))
		}
	})
	if f.Online != nil {
		kept := all[:0]
		for _, v := range all {
			if v.Online == *f.Online {
				kept = append(kept, v)
			}
		}
		all = kept
	}
	sortViews(all, f.OrderBy)
	byID := map[string]View{}
	order := make([]string, len(all))
	for i, v := range all {
		order[i] = v.ID
		byID[v.ID] = v
	}
	page, next := store.Page(order, f.PageSize, f.PageToken)
	out := make([]View, len(page))
	for i, id := range page {
		out[i] = byID[id]
	}
	return out, next, len(all)
}

func sortViews(v []View, orderBy string) {
	field, dir, _ := strings.Cut(orderBy, " ")
	desc := dir == "desc"
	less := func(i, j int) bool { return strings.ToLower(v[i].Name) < strings.ToLower(v[j].Name) }
	switch field {
	case "last_seen_at":
		less = func(i, j int) bool { return deref(v[i].LastSeenAt).Before(deref(v[j].LastSeenAt)) }
	case "created_at":
		less = func(i, j int) bool { return v[i].CreatedAt.Before(v[j].CreatedAt) }
	}
	sort.SliceStable(v, func(i, j int) bool {
		if desc {
			return less(j, i)
		}
		return less(i, j)
	})
}

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// Load returns the device if it exists and the actor may perform action on it.
// A device in another group is reported as NOT FOUND, not forbidden, so IDs
// cannot be probed (SEC-7).
func (s *Service) Load(a *authz.Actor, action, id string) (*model.Device, error) {
	d := s.Device(id)
	if d == nil || !authz.Can(a, authz.DeviceRead, authz.Resource{GroupID: d.GroupID}) {
		return nil, apierr.NotFound(apierr.CodeDeviceNotFound, "No device with that ID (or you cannot see it).")
	}
	if !authz.Can(a, action, authz.Resource{GroupID: d.GroupID}) {
		return nil, apierr.Forbidden("Your role cannot do that on this device.")
	}
	return d, nil
}

// ---- mutations ------------------------------------------------------------------

// Patch is the allow-listed set of editable fields (SEC-10).
type Patch struct {
	Name    *string   `json:"name"`
	GroupID *string   `json:"group_id"`
	Notes   *string   `json:"notes"`
	Tags    *[]string `json:"tags"`
	Debug   *bool     `json:"debug"`
}

// Update applies p if etag matches.
func (s *Service) Update(ctx context.Context, a *authz.Actor, id, etag string, p Patch) (View, error) {
	var out *model.Device
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[id]
		if !ok || !authz.Can(a, authz.DeviceUpdate, authz.Resource{GroupID: d.GroupID}) {
			return apierr.NotFound(apierr.CodeDeviceNotFound, "No device with that ID (or you cannot see it).")
		}
		if etag != d.ETag() {
			return apierr.Precondition()
		}
		if p.Name != nil {
			d.Name = strings.TrimSpace(*p.Name)
		}
		if p.GroupID != nil && *p.GroupID != d.GroupID {
			if _, ok := st.Groups[*p.GroupID]; !ok && *p.GroupID != "" {
				return apierr.BadRequest(apierr.CodeGroupNotFound, "That group does not exist.")
			}
			// Moving a device into a group you are not in would hide it from you.
			if !authz.SeesGroup(a, *p.GroupID) {
				return apierr.Forbidden("You can only move devices into your own groups.")
			}
			d.GroupID = *p.GroupID
		}
		if p.Notes != nil {
			d.Notes = *p.Notes
		}
		if p.Tags != nil {
			d.Tags = *p.Tags
		}
		if p.Debug != nil {
			d.Debug = *p.Debug
		}
		d.Touch(time.Now().UTC())
		cp := *d
		out = &cp
		return nil
	})
	if err != nil {
		s.Audit.Record(ctx, "device.update", outcomeOf(err), "device:"+id, nil)
		return View{}, err
	}
	s.Audit.Record(ctx, "device.update", audit.Success, "device:"+id, patchFields(p))
	return s.ToView(out), nil
}

func patchFields(p Patch) map[string]any {
	var f []string
	if p.Name != nil {
		f = append(f, "name")
	}
	if p.GroupID != nil {
		f = append(f, "group_id")
	}
	if p.Notes != nil {
		f = append(f, "notes")
	}
	if p.Tags != nil {
		f = append(f, "tags")
	}
	if p.Debug != nil {
		f = append(f, "debug")
	}
	return map[string]any{"fields": strings.Join(f, ",")}
}

func outcomeOf(err error) string {
	var e *apierr.Error
	if errors.As(err, &e) && (e.Status == 403 || e.Status == 404) {
		return audit.Denied
	}
	return audit.Failure
}

// ServiceInput is the allow-listed service upsert body.
type ServiceInput struct {
	RemotePort int               `json:"remote_port"`
	Username   string            `json:"username"`
	Password   *string           `json:"password"`
	Options    map[string]string `json:"options"`
}

// UpsertService creates or updates a service. The password is sealed with the
// device ID + kind as associated data.
func (s *Service) UpsertService(ctx context.Context, a *authz.Actor, id, kind string, in ServiceInput) (View, error) {
	if _, ok := model.DefaultRemotePort[kind]; !ok {
		return View{}, apierr.BadRequest(apierr.CodeValidation, "Service must be ssh, rdp or vnc.")
	}
	for k := range in.Options {
		if !AllowedOptions[kind][k] {
			return View{}, apierr.Validation([]apierr.FieldError{{Pointer: "/options/" + k, Code: "NOT_ALLOWED", Detail: "This option is not supported for " + kind + "."}})
		}
	}
	if in.RemotePort == 0 {
		in.RemotePort = model.DefaultRemotePort[kind]
	}
	if in.RemotePort < 1 || in.RemotePort > 65535 {
		return View{}, apierr.Validation([]apierr.FieldError{{Pointer: "/remote_port", Code: "OUT_OF_RANGE", Detail: "Port must be 1–65535."}})
	}
	var sealed *string
	if in.Password != nil {
		v := ""
		if *in.Password != "" {
			var err error
			if v, err = s.Secrets.Seal(*in.Password, id+"/"+kind); err != nil {
				return View{}, apierr.Internal(err)
			}
		}
		sealed = &v
	}
	var out *model.Device
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[id]
		if !ok || !authz.Can(a, authz.DeviceUpdate, authz.Resource{GroupID: d.GroupID}) {
			return apierr.NotFound(apierr.CodeDeviceNotFound, "No device with that ID (or you cannot see it).")
		}
		for _, o := range d.Services {
			if o.Kind != kind && o.RemotePort == in.RemotePort {
				return apierr.Validation([]apierr.FieldError{{Pointer: "/remote_port", Code: "DUPLICATE", Detail: "Another service already uses this port."}})
			}
		}
		svc := d.Service(kind)
		if svc == nil {
			d.Services = append(d.Services, model.Service{Kind: kind})
			svc = &d.Services[len(d.Services)-1]
		}
		svc.RemotePort, svc.Username, svc.Options = in.RemotePort, strings.TrimSpace(in.Username), in.Options
		if sealed != nil {
			svc.CredentialSealed = *sealed
		}
		d.Touch(time.Now().UTC())
		cp := *d
		out = &cp
		return nil
	})
	attrs := map[string]any{"service": kind, "credential_changed": in.Password != nil}
	if err != nil {
		s.Audit.Record(ctx, "device.service.upsert", outcomeOf(err), "device:"+id, attrs)
		return View{}, err
	}
	s.Audit.Record(ctx, "device.service.upsert", audit.Success, "device:"+id, attrs)
	return s.ToView(out), nil
}

// DeleteService removes a service from the registry.
func (s *Service) DeleteService(ctx context.Context, a *authz.Actor, id, kind string) (View, error) {
	var out *model.Device
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[id]
		if !ok || !authz.Can(a, authz.DeviceUpdate, authz.Resource{GroupID: d.GroupID}) {
			return apierr.NotFound(apierr.CodeDeviceNotFound, "No device with that ID (or you cannot see it).")
		}
		kept := d.Services[:0]
		for _, sv := range d.Services {
			if sv.Kind != kind {
				kept = append(kept, sv)
			}
		}
		d.Services = kept
		d.Touch(time.Now().UTC())
		cp := *d
		out = &cp
		return nil
	})
	if err != nil {
		return View{}, err
	}
	s.Audit.Record(ctx, "device.service.delete", audit.Success, "device:"+id, map[string]any{"service": kind})
	return s.ToView(out), nil
}

// SetStatus enables or disables a device; disabling revokes the live tunnel.
func (s *Service) SetStatus(ctx context.Context, a *authz.Actor, id, status string) (View, error) {
	var out *model.Device
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[id]
		if !ok || !authz.Can(a, authz.DeviceUpdate, authz.Resource{GroupID: d.GroupID}) {
			return apierr.NotFound(apierr.CodeDeviceNotFound, "No device with that ID (or you cannot see it).")
		}
		d.Status = status
		d.Touch(time.Now().UTC())
		cp := *d
		out = &cp
		return nil
	})
	if err != nil {
		return View{}, err
	}
	if status == model.DeviceDisabled && s.Tunnel != nil {
		s.Tunnel.Kick(id, "revoked")
	}
	s.Audit.Record(ctx, "device."+map[string]string{model.DeviceActive: "enable", model.DeviceDisabled: "disable"}[status], audit.Success, "device:"+id, nil)
	return s.ToView(out), nil
}

// Delete removes the device, revokes its key and closes its tunnel.
func (s *Service) Delete(ctx context.Context, a *authz.Actor, id string) error {
	err := s.Store.Update(func(st *model.State) error {
		d, ok := st.Devices[id]
		if !ok || !authz.Can(a, authz.DeviceDelete, authz.Resource{GroupID: d.GroupID}) {
			return apierr.NotFound(apierr.CodeDeviceNotFound, "No device with that ID (or you cannot see it).")
		}
		delete(st.Devices, id)
		for k, c := range st.Credentials {
			if c.DeviceID == id {
				delete(st.Credentials, k)
			}
		}
		return nil
	})
	if err != nil {
		s.Audit.Record(ctx, "device.delete", outcomeOf(err), "device:"+id, nil)
		return err
	}
	if s.Tunnel != nil {
		s.Tunnel.Kick(id, "revoked")
	}
	s.logMu.Lock()
	delete(s.clientLogs, id)
	s.logMu.Unlock()
	s.Audit.Record(ctx, "device.delete", audit.Success, "device:"+id, nil)
	return nil
}

// Create pre-registers a device with a public key (admin, advanced path).
func (s *Service) Create(ctx context.Context, name, groupID, pubKey, osName, notes, enrollmentID string) (*model.Device, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKey))
	if err != nil || key.Type() != ssh.KeyAlgoED25519 {
		return nil, apierr.BadRequest(apierr.CodeEnrollKeyInvalid, "The public key must be an ssh-ed25519 key in authorized_keys format.")
	}
	now := time.Now().UTC()
	d := &model.Device{
		Meta: model.Meta{ID: ids.New("dev"), CreatedAt: now, UpdatedAt: now, Version: 1},
		Name: name, GroupID: groupID, OS: osName, Status: model.DeviceActive, Transport: "ssh-r",
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), KeyFingerprint: ssh.FingerprintSHA256(key),
		Notes: notes, Tags: []string{}, EnrollmentID: enrollmentID,
	}
	if d.OS == "" {
		d.OS = "unknown"
	}
	return d, nil
}

// ---- connect, probe, reconnect ------------------------------------------------

// ConnectResult is what the UI opens.
type ConnectResult struct {
	URL            string    `json:"url"`
	ExpiresAt      time.Time `json:"expires_at"`
	ConnectionName string    `json:"connection_name"`
}

// missingLogin explains why a session cannot start without a saved login, or
// returns "". guacd would ask the browser for these ("required"), but
// Guacamole's page never shows that form, so the tab would wait forever.
func missingLogin(kind, deviceOS string, p map[string]string) string {
	hasUserPass := p["username"] != "" && p["password"] != ""
	switch {
	case kind == model.ServiceVNC && deviceOS == "macos" && !hasUserPass:
		return "Screen Sharing on a Mac asks for a macOS username and password. Save them with \"Use my own login\", then connect. The account must be allowed under System Settings → General → Sharing → Screen Sharing."
	case kind == model.ServiceRDP && !hasUserPass:
		switch p["security"] {
		case "", "any", "nla", "nla-ext":
			return "Remote Desktop with Network Level Authentication (the Windows default) needs a username and password before it starts. Save them with \"Use my own login\", then connect."
		}
	}
	return ""
}

// splitRDPDomain turns a Windows-style "DOMAIN\user" login (".\admin" for a local
// account, "AzureAD\user@domain" for Entra) into RDP's separate domain and username.
// FreeRDP sends the username verbatim, so unsplit it never matches an account and the
// automatic sign-in always fails. An explicit domain option is left alone.
func splitRDPDomain(p map[string]string) {
	if p["domain"] != "" {
		return
	}
	dom, user, ok := strings.Cut(p["username"], `\`)
	if !ok || dom == "" || user == "" {
		return
	}
	p["domain"], p["username"] = dom, user
}

// Connect mints a short-lived Guacamole connection for one service.
func (s *Service) Connect(ctx context.Context, a *authz.Actor, id, kind string) (ConnectResult, error) {
	d, err := s.Load(a, authz.DeviceConnect, id)
	if err != nil {
		s.Audit.Record(ctx, "session.open", outcomeOf(err), "device:"+id, map[string]any{"service": kind})
		return ConnectResult{}, err
	}
	var st model.Settings
	s.Store.View(func(x *model.State) { st = x.Settings })
	if kind == model.ServiceVNC && !st.VNCEnabled {
		return ConnectResult{}, apierr.Forbidden("VNC is turned off in Settings.")
	}
	if d.Status != model.DeviceActive {
		return ConnectResult{}, apierr.Conflict(apierr.CodeDeviceDisabled, "This device is disabled. Enable it first.")
	}
	svc := d.Service(kind)
	if svc == nil {
		return ConnectResult{}, apierr.Conflict(apierr.CodeServiceMissing, "This device has no "+strings.ToUpper(kind)+" service. Add it under Services.")
	}
	if s.Tunnel == nil || !s.Tunnel.Online(id) {
		return ConnectResult{}, apierr.Conflict(apierr.CodeDeviceOffline, "The device is offline. It reconnects on its own; check its client log if it stays offline.")
	}
	internal, ok := s.Tunnel.Forwarded(id)[svc.RemotePort]
	if !ok {
		return ConnectResult{}, apierr.Conflict(apierr.CodeServiceNotFwd, "The device is online but is not forwarding "+strings.ToUpper(kind)+". Re-run the enrolment command or check the service on the device.")
	}

	params := map[string]string{"hostname": s.TunnelHost, "port": fmt.Sprint(internal)}
	// Credentials: the user's OWN saved login first (their own OS session);
	// else the device's shared login if an admin set one. Without either,
	// SSH asks in the terminal; RDP with NLA and macOS Screen Sharing are
	// refused below, because Guacamole's page never shows the login form
	// guacd asks for ("required"), so the session would hang for good.
	credSource := "prompt"
	if c := s.userCredential(a.UserID, id, kind); c != nil {
		aad := credentialAAD(a.UserID, id, kind)
		pw := ""
		if c.Sealed != "" {
			var err error
			if pw, err = s.Secrets.Open(c.Sealed, aad); err != nil {
				return ConnectResult{}, apierr.Internal(err)
			}
		}
		params["username"], credSource = c.Username, "personal"
		if c.SealedKey != "" {
			key, err := s.Secrets.Open(c.SealedKey, aad+"/key")
			if err != nil {
				return ConnectResult{}, apierr.Internal(err)
			}
			params["private-key"] = key
			if pw != "" {
				params["passphrase"] = pw
			}
		} else {
			params["password"] = pw
		}
	} else {
		if svc.Username != "" {
			params["username"] = svc.Username
		}
		if svc.CredentialSealed != "" {
			pw, err := s.Secrets.Open(svc.CredentialSealed, id+"/"+kind)
			if err != nil {
				return ConnectResult{}, apierr.Internal(err)
			}
			params["password"], credSource = pw, "shared"
		}
	}
	for k, v := range svc.Options {
		if AllowedOptions[kind][k] {
			params[k] = v
		}
	}
	if msg := missingLogin(kind, d.OS, params); msg != "" {
		s.Audit.Record(ctx, "session.open", audit.Denied, "device:"+id, map[string]any{"service": kind, "reason": apierr.CodeCredsRequired})
		return ConnectResult{}, apierr.Conflict(apierr.CodeCredsRequired, msg)
	}
	if kind == model.ServiceRDP {
		splitRDPDomain(params)
		if _, ok := params["ignore-cert"]; !ok {
			params["ignore-cert"] = "true" // the device's self-signed RDP cert, reached over our own tunnel
		}
		if _, ok := params["resize-method"]; !ok {
			params["resize-method"] = "display-update"
		}
	}
	if st.RecordingEnabled {
		params["recording-path"] = s.GuacRecordingPath
		params["create-recording-path"] = "true"
		params["recording-name"] = sanitizeFile(d.Name) + "-" + kind + "-${GUAC_DATE}-${GUAC_TIME}"
		if kind == model.ServiceSSH {
			params["typescript-path"] = s.GuacRecordingPath
			params["create-typescript-path"] = "true"
			params["typescript-name"] = sanitizeFile(d.Name) + "-ssh-${GUAC_DATE}-${GUAC_TIME}"
		}
	}
	ttl := time.Duration(st.ConnectTokenTTLSeconds) * time.Second
	name := ConnectionName(d.Name, kind)
	connID := ids.New("gcn")
	sealed, err := guac.Seal(s.Secrets.GuacJSONKey.Bytes(), guac.AuthData{
		Username:    a.Email,
		Expires:     guac.Expiry(time.Now(), ttl),
		Connections: map[string]guac.Connection{name: {Protocol: kind, Parameters: params, ID: connID}},
	})
	if err != nil {
		return ConnectResult{}, apierr.Internal(err)
	}
	s.addPending(id, kind, a.UserID, connID, ttl)
	s.Audit.Record(ctx, "session.open", audit.Success, "device:"+id, map[string]any{"service": kind, "recording": st.RecordingEnabled, "credentials": credSource})
	return ConnectResult{URL: guac.ConnectURL(s.GuacPublicPath, name, sealed), ExpiresAt: time.Now().Add(ttl).UTC(), ConnectionName: name}, nil
}

// ConnectionName is the Guacamole connection key, which doubles as its
// identifier in the client URL. Guacamole decodes that identifier as
// Latin-1, so it must be printable ASCII (a "·" or an accented device name
// would not resolve). Non-ASCII runes become "_".
func ConnectionName(device, kind string) string {
	var b strings.Builder
	for _, r := range device {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String() + " - " + strings.ToUpper(kind)
}

func sanitizeFile(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// Probe checks each service through the tunnel.
func (s *Service) Probe(ctx context.Context, a *authz.Actor, id string) ([]tunnel.ProbeResult, error) {
	d, err := s.Load(a, authz.DeviceUpdate, id)
	if err != nil {
		return nil, err
	}
	out := make([]tunnel.ProbeResult, 0, len(d.Services))
	for _, sv := range d.Services {
		out = append(out, s.Tunnel.Probe(ctx, id, sv.Kind, sv.RemotePort))
	}
	s.Audit.Record(ctx, "device.probe", audit.Success, "device:"+id, nil)
	return out, nil
}

// Reconnect asks the device to re-establish its tunnel.
func (s *Service) Reconnect(ctx context.Context, a *authz.Actor, id string) error {
	if _, err := s.Load(a, authz.DeviceUpdate, id); err != nil {
		return err
	}
	if !s.Tunnel.Kick(id, "reconnect") {
		return apierr.Conflict(apierr.CodeDeviceOffline, "The device is offline.")
	}
	s.Audit.Record(ctx, "device.reconnect", audit.Success, "device:"+id, nil)
	return nil
}
