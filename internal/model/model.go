// Package model holds the persisted domain types. They are plain data: no
// behaviour beyond small derived helpers, so the store can clone them by JSON
// round-trip and handlers can map them to response DTOs explicitly (SEC-10:
// no mass assignment — request bodies never decode straight into these).
package model

import (
	"strconv"
	"time"
)

// Roles, lowest to highest privilege. The authz package owns what each may do.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Device statuses. "online" is NOT a status: it is live presence from the
// tunnel server and is computed at read time.
const (
	DeviceActive   = "active"
	DeviceDisabled = "disabled"
)

// Device transports: how the device's tunnel was set up (ADR-0005).
const (
	TransportScript   = "ssh-r"        // bootstrap script + watchdog; sends `agent v1`
	TransportManual   = "ssh-manual"   // typed ssh with a key the person made; sends `hello v1`
	TransportAttended = "ssh-attended" // typed ssh with no key: one session, never logs in again
)

// Enrolment code modes (ADR-0005). "" is read as persistent.
const (
	EnrollModePersistent = "persistent" // the scripts, or ssh with a key
	EnrollModeAttended   = "attended"   // ssh with no key only
)

// Service kinds a device can expose through its tunnel.
const (
	ServiceSSH = "ssh"
	ServiceRDP = "rdp"
	ServiceVNC = "vnc"
)

// DefaultRemotePort is the conventional port for each service kind.
var DefaultRemotePort = map[string]int{ServiceSSH: 22, ServiceRDP: 3389, ServiceVNC: 5900}

// Meta is embedded in every record: identity, timestamps and the optimistic
// concurrency version that becomes the ETag (API-9).
type Meta struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Version   int       `json:"version"`
}

// ETag is the strong validator for If-Match.
func (m Meta) ETag() string { return `"` + strconv.Itoa(m.Version) + `"` }

// Touch bumps the version and update time; call on every mutation.
func (m *Meta) Touch(now time.Time) {
	m.Version++
	m.UpdatedAt = now
}

// Service is one protocol a device forwards. RemotePort is the port on the
// device and doubles as the identity the client uses in `-R port:localhost:port`.
// InternalPort is server-assigned and stable across reconnects.
type Service struct {
	Kind             string            `json:"kind"`
	RemotePort       int               `json:"remote_port"`
	InternalPort     int               `json:"internal_port"`
	Username         string            `json:"username,omitempty"`
	CredentialSealed string            `json:"credential_sealed,omitempty"` // AES-GCM, see core/secrets
	Options          map[string]string `json:"options,omitempty"`
}

// Device is one enrolled machine.
type Device struct {
	Meta
	Name           string    `json:"name"`
	GroupID        string    `json:"group_id"`
	OS             string    `json:"os"`
	OSVersion      string    `json:"os_version"`
	Hostname       string    `json:"hostname"`
	Status         string    `json:"status"`
	Transport      string    `json:"transport"`
	PublicKey      string    `json:"public_key"`
	KeyFingerprint string    `json:"key_fingerprint"`
	Services       []Service `json:"services"`
	ClientVersion  string    `json:"client_version"`
	// InstallScope is how the enrolment script installed the tunnel, as the
	// script reported it: "system" (sudo / Administrator; starts at boot) or
	// "user" (one user's login only). Empty for scripts older than this field.
	InstallScope string `json:"install_scope,omitempty"`
	// InstallUser is the account a "user" install runs as.
	InstallUser  string    `json:"install_user,omitempty"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	LastIP       string    `json:"last_ip"`
	Notes        string    `json:"notes"`
	Tags         []string  `json:"tags"`
	Debug        bool      `json:"debug"`
	EnrollmentID string    `json:"enrollment_id"`
}

// Service returns a pointer to the device's service of the given kind, or nil.
func (d *Device) Service(kind string) *Service {
	for i := range d.Services {
		if d.Services[i].Kind == kind {
			return &d.Services[i]
		}
	}
	return nil
}

// ServiceByRemotePort finds the service a client forward request refers to.
func (d *Device) ServiceByRemotePort(port int) *Service {
	for i := range d.Services {
		if d.Services[i].RemotePort == port {
			return &d.Services[i]
		}
	}
	return nil
}

// Enrollment is a one-time code. Only an HMAC of the code is stored.
type Enrollment struct {
	Meta
	CodeHash  string    `json:"code_hash"`
	CodeHint  string    `json:"code_hint"`
	Name      string    `json:"name"`
	GroupID   string    `json:"group_id"`
	ExpiresAt time.Time `json:"expires_at"`
	UsedAt    time.Time `json:"used_at"`
	DeviceID  string    `json:"device_id"`
	CreatedBy string    `json:"created_by"`
	// ExpectedOS: macos | linux | windows, or "" for any. A machine reporting
	// another OS is refused, and the code stays usable on the right machine.
	ExpectedOS string `json:"expected_os,omitempty"`
	// Mode: EnrollModePersistent ("" too) or EnrollModeAttended.
	Mode string `json:"mode,omitempty"`
}

// Attended reports whether the code is for an attended (keyless) session.
func (e *Enrollment) Attended() bool { return e.Mode == EnrollModeAttended }

// State reports open | used | expired at time now.
func (e *Enrollment) State(now time.Time) string {
	switch {
	case !e.UsedAt.IsZero():
		return "used"
	case now.After(e.ExpiresAt):
		return "expired"
	default:
		return "open"
	}
}

// Group scopes devices for operators and viewers.
type Group struct {
	Meta
	Name        string `json:"name"`
	Description string `json:"description"`
	Color       string `json:"color"`
}

// UserIdentity links a user to one sign-in provider account.
type UserIdentity struct {
	Provider string    `json:"provider"`
	Subject  string    `json:"subject"`
	Email    string    `json:"email"`
	LinkedAt time.Time `json:"linked_at"`
}

// User is an operator. A user may sign in with several linked identities
// (e.g. Microsoft at work and Google at home); each is provider-scoped.
type User struct {
	Meta
	Subject     string         `json:"subject,omitempty"` // legacy (schema 1); migrated into Identities
	Identities  []UserIdentity `json:"identities"`
	Email       string         `json:"email"`
	DisplayName string         `json:"display_name"`
	Role        string         `json:"role"`
	GroupIDs    []string       `json:"group_ids"`
	Disabled    bool           `json:"disabled"`
	LastLoginAt time.Time      `json:"last_login_at"`
	Theme       string         `json:"theme"`
	// SessionGen invalidates every issued session cookie when bumped
	// (disable, role change, "sign out everywhere").
	SessionGen int `json:"session_gen"`
}

// HasIdentity reports whether provider:subject is linked to the user.
func (u *User) HasIdentity(provider, subject string) bool {
	for _, i := range u.Identities {
		if i.Provider == provider && i.Subject == subject {
			return true
		}
	}
	return false
}

// Share modes for joining another user's live session.
const (
	ShareView    = "view"
	ShareControl = "control"
)

// Share is the owner's grant letting another user join a live session.
type Share struct {
	UserID    string    `json:"user_id"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Session is one remote-desktop/terminal connection, observed at the tunnel
// listener — so it is true even if a browser misreports. UserID is the OWNER:
// only the owner can share it; only the owner and live grantees can join it.
type Session struct {
	Meta
	DeviceID      string    `json:"device_id"`
	Service       string    `json:"service"`
	UserID        string    `json:"user_id"`
	GuacConnID    string    `json:"guac_conn_id"` // Guacamole connection id, the target of "join"
	Shares        []Share   `json:"shares"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	ClientAddress string    `json:"client_address"`
	Recording     string    `json:"recording"`
}

// ActiveShare returns the user's unexpired grant on the session, if any.
func (s *Session) ActiveShare(userID string, now time.Time) *Share {
	for i := range s.Shares {
		if s.Shares[i].UserID == userID && now.Before(s.Shares[i].ExpiresAt) {
			return &s.Shares[i]
		}
	}
	return nil
}

// Credential is one user's own login for one device service, sealed with
// AAD = user/device/service so it can only ever be opened for that user.
type Credential struct {
	Meta
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Sealed   string `json:"sealed"` // password, or the key's passphrase when SealedKey is set ("" = none)
	// SealedKey is an SSH private key (ssh only), sealed with AAD
	// credentialAAD(...)+"/key" so it cannot be swapped with the password.
	SealedKey string `json:"sealed_key,omitempty"`
}

// CredentialKey is the map key for a user's credential.
func CredentialKey(userID, deviceID, service string) string {
	return userID + "|" + deviceID + "|" + service
}

// Settings is the runtime, UI-managed configuration singleton (ARCHITECTURE §8).
type Settings struct {
	Meta
	PublicURL              string            `json:"public_url"`
	SSHPublicHost          string            `json:"ssh_public_host"`
	SSHPublicPort          int               `json:"ssh_public_port"`
	EnrollmentTTLMinutes   int               `json:"enrollment_ttl_minutes"`
	ConnectTokenTTLSeconds int               `json:"connect_token_ttl_seconds"`
	RecordingEnabled       bool              `json:"recording_enabled"`
	RecordingRetentionDays int               `json:"recording_retention_days"`
	LogLevel               string            `json:"log_level"`
	SessionIdleMinutes     int               `json:"session_idle_minutes"`
	SessionAbsoluteHours   int               `json:"session_absolute_hours"`
	RolesClaim             string            `json:"roles_claim"`
	RolesMap               map[string]string `json:"roles_map"`
	DefaultGroupID         string            `json:"default_group_id"`
	VNCEnabled             bool              `json:"vnc_enabled"`
	ClientLogsEnabled      bool              `json:"client_logs_enabled"`
	AuditRetentionDays     int               `json:"audit_retention_days"`
	SessionRetentionDays   int               `json:"session_retention_days"`
}

// DefaultSettings are applied on first boot; every value is editable in the UI.
func DefaultSettings(publicURL, sshHost string, sshPort int) Settings {
	return Settings{
		Meta:                   Meta{ID: "settings", Version: 1},
		PublicURL:              publicURL,
		SSHPublicHost:          sshHost,
		SSHPublicPort:          sshPort,
		EnrollmentTTLMinutes:   15,
		ConnectTokenTTLSeconds: 60,
		RecordingEnabled:       false,
		RecordingRetentionDays: 30,
		LogLevel:               "INFO",
		SessionIdleMinutes:     30,
		SessionAbsoluteHours:   12,
		RolesClaim:             "groups",
		RolesMap:               map[string]string{},
		VNCEnabled:             true,
		ClientLogsEnabled:      true,
		AuditRetentionDays:     365,
		SessionRetentionDays:   90,
	}
}

// State is the whole persisted document (see core/store).
type State struct {
	SchemaVersion int                    `json:"schema_version"`
	Devices       map[string]*Device     `json:"devices"`
	Enrollments   map[string]*Enrollment `json:"enrollments"`
	Groups        map[string]*Group      `json:"groups"`
	Users         map[string]*User       `json:"users"`
	Sessions      map[string]*Session    `json:"sessions"`
	Credentials   map[string]*Credential `json:"credentials"`
	Settings      Settings               `json:"settings"`
}

// CurrentSchemaVersion is bumped with a migration in core/store.
const CurrentSchemaVersion = 2

// NewState returns an empty state with initialised maps.
func NewState() *State {
	return &State{
		SchemaVersion: CurrentSchemaVersion,
		Devices:       map[string]*Device{},
		Enrollments:   map[string]*Enrollment{},
		Groups:        map[string]*Group{},
		Users:         map[string]*User{},
		Sessions:      map[string]*Session{},
		Credentials:   map[string]*Credential{},
	}
}
