// Package authz is CORE-5: identity on the context and the single
// authorization decision point.
//
// Contract: every handler that reads non-public data or mutates anything calls
// Can(actor, action, resource) — deny by default (SEC-6). Resource carries the
// owning group so operator/viewer access is scoped to their groups (SEC-7, no
// IDOR). Role names are compared ONLY in this package.
package authz

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/jchirayath/remotehound/internal/model"
)

// Actions. The UI receives the permitted list from /api/v1/me (UX only).
const (
	DeviceRead       = "device.read"
	DeviceCreate     = "device.create"
	DeviceUpdate     = "device.update"
	DeviceDelete     = "device.delete"
	DeviceConnect    = "device.connect"
	EnrollmentRead   = "enrollment.read"
	EnrollmentCreate = "enrollment.create"
	EnrollmentDelete = "enrollment.delete"
	GroupRead        = "group.read"
	GroupWrite       = "group.write"
	UserRead         = "user.read"
	UserWrite        = "user.write"
	SessionRead      = "session.read"     // own sessions and sessions shared with you
	SessionReadAll   = "session.read_all" // every session's metadata (never joining)
	SessionShare     = "session.share"    // share your own live session
	SessionTerminate = "session.terminate"
	RecordingRead    = "recording.read"
	SettingsRead     = "settings.read"
	SettingsWrite    = "settings.write"
	IntegrationRead  = "integration.read"
	IntegrationTest  = "integration.test"
	AuditRead        = "audit.read"
	DebugRead        = "debug.read"
	DebugWrite       = "debug.write"
	LogsRead         = "logs.read"
	JobRun           = "job.run"
	ServicesRead     = "services.read"    // the Services screen: status, ports, problems, container logs
	ServicesControl  = "services.control" // start / stop / restart bundle containers (via rh-control)
)

// grants per role. Group scoping is applied on top for non-admins.
var grants = map[string][]string{
	model.RoleViewer: {
		DeviceRead, GroupRead, SessionRead, EnrollmentRead, IntegrationRead,
	},
	model.RoleOperator: {
		DeviceRead, DeviceUpdate, DeviceConnect, GroupRead, SessionRead, SessionShare, SessionTerminate,
		EnrollmentRead, EnrollmentCreate, EnrollmentDelete, IntegrationRead, IntegrationTest,
	},
	model.RoleAdmin: {
		DeviceRead, DeviceCreate, DeviceUpdate, DeviceDelete, DeviceConnect,
		EnrollmentRead, EnrollmentCreate, EnrollmentDelete, GroupRead, GroupWrite, UserRead, UserWrite,
		SessionRead, SessionReadAll, SessionShare, SessionTerminate, RecordingRead, SettingsRead, SettingsWrite, IntegrationRead,
		IntegrationTest, AuditRead, DebugRead, DebugWrite, LogsRead, JobRun, ServicesRead, ServicesControl,
	},
}

// groupScoped actions are limited to the actor's groups unless admin.
var groupScoped = map[string]bool{
	DeviceRead: true, DeviceUpdate: true, DeviceConnect: true, DeviceDelete: true,
	EnrollmentCreate: true, EnrollmentRead: true, EnrollmentDelete: true,
}

// Actor is the authenticated principal.
type Actor struct {
	UserID   string
	Email    string
	Name     string
	Role     string
	GroupIDs []string
}

// Session rules (not role grants): joining a session is decided ONLY by
// ownership and the owner's share — no role, including admin, can join
// someone else's session. Admins may see every session and end any of them.

// CanJoinSession: the owner, or a user with a live share.
func CanJoinSession(a *Actor, s *model.Session, now time.Time) bool {
	if a.Anonymous() || s == nil || !s.EndedAt.IsZero() {
		return false
	}
	return s.UserID == a.UserID || s.ActiveShare(a.UserID, now) != nil
}

// CanSeeSession: owner, grantee, or anyone with session.read_all.
func CanSeeSession(a *Actor, s *model.Session, now time.Time) bool {
	if a.Anonymous() || s == nil {
		return false
	}
	return s.UserID == a.UserID || s.ActiveShare(a.UserID, now) != nil || Can(a, SessionReadAll, Any)
}

// CanEndSession: the owner or an admin (incident response; audited).
func CanEndSession(a *Actor, s *model.Session) bool {
	if a.Anonymous() || s == nil {
		return false
	}
	return (s.UserID == a.UserID && Can(a, SessionTerminate, Any)) || a.IsAdmin()
}

// CanShareSession: only the owner, with the share permission.
func CanShareSession(a *Actor, s *model.Session) bool {
	return !a.Anonymous() && s != nil && s.UserID == a.UserID && Can(a, SessionShare, Any) && s.EndedAt.IsZero()
}

// Anonymous reports whether there is no authenticated user.
func (a *Actor) Anonymous() bool { return a == nil || a.UserID == "" }

// IsAdmin reports whether the actor has the admin role.
func (a *Actor) IsAdmin() bool { return a != nil && a.Role == model.RoleAdmin }

// Resource is what an action targets. GroupID "" means global (not group-owned).
type Resource struct {
	GroupID string
	Global  bool // e.g. listing: scoping is applied by filtering, not denial
}

// Any is the resource for global actions (settings, users, audit…).
var Any = Resource{Global: true}

// Can decides. Deny by default.
func Can(a *Actor, action string, r Resource) bool {
	if a.Anonymous() {
		return false
	}
	if !slices.Contains(grants[a.Role], action) {
		return false
	}
	if a.IsAdmin() || !groupScoped[action] || r.Global {
		return true
	}
	return r.GroupID != "" && slices.Contains(a.GroupIDs, r.GroupID)
}

// SeesGroup reports whether a list should include items of groupID.
func SeesGroup(a *Actor, groupID string) bool {
	if a.IsAdmin() {
		return true
	}
	return groupID != "" && slices.Contains(a.GroupIDs, groupID)
}

// Permissions lists the actions the actor's role grants (for UI gating).
func Permissions(a *Actor) []string {
	if a.Anonymous() {
		return nil
	}
	out := append([]string{}, grants[a.Role]...)
	sort.Strings(out)
	return out
}

// ValidRole reports whether r is a known role.
func ValidRole(r string) bool { _, ok := grants[r]; return ok }

type ctxKey struct{}

// WithActor attaches the actor to ctx.
func WithActor(ctx context.Context, a *Actor) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// ActorFrom returns the actor on ctx, or nil.
func ActorFrom(ctx context.Context) *Actor {
	a, _ := ctx.Value(ctxKey{}).(*Actor)
	return a
}
