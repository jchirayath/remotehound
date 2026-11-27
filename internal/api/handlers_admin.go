package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/core/validate"
	"github.com/jchirayath/remotehound/internal/model"
)

// ---- enrollments ---------------------------------------------------------------

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.EnrollmentRead) {
		return
	}
	state := qparam(r, "state")
	var v validate.Collector
	v.OneOf("/state", state, "open", "used", "expired")
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	size, token := pageParams(r)
	items, next := s.Enroll.List(authz.ActorFrom(r.Context()), state, size, token)
	writeJSON(w, http.StatusOK, nonNil(items), &meta{NextPageToken: next, Total: len(items)})
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.EnrollmentCreate) {
		return
	}
	var in struct {
		Name       string `json:"name"`
		GroupID    string `json:"group_id"`
		TTLMinutes int    `json:"ttl_minutes"`
		ExpectedOS string `json:"expected_os"`
		Mode       string `json:"mode"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	if in.Name != "" {
		v.Name("/name", in.Name)
	}
	v.ID("/group_id", in.GroupID, "grp")
	if in.TTLMinutes != 0 {
		v.Range("/ttl_minutes", in.TTLMinutes, 5, 1440)
	}
	v.OneOf("/expected_os", in.ExpectedOS, "", "macos", "linux", "windows")
	v.OneOf("/mode", in.Mode, "", model.EnrollModePersistent, model.EnrollModeAttended)
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Enroll.Create(r.Context(), authz.ActorFrom(r.Context()), in.Name, in.GroupID, in.ExpectedOS, in.Mode, in.TTLMinutes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, out, nil)
}

func (s *Server) getEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.EnrollmentRead) {
		return
	}
	v, err := s.Enroll.Get(authz.ActorFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v, nil)
}

func (s *Server) revokeEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.EnrollmentDelete) {
		return
	}
	if err := s.Enroll.Revoke(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id")); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) updateEnrollment(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.EnrollmentCreate) {
		return
	}
	var in struct {
		Name       *string `json:"name"`
		GroupID    *string `json:"group_id"`
		ExpectedOS *string `json:"expected_os"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	var v validate.Collector
	if in.Name != nil && *in.Name != "" {
		v.Name("/name", *in.Name)
	}
	if in.GroupID != nil {
		v.ID("/group_id", *in.GroupID, "grp")
	}
	if in.ExpectedOS != nil {
		v.OneOf("/expected_os", *in.ExpectedOS, "", "macos", "linux", "windows")
	}
	if err := v.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.Enroll.Update(r.Context(), authz.ActorFrom(r.Context()), r.PathValue("id"), in.Name, in.GroupID, in.ExpectedOS)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out, nil)
}

// cleanupEnrollments removes the used and expired codes the caller may delete.
func (s *Server) cleanupEnrollments(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.EnrollmentDelete) {
		return
	}
	n, err := s.Enroll.Cleanup(r.Context(), authz.ActorFrom(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"removed": n}, nil)
}

// ---- groups ---------------------------------------------------------------------

// Group colors are domain tokens (color.domain.group.*) defined in design/.
var groupColors = []string{"teal", "violet", "amber", "rose", "sky", "lime", "slate", "orange"}

type groupView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Color       string    `json:"color"`
	DeviceCount int       `json:"device_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ETag        string    `json:"etag"`
}

func toGroupView(g *model.Group, st *model.State) groupView {
	n := 0
	for _, d := range st.Devices {
		if d.GroupID == g.ID {
			n++
		}
	}
	return groupView{ID: g.ID, Name: g.Name, Description: g.Description, Color: g.Color, DeviceCount: n, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt, ETag: g.ETag()}
}

type groupInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Color       *string `json:"color"`
}

func (in groupInput) validate(create bool) error {
	var v validate.Collector
	if create || in.Name != nil {
		v.Name("/name", deref(in.Name))
	}
	if in.Description != nil {
		v.MaxLen("/description", *in.Description, 500)
	}
	if in.Color != nil {
		v.OneOf("/color", *in.Color, groupColors...)
	}
	return v.Err()
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.GroupRead) {
		return
	}
	a := authz.ActorFrom(r.Context())
	var out []groupView
	s.Store.View(func(st *model.State) {
		for _, g := range st.Groups {
			if authz.SeesGroup(a, g.ID) {
				out = append(out, toGroupView(g, st))
			}
		}
	})
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	writeJSON(w, http.StatusOK, nonNil(out), &meta{Total: len(out)})
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.GroupRead) {
		return
	}
	a := authz.ActorFrom(r.Context())
	var out *groupView
	s.Store.View(func(st *model.State) {
		if g, ok := st.Groups[r.PathValue("id")]; ok && authz.SeesGroup(a, g.ID) {
			v := toGroupView(g, st)
			out = &v
		}
	})
	if out == nil {
		s.fail(w, r, apierr.NotFound(apierr.CodeGroupNotFound, "No group with that ID."))
		return
	}
	w.Header().Set("ETag", out.ETag)
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.GroupWrite) {
		return
	}
	var in groupInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(true); err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	g := &model.Group{Meta: model.Meta{ID: ids.New("grp"), CreatedAt: now, UpdatedAt: now, Version: 1},
		Name: strings.TrimSpace(*in.Name), Description: deref(in.Description), Color: deref(in.Color)}
	if g.Color == "" {
		g.Color = "teal"
	}
	var out groupView
	err := s.Store.Update(func(st *model.State) error {
		for _, o := range st.Groups {
			if strings.EqualFold(o.Name, g.Name) {
				return apierr.Validation([]apierr.FieldError{{Pointer: "/name", Code: "DUPLICATE", Detail: "A group with this name exists."}})
			}
		}
		st.Groups[g.ID] = g
		out = toGroupView(g, st)
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "group.create", audit.Success, "group:"+g.ID, map[string]any{"name": g.Name})
	writeJSON(w, http.StatusCreated, out, nil)
}

func (s *Server) patchGroup(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.GroupWrite) {
		return
	}
	etag, err := ifMatch(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in groupInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(false); err != nil {
		s.fail(w, r, err)
		return
	}
	id := r.PathValue("id")
	var out groupView
	err = s.Store.Update(func(st *model.State) error {
		g, ok := st.Groups[id]
		if !ok {
			return apierr.NotFound(apierr.CodeGroupNotFound, "No group with that ID.")
		}
		if g.ETag() != etag {
			return apierr.Precondition()
		}
		if in.Name != nil {
			g.Name = strings.TrimSpace(*in.Name)
		}
		if in.Description != nil {
			g.Description = *in.Description
		}
		if in.Color != nil {
			g.Color = *in.Color
		}
		g.Touch(time.Now().UTC())
		out = toGroupView(g, st)
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "group.update", audit.Success, "group:"+id, nil)
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.GroupWrite) {
		return
	}
	id := r.PathValue("id")
	err := s.Store.Update(func(st *model.State) error {
		if _, ok := st.Groups[id]; !ok {
			return apierr.NotFound(apierr.CodeGroupNotFound, "No group with that ID.")
		}
		for _, d := range st.Devices {
			if d.GroupID == id {
				return apierr.Conflict(apierr.CodeGroupNotEmpty, "Move or delete this group's devices first.")
			}
		}
		delete(st.Groups, id)
		for _, u := range st.Users {
			u.GroupIDs = removeString(u.GroupIDs, id)
		}
		if st.Settings.DefaultGroupID == id {
			st.Settings.DefaultGroupID = ""
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "group.delete", audit.Success, "group:"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}

func removeString(xs []string, x string) []string {
	out := xs[:0]
	for _, v := range xs {
		if v != x {
			out = append(out, v)
		}
	}
	return out
}

// ---- users ------------------------------------------------------------------------

type userView struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	GroupIDs    []string   `json:"group_ids"`
	Disabled    bool       `json:"disabled"`
	LastLoginAt *time.Time `json:"last_login_at"`
	Bound       bool       `json:"bound"` // has signed in at least once (subject bound)
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ETag        string     `json:"etag"`
}

func toUserView(u *model.User) userView {
	v := userView{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: u.Role, GroupIDs: append([]string{}, u.GroupIDs...),
		Disabled: u.Disabled, Bound: len(u.Identities) > 0, CreatedAt: u.CreatedAt, UpdatedAt: u.UpdatedAt, ETag: u.ETag()}
	if !u.LastLoginAt.IsZero() {
		t := u.LastLoginAt
		v.LastLoginAt = &t
	}
	return v
}

type userInput struct {
	Email       *string   `json:"email"`
	DisplayName *string   `json:"display_name"`
	Role        *string   `json:"role"`
	GroupIDs    *[]string `json:"group_ids"`
	Disabled    *bool     `json:"disabled"`
}

func (in userInput) validate(create bool) error {
	var v validate.Collector
	if create {
		v.Required("/email", deref(in.Email))
		v.Required("/role", deref(in.Role))
	}
	if in.Email != nil {
		v.Email("/email", strings.ToLower(*in.Email))
	}
	if in.DisplayName != nil {
		v.MaxLen("/display_name", *in.DisplayName, 128)
	}
	if in.Role != nil {
		v.OneOf("/role", *in.Role, model.RoleAdmin, model.RoleOperator, model.RoleViewer)
	}
	if in.GroupIDs != nil {
		for _, g := range *in.GroupIDs {
			v.ID("/group_ids", g, "grp")
		}
	}
	return v.Err()
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.UserRead) {
		return
	}
	q := qparam(r, "q")
	var all []*model.User
	s.Store.View(func(st *model.State) {
		for _, u := range st.Users {
			if store.Contains(q, u.Email, u.DisplayName) {
				cp := *u
				all = append(all, &cp)
			}
		}
	})
	sort.Slice(all, func(i, j int) bool { return all[i].Email < all[j].Email })
	order := make([]string, len(all))
	byID := map[string]*model.User{}
	for i, u := range all {
		order[i], byID[u.ID] = u.ID, u
	}
	size, token := pageParams(r)
	page, next := store.Page(order, size, token)
	out := make([]userView, len(page))
	for i, id := range page {
		out[i] = toUserView(byID[id])
	}
	writeJSON(w, http.StatusOK, out, &meta{NextPageToken: next, Total: len(all)})
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.UserRead) {
		return
	}
	var out *userView
	s.Store.View(func(st *model.State) {
		if u, ok := st.Users[r.PathValue("id")]; ok {
			v := toUserView(u)
			out = &v
		}
	})
	if out == nil {
		s.fail(w, r, apierr.NotFound(apierr.CodeUserNotFound, "No user with that ID."))
		return
	}
	w.Header().Set("ETag", out.ETag)
	writeJSON(w, http.StatusOK, out, nil)
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.UserWrite) {
		return
	}
	var in userInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(true); err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	u := &model.User{Meta: model.Meta{ID: ids.New("usr"), CreatedAt: now, UpdatedAt: now, Version: 1},
		Email: strings.ToLower(*in.Email), DisplayName: deref(in.DisplayName), Role: *in.Role, GroupIDs: []string{}, Theme: "system"}
	if in.GroupIDs != nil {
		u.GroupIDs = *in.GroupIDs
	}
	err := s.Store.Update(func(st *model.State) error {
		for _, o := range st.Users {
			if strings.EqualFold(o.Email, u.Email) {
				return apierr.Conflict(apierr.CodeUserExists, "A user with this email already exists.")
			}
		}
		for _, g := range u.GroupIDs {
			if _, ok := st.Groups[g]; !ok {
				return apierr.BadRequest(apierr.CodeGroupNotFound, "One of the groups does not exist.")
			}
		}
		st.Users[u.ID] = u
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "user.create", audit.Success, "user:"+u.ID, map[string]any{"role": u.Role})
	writeJSON(w, http.StatusCreated, toUserView(u), nil)
}

func (s *Server) patchUser(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.UserWrite) {
		return
	}
	etag, err := ifMatch(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in userInput
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(false); err != nil {
		s.fail(w, r, err)
		return
	}
	me := authz.ActorFrom(r.Context())
	id := r.PathValue("id")
	var out userView
	privChange := false
	err = s.Store.Update(func(st *model.State) error {
		privChange = false
		u, ok := st.Users[id]
		if !ok {
			return apierr.NotFound(apierr.CodeUserNotFound, "No user with that ID.")
		}
		if u.ETag() != etag {
			return apierr.Precondition()
		}
		losesAdmin := u.Role == model.RoleAdmin && ((in.Role != nil && *in.Role != model.RoleAdmin) || (in.Disabled != nil && *in.Disabled))
		if losesAdmin && adminCount(st) <= 1 {
			return apierr.Conflict(apierr.CodeLastAdmin, "This is the last admin. Make someone else admin first.")
		}
		if id == me.UserID && in.Disabled != nil && *in.Disabled {
			return apierr.Conflict(apierr.CodeLastAdmin, "You cannot disable yourself.")
		}
		if in.Email != nil && !strings.EqualFold(*in.Email, u.Email) {
			if len(u.Identities) > 0 {
				return apierr.Validation([]apierr.FieldError{{Pointer: "/email", Code: "IMMUTABLE", Detail: "Email is fixed once the user has signed in."}})
			}
			u.Email = strings.ToLower(*in.Email)
		}
		if in.DisplayName != nil {
			u.DisplayName = *in.DisplayName
		}
		if in.Role != nil && *in.Role != u.Role {
			u.Role, privChange = *in.Role, true
		}
		if in.GroupIDs != nil {
			for _, g := range *in.GroupIDs {
				if _, ok := st.Groups[g]; !ok {
					return apierr.BadRequest(apierr.CodeGroupNotFound, "One of the groups does not exist.")
				}
			}
			// The edit form always sends the groups; only a real change ends
			// sessions (it also rotates a proxy session's CSRF token).
			if !sameSet(u.GroupIDs, *in.GroupIDs) {
				privChange = true
			}
			u.GroupIDs = *in.GroupIDs
		}
		if in.Disabled != nil && *in.Disabled != u.Disabled {
			u.Disabled, privChange = *in.Disabled, true
		}
		if privChange {
			u.SessionGen++ // end existing sessions so the new rights apply now
		}
		u.Touch(time.Now().UTC())
		out = toUserView(u)
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "user.update", audit.Success, "user:"+id, map[string]any{"role": out.Role, "disabled": out.Disabled})
	if privChange {
		s.EndUserAccess(r.Context(), id, "user_updated")
	}
	writeJSON(w, http.StatusOK, out, nil)
}

func adminCount(st *model.State) int {
	n := 0
	for _, u := range st.Users {
		if u.Role == model.RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.UserWrite) {
		return
	}
	me := authz.ActorFrom(r.Context())
	id := r.PathValue("id")
	err := s.Store.Update(func(st *model.State) error {
		u, ok := st.Users[id]
		if !ok {
			return apierr.NotFound(apierr.CodeUserNotFound, "No user with that ID.")
		}
		if id == me.UserID {
			return apierr.Conflict(apierr.CodeLastAdmin, "You cannot delete yourself.")
		}
		if u.Role == model.RoleAdmin && adminCount(st) <= 1 {
			return apierr.Conflict(apierr.CodeLastAdmin, "This is the last admin.")
		}
		delete(st.Users, id)
		for k, c := range st.Credentials {
			if c.UserID == id {
				delete(st.Credentials, k)
			}
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Audit.Record(r.Context(), "user.delete", audit.Success, "user:"+id, nil)
	s.EndUserAccess(r.Context(), id, "user_deleted")
	w.WriteHeader(http.StatusNoContent)
}

// ---- settings ----------------------------------------------------------------------

type settingsView struct {
	model.Settings
	ETag string `json:"etag"`
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.SettingsRead) {
		return
	}
	var st model.Settings
	s.Store.View(func(x *model.State) { st = x.Settings })
	w.Header().Set("ETag", st.ETag())
	writeJSON(w, http.StatusOK, settingsView{Settings: st, ETag: st.ETag()}, nil)
}

type settingsPatch struct {
	PublicURL              *string             `json:"public_url"`
	SSHPublicHost          *string             `json:"ssh_public_host"`
	SSHPublicPort          *int                `json:"ssh_public_port"`
	EnrollmentTTLMinutes   *int                `json:"enrollment_ttl_minutes"`
	ConnectTokenTTLSeconds *int                `json:"connect_token_ttl_seconds"`
	RecordingEnabled       *bool               `json:"recording_enabled"`
	RecordingRetentionDays *int                `json:"recording_retention_days"`
	LogLevel               *string             `json:"log_level"`
	SessionIdleMinutes     *int                `json:"session_idle_minutes"`
	SessionAbsoluteHours   *int                `json:"session_absolute_hours"`
	RolesClaim             *string             `json:"roles_claim"`
	RolesMap               *map[string]*string `json:"roles_map"` // merge patch: null deletes a key
	DefaultGroupID         *string             `json:"default_group_id"`
	VNCEnabled             *bool               `json:"vnc_enabled"`
	ClientLogsEnabled      *bool               `json:"client_logs_enabled"`
	AuditRetentionDays     *int                `json:"audit_retention_days"`
	SessionRetentionDays   *int                `json:"session_retention_days"`
	// Read-only fields the UI may echo back; accepted and ignored.
	ID        *string `json:"id"`
	ETag      *string `json:"etag"`
	Version   *int    `json:"version"`
	CreatedAt *string `json:"created_at"`
	UpdatedAt *string `json:"updated_at"`
}

func (p settingsPatch) validate(allowHTTP bool) error {
	var v validate.Collector
	if p.PublicURL != nil {
		v.PublicURL("/public_url", *p.PublicURL, allowHTTP) // substituted into bootstrap scripts: strict allow-list
	}
	if p.SSHPublicHost != nil {
		v.Required("/ssh_public_host", *p.SSHPublicHost)
		v.Hostname("/ssh_public_host", *p.SSHPublicHost)
	}
	rng := func(ptr string, x *int, lo, hi int) {
		if x != nil {
			v.Range(ptr, *x, lo, hi)
		}
	}
	rng("/ssh_public_port", p.SSHPublicPort, 1, 65535)
	rng("/enrollment_ttl_minutes", p.EnrollmentTTLMinutes, 5, 1440)
	rng("/connect_token_ttl_seconds", p.ConnectTokenTTLSeconds, 15, 600)
	rng("/recording_retention_days", p.RecordingRetentionDays, 1, 3650)
	rng("/session_idle_minutes", p.SessionIdleMinutes, 5, 1440)
	rng("/session_absolute_hours", p.SessionAbsoluteHours, 1, 168)
	rng("/audit_retention_days", p.AuditRetentionDays, 30, 3650)
	rng("/session_retention_days", p.SessionRetentionDays, 7, 3650)
	if p.LogLevel != nil {
		v.OneOf("/log_level", *p.LogLevel, "DEBUG", "INFO", "WARN", "ERROR")
	}
	if p.RolesClaim != nil {
		v.MaxLen("/roles_claim", *p.RolesClaim, 64)
	}
	if p.RolesMap != nil {
		if len(*p.RolesMap) > 100 {
			v.Add("/roles_map", "TOO_MANY", "Use at most 100 mappings.")
		}
		for k, role := range *p.RolesMap {
			if k == "" || len(k) > 256 {
				v.Add("/roles_map", "INVALID_KEY", "Group names must be 1–256 characters.")
			}
			if role != nil {
				v.Required("/roles_map/"+k, *role)
				v.OneOf("/roles_map/"+k, *role, model.RoleAdmin, model.RoleOperator, model.RoleViewer)
			}
		}
	}
	if p.DefaultGroupID != nil {
		v.ID("/default_group_id", *p.DefaultGroupID, "grp")
	}
	return v.Err()
}

func (s *Server) patchSettings(w http.ResponseWriter, r *http.Request) {
	if !s.can(w, r, authz.SettingsWrite) {
		return
	}
	etag, err := ifMatch(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var p settingsPatch
	if err := decode(r, &p); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := p.validate(s.AllowHTTPPublicURL); err != nil {
		s.fail(w, r, err)
		return
	}
	var out model.Settings
	var changed []string
	err = s.Store.Update(func(st *model.State) error {
		x := &st.Settings
		if x.ETag() != etag {
			return apierr.Precondition()
		}
		if p.DefaultGroupID != nil && *p.DefaultGroupID != "" {
			if _, ok := st.Groups[*p.DefaultGroupID]; !ok {
				return apierr.BadRequest(apierr.CodeGroupNotFound, "That group does not exist.")
			}
		}
		set := func(name string, apply func()) { apply(); changed = append(changed, name) }
		if p.PublicURL != nil {
			set("public_url", func() { x.PublicURL = strings.TrimRight(*p.PublicURL, "/") })
		}
		if p.SSHPublicHost != nil {
			set("ssh_public_host", func() { x.SSHPublicHost = *p.SSHPublicHost })
		}
		if p.SSHPublicPort != nil {
			set("ssh_public_port", func() { x.SSHPublicPort = *p.SSHPublicPort })
		}
		if p.EnrollmentTTLMinutes != nil {
			set("enrollment_ttl_minutes", func() { x.EnrollmentTTLMinutes = *p.EnrollmentTTLMinutes })
		}
		if p.ConnectTokenTTLSeconds != nil {
			set("connect_token_ttl_seconds", func() { x.ConnectTokenTTLSeconds = *p.ConnectTokenTTLSeconds })
		}
		if p.RecordingEnabled != nil {
			set("recording_enabled", func() { x.RecordingEnabled = *p.RecordingEnabled })
		}
		if p.RecordingRetentionDays != nil {
			set("recording_retention_days", func() { x.RecordingRetentionDays = *p.RecordingRetentionDays })
		}
		if p.LogLevel != nil {
			set("log_level", func() { x.LogLevel = *p.LogLevel })
		}
		if p.SessionIdleMinutes != nil {
			set("session_idle_minutes", func() { x.SessionIdleMinutes = *p.SessionIdleMinutes })
		}
		if p.SessionAbsoluteHours != nil {
			set("session_absolute_hours", func() { x.SessionAbsoluteHours = *p.SessionAbsoluteHours })
		}
		if p.RolesClaim != nil {
			set("roles_claim", func() { x.RolesClaim = *p.RolesClaim })
		}
		if p.RolesMap != nil {
			set("roles_map", func() {
				if x.RolesMap == nil {
					x.RolesMap = map[string]string{}
				}
				for k, role := range *p.RolesMap {
					if role == nil {
						delete(x.RolesMap, k)
					} else {
						x.RolesMap[k] = *role
					}
				}
			})
		}
		if p.DefaultGroupID != nil {
			set("default_group_id", func() { x.DefaultGroupID = *p.DefaultGroupID })
		}
		if p.VNCEnabled != nil {
			set("vnc_enabled", func() { x.VNCEnabled = *p.VNCEnabled })
		}
		if p.ClientLogsEnabled != nil {
			set("client_logs_enabled", func() { x.ClientLogsEnabled = *p.ClientLogsEnabled })
		}
		if p.AuditRetentionDays != nil {
			set("audit_retention_days", func() { x.AuditRetentionDays = *p.AuditRetentionDays })
		}
		if p.SessionRetentionDays != nil {
			set("session_retention_days", func() { x.SessionRetentionDays = *p.SessionRetentionDays })
		}
		x.Touch(time.Now().UTC())
		out = *x
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p.LogLevel != nil {
		logx.SetLevel(*p.LogLevel)
	}
	s.Audit.Record(r.Context(), "settings.update", audit.Success, "settings", map[string]any{"fields": strings.Join(changed, ",")})
	w.Header().Set("ETag", out.ETag())
	writeJSON(w, http.StatusOK, settingsView{Settings: out, ETag: out.ETag()}, nil)
}

// nonNil turns a nil slice into an empty one so JSON says [] not null.
func nonNil[T any](xs []T) []T {
	if xs == nil {
		return []T{}
	}
	return xs
}

// sameSet reports whether a and b hold the same IDs, ignoring order and repeats.
func sameSet(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range a {
		in[x] = true
	}
	seen := map[string]bool{}
	for _, x := range b {
		if !in[x] {
			return false
		}
		seen[x] = true
	}
	return len(seen) == len(in)
}
