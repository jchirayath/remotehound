package device

import (
	"context"
	"sort"
	"time"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/guac"
	"github.com/jchirayath/remotehound/internal/model"
)

// SessionView is a session as the caller may see it. The can_* flags are
// computed by the same authz rules the server enforces (UI gating only).
type SessionView struct {
	ID            string      `json:"id"`
	DeviceID      string      `json:"device_id"`
	DeviceName    string      `json:"device_name"`
	DeviceDeleted bool        `json:"device_deleted,omitempty"`
	Service       string      `json:"service"`
	UserID        string      `json:"user_id"`
	UserEmail     string      `json:"user_email"`
	StartedAt     time.Time   `json:"started_at"`
	EndedAt       *time.Time  `json:"ended_at"`
	Active        bool        `json:"active"`
	BytesIn       int64       `json:"bytes_in"`
	BytesOut      int64       `json:"bytes_out"`
	Recording     string      `json:"recording"`
	Mine          bool        `json:"mine"`
	Shares        []ShareView `json:"shares"`
	MyShare       *ShareView  `json:"my_share"`
	CanJoin       bool        `json:"can_join"`
	CanShare      bool        `json:"can_share"`
	CanTerminate  bool        `json:"can_terminate"`
}

// ShareView is a grant with the grantee's email.
type ShareView struct {
	UserID    string    `json:"user_id"`
	UserEmail string    `json:"user_email"`
	Mode      string    `json:"mode"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionFilter for ListSessions.
type SessionFilter struct {
	DeviceID  string
	Active    *bool
	Scope     string // "" = everything visible, "mine", "shared"
	PageSize  int
	PageToken string
}

func toSessionView(a *authz.Actor, ss *model.Session, st *model.State, now time.Time) SessionView {
	devGroup := ""
	if d := st.Devices[ss.DeviceID]; d != nil {
		devGroup = d.GroupID
	}
	v := SessionView{ID: ss.ID, DeviceID: ss.DeviceID, DeviceName: "(deleted device)", Service: ss.Service, UserID: ss.UserID,
		StartedAt: ss.StartedAt, Active: ss.EndedAt.IsZero(), BytesIn: ss.BytesIn, BytesOut: ss.BytesOut, Recording: ss.Recording,
		Mine: ss.UserID == a.UserID, Shares: []ShareView{},
		CanJoin: authz.CanJoinSession(a, ss, devGroup, now) && ss.GuacConnID != "", CanShare: authz.CanShareSession(a, ss), CanTerminate: authz.CanEndSession(a, ss) && ss.EndedAt.IsZero()}
	if d := st.Devices[ss.DeviceID]; d != nil {
		v.DeviceName = d.Name
	} else {
		v.DeviceDeleted = true
		// Keep the name people knew it by: the enrolment that created it remembers it.
		for _, e := range st.Enrollments {
			if e.DeviceID == ss.DeviceID && e.Name != "" {
				v.DeviceName = e.Name + " (deleted device)"
				break
			}
		}
	}
	if u := st.Users[ss.UserID]; u != nil {
		v.UserEmail = u.Email
	}
	if !ss.EndedAt.IsZero() {
		t := ss.EndedAt
		v.EndedAt = &t
	}
	for _, sh := range ss.Shares {
		if !now.Before(sh.ExpiresAt) {
			continue
		}
		sv := ShareView{UserID: sh.UserID, Mode: sh.Mode, ExpiresAt: sh.ExpiresAt}
		if u := st.Users[sh.UserID]; u != nil {
			sv.UserEmail = u.Email
		}
		// Only the owner and admins see the whole share list; a grantee sees their own grant.
		if v.Mine || a.IsAdmin() {
			v.Shares = append(v.Shares, sv)
		}
		if sh.UserID == a.UserID {
			cp := sv
			v.MyShare = &cp
		}
	}
	return v
}

// ListSessions returns the sessions the actor may see: their own, those shared
// with them, and (admins) every session's metadata.
func (s *Service) ListSessions(a *authz.Actor, f SessionFilter) ([]SessionView, string, int) {
	now := time.Now().UTC()
	var all []SessionView
	s.Store.View(func(st *model.State) {
		for _, ss := range st.Sessions {
			if !authz.CanSeeSession(a, ss, now) || (f.DeviceID != "" && ss.DeviceID != f.DeviceID) {
				continue
			}
			active := ss.EndedAt.IsZero()
			if f.Active != nil && *f.Active != active {
				continue
			}
			switch f.Scope {
			case "mine":
				if ss.UserID != a.UserID {
					continue
				}
			case "shared":
				if ss.ActiveShare(a.UserID, now) == nil {
					continue
				}
			}
			all = append(all, toSessionView(a, ss, st, now))
		}
	})
	sort.Slice(all, func(i, j int) bool { return all[i].StartedAt.After(all[j].StartedAt) })
	order := make([]string, len(all))
	byID := map[string]SessionView{}
	for i, v := range all {
		order[i], byID[v.ID] = v.ID, v
	}
	page, next := store.Page(order, f.PageSize, f.PageToken)
	out := make([]SessionView, len(page))
	for i, id := range page {
		out[i] = byID[id]
	}
	return out, next, len(all)
}

func (s *Service) sessionNotFound() error {
	return apierr.NotFound(apierr.CodeSessionNotFound, "No session with that ID (or you cannot see it).")
}

// Share lets the owner grant another user view or control of a live session.
func (s *Service) Share(ctx context.Context, a *authz.Actor, sessionID, userID, mode string, ttl time.Duration) (SessionView, error) {
	now := time.Now().UTC()
	var out SessionView
	err := s.Store.Update(func(st *model.State) error {
		ss, ok := st.Sessions[sessionID]
		if !ok || !authz.CanSeeSession(a, ss, now) {
			return s.sessionNotFound()
		}
		if !authz.CanShareSession(a, ss) {
			return apierr.Forbidden("Only the person who opened a live session can share it.")
		}
		if userID == a.UserID {
			return apierr.Validation([]apierr.FieldError{{Pointer: "/user_id", Code: "SELF", Detail: "You already own this session."}})
		}
		u, ok := st.Users[userID]
		if !ok || u.Disabled {
			return apierr.Validation([]apierr.FieldError{{Pointer: "/user_id", Code: "NOT_FOUND", Detail: "Pick an active user."}})
		}
		// Only someone who may see the device: a member of its group, or an
		// admin. (A non-admin owner's devices are in their own groups, so this
		// is at least as strict as "shares a group with the owner".)
		groupID := ""
		if d := st.Devices[ss.DeviceID]; d != nil {
			groupID = d.GroupID
		}
		if !authz.SeesGroup(&authz.Actor{UserID: u.ID, Role: u.Role, GroupIDs: u.GroupIDs}, groupID) {
			return apierr.Validation([]apierr.FieldError{{Pointer: "/user_id", Code: "NO_ACCESS", Detail: "Pick someone in this device's group (or an admin)."}})
		}
		if mode == model.ShareControl && u.Role == model.RoleViewer {
			return apierr.Validation([]apierr.FieldError{{Pointer: "/mode", Code: "ROLE", Detail: "Viewers can only be given view access."}})
		}
		kept := ss.Shares[:0]
		for _, sh := range ss.Shares {
			if sh.UserID != userID && now.Before(sh.ExpiresAt) {
				kept = append(kept, sh)
			}
		}
		ss.Shares = append(kept, model.Share{UserID: userID, Mode: mode, CreatedAt: now, ExpiresAt: now.Add(ttl)})
		ss.Touch(now)
		out = toSessionView(a, ss, st, now)
		return nil
	})
	attrs := map[string]any{"grantee": userID, "mode": mode, "ttl_minutes": int(ttl.Minutes())}
	if err != nil {
		s.Audit.Record(ctx, "session.share", outcomeOf(err), "session:"+sessionID, attrs)
		return SessionView{}, err
	}
	s.Audit.Record(ctx, "session.share", audit.Success, "session:"+sessionID, attrs)
	return out, nil
}

// Unshare removes a grant (owner or admin).
func (s *Service) Unshare(ctx context.Context, a *authz.Actor, sessionID, userID string) (SessionView, error) {
	now := time.Now().UTC()
	var out SessionView
	err := s.Store.Update(func(st *model.State) error {
		ss, ok := st.Sessions[sessionID]
		if !ok || !authz.CanSeeSession(a, ss, now) {
			return s.sessionNotFound()
		}
		if ss.UserID != a.UserID && !a.IsAdmin() {
			return apierr.Forbidden("Only the session owner or an admin can remove access.")
		}
		kept := ss.Shares[:0]
		for _, sh := range ss.Shares {
			if sh.UserID != userID {
				kept = append(kept, sh)
			}
		}
		ss.Shares = kept
		ss.Touch(now)
		out = toSessionView(a, ss, st, now)
		return nil
	})
	if err == nil {
		s.Audit.Record(ctx, "session.unshare", audit.Success, "session:"+sessionID, map[string]any{"grantee": userID})
	}
	return out, err
}

// Join mints a token that joins the owner's live Guacamole connection — for
// the owner (rejoin) or a user with a live share. No role can bypass this.
func (s *Service) Join(ctx context.Context, a *authz.Actor, sessionID string) (ConnectResult, error) {
	now := time.Now().UTC()
	var ss model.Session
	var devName, devGroup string
	var ttlSec int
	found := false
	s.Store.View(func(st *model.State) {
		if x, ok := st.Sessions[sessionID]; ok && authz.CanSeeSession(a, x, now) {
			ss, found = *x, true
			ss.Shares = append([]model.Share{}, x.Shares...)
			if d := st.Devices[x.DeviceID]; d != nil {
				devName, devGroup = d.Name, d.GroupID
			}
		}
		ttlSec = st.Settings.ConnectTokenTTLSeconds
	})
	if !found {
		return ConnectResult{}, s.sessionNotFound()
	}
	if ss.UserID == a.UserID && !authz.Can(a, authz.DeviceConnect, authz.Resource{GroupID: devGroup}) {
		// The owner's rights changed since they opened it (demoted, removed from
		// the device's group, device deleted): rejoining would restore control.
		s.Audit.Record(ctx, "session.join", audit.Denied, "session:"+sessionID, map[string]any{"reason": "no_device_access"})
		if !authz.Can(a, authz.DeviceRead, authz.Resource{GroupID: devGroup}) {
			return ConnectResult{}, s.sessionNotFound()
		}
		return ConnectResult{}, apierr.Forbidden("Your role no longer lets you connect to this device, so you cannot rejoin this session.")
	}
	if !authz.CanJoinSession(a, &ss, devGroup, now) {
		s.Audit.Record(ctx, "session.join", audit.Denied, "session:"+sessionID, nil)
		return ConnectResult{}, apierr.Forbidden("Only the session owner, or someone they shared it with, can join it.")
	}
	if ss.GuacConnID == "" {
		return ConnectResult{}, apierr.Conflict(apierr.CodeSessionNotFound, "This session cannot be joined (it was opened before sharing was available).")
	}
	params := map[string]string{}
	mode := "owner"
	if ss.UserID != a.UserID {
		mode = ss.ActiveShare(a.UserID, now).Mode
		// Re-check the grantee's CURRENT role: a user demoted to viewer after
		// receiving a control share must only watch.
		if mode == model.ShareView || a.Role == model.RoleViewer {
			mode = model.ShareView
			params["read-only"] = "true"
		}
	}
	ttl := time.Duration(ttlSec) * time.Second
	name := ConnectionName(devName, ss.Service) + " (shared)"
	sealed, err := guac.Seal(s.Secrets.GuacJSONKey.Bytes(), guac.AuthData{Username: a.Email, Expires: guac.Expiry(now, ttl),
		Connections: map[string]guac.Connection{name: {Join: ss.GuacConnID, Parameters: params}}})
	if err != nil {
		return ConnectResult{}, apierr.Internal(err)
	}
	s.Audit.Record(ctx, "session.join", audit.Success, "session:"+sessionID, map[string]any{"mode": mode, "owner": ss.UserID})
	return ConnectResult{URL: guac.ConnectURL(s.GuacPublicPath, name, sealed), ExpiresAt: now.Add(ttl), ConnectionName: name}, nil
}

// Terminate ends a live session at the tunnel (owner or admin).
func (s *Service) Terminate(ctx context.Context, a *authz.Actor, sessionID string) error {
	now := time.Now().UTC()
	var ss *model.Session
	s.Store.View(func(st *model.State) {
		if x, ok := st.Sessions[sessionID]; ok && authz.CanSeeSession(a, x, now) {
			cp := *x
			ss = &cp
		}
	})
	if ss == nil {
		return s.sessionNotFound()
	}
	if !authz.CanEndSession(a, ss) {
		s.Audit.Record(ctx, "session.terminate", audit.Denied, "session:"+sessionID, nil)
		return apierr.Forbidden("Only the session owner or an admin can end it.")
	}
	if !s.Tunnel.TerminateSession(sessionID) {
		return apierr.Conflict(apierr.CodeSessionNotFound, "That session has already ended.")
	}
	s.Audit.Record(ctx, "session.terminate", audit.Success, "session:"+sessionID, map[string]any{"owner": ss.UserID, "by_admin": ss.UserID != a.UserID})
	return nil
}
