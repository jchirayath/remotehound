package api

import (
	"context"
	"sort"
	"time"

	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/model"
)

// EndUserAccess is called whenever a user's rights shrink or might have changed
// (role, groups, disabled, deleted, an IdP role mapping change). Bumping
// SessionGen only ends RemoteHound's cookie; a desktop already open in
// Guacamole would keep running. So, with the simplest correct rule (no
// per-device re-evaluation):
//   - every live session the user OWNS is terminated at the tunnel;
//   - every share granted TO the user on someone else's session is removed,
//     so they cannot rejoin (the owner can share again if still wanted);
//   - their Guacamole sessions are revoked, which closes any connection they
//     joined as a grantee without ending the owner's session.
//
// One audit record per call, only when something was ended or removed.
func (s *Server) EndUserAccess(ctx context.Context, userID, reason string) {
	var live []string
	granted := false
	s.Store.View(func(st *model.State) {
		for _, ss := range st.Sessions {
			if ss.UserID == userID && ss.EndedAt.IsZero() {
				live = append(live, ss.ID)
			}
			for _, sh := range ss.Shares {
				if sh.UserID == userID {
					granted = true
				}
			}
		}
	})
	sort.Strings(live)
	ended := []string{}
	for _, id := range live {
		if s.Tunnel.TerminateSession(id) {
			ended = append(ended, id)
		}
	}
	unshared := []string{}
	if granted {
		now := time.Now().UTC()
		_ = s.Store.Update(func(st *model.State) error {
			unshared = unshared[:0]
			for _, ss := range st.Sessions {
				kept := ss.Shares[:0]
				for _, sh := range ss.Shares {
					if sh.UserID != userID {
						kept = append(kept, sh)
					}
				}
				if len(kept) != len(ss.Shares) {
					ss.Shares = kept
					ss.Touch(now)
					unshared = append(unshared, ss.ID)
				}
			}
			return nil
		})
		sort.Strings(unshared)
	}
	revoked := 0
	if s.GuacSessions != nil {
		revoked = s.GuacSessions.Revoke(ctx, userID)
	}
	if len(ended) == 0 && len(unshared) == 0 && revoked == 0 {
		return
	}
	s.Audit.Record(ctx, "user.sessions_ended", audit.Success, "user:"+userID,
		map[string]any{"reason": reason, "sessions": ended, "shares_removed": unshared, "guacamole_sessions": revoked})
}
