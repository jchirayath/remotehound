package integration

// @kind:integration
// @feature:sessions @feature:users

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/core/authz"
)

// liveSessionAs opens a Connect as u and plays guacd: it dials the tunnel
// listener so the session becomes live. Returns the session ID and the conn.
func liveSessionAs(t *testing.T, u *harness, devID string) (string, net.Conn) {
	t.Helper()
	var conn struct{ Data struct{ URL string } }
	u.do("POST", "/api/v1/devices/"+devID+"/connect", map[string]any{"service": "ssh"}, 200, &conn)
	var params map[string]string
	for _, c := range openBlob(t, u, conn.Data.URL).Connections {
		params = c.Parameters
	}
	g, err := net.Dial("tcp", net.JoinHostPort(params["hostname"], params["port"]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close() })
	io.ReadFull(g, make([]byte, 7)) //nolint:errcheck // banner
	var list struct {
		Data []struct {
			ID string `json:"id"`
		}
	}
	for i := 0; i < 200 && len(list.Data) == 0; i++ {
		u.do("GET", "/api/v1/sessions?scope=mine&active=true", nil, 200, &list)
		time.Sleep(10 * time.Millisecond)
	}
	if len(list.Data) != 1 {
		t.Fatalf("no live session: %+v", list.Data)
	}
	return list.Data[0].ID, g
}

// closedSoon reports whether the peer closed g within 3 s.
func closedSoon(g net.Conn) bool {
	g.SetReadDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	_, err := io.ReadAll(g)                            // nil at EOF; a timeout means it stayed open
	return err == nil
}

type accessFixture struct {
	h     *harness
	grp   string
	devID string
	uid   string
	op    *harness
}

func newAccessFixture(t *testing.T) accessFixture {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Ops"}, 201, &grp)
	devID := enrolOnline(t, h, grp.Data.ID)
	var u struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "owner@example.com", "role": "operator", "group_ids": []string{grp.Data.ID}}, 201, &u)
	return accessFixture{h: h, grp: grp.Data.ID, devID: devID, uid: u.Data.ID, op: h.as(u.Data.ID)}
}

func (f accessFixture) patchUser(t *testing.T, body map[string]any) {
	t.Helper()
	var cur struct {
		Data struct {
			ETag string `json:"etag"`
		}
	}
	f.h.do("GET", "/api/v1/users/"+f.uid, nil, 200, &cur)
	f.h.do("PATCH", "/api/v1/users/"+f.uid, body, 200, nil, "If-Match", cur.Data.ETag)
}

func auditHas(t *testing.T, h *harness, event, outcome string) bool {
	var aud struct {
		Data []struct{ Event, Outcome string }
	}
	h.do("GET", "/api/v1/audit?page_size=200", nil, 200, &aud)
	for _, e := range aud.Data {
		if e.Event == event && e.Outcome == outcome {
			return true
		}
	}
	return false
}

// S1: demoting the owner ends their live session, and the owner can no longer
// rejoin with control (Join checks device.connect for the owner too).
func TestDemotedOwnerCannotRejoinWithControl(t *testing.T) {
	f := newAccessFixture(t)
	sid, g := liveSessionAs(t, f.op, f.devID)

	// The Join gate on its own (as if termination had not happened yet): the
	// owner's actor is now a viewer → refused, never a control token.
	demoted := &authz.Actor{UserID: f.uid, Email: "owner@example.com", Role: "viewer", GroupIDs: []string{f.grp}}
	if _, err := f.h.app.Devices.Join(context.Background(), demoted, sid); err == nil {
		t.Fatal("a viewer-role owner got a join token")
	}
	removed := &authz.Actor{UserID: f.uid, Email: "owner@example.com", Role: "operator"}
	if _, err := f.h.app.Devices.Join(context.Background(), removed, sid); err == nil {
		t.Fatal("an owner outside the device's group got a join token")
	}

	f.patchUser(t, map[string]any{"role": "viewer"})
	if !closedSoon(g) {
		t.Fatal("demoted owner's live session was not terminated")
	}
	v := f.h.asGen(f.uid, 1)
	var out struct{ Code string }
	v.do("POST", "/api/v1/sessions/"+sid+"/join", nil, 403, &out)
	if !auditHas(t, f.h, "user.sessions_ended", "success") {
		t.Error("audit lacks user.sessions_ended")
	}
}

// S1: disabling a user terminates their live session.
func TestDisabledUsersLiveSessionIsTerminated(t *testing.T) {
	f := newAccessFixture(t)
	_, g := liveSessionAs(t, f.op, f.devID)
	f.patchUser(t, map[string]any{"disabled": true})
	if !closedSoon(g) {
		t.Fatal("disabled user's live session was not terminated")
	}
}

// S1: removing a user from the device's group ends their session and they
// cannot rejoin (404: the device is no longer theirs to see).
func TestUserRemovedFromGroupLosesSession(t *testing.T) {
	f := newAccessFixture(t)
	sid, g := liveSessionAs(t, f.op, f.devID)
	f.patchUser(t, map[string]any{"group_ids": []string{}})
	if !closedSoon(g) {
		t.Fatal("session survived removal from the device's group")
	}
	f.h.asGen(f.uid, 1).do("POST", "/api/v1/sessions/"+sid+"/join", nil, 404, nil)
}

// S1: deleting a user ends their live session.
func TestDeletedUsersLiveSessionIsTerminated(t *testing.T) {
	f := newAccessFixture(t)
	_, g := liveSessionAs(t, f.op, f.devID)
	f.h.do("DELETE", "/api/v1/users/"+f.uid, nil, 204, nil)
	if !closedSoon(g) {
		t.Fatal("deleted user's live session was not terminated")
	}
}

// L5: a session can be shared only with someone who may see its device (a
// member of the device's group) or an admin.
func TestShareRecipientMustBeInTheDevicesGroup(t *testing.T) {
	f := newAccessFixture(t)
	sid, _ := liveSessionAs(t, f.op, f.devID)
	var other struct{ Data struct{ ID string } }
	f.h.do("POST", "/api/v1/groups", map[string]any{"name": "Elsewhere"}, 201, &other)
	var outsider, admin2 struct{ Data struct{ ID string } }
	f.h.do("POST", "/api/v1/users", map[string]any{"email": "out@example.com", "role": "operator", "group_ids": []string{other.Data.ID}}, 201, &outsider)
	f.h.do("POST", "/api/v1/users", map[string]any{"email": "admin2@example.com", "role": "admin"}, 201, &admin2)
	var prob struct{ Errors []struct{ Code string } }
	f.op.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": outsider.Data.ID, "mode": "view"}, 400, &prob)
	f.h.as(outsider.Data.ID).do("POST", "/api/v1/sessions/"+sid+"/join", nil, 404, nil)
	f.op.do("POST", "/api/v1/sessions/"+sid+"/shares", map[string]any{"user_id": admin2.Data.ID, "mode": "view"}, 200, nil)
	if !auditHas(t, f.h, "session.share", "failure") && !auditHas(t, f.h, "session.share", "denied") {
		t.Error("refused share not audited")
	}
}
