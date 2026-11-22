package authz

// @feature:users

import (
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/model"
)

func TestDenyByDefault(t *testing.T) {
	if Can(nil, DeviceRead, Any) || Can(&Actor{}, DeviceRead, Any) {
		t.Fatal("anonymous allowed")
	}
	if Can(&Actor{UserID: "u", Role: "superuser"}, DeviceRead, Any) {
		t.Fatal("unknown role allowed")
	}
}

func TestRoleGrants(t *testing.T) {
	viewer := &Actor{UserID: "v", Role: model.RoleViewer, GroupIDs: []string{"grp_a"}}
	op := &Actor{UserID: "o", Role: model.RoleOperator, GroupIDs: []string{"grp_a"}}
	admin := &Actor{UserID: "a", Role: model.RoleAdmin}
	inA := Resource{GroupID: "grp_a"}
	if Can(viewer, DeviceConnect, inA) {
		t.Error("viewer can connect")
	}
	if !Can(op, DeviceConnect, inA) {
		t.Error("operator cannot connect in own group")
	}
	if Can(op, SettingsWrite, Any) || Can(op, UserWrite, Any) || Can(op, DeviceDelete, inA) {
		t.Error("operator has admin powers")
	}
	if !Can(admin, SettingsWrite, Any) || !Can(admin, DeviceConnect, Resource{GroupID: "grp_z"}) {
		t.Error("admin restricted")
	}
}

// TEST-2: the denied path for another group's device (IDOR).
func TestGroupScopingDeniesOtherGroups(t *testing.T) {
	op := &Actor{UserID: "o", Role: model.RoleOperator, GroupIDs: []string{"grp_a"}}
	if Can(op, DeviceConnect, Resource{GroupID: "grp_b"}) || Can(op, DeviceRead, Resource{GroupID: ""}) {
		t.Fatal("operator reached a device outside their groups")
	}
	if SeesGroup(op, "grp_b") || !SeesGroup(op, "grp_a") {
		t.Fatal("list scoping wrong")
	}
}

func TestPermissionsListMatchesGrants(t *testing.T) {
	p := Permissions(&Actor{UserID: "v", Role: model.RoleViewer})
	for _, x := range p {
		if x == DeviceConnect || x == SettingsWrite {
			t.Fatalf("viewer permissions include %s", x)
		}
	}
	if len(Permissions(nil)) != 0 {
		t.Fatal("anonymous has permissions")
	}
}

// @feature:sessions — joining is ownership + share only; admins see and end, never join.
func TestSessionRules(t *testing.T) {
	now := time.Now()
	owner := &Actor{UserID: "usr_owner", Role: model.RoleOperator, GroupIDs: []string{"grp_a"}}
	guest := &Actor{UserID: "usr_guest", Role: model.RoleViewer}
	other := &Actor{UserID: "usr_other", Role: model.RoleOperator}
	admin := &Actor{UserID: "usr_admin", Role: model.RoleAdmin}
	s := &model.Session{UserID: "usr_owner"}
	if !CanJoinSession(owner, s, "grp_a", now) || CanJoinSession(guest, s, "grp_a", now) || CanJoinSession(admin, s, "grp_a", now) || CanJoinSession(other, s, "grp_a", now) {
		t.Fatal("join rules wrong before sharing")
	}
	s.Shares = []model.Share{{UserID: "usr_guest", Mode: model.ShareView, ExpiresAt: now.Add(time.Hour)}}
	if !CanJoinSession(guest, s, "grp_a", now) || CanJoinSession(admin, s, "grp_a", now) {
		t.Fatal("join rules wrong after sharing")
	}
	if CanJoinSession(guest, s, "grp_a", now.Add(2*time.Hour)) {
		t.Fatal("expired share still joins")
	}
	demoted := &Actor{UserID: "usr_owner", Role: model.RoleViewer, GroupIDs: []string{"grp_a"}}
	if CanJoinSession(demoted, s, "grp_a", now) || CanJoinSession(owner, s, "grp_b", now) || CanJoinSession(owner, s, "", now) {
		t.Fatal("owner rejoins without device.connect on the device")
	}
	if !CanSeeSession(admin, s, now) || CanSeeSession(other, s, now) {
		t.Fatal("visibility wrong")
	}
	if !CanEndSession(admin, s) || !CanEndSession(owner, s) || CanEndSession(guest, s) || CanEndSession(other, s) {
		t.Fatal("end rules wrong")
	}
	if CanShareSession(admin, s) || !CanShareSession(owner, s) {
		t.Fatal("only the owner shares")
	}
	s.EndedAt = now
	if CanJoinSession(owner, s, "grp_a", now) || CanShareSession(owner, s) {
		t.Fatal("ended session joinable/shareable")
	}
}
