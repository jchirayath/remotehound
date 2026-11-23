// CRUD round trips for the admin resources the journey test only touches in
// passing, each with its denied path and an exact audit count: every state
// change records exactly one audit event (CLAUDE.md "Audit"), never zero and
// never two.
//
// @kind:integration
// @feature:groups @feature:users @feature:debug @feature:audit @feature:sessions @feature:help
package integration

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// auditCount is how many audit events named event exist for resource.
func auditCount(h *harness, event, resource string) int {
	h.t.Helper()
	var aud struct {
		Data []struct{ Event, Resource string }
	}
	h.do("GET", "/api/v1/audit?page_size=500&event="+event, nil, 200, &aud)
	n := 0
	for _, e := range aud.Data {
		if e.Event == event && e.Resource == resource {
			n++
		}
	}
	return n
}

func wantAudit(t *testing.T, h *harness, event, resource string, want int) {
	t.Helper()
	if got := auditCount(h, event, resource); got != want {
		t.Errorf("audit %s %s: %d events, want %d", event, resource, got, want)
	}
}

type etagged struct {
	Data struct {
		ID          string `json:"id"`
		ETag        string `json:"etag"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Color       string `json:"color"`
		Role        string `json:"role"`
		Disabled    bool   `json:"disabled"`
		DisplayName string `json:"display_name"`
	} `json:"data"`
}

func TestGroupCRUDAuditsEachChangeOnce(t *testing.T) {
	h := start(t)
	var g etagged
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Lab", "color": "teal"}, 201, &g)
	id := g.Data.ID
	res := "group:" + id

	h.do("GET", "/api/v1/groups/"+id, nil, 200, &g)
	stale := g.Data.ETag
	h.do("PATCH", "/api/v1/groups/"+id, map[string]any{"name": "Lab 2"}, 428, nil) // no If-Match
	h.do("PATCH", "/api/v1/groups/"+id, map[string]any{"name": "Lab 2", "description": "Bench", "color": "rose"}, 200, &g, "If-Match", stale)
	if g.Data.Name != "Lab 2" || g.Data.Description != "Bench" || g.Data.Color != "rose" {
		t.Fatalf("patch not applied: %+v", g.Data)
	}
	h.do("PATCH", "/api/v1/groups/"+id, map[string]any{"name": "Lost update"}, 412, nil, "If-Match", stale)
	h.do("PATCH", "/api/v1/groups/"+id, map[string]any{"name": ""}, 400, nil, "If-Match", g.Data.ETag)
	h.do("PATCH", "/api/v1/groups/"+id, map[string]any{"color": "#ff0000"}, 400, nil, "If-Match", g.Data.ETag) // tokens only

	// Denied: an operator in the group can read it but not change or delete it.
	var op struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator", "group_ids": []string{id}}, 201, &op)
	opH := h.as(op.Data.ID)
	opH.do("PATCH", "/api/v1/groups/"+id, map[string]any{"name": "Mine now"}, 403, nil, "If-Match", g.Data.ETag)
	opH.do("DELETE", "/api/v1/groups/"+id, nil, 403, nil)
	opH.do("POST", "/api/v1/groups", map[string]any{"name": "Shadow"}, 403, nil)

	h.do("GET", "/api/v1/groups/"+id, nil, 200, &g)
	if g.Data.Name != "Lab 2" {
		t.Fatalf("denied or failed patches changed the group: %+v", g.Data)
	}
	h.do("DELETE", "/api/v1/groups/"+id, nil, 204, nil)
	h.do("GET", "/api/v1/groups/"+id, nil, 404, nil)
	h.do("DELETE", "/api/v1/groups/"+id, nil, 404, nil)

	// One event per successful change; refused requests change nothing and add no success event.
	wantAudit(t, h, "group.create", res, 1)
	wantAudit(t, h, "group.update", res, 1)
	wantAudit(t, h, "group.delete", res, 1)
}

func TestUserCRUDAuditsEachChangeOnce(t *testing.T) {
	h := start(t)
	var grp struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/groups", map[string]any{"name": "Support"}, 201, &grp)
	var u etagged
	h.do("POST", "/api/v1/users", map[string]any{"email": "sam@example.com", "role": "viewer"}, 201, &u)
	id := u.Data.ID
	res := "user:" + id
	h.do("POST", "/api/v1/users", map[string]any{"email": "sam@example.com", "role": "viewer"}, 409, nil) // duplicate
	h.do("POST", "/api/v1/users", map[string]any{"email": "not-an-email", "role": "viewer"}, 400, nil)
	h.do("POST", "/api/v1/users", map[string]any{"email": "x@example.com", "role": "root"}, 400, nil)

	h.do("GET", "/api/v1/users/"+id, nil, 200, &u)
	h.do("PATCH", "/api/v1/users/"+id, map[string]any{"display_name": "Sam", "role": "operator", "group_ids": []string{grp.Data.ID}, "disabled": true}, 200, &u, "If-Match", u.Data.ETag)
	if u.Data.Role != "operator" || !u.Data.Disabled || u.Data.DisplayName != "Sam" {
		t.Fatalf("patch not applied: %+v", u.Data)
	}
	// A blocked user cannot use the API even with a session cookie minted the way login does.
	rec := httptest.NewRecorder()
	h.app.API.Auth.Sessions.Issue(rec, id, 0)
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/v1/devices", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	if resp, err := h.srv.Client().Do(req); err != nil || resp.StatusCode != 401 {
		t.Fatalf("blocked user's session: %v %v, want 401", err, resp)
	} else {
		resp.Body.Close()
	}

	// Denied: an operator cannot manage users.
	var op struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator", "group_ids": []string{grp.Data.ID}}, 201, &op)
	opH := h.as(op.Data.ID)
	opH.do("PATCH", "/api/v1/users/"+id, map[string]any{"role": "admin"}, 403, nil, "If-Match", u.Data.ETag)
	opH.do("DELETE", "/api/v1/users/"+id, nil, 403, nil)
	opH.do("POST", "/api/v1/users", map[string]any{"email": "eve@example.com", "role": "admin"}, 403, nil)

	h.do("DELETE", "/api/v1/users/"+id, nil, 204, nil)
	h.do("GET", "/api/v1/users/"+id, nil, 404, nil)

	wantAudit(t, h, "user.create", res, 1)
	wantAudit(t, h, "user.update", res, 1)
	wantAudit(t, h, "user.delete", res, 1)
}

func TestThemePreferencePersists(t *testing.T) {
	h := start(t)
	var me struct{ Data struct{ Theme string } }
	h.do("GET", "/api/v1/me", nil, 200, &me)
	if me.Data.Theme != "system" {
		t.Fatalf("default theme = %q", me.Data.Theme)
	}
	h.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "dark"}, 200, nil)
	h.do("GET", "/api/v1/me", nil, 200, &me)
	if me.Data.Theme != "dark" {
		t.Fatalf("theme after PUT = %q", me.Data.Theme)
	}
	h.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "neon"}, 400, nil)
	h.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "light", "role": "admin"}, 400, nil) // unknown field
	// Another user's preference is their own: a viewer's change does not touch the admin's.
	var v struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "v@example.com", "role": "viewer"}, 201, &v)
	h.as(v.Data.ID).do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "light"}, 200, nil)
	h.do("GET", "/api/v1/me", nil, 200, &me)
	if me.Data.Theme != "dark" {
		t.Fatalf("viewer's preference leaked into the admin's: %q", me.Data.Theme)
	}
	// Each change is audited once, against the user who made it; refused changes add nothing.
	wantAudit(t, h, "user.preferences", "user:"+meID(h), 1)
	wantAudit(t, h, "user.preferences", "user:"+v.Data.ID, 1)
}

func TestJobRunAndLogLevelAreAdminOnlyAndAudited(t *testing.T) {
	h := start(t)
	h.do("POST", "/api/v1/jobs/audit-verify/run", nil, 202, nil)
	h.do("POST", "/api/v1/jobs/no-such-job/run", nil, 404, nil)

	h.do("PUT", "/api/v1/debug/log-level", map[string]any{"level": "DEBUG"}, 200, nil)
	var rt struct {
		Data struct {
			LogLevel string `json:"log_level"`
		}
	}
	h.do("GET", "/api/v1/debug/runtime", nil, 200, &rt)
	if rt.Data.LogLevel != "DEBUG" {
		t.Fatalf("log level after PUT = %q", rt.Data.LogLevel)
	}
	h.do("PUT", "/api/v1/debug/log-level", map[string]any{"level": "TRACE"}, 400, nil)
	h.do("PUT", "/api/v1/debug/log-level", map[string]any{"level": "WARN"}, 200, nil)

	var op struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator"}, 201, &op)
	opH := h.as(op.Data.ID)
	opH.do("POST", "/api/v1/jobs/audit-verify/run", nil, 403, nil)
	opH.do("PUT", "/api/v1/debug/log-level", map[string]any{"level": "DEBUG"}, 403, nil)
	opH.do("GET", "/api/v1/jobs", nil, 403, nil)
	h.do("GET", "/api/v1/debug/runtime", nil, 200, &rt)
	if rt.Data.LogLevel != "WARN" {
		t.Fatalf("operator changed the log level: %q", rt.Data.LogLevel)
	}

	wantAudit(t, h, "job.run", "job:audit-verify", 1)
	wantAudit(t, h, "debug.log_level", "settings", 2) // DEBUG, then WARN; the refused ones add nothing
}

func TestRecordingsListDownloadAndConfinement(t *testing.T) {
	h := start(t)
	rec := h.app.API.RecordingsDir
	if err := os.MkdirAll(filepath.Join(rec, "dev_x"), 0o700); err != nil {
		t.Fatal(err)
	}
	want := "guac recording bytes"
	if err := os.WriteFile(filepath.Join(rec, "dev_x", "s1.guac"), []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	// A file next to (not inside) the recordings root must never be served.
	if err := os.WriteFile(filepath.Join(filepath.Dir(rec), "outside.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	var list struct{ Data []struct{ Name string } }
	h.do("GET", "/api/v1/recordings", nil, 200, &list)
	if len(list.Data) != 1 || list.Data[0].Name != "dev_x/s1.guac" {
		t.Fatalf("recordings: %+v", list.Data)
	}

	get := func(c *http.Client, path string) (int, string) {
		resp, err := c.Get(h.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get(h.client, "/api/v1/recordings/dev_x%2Fs1.guac"); code != 200 || body != want {
		t.Fatalf("download: %d %q", code, body)
	}
	for _, p := range []string{"..%2Foutside.txt", "dev_x%2F..%2F..%2Foutside.txt", "dev_x", "missing.guac"} {
		if code, body := get(h.client, "/api/v1/recordings/"+p); code != 404 || body == "secret" {
			t.Errorf("%s: %d %q, want 404", p, code, body)
		}
	}

	var op struct{ Data struct{ ID string } }
	h.do("POST", "/api/v1/users", map[string]any{"email": "op@example.com", "role": "operator"}, 201, &op)
	opH := h.as(op.Data.ID)
	opH.do("GET", "/api/v1/recordings", nil, 403, nil)
	if code, _ := get(opH.client, "/api/v1/recordings/dev_x%2Fs1.guac"); code != 403 {
		t.Errorf("operator download: %d, want 403", code)
	}
	wantAudit(t, h, "recording.download", "recording:s1.guac", 1)
}
