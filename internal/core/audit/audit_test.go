package audit

// @feature:audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jchirayath/remotehound/internal/core/authz"
)

func TestRecordChainsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := authz.WithActor(context.Background(), &authz.Actor{UserID: "usr_1", Email: "a@x", Role: "admin"})
	ctx = WithOrigin(ctx, Origin{ClientAddress: "203.0.113.9"})
	l.Record(ctx, "device.delete", Success, "device:dev_1", map[string]any{"password": "hunter2"})
	l.Record(ctx, "settings.update", Success, "settings", nil)
	if n, err := l.Verify(); err != nil || n != 2 {
		t.Fatalf("verify: n=%d err=%v", n, err)
	}
	evs, _ := l.List(Query{})
	if len(evs) != 2 || evs[0].Event != "settings.update" || evs[1].UserRoles[0] != "admin" || evs[1].ClientAddress != "203.0.113.9" {
		t.Fatalf("list: %+v", evs)
	}
	if evs[1].Attrs["password"] != "[REDACTED]" {
		t.Fatal("secret attr stored in audit")
	}
	l.Close()
}

func TestVerifyDetectsEdits(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir)
	l.Record(context.Background(), "a.one", Success, "", nil)
	l.Record(context.Background(), "a.two", Success, "", nil)
	l.Close()
	p := filepath.Join(dir, "audit.jsonl")
	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Replace(string(b), "a.one", "a.0ne", 1)), 0o600)
	l2, _ := Open(dir)
	if _, err := l2.Verify(); err == nil {
		t.Fatal("edited audit record not detected")
	}
}

func TestPruneKeepsChainVerifiable(t *testing.T) {
	dir := t.TempDir()
	l, _ := Open(dir)
	for i := 0; i < 5; i++ {
		l.Record(context.Background(), "x.event", Success, "", nil)
	}
	dropped, err := l.Prune(time.Now().Add(time.Hour)) // drop everything older than the future: all
	if err != nil || dropped != 5 {
		t.Fatalf("prune: %d %v", dropped, err)
	}
	l.Record(context.Background(), "y.event", Success, "", nil)
	if _, err := l.Verify(); err != nil {
		t.Fatalf("chain broken after prune: %v", err)
	}
}
