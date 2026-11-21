package store

// @feature:devices

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jchirayath/remotehound/internal/model"
)

func TestUpdateIsTransactional(t *testing.T) {
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Update(func(st *model.State) error { st.Groups["grp_a"] = &model.Group{Name: "A"}; return nil })
	boom := errors.New("boom")
	err = s.Update(func(st *model.State) error {
		st.Groups["grp_b"] = &model.Group{Name: "B"}
		delete(st.Groups, "grp_a")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("error not returned: %v", err)
	}
	s.View(func(st *model.State) {
		if _, ok := st.Groups["grp_a"]; !ok {
			t.Error("rolled-back delete applied")
		}
		if _, ok := st.Groups["grp_b"]; ok {
			t.Error("rolled-back insert applied")
		}
	})
}

func TestPersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, nil)
	_ = s.Update(func(st *model.State) error { st.Groups["grp_a"] = &model.Group{Name: "A"}; return nil })
	s2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.View(func(st *model.State) {
		if st.Groups["grp_a"] == nil || st.Groups["grp_a"].Name != "A" {
			t.Fatal("not persisted")
		}
	})
}

// Self-healing: a corrupt state.json falls back to the last good backup.
func TestCorruptStateFallsBackToBackup(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, nil)
	_ = s.Update(func(st *model.State) error { st.Groups["grp_a"] = &model.Group{Name: "A"}; return nil })
	_ = s.Update(func(st *model.State) error { st.Groups["grp_b"] = &model.Group{Name: "B"}; return nil })
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s2.RecoveredFrom() != "state.json.bak" {
		t.Fatalf("recovered from %q", s2.RecoveredFrom())
	}
	s2.View(func(st *model.State) {
		if st.Groups["grp_a"] == nil {
			t.Fatal("backup content missing")
		}
	})
}

func TestRefusesToStartEmptyOverUnreadableData(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "state.json"), []byte("garbage"), 0o600)
	if _, err := Open(dir, nil); err == nil {
		t.Fatal("started with empty state over unreadable data")
	}
}

func TestPage(t *testing.T) {
	ids := []string{"a", "b", "c", "d", "e"}
	p, next := Page(ids, 2, "")
	if len(p) != 2 || next != "b" {
		t.Fatalf("page1 %v %q", p, next)
	}
	p, next = Page(ids, 2, next)
	if p[0] != "c" || next != "d" {
		t.Fatalf("page2 %v %q", p, next)
	}
	p, next = Page(ids, 2, next)
	if len(p) != 1 || next != "" {
		t.Fatalf("page3 %v %q", p, next)
	}
}

func TestSnapshotKeepsSeven(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir, nil)
	for i := 0; i < 9; i++ {
		_ = os.WriteFile(filepath.Join(dir, "snapshots", "state-2026010"+string(rune('0'+i))+"T000000Z.json"), []byte("{}"), 0o600)
	}
	if _, err := s.Snapshot(); err != nil {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if len(m) != 7 {
		t.Fatalf("kept %d snapshots", len(m))
	}
}
