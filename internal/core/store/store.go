// Package store is CORE-8: the only code that persists state.
//
// Contract:
//   - Store is the interface; FileStore is the JSON-document implementation
//     (ADR-0003). A Postgres implementation can replace it without touching
//     callers.
//   - View(fn) gives fn a read-only snapshot under a read lock.
//   - Update(fn) runs fn on a deep copy; if fn returns nil the copy replaces
//     the live state and is persisted atomically (temp file → fsync → rename).
//     If fn returns an error nothing changes — Update is a transaction.
//   - The previous good file is kept as state.json.bak. On boot, a corrupt
//     state.json falls back to the backup, then to the newest daily snapshot,
//     and RecoveredFrom() reports it so the UI can raise a banner.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/model"
)

// Store is the persistence seam.
type Store interface {
	View(fn func(s *model.State))
	Update(fn func(s *model.State) error) error
	Snapshot() (string, error)
	RecoveredFrom() string
	Path() string
	Writable() error
}

// FileStore keeps the state in memory and in one JSON file.
type FileStore struct {
	mu        sync.RWMutex
	dir       string
	path      string
	state     *model.State
	recovered string
}

// Open loads (or initializes) the store in dir. init seeds a fresh state.
func Open(dir string, init func(s *model.State)) (*FileStore, error) {
	if err := os.MkdirAll(filepath.Join(dir, "snapshots"), 0o700); err != nil {
		return nil, err
	}
	fs := &FileStore{dir: dir, path: filepath.Join(dir, "state.json")}
	st, from, err := fs.loadWithFallback()
	if err != nil {
		return nil, err
	}
	if st == nil {
		st = model.NewState()
		if init != nil {
			init(st)
		}
		fs.state = st
		if err := fs.persist(st); err != nil {
			return nil, err
		}
	} else {
		fs.state = st
	}
	fs.recovered = from
	if err := migrate(fs.state); err != nil {
		return nil, err
	}
	return fs, nil
}

func (fs *FileStore) loadWithFallback() (*model.State, string, error) {
	candidates := []string{fs.path, fs.path + ".bak"}
	snaps, _ := filepath.Glob(filepath.Join(fs.dir, "snapshots", "state-*.json"))
	sort.Sort(sort.Reverse(sort.StringSlice(snaps)))
	candidates = append(candidates, snaps...)

	anyExists := false
	var lastErr error
	for i, p := range candidates {
		b, err := os.ReadFile(p) // #nosec G304 -- paths built from the data dir
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		anyExists = true
		if err != nil {
			lastErr = err
			continue
		}
		st := model.NewState()
		if err := json.Unmarshal(b, st); err != nil {
			lastErr = fmt.Errorf("%s: %w", filepath.Base(p), err)
			continue
		}
		ensureMaps(st)
		from := ""
		if i > 0 {
			from = filepath.Base(p)
		}
		return st, from, nil
	}
	if anyExists {
		return nil, "", fmt.Errorf("no readable state file (last error: %v); refusing to start with empty state over existing data", lastErr)
	}
	return nil, "", nil
}

func ensureMaps(s *model.State) {
	if s.Devices == nil {
		s.Devices = map[string]*model.Device{}
	}
	if s.Enrollments == nil {
		s.Enrollments = map[string]*model.Enrollment{}
	}
	if s.Groups == nil {
		s.Groups = map[string]*model.Group{}
	}
	if s.Users == nil {
		s.Users = map[string]*model.User{}
	}
	if s.Sessions == nil {
		s.Sessions = map[string]*model.Session{}
	}
	if s.Credentials == nil {
		s.Credentials = map[string]*model.Credential{}
	}
	if s.Settings.RolesMap == nil {
		s.Settings.RolesMap = map[string]string{}
	}
}

// View runs fn with the live state under a read lock. fn must not mutate it
// or retain pointers after returning.
func (fs *FileStore) View(fn func(s *model.State)) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	fn(fs.state)
}

// Update runs fn transactionally on a copy and persists on success.
func (fs *FileStore) Update(fn func(s *model.State) error) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	cp, err := clone(fs.state)
	if err != nil {
		return err
	}
	if err := fn(cp); err != nil {
		return err
	}
	if err := fs.persist(cp); err != nil {
		return fmt.Errorf("persist state: %w", err)
	}
	fs.state = cp
	return nil
}

func clone(s *model.State) (*model.State, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	cp := model.NewState()
	if err := json.Unmarshal(b, cp); err != nil {
		return nil, err
	}
	ensureMaps(cp)
	return cp, nil
}

// persist writes atomically and rotates the previous file to .bak.
func (fs *FileStore) persist(s *model.State) error {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return err
	}
	tmp := fs.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- data dir
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(fs.path); err == nil {
		if err := copyFile(fs.path, fs.path+".bak"); err != nil {
			return err
		}
	}
	return os.Rename(tmp, fs.path)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src) // #nosec G304 -- data dir
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o600)
}

// Snapshot writes a dated copy to snapshots/ and keeps the newest 7.
func (fs *FileStore) Snapshot() (string, error) {
	fs.mu.RLock()
	b, err := json.Marshal(fs.state)
	fs.mu.RUnlock()
	if err != nil {
		return "", err
	}
	name := filepath.Join(fs.dir, "snapshots", "state-"+time.Now().UTC().Format("20060102T150405Z")+".json")
	if err := os.WriteFile(name, b, 0o600); err != nil {
		return "", err
	}
	snaps, _ := filepath.Glob(filepath.Join(fs.dir, "snapshots", "state-*.json"))
	sort.Strings(snaps)
	for len(snaps) > 7 {
		if err := os.Remove(snaps[0]); err != nil {
			return name, err
		}
		snaps = snaps[1:]
	}
	return name, nil
}

// RecoveredFrom names the fallback file used at boot ("" when state.json was fine).
func (fs *FileStore) RecoveredFrom() string { return fs.recovered }

// Path returns the state file path.
func (fs *FileStore) Path() string { return fs.path }

// Writable checks the data dir accepts writes (readiness probe).
func (fs *FileStore) Writable() error {
	p := filepath.Join(fs.dir, ".probe")
	if err := os.WriteFile(p, []byte("ok"), 0o600); err != nil {
		return err
	}
	return os.Remove(p)
}

// migrate upgrades older schemas in place. Add a case per version bump.
func migrate(s *model.State) error {
	if s.SchemaVersion > model.CurrentSchemaVersion {
		return fmt.Errorf("state schema %d is newer than this binary supports (%d); upgrade RemoteHound", s.SchemaVersion, model.CurrentSchemaVersion)
	}
	if s.SchemaVersion < 2 {
		// v2: users may link several provider identities. The single legacy
		// subject ("oidc"/"proxy:…") becomes the first identity.
		for _, u := range s.Users {
			if u.Subject != "" && len(u.Identities) == 0 {
				prov, sub := "oidc", u.Subject
				if p, rest, ok := strings.Cut(u.Subject, ":"); ok && (p == "proxy" || p == "dev") {
					prov, sub = p, rest
				}
				u.Identities = []model.UserIdentity{{Provider: prov, Subject: sub, Email: u.Email, LinkedAt: u.CreatedAt}}
			}
			u.Subject = ""
		}
	}
	s.SchemaVersion = model.CurrentSchemaVersion
	return nil
}

// ---- pagination helper shared by list endpoints (API-7) --------------------

// Page applies cursor pagination over a sorted slice of IDs. The token is the
// last ID of the previous page.
func Page(ids []string, pageSize int, token string) (page []string, next string) {
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 200 {
		pageSize = 200
	}
	start := 0
	if token != "" {
		for i, id := range ids {
			if id == token {
				start = i + 1
				break
			}
		}
	}
	end := start + pageSize
	if end >= len(ids) {
		return ids[start:], ""
	}
	return ids[start:end], ids[end-1]
}

// Contains reports whether q (lower-cased) appears in any field (filter helper).
func Contains(q string, fields ...string) bool {
	if q == "" {
		return true
	}
	q = strings.ToLower(q)
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}
