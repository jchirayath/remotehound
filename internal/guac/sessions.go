package guac

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/httpx"
	"github.com/jchirayath/remotehound/internal/core/logx"
)

// Sessions ties Guacamole auth tokens and connect blobs to RemoteHound users.
//
// Guacamole knows nothing about RemoteHound users: whoever presents a token
// (Guacamole-Token header, token= query or form field) acts as its session, and
// a sealed ?data= blob can be redeemed as often as Guacamole likes until it
// expires. The /guacamole proxy consults this registry so that
//   - a blob is redeemed by the user it was minted for, and creates at most
//     ONE Guacamole session (a repeat by the same user gets that same session
//     back while it is alive; anyone else, or anyone after revocation, is refused);
//   - a token is accepted only from the RemoteHound user it was issued to,
//     and tokens this process never issued are refused;
//   - logout and every access change revoke the user's Guacamole sessions
//     (DELETE /api/session), which closes their tunnels in Guacamole.
//
// State is in memory: a restart also drops every tunnel (the SSH server is in
// process), so nothing usable outlives it.
type Sessions struct {
	GuacURL *url.URL // internal, e.g. http://guacamole:8080/guacamole
	HTTP    *httpx.Client
	Key     []byte // the guacamole-auth-json key, to read a blob's user and expiry

	mu     sync.Mutex
	tokens map[string]*tokenInfo // auth token -> owner
	blobs  map[string]*blobInfo  // sha256(data) -> first redemption
	revGen map[string]uint64     // user -> revocations so far (a token answer from before one is discarded)
}

type tokenInfo struct {
	userID   string
	lastUsed time.Time
}

type blobInfo struct {
	userID  string
	expires time.Time
	pending bool   // first redemption in flight
	gen     uint64 // the user's revocation generation when the redemption started
	token   string // "" once revoked
	body    []byte // Guacamole's /api/tokens answer, replayed to the same user
}

// Errors returned by Redeem / Allow (the proxy maps them to 403).
var (
	ErrForeignBlob   = errors.New("connect link belongs to another user")
	ErrBlobUsed      = errors.New("connect link already used")
	ErrBadBlob       = errors.New("connect link is invalid or expired")
	ErrForeignToken  = errors.New("guacamole token belongs to another user")
	ErrUnknownToken  = errors.New("guacamole token not issued through this RemoteHound")
	maxTokenIdle     = 24 * time.Hour
	maxTrackedTokens = 20000
)

func (s *Sessions) init() {
	if s.tokens == nil {
		s.tokens = map[string]*tokenInfo{}
		s.blobs = map[string]*blobInfo{}
		s.revGen = map[string]uint64{}
	}
}

// BlobHash identifies a sealed blob without keeping it.
func BlobHash(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// Redeem is called before a POST /api/tokens carrying data= is forwarded.
// It returns (cached answer, nil) when the same user repeats a redemption of a
// blob whose session is still alive; (nil, nil) when the request may go to
// Guacamole (the caller must then report the result with Redeemed); or an error.
func (s *Sessions) Redeem(userID, email, data string, now time.Time) ([]byte, error) {
	d, err := Open(s.Key, data)
	if err != nil || d.Expires <= now.UnixMilli() {
		return nil, ErrBadBlob
	}
	if !strings.EqualFold(d.Username, email) {
		return nil, ErrForeignBlob
	}
	h := BlobHash(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.pruneLocked(now)
	if b, ok := s.blobs[h]; ok {
		if b.userID == userID && !b.pending && b.token != "" {
			if t, ok := s.tokens[b.token]; ok {
				t.lastUsed = now
				return b.body, nil
			}
		}
		return nil, ErrBlobUsed
	}
	s.blobs[h] = &blobInfo{userID: userID, expires: time.UnixMilli(d.Expires), pending: true, gen: s.revGen[userID]}
	return nil, nil
}

// Gen returns userID's revocation generation; pass it to Bind for a token
// answer to a request forwarded after this call.
func (s *Sessions) Gen(userID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	return s.revGen[userID]
}

// Redeemed records Guacamole's answer to a forwarded redemption: token is ""
// when Guacamole refused it (the blob may then be tried again). If the user
// was revoked while the redemption was in flight, the new session is not
// bound and Guacamole is told to end it (fail closed). It reports whether the
// token was bound; when false the caller must not hand it out.
func (s *Sessions) Redeemed(ctx context.Context, userID, data, token string, body []byte, now time.Time) bool {
	h := BlobHash(data)
	s.mu.Lock()
	s.init()
	b, ok := s.blobs[h]
	if token == "" {
		if ok && b.pending {
			delete(s.blobs, h)
		}
		s.mu.Unlock()
		return false
	}
	if !ok || b.gen != s.revGen[userID] {
		if ok {
			b.pending, b.token, b.body = false, "", nil // stays used until it expires
		}
		s.mu.Unlock()
		s.revokeTokens(ctx, []string{token})
		return false
	}
	b.pending, b.token, b.body = false, token, append([]byte{}, body...)
	s.bindLocked(token, userID, now)
	s.mu.Unlock()
	return true
}

// Bind records that token belongs to userID: a token answer to a request
// whose own token(s) presented Allow approved for userID at generation gen.
// If the user was revoked since, or any presented token is no longer theirs,
// the new session is ended instead. It reports whether the token was bound.
func (s *Sessions) Bind(ctx context.Context, token, userID string, gen uint64, presented []string, now time.Time) bool {
	s.mu.Lock()
	s.init()
	still := gen == s.revGen[userID]
	for _, p := range presented {
		if t, ok := s.tokens[p]; !ok || t.userID != userID {
			still = false
		}
	}
	if !still {
		s.mu.Unlock()
		s.revokeTokens(ctx, []string{token})
		return false
	}
	s.bindLocked(token, userID, now)
	s.mu.Unlock()
	return true
}

func (s *Sessions) bindLocked(token, userID string, now time.Time) {
	if t, ok := s.tokens[token]; ok && t.userID != userID {
		return // never re-bind someone else's token
	}
	if len(s.tokens) >= maxTrackedTokens {
		s.pruneLocked(now)
		var oldest string
		for k, t := range s.tokens {
			if oldest == "" || t.lastUsed.Before(s.tokens[oldest].lastUsed) {
				oldest = k
			}
		}
		delete(s.tokens, oldest)
	}
	s.tokens[token] = &tokenInfo{userID: userID, lastUsed: now}
}

// Stale returns the tokens this process does not track: issued before a
// restart, revoked, pruned, or never issued here. The proxy removes them
// before forwarding, so they authenticate nothing.
func (s *Sessions) Stale(tokens []string) map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	var out map[string]bool
	for _, t := range tokens {
		if _, ok := s.tokens[t]; !ok {
			if out == nil {
				out = map[string]bool{}
			}
			out[t] = true
		}
	}
	return out
}

// Allow checks every token a request by userID carries and returns, from
// the same locked section, the user's revocation generation (for Bind).
func (s *Sessions) Allow(userID string, tokens []string, now time.Time) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	for _, token := range tokens {
		t, ok := s.tokens[token]
		switch {
		case !ok:
			return 0, ErrUnknownToken
		case t.userID != userID:
			return 0, ErrForeignToken
		}
	}
	for _, token := range tokens {
		s.tokens[token].lastUsed = now
	}
	return s.revGen[userID], nil
}

// Revoke forgets every token of userID at once (the proxy refuses them from
// now on) and asks Guacamole to end those sessions in the background. It
// returns how many sessions were revoked.
func (s *Sessions) Revoke(ctx context.Context, userID string) int {
	s.mu.Lock()
	s.init()
	s.revGen[userID]++
	var toks []string
	for k, t := range s.tokens {
		if t.userID == userID {
			toks = append(toks, k)
			delete(s.tokens, k)
		}
	}
	for _, b := range s.blobs {
		if b.userID == userID {
			b.token, b.body = "", nil
		}
	}
	s.mu.Unlock()
	s.revokeTokens(ctx, toks)
	return len(toks)
}

// Discard ends a Guacamole session RemoteHound will not hand out.
func (s *Sessions) Discard(ctx context.Context, token string) { s.revokeTokens(ctx, []string{token}) }

// revokeTokens asks Guacamole, in the background, to end each token's session.
func (s *Sessions) revokeTokens(ctx context.Context, toks []string) {
	if len(toks) == 0 || s.HTTP == nil || s.GuacURL == nil {
		return
	}
	bg := context.WithoutCancel(ctx)
	go func() {
		for _, tok := range toks {
			s.deleteSession(bg, tok)
		}
	}()
}

func (s *Sessions) deleteSession(ctx context.Context, token string) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, s.GuacURL.String()+"/api/session", nil)
	if err != nil {
		return
	}
	req.Header.Set("Guacamole-Token", token)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		logx.L().WarnContext(ctx, "Guacamole session revoke failed", logx.Event("guacamole.revoke_failed"), logx.Err(err))
		return
	}
	resp.Body.Close()
}

func (s *Sessions) pruneLocked(now time.Time) {
	for k, b := range s.blobs {
		if !now.Before(b.expires) {
			delete(s.blobs, k)
		}
	}
	for k, t := range s.tokens {
		if now.Sub(t.lastUsed) > maxTokenIdle {
			delete(s.tokens, k)
		}
	}
}
