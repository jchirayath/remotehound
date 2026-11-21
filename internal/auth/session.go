// Package auth authenticates operators and maintains their sessions.
//
// Modes (RH_AUTH_MODE):
//   - oidc:  Authorization Code + PKCE with state and nonce (SEC-25); the ID
//     token is verified against the issuer's JWKS with a pinned algorithm,
//     iss, aud, exp, nbf and nonce checks (SEC-23). MFA is the IdP's job.
//   - proxy: an authenticating reverse proxy (oauth2-proxy, Caddy
//     forward_auth, Authelia…) sets identity headers; they are trusted ONLY
//     from RH_TRUSTED_PROXIES and, if configured, with a shared secret header.
//   - dev:   loopback-only development login (refused by config otherwise).
//
// Sessions are stateless signed cookies (HMAC-SHA256 with a purpose-derived
// key): `__Host-rh_session`, HttpOnly, Secure, SameSite=Lax, idle and absolute
// timeouts from Settings, and a per-user generation counter so disabling a
// user or changing their role ends every session immediately (SESS-*). CSRF:
// a per-session token, returned by /api/v1/me and set as the readable
// `rh_csrf` cookie, must be echoed in X-CSRF-Token on every mutation.
package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/ids"
)

// SessionCookie and CSRFCookie names. __Host- requires Secure, Path=/ and no Domain.
const (
	SessionCookie = "__Host-rh_session"
	CSRFCookie    = "rh_csrf"
	CSRFHeader    = "X-CSRF-Token"
	devCookie     = "rh_session_dev" // __Host- needs https; dev runs on http://127.0.0.1
)

// claims is the signed session payload.
type claims struct {
	UserID   string `json:"u"`
	Gen      int    `json:"g"`
	IssuedAt int64  `json:"iat"`
	LastSeen int64  `json:"ls"`
	SID      string `json:"sid"`
}

// Sessions issues and verifies session cookies.
type Sessions struct {
	Key    []byte
	Secure bool // false only in dev over http
	Now    func() time.Time
}

func (s *Sessions) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sessions) cookieName() string {
	if s.Secure {
		return SessionCookie
	}
	return devCookie
}

func (s *Sessions) sign(payload []byte) string {
	m := hmac.New(sha256.New, s.Key)
	m.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Sessions) verify(v string) ([]byte, error) {
	p, sig, ok := strings.Cut(v, ".")
	if !ok {
		return nil, errors.New("malformed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return nil, errors.New("malformed")
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return nil, errors.New("malformed")
	}
	m := hmac.New(sha256.New, s.Key)
	m.Write(payload)
	if subtle.ConstantTimeCompare(got, m.Sum(nil)) != 1 {
		return nil, errors.New("bad signature")
	}
	return payload, nil
}

// Issue sets a fresh session for userID (new SID: session fixation defence).
func (s *Sessions) Issue(w http.ResponseWriter, userID string, gen int) string {
	now := s.now().Unix()
	c := claims{UserID: userID, Gen: gen, IssuedAt: now, LastSeen: now, SID: ids.Hex(16)}
	s.write(w, c, 0)
	return c.SID
}

func (s *Sessions) write(w http.ResponseWriter, c claims, maxAge int) {
	b, _ := json.Marshal(c) // plain struct
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: s.sign(append([]byte("sess:"), b...)), Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: s.CSRFToken(c.SID), Path: "/", HttpOnly: false, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: maxAge})
}

// CSRFToken derives the CSRF token for a session ID.
func (s *Sessions) CSRFToken(sid string) string {
	m := hmac.New(sha256.New, s.Key)
	m.Write([]byte("csrf:" + sid))
	return hex.EncodeToString(m.Sum(nil))[:40]
}

// Session is a verified session.
type Session struct {
	UserID string
	Gen    int
	SID    string
	CSRF   string
}

// Read verifies the cookie and enforces timeouts. It slides the idle window
// (re-issuing at most once a minute). Returns nil when there is no valid session.
func (s *Sessions) Read(w http.ResponseWriter, r *http.Request, idle, absolute time.Duration) *Session {
	ck, err := r.Cookie(s.cookieName())
	if err != nil {
		return nil
	}
	payload, err := s.verify(ck.Value)
	if err != nil {
		return nil
	}
	payload, ok := bytes.CutPrefix(payload, []byte("sess:"))
	if !ok {
		return nil
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil || c.UserID == "" {
		return nil
	}
	now := s.now()
	if now.Sub(time.Unix(c.IssuedAt, 0)) > absolute || now.Sub(time.Unix(c.LastSeen, 0)) > idle {
		s.Clear(w)
		return nil
	}
	if w != nil && now.Sub(time.Unix(c.LastSeen, 0)) > time.Minute {
		c.LastSeen = now.Unix()
		s.write(w, c, 0)
	}
	return &Session{UserID: c.UserID, Gen: c.Gen, SID: c.SID, CSRF: s.CSRFToken(c.SID)}
}

// Clear removes the session cookies.
func (s *Sessions) Clear(w http.ResponseWriter) {
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: CSRFCookie, Value: "", Path: "/", Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// CheckCSRF validates the header against the session's token (constant time).
func CheckCSRF(r *http.Request, sess *Session) bool {
	got := r.Header.Get(CSRFHeader)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) == 1
}

// ---- short-lived signed state cookie for the OIDC round trip ------------------

type flowState struct {
	Provider   string `json:"p"`
	State      string `json:"s"`
	Nonce      string `json:"n,omitempty"`
	Verifier   string `json:"v"`
	Return     string `json:"r"`
	Link       string `json:"l,omitempty"` // user ID when linking an extra identity to a signed-in user
	RolesClaim string `json:"c,omitempty"`
	Exp        int64  `json:"e"`
}

// flowSameSite: Apple returns via a cross-site form POST, which a Lax cookie
// would not accompany. The flow cookie is integrity-protected, single-use,
// 10-minute and carries no authority by itself, so None is acceptable (it
// requires Secure; plain-http dev keeps Lax).
func (s *Sessions) flowSameSite(provider string) http.SameSite {
	if s.Secure && provider == "apple" {
		return http.SameSiteNoneMode
	}
	return http.SameSiteLaxMode
}

const flowCookie = "rh_oidc"

func (s *Sessions) setFlow(w http.ResponseWriter, f flowState) {
	b, _ := json.Marshal(f)
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: s.sign(append([]byte("flow:"), b...)), Path: "/auth/", HttpOnly: true, Secure: s.Secure, SameSite: s.flowSameSite(f.Provider), MaxAge: 600})
}

// NewFlow prepares a flow for Provider.Start.
func NewFlow(returnTo, linkTo, rolesClaim string) flowState {
	return flowState{Return: SafeReturn(returnTo), Link: linkTo, RolesClaim: rolesClaim}
}

// FlowProvider, FlowLink and FlowReturn read a consumed flow.
func FlowProvider(f flowState) string { return f.Provider }
func FlowLink(f flowState) string     { return f.Link }
func FlowReturn(f flowState) string   { return SafeReturn(f.Return) }

// TakeFlow consumes the flow cookie (exported for the HTTP layer).
func (s *Sessions) TakeFlow(w http.ResponseWriter, r *http.Request) (flowState, error) {
	return s.takeFlow(w, r)
}

func (s *Sessions) takeFlow(w http.ResponseWriter, r *http.Request) (flowState, error) {
	var f flowState
	ck, err := r.Cookie(flowCookie)
	if err != nil {
		return f, errors.New("login flow expired; start again")
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookie, Value: "", Path: "/auth/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	payload, err := s.verify(ck.Value)
	if err != nil {
		return f, errors.New("login flow tampered")
	}
	payload, ok := bytes.CutPrefix(payload, []byte("flow:")) // purpose-bound: a session cookie is not a flow
	if !ok {
		return f, errors.New("login flow tampered")
	}
	if json.Unmarshal(payload, &f) != nil || s.now().Unix() > f.Exp {
		return f, errors.New("login flow expired; start again")
	}
	return f, nil
}

// SafeReturn allows only same-origin relative paths (open-redirect guard, SEC-28).
func SafeReturn(rd string) string {
	if rd == "" || len(rd) > 512 || rd[0] != '/' || strings.ContainsRune(rd, '\\') {
		return "/"
	}
	for i := 0; i < len(rd); i++ {
		if rd[i] < 0x20 || rd[i] == 0x7f { // tabs/newlines are stripped by browsers ("/\t/evil" → "//evil")
			return "/"
		}
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(rd, "//") {
		return "/"
	}
	return rd
}
