package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/guac"
)

// guacGate binds Guacamole to the RemoteHound user in front of the proxy (see
// guac.Sessions): a connect blob is redeemed only by the user it was minted
// for and creates one Guacamole session; a Guacamole token is accepted only
// from the user it was issued to.
func (s *Server) guacGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.GuacSessions == nil {
			next.ServeHTTP(w, r)
			return
		}
		a := authz.ActorFrom(r.Context())
		now := time.Now()
		form, err := formOf(r)
		if errors.Is(err, errBodyType) {
			// Fail closed: a body we cannot read for a token= field is refused
			// rather than forwarded for Guacamole to read differently.
			s.Audit.Record(r.Context(), "session.guacamole_denied", audit.Denied, "", map[string]any{"reason": "unsupported body type"})
			s.fail(w, r, apierr.New(http.StatusUnsupportedMediaType, apierr.CodeValidation, "This request type is not accepted by the remote session proxy."))
			return
		}
		if err != nil {
			s.fail(w, r, apierr.BadRequest(apierr.CodeValidation, "Unreadable request body."))
			return
		}
		if guac.AmbiguousTokensPath(r) {
			s.guacDenied(w, r, guac.ErrBadBlob)
			return
		}
		tokensCall := guac.IsTokensLogin(r)
		// On the login call Guacamole reads data= from the query and the body
		// alike. Accept it there in the body only, exactly once, so the value
		// redeemed here is the one Guacamole sees, and the re-auth branch below
		// never carries one. Elsewhere data= is inert (only /api/tokens
		// authenticates) and the connect link itself is GET /guacamole/?data=…,
		// whose page then posts the blob to /api/tokens in a form body.
		if tokensCall && (r.URL.Query().Has("data") || len(form["data"]) > 1) {
			s.guacDenied(w, r, guac.ErrBadBlob)
			return
		}
		if data := form.Get("data"); tokensCall && data != "" {
			// A login with a connect blob: any token sent along is the browser's
			// stale one (Guacamole's app always sends it). The gate removes it
			// itself, from header, query and body, so only the blob counts.
			dropTokens(r, form, func(string) bool { return true })
			cached, err := s.GuacSessions.Redeem(a.UserID, a.Email, data, now)
			if err != nil {
				s.guacDenied(w, r, err)
				return
			}
			if cached != nil {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(cached)
				return
			}
			c := captureFrom(r, next)
			if tok := authToken(c.status, c.buf.Bytes()); tok != "" && !s.GuacSessions.Redeemed(r.Context(), a.UserID, data, tok, c.buf.Bytes(), now) {
				s.guacDenied(w, r, guac.ErrBlobUsed) // revoked while in flight: the new session was ended
				return
			} else if tok == "" {
				s.GuacSessions.Redeemed(r.Context(), a.UserID, data, "", nil, now)
			}
			c.writeTo(w)
			return
		}
		toks := guacTokens(r, form)
		if stale := s.GuacSessions.Stale(toks); len(stale) > 0 {
			// A token this process does not track (issued before a restart, or
			// revoked) is what a browser tab left open sends while it polls. Strip
			// it and forward the request unauthenticated: Guacamole answers as for
			// an expired session and its app stops. A token in the path cannot be
			// stripped; it stays and is refused below. Another user's token is
			// not stale and is refused (and audited) by Allow.
			dropTokens(r, form, func(t string) bool { return stale[t] })
			logx.L().InfoContext(r.Context(), "Stale Guacamole token removed", logx.Event("guacamole.stale_token"),
				slog.Int("app.count", len(stale)))
			toks = guacTokens(r, form)
		}
		gen, err := s.GuacSessions.Allow(a.UserID, toks, now) // tokens and generation checked together
		if err != nil {
			s.guacDenied(w, r, err)
			return
		}
		if tokensCall {
			// Re-authentication: bind the answer only when the request's own
			// token(s) were approved for this user and are still theirs at the
			// same generation; any other login (no token, no data) yields a
			// token nobody may use.
			c := captureFrom(r, next)
			if tok := authToken(c.status, c.buf.Bytes()); tok != "" && (len(toks) == 0 || !s.GuacSessions.Bind(r.Context(), tok, a.UserID, gen, toks, now)) {
				if len(toks) == 0 {
					s.GuacSessions.Discard(r.Context(), tok)
				}
				s.guacDenied(w, r, guac.ErrUnknownToken)
				return
			}
			c.writeTo(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) guacDenied(w http.ResponseWriter, r *http.Request, err error) {
	s.Audit.Record(r.Context(), "session.guacamole_denied", audit.Denied, "", map[string]any{"reason": err.Error()})
	msg := "This remote session link is not yours or has been used. Go back to RemoteHound and select Connect again."
	if errors.Is(err, guac.ErrBadBlob) {
		msg = "This connect link is invalid or expired. Go back to RemoteHound and select Connect again."
	}
	s.fail(w, r, apierr.Forbidden(msg))
}

var errBodyType = errors.New("unsupported body type")

// formOf reads (and restores) an urlencoded body, whatever the method and
// however the media type is spelled (guac.BodyKind, shared with the proxy).
// JSON and octet-stream bodies pass untouched; any other body type is refused
// (multipart included), as is a form body over 1 MiB.
func formOf(r *http.Request) (url.Values, error) {
	switch guac.BodyKind(r) {
	case guac.BodyNone, guac.BodyOpaque:
		return url.Values{}, nil
	case guac.BodyRefused:
		return nil, errBodyType
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errBodyType
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.Header.Set("Content-Type", guac.FormContentType)
	return url.ParseQuery(string(b))
}

// dropTokens removes the Guacamole tokens drop selects from r's header, query
// and form body (not from the path).
func dropTokens(r *http.Request, form url.Values, drop func(string) bool) {
	keep := func(vs []string) (out []string) {
		for _, v := range vs {
			if !drop(v) {
				out = append(out, v)
			}
		}
		return out
	}
	if vs := r.Header.Values("Guacamole-Token"); len(vs) > 0 {
		r.Header.Del("Guacamole-Token")
		for _, v := range keep(vs) {
			r.Header.Add("Guacamole-Token", v)
		}
	}
	if q := r.URL.Query(); q.Has("token") {
		if kept := keep(q["token"]); len(kept) != len(q["token"]) {
			q["token"] = kept
			if len(kept) == 0 {
				q.Del("token")
			}
			r.URL.RawQuery = q.Encode()
		}
	}
	if form.Has("token") {
		kept := keep(form["token"])
		if len(kept) == len(form["token"]) {
			return
		}
		form["token"] = kept
		if len(kept) == 0 {
			form.Del("token")
		}
		b := []byte(form.Encode())
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}
}

// guacTokens lists every Guacamole auth token the request carries.
func guacTokens(r *http.Request, form url.Values) []string {
	var out []string
	add := func(t string) {
		if t != "" {
			out = append(out, t)
		}
	}
	for _, t := range r.Header.Values("Guacamole-Token") { // every value: the proxy forwards them all
		add(t)
	}
	for _, t := range r.URL.Query()["token"] {
		add(t)
	}
	for _, t := range form["token"] {
		add(t)
	}
	if _, rest, ok := strings.Cut(r.URL.Path, "/api/tokens/"); ok {
		add(strings.SplitN(rest, "/", 2)[0])
	}
	return out
}

func authToken(status int, body []byte) string {
	if status != http.StatusOK {
		return ""
	}
	var v struct {
		AuthToken string `json:"authToken"`
	}
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	return v.AuthToken
}

// captureFrom serves r through next, buffering the (small JSON) answer so the
// token can be checked before anything reaches the browser.
func captureFrom(r *http.Request, next http.Handler) *capture {
	c := &capture{h: http.Header{}}
	next.ServeHTTP(c, r)
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return c
}

func (c *capture) writeTo(w http.ResponseWriter) {
	for k, v := range c.h {
		w.Header()[k] = v
	}
	w.WriteHeader(c.status)
	_, _ = w.Write(c.buf.Bytes())
}

type capture struct {
	h      http.Header
	status int
	buf    bytes.Buffer
}

func (c *capture) Header() http.Header { return c.h }
func (c *capture) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
}
func (c *capture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.buf.Len()+len(b) > 1<<20 {
		return 0, errors.New("guacamole token answer too large")
	}
	return c.buf.Write(b)
}
func (c *capture) Flush() {}
