package auth

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/apierr"
	"github.com/jchirayath/remotehound/internal/core/audit"
	"github.com/jchirayath/remotehound/internal/core/authz"
	"github.com/jchirayath/remotehound/internal/core/ids"
	"github.com/jchirayath/remotehound/internal/core/logx"
	"github.com/jchirayath/remotehound/internal/core/store"
	"github.com/jchirayath/remotehound/internal/model"
)

// Authenticator resolves the actor for each request.
type Authenticator struct {
	Mode           string // oidc | proxy | dev
	Store          store.Store
	Audit          *audit.Log
	Sessions       *Sessions
	Providers      *Registry
	BootstrapAdmin string
	TrustedProxies []netip.Prefix
	ProxyEmail     string
	ProxyName      string
	ProxyGroups    string
	ProxySecret    []byte
}

func (a *Authenticator) timeouts() (idle, abs time.Duration) {
	var st model.Settings
	a.Store.View(func(s *model.State) { st = s.Settings })
	return time.Duration(st.SessionIdleMinutes) * time.Minute, time.Duration(st.SessionAbsoluteHours) * time.Hour
}

// Authenticate returns the actor and session for r, or (nil, nil).
func (a *Authenticator) Authenticate(w http.ResponseWriter, r *http.Request) (*authz.Actor, *Session) {
	if a.Mode == "proxy" {
		return a.fromProxy(r)
	}
	idle, abs := a.timeouts()
	sess := a.Sessions.Read(w, r, idle, abs)
	if sess == nil {
		return nil, nil
	}
	var actor *authz.Actor
	a.Store.View(func(s *model.State) {
		u, ok := s.Users[sess.UserID]
		if !ok || u.Disabled || u.SessionGen != sess.Gen {
			return
		}
		actor = actorOf(u)
	})
	if actor == nil {
		a.Sessions.Clear(w)
		return nil, nil
	}
	return actor, sess
}

func actorOf(u *model.User) *authz.Actor {
	return &authz.Actor{UserID: u.ID, Email: u.Email, Name: u.DisplayName, Role: u.Role, GroupIDs: append([]string{}, u.GroupIDs...)}
}

// TrustedPeer reports whether the direct peer is a configured proxy.
func TrustedPeer(r *http.Request, nets []netip.Prefix) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// fromProxy trusts identity headers only from trusted peers. In proxy mode the
// "session" is the proxy's; we still derive a stable CSRF token per user.
func (a *Authenticator) fromProxy(r *http.Request) (*authz.Actor, *Session) {
	if !TrustedPeer(r, a.TrustedProxies) {
		logx.L().DebugContext(r.Context(), "Proxy identity ignored: peer is not a trusted proxy", logx.Event("auth.proxy_rejected"),
			slog.String("app.reason", "untrusted_peer"))
		return nil, nil
	}
	if len(a.ProxySecret) > 0 && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-RemoteHound-Proxy-Secret")), a.ProxySecret) != 1 {
		// A trusted address without the secret: a misconfigured proxy, or
		// something else on the proxy's network. Worth a warning.
		logx.L().WarnContext(r.Context(), "Proxy identity ignored: proxy secret missing or wrong", logx.Event("auth.proxy_rejected"),
			slog.String("app.reason", "secret_mismatch"))
		return nil, nil
	}
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(a.ProxyEmail)))
	if email == "" || len(email) > 254 || !strings.Contains(email, "@") {
		// Normal for the ungated device paths; for console paths it means the
		// proxy dropped the identity (see the Caddy route ordering note in RUNBOOK).
		logx.L().DebugContext(r.Context(), "Proxy identity missing: no usable email header", logx.Event("auth.proxy_rejected"),
			slog.String("app.reason", "no_email"), slog.String("app.header", a.ProxyEmail))
		return nil, nil
	}
	id := Identity{Provider: "proxy", Subject: email, Email: email, EmailVerified: true, Name: truncateStr(r.Header.Get(a.ProxyName), 128)}
	if g := r.Header.Get(a.ProxyGroups); g != "" {
		for _, p := range strings.Split(g, ",") {
			if p = strings.TrimSpace(p); p != "" {
				id.Groups = append(id.Groups, p)
			}
		}
	}
	u, err := a.Resolve(r.Context(), id, "", false)
	if err != nil {
		return nil, nil
	}
	sid := "proxy:" + u.ID + ":" + itoa(u.SessionGen)
	return actorOf(u), &Session{UserID: u.ID, Gen: u.SessionGen, SID: sid, CSRF: a.Sessions.CSRFToken(sid)}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Resolve maps a verified identity to a user:
//  1. the user who already has this provider identity linked;
//  2. linkTo (a signed-in user adding another sign-in method) — refused if the
//     identity already belongs to someone else;
//  3. a pre-authorised user with the same email, only when the provider says
//     the email is VERIFIED and that user has never signed in (no identities) —
//     so an unverified address can never take over an account;
//  4. the bootstrap admin (verified email) while no admin exists;
//  5. just-in-time creation when roles_map grants a role for the identity's groups.
//
// Otherwise access is denied (no silent self-registration). A role granted by
// roles_map is re-applied at every login so IdP group changes take effect.
func (a *Authenticator) Resolve(ctx context.Context, id Identity, linkTo string, interactive bool) (*model.User, error) {
	if id.Provider == "" || id.Subject == "" {
		return nil, apierr.Forbidden("The sign-in did not return a usable identity.")
	}
	var out *model.User
	err := a.Store.Update(func(s *model.State) error {
		now := time.Now().UTC()
		mapped := mappedRole(s.Settings.RolesMap, id.Groups)
		var u *model.User
		for _, c := range s.Users {
			if c.HasIdentity(id.Provider, id.Subject) {
				u = c
				break
			}
		}
		link := func(c *model.User) {
			c.Identities = append(c.Identities, model.UserIdentity{Provider: id.Provider, Subject: id.Subject, Email: id.Email, LinkedAt: now})
		}
		switch {
		case linkTo != "":
			target, ok := s.Users[linkTo]
			if !ok {
				return apierr.NotFound(apierr.CodeUserNotFound, "Your account no longer exists.")
			}
			if u != nil && u.ID != linkTo {
				return apierr.Conflict(apierr.CodeUserExists, "That "+id.Provider+" account is already linked to another RemoteHound user.")
			}
			if u == nil {
				link(target)
			}
			u = target
		case u == nil && id.Email != "" && id.EmailVerified:
			for _, c := range s.Users {
				if len(c.Identities) == 0 && strings.EqualFold(c.Email, id.Email) {
					u = c
					link(u)
					break
				}
			}
		}
		if u == nil {
			role := mapped
			if a.BootstrapAdmin != "" && id.EmailVerified && strings.EqualFold(a.BootstrapAdmin, id.Email) && !hasAdmin(s) {
				role = model.RoleAdmin
			}
			if role == "" {
				who := id.Email
				if who == "" {
					who = "your " + id.Provider + " account"
				}
				return apierr.Forbidden("Your account is not authorised for RemoteHound. Ask an admin to add " + who + ".")
			}
			u = &model.User{Meta: model.Meta{ID: ids.New("usr"), CreatedAt: now, UpdatedAt: now, Version: 1},
				Email: id.Email, DisplayName: personName(id.Name), Role: role, GroupIDs: []string{}, Theme: "system"}
			link(u)
			s.Users[u.ID] = u
		} else if mapped != "" && mapped != u.Role && !(u.Role == model.RoleAdmin && countAdmins(s) == 1) {
			u.Role = mapped
		}
		if u.Disabled {
			return apierr.Forbidden("Your RemoteHound account is disabled.")
		}
		// Fill an empty name, and replace one an earlier sign-in stored from a
		// proxy header that carried an ID instead of a name.
		if personName(u.DisplayName) == "" {
			if n := personName(id.Name); n != u.DisplayName {
				u.DisplayName = n
				u.Touch(now)
			}
		}
		if interactive {
			u.LastLoginAt = now
			u.Touch(now)
		}
		cp := *u
		out = &cp
		return nil
	})
	return out, err
}

func mappedRole(m map[string]string, groups []string) string {
	best := ""
	rank := map[string]int{model.RoleViewer: 1, model.RoleOperator: 2, model.RoleAdmin: 3}
	for _, g := range groups {
		if r, ok := m[g]; ok && rank[r] > rank[best] {
			best = r
		}
	}
	return best
}

func hasAdmin(s *model.State) bool { return countAdmins(s) > 0 }

func countAdmins(s *model.State) int {
	n := 0
	for _, u := range s.Users {
		if u.Role == model.RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n
}

// DevLogin creates/loads the development admin (dev mode only, loopback only).
func (a *Authenticator) DevLogin(ctx context.Context) (*model.User, error) {
	return a.Resolve(ctx, Identity{Provider: "dev", Subject: "admin", Email: "dev@localhost", EmailVerified: true, Name: "Developer"}, "", true)
}

// opaqueRe: one unbroken run of ID characters, as in an IdP subject
// ("7HFBnaKsHAmdpq…", a GUID) or a token.
var opaqueRe = regexp.MustCompile(`^[A-Za-z0-9_+/=.:-]{16,}$`)

// personName returns name when it reads like a person's name, else "".
// Sign-in proxies often put the IdP subject or an email address in the "user"
// header (oauth2-proxy with Entra sends the opaque subject), and that must not
// become the name the console greets people with.
func personName(name string) string {
	n := strings.TrimSpace(name)
	if n == "" || strings.Contains(n, "@") || (opaqueRe.MatchString(n) && strings.ContainsAny(n, "0123456789")) {
		return ""
	}
	return truncateStr(n, 128)
}
