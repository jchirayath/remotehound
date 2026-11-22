package auth

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
)

// Provider is one sign-in method (Microsoft Entra ID, Google, Apple,
// Facebook, GitHub, any OIDC issuer). The registry holds every configured
// provider; the login page lists them and the user picks one.
//
// Contract for implementations:
//   - Start stores state (+ nonce + PKCE verifier where supported) in the
//     signed, short-lived flow cookie and returns the IdP authorization URL.
//   - Finish validates state, exchanges the code, VERIFIES the identity (an
//     ID token against the issuer's JWKS for OIDC, or the provider's user API
//     over TLS for plain OAuth 2.0) and returns a provider-scoped Identity.
//   - EmailVerified is true only when the provider asserts it; RemoteHound
//     binds a first sign-in to a pre-authorised user by email only then.
type Provider interface {
	ID() string
	Display() ProviderInfo
	Start(ctx context.Context, w http.ResponseWriter, s *Sessions, f flowState) (string, error)
	Finish(ctx context.Context, w http.ResponseWriter, r *http.Request, s *Sessions, f flowState) (Identity, error)
}

// ProviderInfo is what the login page shows.
type ProviderInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"` // entra | google | apple | facebook | github | oidc
}

// Identity is a verified sign-in, scoped to its provider.
type Identity struct {
	Provider      string
	Subject       string // stable, provider-scoped user ID (OIDC "sub", Facebook/GitHub numeric ID)
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string // values of the roles claim (OIDC) — mapped through Settings.roles_map
	// MigrateFrom (proxy mode with a subject header): the request's verified
	// email. If no user has this provider:subject yet, the user whose legacy
	// "proxy" identity is keyed on exactly that email has it converted, once.
	MigrateFrom string

	emailFromFallback bool // Email came from preferred_username, not the email claim
}

// Key is the globally unique identity key, e.g. "google:1180…".
func (i Identity) Key() string { return i.Provider + ":" + i.Subject }

// Registry holds the configured providers in display order.
type Registry struct {
	byID  map[string]Provider
	order []string
}

// NewRegistry builds a registry; duplicate IDs are rejected.
func NewRegistry(ps ...Provider) (*Registry, error) {
	r := &Registry{byID: map[string]Provider{}}
	for _, p := range ps {
		if _, dup := r.byID[p.ID()]; dup {
			return nil, errors.New("duplicate auth provider " + p.ID())
		}
		r.byID[p.ID()] = p
		r.order = append(r.order, p.ID())
	}
	return r, nil
}

// Get returns a provider by ID.
func (r *Registry) Get(id string) (Provider, bool) {
	if r == nil {
		return nil, false
	}
	p, ok := r.byID[strings.ToLower(id)]
	return p, ok
}

// List returns display info for every provider, in configured order.
func (r *Registry) List() []ProviderInfo {
	if r == nil {
		return nil
	}
	out := make([]ProviderInfo, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id].Display())
	}
	return out
}

// Only returns the single provider when exactly one is configured.
func (r *Registry) Only() (Provider, bool) {
	if r == nil || len(r.order) != 1 {
		return nil, false
	}
	return r.byID[r.order[0]], true
}

// Len is the number of providers.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.order)
}

// IDs returns provider IDs sorted (for logs/diagnostics).
func (r *Registry) IDs() []string {
	ids := append([]string{}, r.order...)
	sort.Strings(ids)
	return ids
}
