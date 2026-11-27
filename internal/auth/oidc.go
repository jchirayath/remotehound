package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jchirayath/remotehound/internal/core/httpx"
	"github.com/jchirayath/remotehound/internal/core/ids"
)

// OIDC is a strict OpenID Connect relying party and a Provider. It serves
// Microsoft Entra ID, Google, Apple (with AppleSecret) and any standard issuer
// (Keycloak, Okta, Auth0, Authentik, …).
type OIDC struct {
	ProviderID   string // e.g. "entra", "google", "oidc"
	Name         string // shown on the login button
	Kind         string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	HTTP         *httpx.Client
	Now          func() time.Time
	// TrustEmail marks emails from this issuer as verified even without an
	// email_verified claim (e.g. a single-tenant Entra directory you control).
	TrustEmail bool
	// AcceptIssuers allows multiple issuer values (Entra "common"/"organizations").
	AcceptIssuers func(iss string) bool
	// ClientSecretFunc mints the client secret per request (Apple: a signed JWT).
	ClientSecretFunc func() (string, error)
	// FormPost asks the IdP to POST the callback (Apple when name/email are requested).
	FormPost bool

	mu     sync.Mutex
	meta   *discovery
	metaAt time.Time
	keys   map[string]crypto.PublicKey
	keysAt time.Time
}

type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// ID implements Provider.
func (o *OIDC) ID() string { return o.ProviderID }

// Display implements Provider.
func (o *OIDC) Display() ProviderInfo {
	return ProviderInfo{ID: o.ProviderID, Name: o.Name, Kind: o.Kind}
}

func (o *OIDC) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func getJSON(ctx context.Context, c *httpx.Client, u string, v any, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", req.URL.Host+req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func (o *OIDC) discover(ctx context.Context) (*discovery, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.meta != nil && o.now().Sub(o.metaAt) < time.Hour {
		return o.meta, nil
	}
	var d discovery
	if err := getJSON(ctx, o.HTTP, o.Issuer+"/.well-known/openid-configuration", &d, nil); err != nil {
		return nil, err
	}
	if o.AcceptIssuers == nil && strings.TrimRight(d.Issuer, "/") != o.Issuer {
		return nil, fmt.Errorf("issuer mismatch: discovery says %q", d.Issuer)
	}
	if !strings.HasPrefix(d.AuthorizationEndpoint, "https://") || !strings.HasPrefix(d.TokenEndpoint, "https://") || !strings.HasPrefix(d.JWKSURI, "https://") {
		return nil, errors.New("IdP endpoints must be https")
	}
	o.meta, o.metaAt = &d, o.now()
	return o.meta, nil
}

// Start implements Provider.
func (o *OIDC) Start(ctx context.Context, w http.ResponseWriter, s *Sessions, f flowState) (string, error) {
	d, err := o.discover(ctx)
	if err != nil {
		return "", err
	}
	f.Provider, f.State, f.Nonce, f.Verifier = o.ProviderID, ids.Hex(16), ids.Hex(16), ids.Hex(32)
	f.Exp = o.now().Add(10 * time.Minute).Unix()
	s.setFlow(w, f)
	sum := sha256.Sum256([]byte(f.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.ClientID},
		"redirect_uri":          {o.RedirectURL},
		"scope":                 {strings.Join(o.Scopes, " ")},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if o.FormPost {
		q.Set("response_mode", "form_post")
	}
	return d.AuthorizationEndpoint + "?" + q.Encode(), nil
}

// callbackParam reads a callback parameter from the query or (form_post) body.
func callbackParam(r *http.Request, k string) string {
	if r.Method == http.MethodPost {
		return r.PostFormValue(k)
	}
	return r.URL.Query().Get(k)
}

// checkCallback validates the IdP error and state, returning the code.
func checkCallback(r *http.Request, f flowState) (string, error) {
	if e := callbackParam(r, "error"); e != "" {
		return "", fmt.Errorf("identity provider returned %q", truncateStr(e, 64))
	}
	if subtle.ConstantTimeCompare([]byte(callbackParam(r, "state")), []byte(f.State)) != 1 {
		return "", errors.New("state mismatch")
	}
	code := callbackParam(r, "code")
	if code == "" || len(code) > 4096 {
		return "", errors.New("missing code")
	}
	return code, nil
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Finish implements Provider.
func (o *OIDC) Finish(ctx context.Context, w http.ResponseWriter, r *http.Request, s *Sessions, f flowState) (Identity, error) {
	code, err := checkCallback(r, f)
	if err != nil {
		return Identity{}, err
	}
	d, err := o.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	secret := o.ClientSecret
	if o.ClientSecretFunc != nil {
		if secret, err = o.ClientSecretFunc(); err != nil {
			return Identity{}, err
		}
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {o.RedirectURL},
		"client_id": {o.ClientID}, "client_secret": {secret}, "code_verifier": {f.Verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil || resp.StatusCode != http.StatusOK || tok.IDToken == "" {
		return Identity{}, fmt.Errorf("token exchange failed (HTTP %d)", resp.StatusCode)
	}
	cl, err := o.Verify(ctx, tok.IDToken, f.Nonce)
	if err != nil {
		return Identity{}, err
	}
	id := identityFrom(cl, f.RolesClaim)
	id.Provider = o.ProviderID
	if o.TrustEmail && id.Email != "" && !id.emailFromFallback {
		id.EmailVerified = true
	}
	// Apple sends the user's name only on the first authorization, as a form field.
	if u := callbackParam(r, "user"); u != "" && id.Name == id.Email {
		var au struct {
			Name struct{ FirstName, LastName string } `json:"name"`
		}
		if json.Unmarshal([]byte(u), &au) == nil {
			if n := strings.TrimSpace(au.Name.FirstName + " " + au.Name.LastName); n != "" {
				id.Name = truncateStr(n, 128)
			}
		}
	}
	return id, nil
}

func identityFrom(cl map[string]any, rolesClaim string) Identity {
	str := func(k string) string { v, _ := cl[k].(string); return v }
	id := Identity{Subject: str("sub"), Name: str("name")}
	id.Email = strings.ToLower(str("email"))
	switch v := cl["email_verified"].(type) {
	case bool:
		id.EmailVerified = v
	case string: // Apple sends "true"/"false" strings
		id.EmailVerified = v == "true"
	}
	if id.Email == "" {
		// Display-only fallback: preferred_username is user-editable in many
		// IdPs, so it is NEVER treated as verified (and TrustEmail ignores it).
		id.Email = strings.ToLower(str("preferred_username"))
		id.EmailVerified = false
		id.emailFromFallback = true
	}
	if rolesClaim == "" {
		rolesClaim = "groups"
	}
	switch v := cl[rolesClaim].(type) {
	case []any:
		for _, g := range v {
			if s, ok := g.(string); ok {
				id.Groups = append(id.Groups, s)
			}
		}
	case string:
		id.Groups = strings.Fields(strings.ReplaceAll(v, ",", " "))
	}
	if id.Name == "" {
		id.Name = id.Email
	}
	return id
}

// Verify checks signature, algorithm, iss, aud, exp, nbf/iat and nonce.
func (o *OIDC) Verify(ctx context.Context, raw, nonce string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("id_token malformed")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("id_token malformed")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if json.Unmarshal(hb, &hdr) != nil {
		return nil, errors.New("id_token malformed")
	}
	if hdr.Alg != "RS256" && hdr.Alg != "ES256" { // pinned: no "none", no HS* confusion
		return nil, fmt.Errorf("id_token alg %q not allowed", hdr.Alg)
	}
	key, err := o.key(ctx, hdr.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("id_token malformed")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr.Alg {
	case "RS256":
		pk, ok := key.(*rsa.PublicKey)
		if !ok || rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig) != nil {
			return nil, errors.New("id_token signature invalid")
		}
	case "ES256":
		pk, ok := key.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 || !ecdsa.Verify(pk, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return nil, errors.New("id_token signature invalid")
		}
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("id_token malformed")
	}
	var cl map[string]any
	if err := json.Unmarshal(pb, &cl); err != nil {
		return nil, errors.New("id_token malformed")
	}
	now := o.now()
	const skew = 60
	num := func(k string) (int64, bool) { f, ok := cl[k].(float64); return int64(f), ok }
	iss, _ := cl["iss"].(string)
	iss = strings.TrimRight(iss, "/")
	if o.AcceptIssuers != nil {
		if !o.AcceptIssuers(iss) {
			return nil, errors.New("id_token issuer not accepted")
		}
	} else if iss != o.Issuer {
		return nil, errors.New("id_token issuer mismatch")
	}
	if !audienceOK(cl["aud"], o.ClientID) {
		return nil, errors.New("id_token audience mismatch")
	}
	if azp, ok := cl["azp"].(string); ok && azp != o.ClientID {
		return nil, errors.New("id_token azp mismatch")
	}
	if exp, ok := num("exp"); !ok || now.Unix() > exp+skew {
		return nil, errors.New("id_token expired")
	}
	if nbf, ok := num("nbf"); ok && now.Unix()+skew < nbf {
		return nil, errors.New("id_token not yet valid")
	}
	if iat, ok := num("iat"); ok && now.Unix()+skew < iat {
		return nil, errors.New("id_token issued in the future")
	}
	if n, _ := cl["nonce"].(string); subtle.ConstantTimeCompare([]byte(n), []byte(nonce)) != 1 {
		return nil, errors.New("id_token nonce mismatch")
	}
	if sub, _ := cl["sub"].(string); sub == "" {
		return nil, errors.New("id_token has no subject")
	}
	return cl, nil
}

func audienceOK(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// key returns the JWKS key for kid, refreshing the cache on a miss (rotation)
// at most once a minute.
func (o *OIDC) key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	k, ok := o.keys[kid]
	fresh := o.now().Sub(o.keysAt) < time.Minute
	o.mu.Unlock()
	if ok {
		return k, nil
	}
	if fresh {
		return nil, errors.New("id_token signed with unknown key")
	}
	d, err := o.discover(ctx)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := getJSON(ctx, o.HTTP, d.JWKSURI, &set, nil); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, j := range set.Keys {
		if pk, err := j.public(); err == nil {
			keys[j.Kid] = pk
		}
	}
	o.mu.Lock()
	o.keys, o.keysAt = keys, o.now()
	o.mu.Unlock()
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("id_token signed with unknown key")
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (j jwk) public() (crypto.PublicKey, error) {
	if j.Use != "" && j.Use != "sig" {
		return nil, errors.New("not a signing key")
	}
	dec := base64.RawURLEncoding.DecodeString
	switch j.Kty {
	case "RSA":
		n, err1 := dec(j.N)
		e, err2 := dec(j.E)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad rsa jwk")
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pk.N.BitLen() < 2048 {
			return nil, errors.New("rsa key too small")
		}
		return pk, nil
	case "EC":
		if j.Crv != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		x, err1 := dec(j.X)
		y, err2 := dec(j.Y)
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad ec jwk")
		}
		pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pk.Curve.IsOnCurve(pk.X, pk.Y) { //nolint:staticcheck // validation of untrusted point
			return nil, errors.New("ec point not on curve")
		}
		return pk, nil
	}
	return nil, errors.New("unsupported key type")
}
