package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/httpx"
	"github.com/jchirayath/remotehound/internal/core/ids"
)

// OAuth2 is a plain OAuth 2.0 provider (no ID token): the identity is read
// from the provider's user API with the access token, over TLS, and only the
// provider's stable numeric/opaque user ID is used as the subject. Used for
// Facebook and GitHub.
type OAuth2 struct {
	ProviderID   string
	Name         string
	Kind         string
	AuthURL      string
	TokenURL     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	HTTP         *httpx.Client
	// Profile fetches the verified profile with the access token.
	Profile func(ctx context.Context, c *httpx.Client, token string) (Identity, error)
}

// ID implements Provider.
func (o *OAuth2) ID() string { return o.ProviderID }

// Display implements Provider.
func (o *OAuth2) Display() ProviderInfo {
	return ProviderInfo{ID: o.ProviderID, Name: o.Name, Kind: o.Kind}
}

// Start implements Provider (state + PKCE S256).
func (o *OAuth2) Start(ctx context.Context, w http.ResponseWriter, s *Sessions, f flowState) (string, error) {
	f.Provider, f.State, f.Verifier = o.ProviderID, ids.Hex(16), ids.Hex(32)
	f.Exp = time.Now().Add(10 * time.Minute).Unix()
	s.setFlow(w, f)
	sum := sha256.Sum256([]byte(f.Verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {o.ClientID}, "redirect_uri": {o.RedirectURL},
		"scope": {strings.Join(o.Scopes, " ")}, "state": {f.State},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	return o.AuthURL + "?" + q.Encode(), nil
}

// Finish implements Provider.
func (o *OAuth2) Finish(ctx context.Context, w http.ResponseWriter, r *http.Request, s *Sessions, f flowState) (Identity, error) {
	code, err := checkCallback(r, f)
	if err != nil {
		return Identity{}, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {o.RedirectURL},
		"client_id": {o.ClientID}, "client_secret": {o.ClientSecret}, "code_verifier": {f.Verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, o.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return Identity{}, err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil || resp.StatusCode != http.StatusOK || tok.AccessToken == "" {
		return Identity{}, fmt.Errorf("token exchange failed (HTTP %d %s)", resp.StatusCode, truncateStr(tok.Error, 40))
	}
	id, err := o.Profile(ctx, o.HTTP, tok.AccessToken)
	if err != nil {
		return Identity{}, err
	}
	if id.Subject == "" {
		return Identity{}, errors.New("provider returned no user id")
	}
	id.Provider = o.ProviderID
	if id.Name == "" {
		id.Name = id.Email
	}
	return id, nil
}

// facebookProfile reads /me. Facebook only returns confirmed email addresses.
func facebookProfile(ctx context.Context, c *httpx.Client, token string) (Identity, error) {
	var me struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := getJSON(ctx, c, "https://graph.facebook.com/v19.0/me?fields=id,name,email", &me, map[string]string{"Authorization": "Bearer " + token}); err != nil {
		return Identity{}, err
	}
	return Identity{Subject: me.ID, Name: me.Name, Email: strings.ToLower(me.Email), EmailVerified: me.Email != ""}, nil
}

// githubProfile reads /user and the primary verified address from /user/emails.
func githubProfile(ctx context.Context, c *httpx.Client, token string) (Identity, error) {
	hdr := map[string]string{"Authorization": "Bearer " + token, "X-GitHub-Api-Version": "2022-11-28"}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := getJSON(ctx, c, "https://api.github.com/user", &u, hdr); err != nil {
		return Identity{}, err
	}
	id := Identity{Subject: strconv.FormatInt(u.ID, 10), Name: u.Name}
	if id.Name == "" {
		id.Name = u.Login
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := getJSON(ctx, c, "https://api.github.com/user/emails", &emails, hdr); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				id.Email, id.EmailVerified = strings.ToLower(e.Email), true
			}
		}
	}
	return id, nil
}

// AppleSecret returns a ClientSecretFunc that mints Apple's client secret: an
// ES256 JWT signed with the .p8 key from the Apple developer account
// (iss = team ID, sub = services ID, aud = https://appleid.apple.com). Each
// secret lives 10 minutes; Apple allows up to 6 months.
func AppleSecret(teamID, keyID, clientID string, p8 []byte) (func() (string, error), error) {
	blk, _ := pem.Decode(p8)
	if blk == nil {
		return nil, errors.New("apple private key: not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apple private key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("apple private key: not an EC key")
	}
	return func() (string, error) {
		now := time.Now()
		hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
		cl, _ := json.Marshal(map[string]any{"iss": teamID, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
			"aud": "https://appleid.apple.com", "sub": clientID})
		signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(cl)
		digest := sha256.Sum256([]byte(signing))
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return "", err
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
	}, nil
}
