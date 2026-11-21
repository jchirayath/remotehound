package auth

import (
	"fmt"
	"strings"
	"time"

	"github.com/jchirayath/remotehound/internal/core/config"
	"github.com/jchirayath/remotehound/internal/core/httpx"
)

// Credentials are the secret parts of a provider's configuration, resolved by
// core/secrets (never read from env here).
type Credentials struct {
	ClientSecret string
	AppleKeyPEM  []byte
}

// Build turns a provider config into a Provider. publicURL is RemoteHound's
// external base URL; the redirect URI is <publicURL>/auth/callback/<id>.
func Build(pc config.ProviderConfig, cred Credentials, publicURL string) (Provider, error) {
	hc := httpx.New(httpx.Options{Timeout: 10 * time.Second})
	redirect := strings.TrimRight(publicURL, "/") + "/auth/callback/" + pc.ID
	scopes := pc.Scopes
	switch pc.ID {
	case "entra":
		tenant := strings.ToLower(pc.Tenant) // config guarantees it is set
		o := &OIDC{ProviderID: "entra", Name: "Microsoft", Kind: "entra", ClientID: pc.ClientID, ClientSecret: cred.ClientSecret,
			RedirectURL: redirect, Scopes: orDefault(scopes, "openid profile email"), HTTP: hc,
			Issuer: "https://login.microsoftonline.com/" + tenant + "/v2.0"}
		switch tenant {
		case "common", "organizations":
			// Multi-tenant: the token's iss names the user's own tenant. Only
			// explicitly allowed tenants are accepted — otherwise an admin of ANY
			// tenant could assign themselves a mapped role and walk in.
			allowed := map[string]bool{}
			for _, t := range pc.AllowedTenants {
				allowed["https://login.microsoftonline.com/"+t+"/v2.0"] = true
			}
			o.AcceptIssuers = func(iss string) bool { return allowed[strings.ToLower(iss)] }
		default:
			o.TrustEmail = pc.TrustEmail // your own single tenant: emails are directory-managed
		}
		return o, nil
	case "google":
		return &OIDC{ProviderID: "google", Name: "Google", Kind: "google", Issuer: "https://accounts.google.com",
			ClientID: pc.ClientID, ClientSecret: cred.ClientSecret, RedirectURL: redirect,
			Scopes: orDefault(scopes, "openid profile email"), HTTP: hc}, nil
	case "apple":
		secret, err := AppleSecret(pc.TeamID, pc.KeyID, pc.ClientID, cred.AppleKeyPEM)
		if err != nil {
			return nil, err
		}
		return &OIDC{ProviderID: "apple", Name: "Apple", Kind: "apple", Issuer: "https://appleid.apple.com",
			ClientID: pc.ClientID, RedirectURL: redirect, Scopes: orDefault(scopes, "openid name email"), HTTP: hc,
			ClientSecretFunc: secret, FormPost: true}, nil
	case "facebook":
		return &OAuth2{ProviderID: "facebook", Name: "Facebook", Kind: "facebook",
			AuthURL: "https://www.facebook.com/v19.0/dialog/oauth", TokenURL: "https://graph.facebook.com/v19.0/oauth/access_token",
			ClientID: pc.ClientID, ClientSecret: cred.ClientSecret, RedirectURL: redirect,
			Scopes: orDefault(scopes, "public_profile email"), HTTP: hc, Profile: facebookProfile}, nil
	case "github":
		return &OAuth2{ProviderID: "github", Name: "GitHub", Kind: "github",
			AuthURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token",
			ClientID: pc.ClientID, ClientSecret: cred.ClientSecret, RedirectURL: redirect,
			Scopes: orDefault(scopes, "read:user user:email"), HTTP: hc, Profile: githubProfile}, nil
	case "oidc":
		name := pc.DisplayName
		if name == "" {
			name = "Single sign-on"
		}
		return &OIDC{ProviderID: "oidc", Name: name, Kind: "oidc", Issuer: strings.TrimRight(pc.Issuer, "/"),
			ClientID: pc.ClientID, ClientSecret: cred.ClientSecret, RedirectURL: redirect,
			Scopes: orDefault(scopes, "openid profile email"), HTTP: hc, TrustEmail: pc.TrustEmail}, nil
	}
	return nil, fmt.Errorf("unknown auth provider %q", pc.ID)
}

func orDefault(v []string, def string) []string {
	if len(v) > 0 {
		return v
	}
	return strings.Fields(def)
}
