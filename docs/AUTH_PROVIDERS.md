# Sign-in providers

RemoteHound's authentication module (`internal/auth`) is pluggable: every provider implements one
interface (`Provider`: `Start` → IdP, `Finish` → verified `Identity`), and you enable any mix of them.
The login page shows one button per provider, in the order you list them.

```env
RH_AUTH_MODE=oauth
RH_AUTH_PROVIDERS=entra,google,apple,facebook,github,oidc   # any subset, in display order
```

**Redirect URI** to register at every provider: `https://<your domain>/auth/callback/<provider>`
(e.g. `https://rh.example.com/auth/callback/google`). Secrets can be given as `…_CLIENT_SECRET` or as a file
via `…_CLIENT_SECRET_FILE` (Docker/Kubernetes secrets).

| Provider | Protocol | Identity is verified by | Email counted as verified when |
|---|---|---|---|
| `entra` Microsoft Entra ID (Azure AD) | OIDC + PKCE | ID token signature (JWKS), issuer, audience, nonce | `RH_AUTH_ENTRA_TRUST_EMAIL=true` on a **single** tenant you control |
| `google` | OIDC + PKCE | ID token (JWKS), issuer `https://accounts.google.com` | `email_verified=true` |
| `apple` Sign in with Apple | OIDC + PKCE, `form_post` | ID token (JWKS), issuer `https://appleid.apple.com` | `email_verified="true"` (incl. private-relay addresses) |
| `facebook` | OAuth 2.0 + PKCE | Graph API `/me` with the access token, over TLS | Facebook returns an email (only confirmed ones are returned) |
| `github` | OAuth 2.0 + PKCE | REST `/user` + `/user/emails` | the primary address is `verified` |
| `oidc` any issuer (Keycloak, Okta, Auth0, Authentik, Zitadel…) | OIDC + PKCE | ID token (JWKS), your issuer | `email_verified=true`, or `RH_AUTH_OIDC_TRUST_EMAIL=true` |

## Who gets in

Signing in with a provider proves *who* someone is; it does not let them in. Access is granted when:

1. that provider account is **already linked** to a RemoteHound user, or
2. an admin **pre-authorised the email** (Users → Add) and the provider says the email is **verified** — the
   account links on that first sign-in, or
3. the email is `RH_BOOTSTRAP_ADMIN` (verified) and no admin exists yet, or
4. Settings → **Role mapping** grants a role for one of the identity's groups (OIDC `groups`/`roles` claim — Entra, Keycloak, Okta…).

Everyone else sees "not authorised". An **unverified email never binds or bootstraps** an account
(this prevents account takeover through a provider that lets anyone claim any address). Users add further
sign-in methods themselves on **Profile → Sign-in methods** (link while signed in); a provider account can
belong to only one RemoteHound user, and the last method cannot be removed.

## Microsoft Entra ID

1. Entra admin centre → App registrations → New: *Web* redirect `https://<domain>/auth/callback/entra`.
2. Certificates & secrets → new client secret. Token configuration → add optional claim `email`; for role
   mapping add the `groups` claim (or app roles and set Settings → Roles claim = `roles`).
3. ```env
   RH_AUTH_ENTRA_CLIENT_ID=<application id>
   RH_AUTH_ENTRA_CLIENT_SECRET=<secret value>
   RH_AUTH_ENTRA_TENANT=<directory id>          # or organizations / common / consumers (multi-tenant)
   RH_AUTH_ENTRA_TRUST_EMAIL=true               # single tenant only
   ```
   Multi-tenant (`organizations`/`common`) accepts any Microsoft tenant's issuer — gate access with
   pre-authorised users or role mapping, never with the issuer.

## Google
Google Cloud console → APIs & Services → Credentials → OAuth client ID (*Web application*), redirect
`…/auth/callback/google`. Set `RH_AUTH_GOOGLE_CLIENT_ID` / `_CLIENT_SECRET`.

## Apple
Apple Developer → Identifiers → **Services ID** (this is the client ID) with Sign in with Apple, return URL
`…/auth/callback/apple`; Keys → new key with Sign in with Apple → download the `.p8` once.
```env
RH_AUTH_APPLE_CLIENT_ID=com.example.remotehound   # Services ID
RH_AUTH_APPLE_TEAM_ID=ABCDE12345
RH_AUTH_APPLE_KEY_ID=XYZ987
RH_AUTH_APPLE_PRIVATE_KEY_FILE=/run/secrets/apple_signin.p8
```
RemoteHound signs a fresh ES256 client secret for each exchange (no 6-month expiry to babysit). Apple
returns via a cross-site **POST**; the short-lived, signed login-flow cookie is therefore `SameSite=None; Secure`.
Apple sends the user's name only on their first authorisation.

## Facebook
Meta for Developers → app → Facebook Login → Valid OAuth redirect URI `…/auth/callback/facebook`;
request `email` permission. Set `RH_AUTH_FACEBOOK_CLIENT_ID` (App ID) / `_CLIENT_SECRET` (App secret).

## GitHub
Settings → Developer settings → OAuth Apps → callback `…/auth/callback/github`. Set
`RH_AUTH_GITHUB_CLIENT_ID` / `_CLIENT_SECRET`. Users need a verified primary email to be matched by email.

## Generic OIDC
```env
RH_AUTH_OIDC_ISSUER=https://id.example.com/realms/main   # must serve /.well-known/openid-configuration over https
RH_AUTH_OIDC_NAME=Company SSO
RH_AUTH_OIDC_CLIENT_ID=remotehound
RH_AUTH_OIDC_CLIENT_SECRET=…
```

## Adding a provider (developers)
Implement `auth.Provider` (or configure `auth.OIDC` / `auth.OAuth2`), add a case to `auth.Build`
(`internal/auth/presets.go`), add its ID to `config.ProviderIDs` (keys are generated and documented
automatically), regenerate `docs/CONFIG.md`, extend `deploy/.env.example` (a test checks), and add
tests in `internal/auth/auth_test.go` for its verification and rejection paths.

## Not using a provider
`RH_AUTH_MODE=proxy` trusts identity headers from an authenticating proxy you already run (oauth2-proxy,
Caddy `forward_auth`, Authelia, Cloudflare Access…) — only from `RH_TRUSTED_PROXIES`, and only when the
request carries `X-RemoteHound-Proxy-Secret` equal to `RH_PROXY_SECRET`, which is **required** in proxy mode
(RemoteHound refuses to start without it). By default the email header is the identity key; set
`RH_PROXY_SUBJECT_HEADER` to the header carrying the IdP's stable subject (oauth2-proxy:
`X-Auth-Request-User`) to key identities on it instead — existing users are converted on their next request.
Make sure the proxy always overwrites (never passes through) that header.
