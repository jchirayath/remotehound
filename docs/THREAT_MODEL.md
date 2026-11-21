# Threat model (SEC-20)

RemoteHound grants **unattended desktop and shell access** to machines. A compromise of RemoteHound is
a compromise of every enrolled device, so the design minimises what each component can do.

## Assets

| Asset | Where | Impact if lost |
|---|---|---|
| Access to enrolled devices | the tunnel server + Guacamole | Full control of every device (critical) |
| Device private keys | each device only (never sent) | Impersonate that device's tunnel; cannot reach the server side |
| `RH_SECRET_KEY` | env / secret file | Forge sessions (admin), decrypt stored service credentials, compute code hashes |
| `RH_GUAC_JSON_SECRET` | env (RemoteHound + Guacamole) | Mint Guacamole connections to **any tunnel port** — bypasses RemoteHound authz |
| Stored service credentials | `state.json`, AES-256-GCM sealed | Log in to devices' RDP/SSH |
| Audit log | `audit.jsonl`, hash-chained | Hide abuse |
| Session recordings | recordings volume | Disclose screen contents of other people's machines (privacy) |

## Actors

Anonymous internet · a person with a (leaked) enrolment code · an enrolled device (or someone who stole
its key) · viewer / operator / admin · someone on the Docker host · a malicious IdP group change.

## Trust boundaries

1. Internet → Caddy/RemoteHound HTTPS (UI, API, `/e/{code}`, `/api/v1/enroll`).
2. Internet → RemoteHound SSH :2222 (devices).
3. RemoteHound → Guacamole/guacd (internal network, shared JSON key).
4. guacd → tunnel listeners (internal network only, bound to RemoteHound's guac-network IP).
5. Device ← script delivered over HTTPS and executed by a person.
6. RemoteHound → rh-control → Docker socket (optional `control` profile; ADR-0004). The socket is
   root-equivalent. Controls: internal network only, shared token, label allowlist enforced in the
   helper, no container environments returned, admin-only + audited + rate-limited in RemoteHound,
   RemoteHound may only restart itself. Residual: a compromise of rh-control itself is a host compromise.

## Abuse cases and controls (STRIDE)

| # | Threat | Control |
|---|---|---|
| S1 | Forged operator session | HMAC-signed cookies with purpose-derived key; `__Host-` prefix, HttpOnly, Secure, SameSite=Lax; idle + absolute timeouts; per-user generation bumped on role/disable change (`internal/auth/session.go`). |
| S2 | IdP token forgery / mix-up | Code + PKCE + state + nonce; ID token verified against JWKS, pinned RS256/ES256, iss/aud/azp/exp/nbf/nonce (`internal/auth/oidc.go`). |
| S2b | Account takeover via an unverified provider email (e.g. a GitHub/OIDC account claiming the admin's address) | Identities match by `provider:subject`; email binds a first sign-in only when the provider asserts it verified, only to a never-signed-in pre-authorised user; bootstrap admin needs a verified email; linking extra providers only while signed in; a provider account belongs to one user (`internal/auth/auth.go`, tested). |
| S2c | Login CSRF / mix-up across providers | Flow cookie binds state, nonce, PKCE verifier and provider; callback refuses a flow started at another provider; linking requires the same signed-in user who started it. Apple's form_post needs the flow cookie `SameSite=None` — it is signed, 10-minute, single-use and grants nothing alone. |
| S3 | Spoofed identity headers in proxy mode | Headers honoured only from `RH_TRUSTED_PROXIES`, optional shared secret header; config refuses proxy mode without trusted CIDRs. |
| S4 | Device impersonation | ed25519 key generated on the device; server stores the public key; constant-time compare; disabled/deleted devices refused at auth. |
| S5 | Enrolment code guessing | 31⁶ ≈ 887 M space, CSPRNG, 15 min, single use, stored as HMAC (no offline brute force from a stolen state file), per-IP rate limit (30/min). |
| T1 | Tampering with audit | Append-only JSONL with SHA-256 hash chain; `audit-verify` job every 6 h; retention rewrites keep original hashes. |
| T2 | Script tampering in transit | HTTPS only (`curl -fsSL https://`, `irm https://`); scripts validate every server value before use; host key pinned from the enrol response. |
| R1 | Operator denies opening a session | `session.open` audited with actor, role, IP; tunnel-observed session record attributed to the user who minted the token. |
| I1 | Device key used to reach server-side networks | SSH server refuses `direct-tcpip`, shell, exec (other than `agent v1`), X11, agent forwarding; only declared forwards bind. |
| I2 | Desktop reachable by others than guacd | Tunnel listeners bind only on RemoteHound's `guac` network IP; `guac` network is `internal`. |
| I3 | Credential disclosure | Service passwords sealed with AES-256-GCM, AAD = device/service; never returned by the API; redacted from logs/audit. |
| I4 | Secrets in logs | Redaction at the logger (keys + JWT/bearer/hex/base64/private-key/`?data=` patterns), tested. |
| I5 | Guacamole connect token leakage | 60 s expiry, one connection, user-bound; `?data=` scrubbed from logs; `Referrer-Policy: no-referrer`; flows only within our origin. **Residual:** replayable within its 60 s by someone who has the URL. |
| I5b | Watching another user's desktop | Join requires ownership or the owner's live, expiring share (`authz.CanJoinSession`); **no role bypasses it** — admins see metadata and can end sessions, not join. View shares are `read-only` in Guacamole. Personal credentials are sealed per user (AAD) and never returned. **Residual:** an operator of the host (root, or the Guacamole JSON key) can mint tokens outside RemoteHound — mitigated by audit and host access control, not cryptography. |
| I6 | IDOR across groups | `authz.Can` with group-scoped resources; other-group devices return 404; integration tests cover the denied paths. |
| D1 | Handshake floods on :2222 | 15 s pre-auth deadline, 8 concurrent handshakes per IP, MaxAuthTries 2. |
| D2 | API floods | Token-bucket limits per IP (public) and per user (authenticated); body size caps. |
| E1 | Viewer escalates | Deny-by-default role grants; settings/users/debug admin-only; last-admin protection. |
| E2 | Compromised RemoteHound container | Non-root distroless, read-only root FS, all caps dropped, no Docker socket (vector profile is opt-in and separate). |
| E3 | Leaked `RH_GUAC_JSON_SECRET` | Rotation runbook ([RUNBOOK.md](RUNBOOK.md#rotate-secrets)); Guacamole reachable only via RemoteHound's authenticated proxy, so a leaked key alone needs network access to `guac`. |

## Consent and privacy

Unattended access is consented to **once**, by the person who runs the enrolment command; the script
says what it will do before doing it, and `uninstall.sh|ps1` reverses it. Recordings are off by default,
retained 30 days when on, and admin-only. See [DATA_INVENTORY.md](DATA_INVENTORY.md).

## Security review 2026-11-20 — fixed and residual

An independent review found one critical issue (multi-tenant Entra accepted any tenant's admins) and
several medium ones; all fixed with regression tests:
multi-tenant Entra now requires `RH_AUTH_ENTRA_ALLOWED_TENANTS` and the tenant is mandatory;
`SafeReturn` rejects control characters and backslashes (tab-based open redirect); the cross-device log
ring is admin-only (operators read client logs only for devices in their groups); probes use a direct
channel and never create or steal sessions, and ambiguous session attribution is recorded unattributed
instead of crediting the wrong user; enrolment code hints are visible only to the code's creator, wrong
codes trip a global per-minute brake, rate limits key IPv6 by /64; one `agent` exec and one session channel
per tunnel; tunnel listeners default to `127.0.0.1` and refuse `0.0.0.0` without an explicit opt-in; kick
and keepalive control writes can no longer block; the pre-auth handshake map is bounded; logout ends every
session of the user; the Guacamole proxy strips identity/secret headers and uses `connect-src 'self'`;
cookies are purpose-bound (`sess:` / `flow:`) and only Apple's flow is `SameSite=None`; `public_url` must be
https outside development; the share directory only lists users in your groups; live tails are capped
per user; guacd runs with no capabilities and a read-only root.

**Residual risks (accepted, tracked):**

| # | Residual | Why it remains | Mitigation |
|---|---|---|---|
| R1 | Whoever holds a device key can impersonate that device's services and receive the credentials operators send to it (no SSH host-key pinning yet; RDP `ignore-cert`). A local non-admin user on a user-mode install can restart the tunnel to their own listener. | Pinning needs the device's service host key captured at enrolment and passed to guacd (`host-key`), not yet built. | Prefer **personal** logins over shared admin passwords; never reuse a shared password across devices; install system-wide (admin) so only admins control the tunnel. |
| R2 | Session attribution is unattributed (not wrong) when two users click Connect on the same device+service within the token TTL. | The tunnel cannot see which Guacamole token a connection serves. | Per-token one-time listeners (planned) remove it. |
| R3 | Guacamole runs same-origin under its relaxed CSP (`unsafe-eval`, inline styles). An HTML injection in Guacamole would reach RemoteHound's API. | Guacamole's AngularJS client needs it. | Keep Guacamole patched (Dependabot on the image digest); a separate origin for `/guacamole` is planned. |
| R4 | The Windows bootstrap's ACL hardening is tested by parsing only, not on Windows. | No Windows CI runner yet. | Add a Windows job; review `client/bootstrap.ps1` changes with the `tunnel-security-reviewer` agent. |
