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
2. Internet → RemoteHound SSH :2222 (devices, and script-free enrolment where the username is an
   enrolment code: ADR-0005).
3. RemoteHound → Guacamole/guacd (internal network, shared JSON key).
4. guacd → tunnel listeners (internal network only, bound to RemoteHound's guac-network IP).
5. Device ← script delivered over HTTPS and executed by a person.
6. RemoteHound → rh-control → Docker socket (optional `control` profile; ADR-0004). The socket is
   root-equivalent. Controls: internal network only, shared token, label allowlist enforced in the
   helper, no container environments returned, admin-only + audited + rate-limited in RemoteHound,
   RemoteHound may only restart itself. rh-control never holds the socket: `rh-docker-proxy` does, and
   answers only the six calls rh-control makes (ping, list, inspect, logs, start/stop/restart),
   refusing create, exec, images and the daemon API. Residual: a compromise of rh-control can stop,
   start or read the logs of any container on the host, not just the labelled ones (the label
   allowlist lives in rh-control); a compromise of the proxy itself is a host compromise.

## Abuse cases and controls (STRIDE)

| # | Threat | Control |
|---|---|---|
| S1 | Forged operator session | HMAC-signed cookies with purpose-derived key; `__Host-` prefix, HttpOnly, Secure, SameSite=Lax; idle + absolute timeouts; per-user generation bumped on role/group/disable change (`internal/auth/session.go`); the same change, a deletion or an IdP role-mapping change also terminates the user's live desktop sessions at the tunnel (`api.endUserAccess`, audited `user.sessions_ended`), because the cookie generation does not reach an open Guacamole websocket. |
| S2 | IdP token forgery / mix-up | Code + PKCE + state + nonce; ID token verified against JWKS, pinned RS256/ES256, iss/aud/azp/exp/nbf/nonce (`internal/auth/oidc.go`). |
| S2b | Account takeover via an unverified provider email (e.g. a GitHub/OIDC account claiming the admin's address) | Identities match by `provider:subject`; email binds a first sign-in only when the provider asserts it verified, only to a never-signed-in pre-authorised user; bootstrap admin needs a verified email; linking extra providers only while signed in; a provider account belongs to one user (`internal/auth/auth.go`, tested). |
| S2c | Login CSRF / mix-up across providers | Flow cookie binds state, nonce, PKCE verifier and provider; callback refuses a flow started at another provider; linking requires the same signed-in user who started it. Apple's form_post needs the flow cookie `SameSite=None` — it is signed, 10-minute, single-use and grants nothing alone. |
| S3 | Spoofed identity headers in proxy mode | Headers honoured only from `RH_TRUSTED_PROXIES` **and** with the shared `X-RemoteHound-Proxy-Secret` header (constant-time compare); config refuses proxy mode without trusted CIDRs or without `RH_PROXY_SECRET`, so a trusted CIDR alone never admits another host on that network. Optional `RH_PROXY_SUBJECT_HEADER` keys identities on the IdP's stable subject instead of the email (an email reassigned at the IdP cannot inherit an account). Identity headers are ignored on public routes and stripped before Guacamole. |
| S4 | Device impersonation | ed25519 key generated on the device; server stores the public key; constant-time compare; disabled/deleted devices refused at auth. `ssh-attended` devices have no key and are refused at auth (one session, then gone); the `none` method is refused for every username that is not an attended code. |
| S4b | Script-free enrolment over SSH (ADR-0005) | The code is the SSH username and goes through the **same** wrong-code limiter as `/e/{code}` (S5: no extra guessing budget; every code lookup counts — a non-ed25519 key, or code logins being disabled, refuse before any lookup with the same reply whatever the code, so they reveal nothing and cost nothing). At most 3 code lookups per TCP connection (`none` + `publickey` queries); a valid code is refunded, so what one code holder can open is capped too: 2 logins waiting for hello per code, 64 in total. `attended` codes authenticate only with `none`; `persistent` codes only with an ed25519 `publickey` and a verified signature, so the key bound to the device is one the client holds. An attended code cannot create a device that logs in again; a persistent code over SSH grants exactly what the script would (one key, declared forwards). Code logins get no device until `hello`, wait at most 10 s for it (a redeem in progress is not cut off), and their held global requests are capped (8). A login whose client drops as its device is made is never left registered as online. Typed commands keep each server's key and pin in their own folder (`~/.remotehound/<host>-<port>/`), so enrolling on a second server cannot break the first. The device is created and the code consumed in one store transaction (two racing logins: one wins). `ExpectedOS` is checked against the `os=` fact (or a Windows banner) before consuming. Host key: the command pins `known_hosts` and runs `StrictHostKeyChecking=yes` (no TOFU). `os=`/`host=` are client-reported, charset-limited facts (as with the script) and stated as such in the UI. **Residual:** attended sessions appear as a new device each time (operators delete them); a manual tunnel never reconnects by itself. |
| S5 | Enrolment code guessing | 31⁶ = 887,503,681 codes, CSPRNG, 15 min default TTL (max 24 h), single use, stored as HMAC (no offline brute force from a stolen state file), per-IP HTTP limit (30/min), and wrong codes paused per client (IPv4 / IPv6 /64) after 10 a minute and for everyone after **300 a minute** (check and count are one atomic step) — paused callers are told "busy", not "invalid"; metric `remotehound_enroll_throttled_total{scope=client\|global}` (`internal/enroll`, tested). **Arithmetic at the ceiling** (an attacker needs ≥ 30 clients to reach it), with *k* codes open the whole time and never repeating a guess: expected time to the first hit = (887.5 M + 1) / (k + 1) / 300 per minute — *k* = 1: ≈ 1.48 M min ≈ **2.8 years**; *k* = 5: ≈ 493 k min ≈ **11 months** (random guessing: 5.6 years and 1.1 years). Per code: at most 4,500 guesses in a 15-minute life, ≈ 1 in 197,000 that it is hit (1 in 2,050 for a 24 h code — keep TTLs short). **Residual (P3):** clients behind one IPv4 (CGNAT, an office or school NAT) share a key, so 10 wrong codes from anyone there pause enrolment for all of them for up to a minute; and a global flood (≥ 300 misses/min) pauses enrolment for everyone. Both fail safe ("busy, try again in a minute", the code is not consumed) and show in the metric. |
| T1 | Tampering with audit | Append-only JSONL with SHA-256 hash chain; `audit-verify` job every 6 h; retention rewrites keep original hashes. |
| T2 | Script tampering in transit | HTTPS only (`curl -fsSL https://`, `irm https://`); scripts validate every server value before use; host key pinned from the enrol response. |
| R1 | Operator denies opening a session | `session.open` audited with actor, role, IP; tunnel-observed session record attributed to the user who minted the token. |
| I1 | Device key used to reach server-side networks | SSH server refuses `direct-tcpip`, shell, exec (other than `agent v1` for script devices, `hello v1` for manual ones — each only on its own transport), X11, agent forwarding, pty; only declared forwards bind. A manual device's `shell` request is answered as `hello`: no shell exists to run. stdin of a manual tunnel is never read. |
| I2 | Desktop reachable by others than guacd | Tunnel listeners bind only on RemoteHound's `guac` network IP; `guac` network is `internal`. |
| I3 | Credential disclosure | Service passwords sealed with AES-256-GCM, AAD = device/service; never returned by the API; redacted from logs/audit. |
| I4 | Secrets in logs | Redaction at the logger (keys + JWT/bearer/hex/base64/private-key/`?data=` patterns), tested. |
| I5 | Guacamole connect token leakage | 60 s expiry (`connect_token_ttl_seconds`, max 600 s), one connection; `?data=` scrubbed from logs; `Referrer-Policy: no-referrer`; flows only within our origin. The `/guacamole` proxy (`api.guacGate` + `guac.Sessions`) redeems a blob only for the RemoteHound user it was minted for (the blob's `username`) and creates **at most one Guacamole session per blob**: a repeat by the same user gets that session back while it is alive, anyone else — and anyone after Sign out or an access change — is refused (`session.guacamole_denied` denied). The blob itself is not single-use inside Guacamole (guacamole-auth-json's own flags are not relied on), so this holds only for requests through RemoteHound's proxy, which is the only way to reach Guacamole (`guac` network is internal). |
| I5c | Guacamole token theft / reuse | Guacamole keeps its auth token in same-origin `localStorage` and sends it as `Guacamole-Token` or `token=`. The proxy learns which RemoteHound user each token was issued to from `/api/tokens` answers and refuses a token presented by anyone else. A token it does not track (never issued here, revoked, idle-pruned, or issued before a restart — what a browser tab left open keeps sending) is removed from the header, query and form before forwarding, so it authenticates nothing and Guacamole answers as for an expired session (logged as `guacamole.stale_token`, not audited as a denial; one in the `/api/tokens/{token}` path cannot be removed and is refused). Sign out and every access change (role/group/disabled/delete, IdP role mapping) revoke the user's Guacamole sessions (`DELETE /api/session`, which closes their tunnels); the UI also removes `GUAC_AUTH*` keys at sign out. The proxy forwards no cookies but `JSESSIONID`, no `X-Auth-Request-*`, configured identity headers, proxy secret or `Authorization`, and refuses paths containing `;` (Tomcat `..;` traversal). The gate and the proxy share one body classification (`guac.BodyKind`) and one login-path test (`guac.IsTokensLogin`): form bodies only in UTF-8/ASCII, forwarded as canonical `charset=UTF-8`; JSON and octet-stream pass; any other body type is refused (415); `data=` only once and only in the body; ambiguous login paths (`/api/tokens/`, path parameters, other case) are refused; the stale token sent with a `data=` login is removed by the gate itself. **Residual:** bindings are in memory (a restart also drops every tunnel, so nothing usable survives it); a token idle for 24 h is forgotten and then stripped like any stale token; replaying a token after its owner signed out (or was revoked) authenticates nothing but is only logged (`guacamole.stale_token`), no longer audited. |
| I5b | Watching another user's desktop | Join requires ownership **while the owner may still `device.connect` that device** (a demoted owner, or one removed from the device's group, cannot rejoin with control) or the owner's live, expiring share, which can only be granted to a member of the device's group or an admin (`authz.CanJoinSession`, `device.Share`); **no role bypasses it** — admins see metadata and can end sessions, not join. View shares are `read-only` in Guacamole. Personal credentials are sealed per user (AAD) and never returned. **Residual:** an operator of the host (root, or the Guacamole JSON key) can mint tokens outside RemoteHound — mitigated by audit and host access control, not cryptography. |
| I6 | IDOR across groups | `authz.Can` with group-scoped resources; other-group devices return 404; integration tests cover the denied paths. |
| D1 | Handshake floods on :2222 | 5 s pre-auth deadline; 8 concurrent handshakes per client (IPv4 address — IPv4-mapped IPv6 counts as the same — or IPv6 /64) and 64 per IPv6 /48; 1024 in total, and when full the oldest handshake of the client holding the **most** is evicted (a client with one pending is evicted only once every pending client holds one), never refuse-all; a handshake evicted as it authenticates is closed, not registered; MaxAuthTries 2 (`internal/tunnel/server.go`, tested). Metrics `remotehound_tunnel_preauth_refused_total`, `remotehound_tunnel_preauth_evicted_total`. **Residual (P3):** devices behind one IPv4 NAT/CGNAT share the 8-handshake budget. |
| D2 | API floods | Token-bucket limits per IP (public) and per user (authenticated); body size caps. Proxy-mode identity resolution is a read-only lookup (the store is written only on a real change) and is skipped on public routes, so request floods cannot turn into state-file writes. |
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
codes trip a per-minute brake (per client since the follow-up below), rate limits key IPv6 by /64; one `agent` exec and one session channel
per tunnel; tunnel listeners default to `127.0.0.1` and refuse `0.0.0.0` without an explicit opt-in; kick
and keepalive control writes can no longer block; the pre-auth handshake map is bounded; logout ends every
session of the user; the Guacamole proxy strips identity/secret headers and uses `connect-src 'self'`;
cookies are purpose-bound (`sess:` / `flow:`) and only Apple's flow is `SameSite=None`; `public_url` must be
https outside development; the share directory only lists users in your groups; live tails are capped
per user; guacd runs with no capabilities and a read-only root.

**Follow-up review 2026-11-21 (device and enrolment surface):**

- *Script injection through `public_url` (critical).* `public_url` is substituted into both bootstrap
  scripts inside string literals and into the copy-paste one-liners. The old check refused ASCII quotes
  but not the Unicode quotes PowerShell also honours (‘ ’ ‚ ‛ “ ” „), so an admin-set value (or a stolen
  admin session) could run code on every machine that enrols. `public_url` is now a strict ASCII
  allow-list, `^https?://[A-Za-z0-9.-]+(:port)?(/[A-Za-z0-9._~/-]*)?$` (https unless development), in
  `internal/core/validate.PublicURL`, applied to the Settings validator and to `RH_PUBLIC_URL` (which
  seeds Settings). Script rendering and `enroll.Commands` re-check the stored value and the code and
  fail closed (an explanatory script; `409 SETTINGS_PUBLIC_URL_INVALID` on create), so a value stored by
  an older release cannot reach a device.
- *Tunnel pre-auth exhaustion (medium).* Unauthenticated SSH handshakes were capped per exact IP (so one
  IPv6 /64 could hold every slot), had a 15 s budget, and a full table refused new connections, so a
  modest flood of slow handshakes kept every device offline. The cap is now per client
  (`ids.ClientKey`: IPv4 address, IPv6 /64 — the same key the HTTP limiter uses) plus 64 per IPv6 /48,
  the budget is 5 s, the table holds 1024, and when it is full the oldest pending handshake **of the
  busiest client** is closed instead of the new one being refused, so a flooder evicts its own
  handshakes first and a device is delayed by at most a retry (see D1).
- *Enrolment brake as a kill switch (medium).* The wrong-code brake was one global counter (121 misses a
  minute paused every lookup and redeem for everyone, i.e. ~2 requests a second blocked all enrolment),
  each `GET /e/{code}` counted twice, and paused callers were told their code was invalid. Misses are now
  counted once per request, atomically, per client (10 a minute per IPv4 address / IPv6 /64) with an
  absolute ceiling of 300 a minute, and a paused caller gets a distinct "busy, try again in a minute"
  script / `429`. See S5 for the guessing arithmetic and the shared-IP residual.
- *Client log tail (low).* The spec promised stripped control characters but the server only truncated,
  so a device could store terminal escapes or bidi overrides that mislead whoever reads its log. Control
  characters (except tab), DEL, C1, Unicode format characters (Cf: bidi controls, zero-width characters,
  BOM, tag characters), line/paragraph separators and invalid UTF-8 are now removed before storing.
- *SHA-1 in the tunnel's SSH algorithms (low).* The server offered x/crypto's defaults, including
  `diffie-hellman-group14-sha1`, `hmac-sha1` and `hmac-sha1-96`. They are no longer offered; what remains is
  the mlkem768x25519, curve25519, ECDH and group14-sha256 exchanges and the hmac-sha2-256/512 MACs. Every
  supported client (OpenSSH ≥ 7.4, including Windows 10's 7.7) negotiates curve25519-sha256 with AES-GCM or
  chacha20; strict-kex (Terrapin) is still offered. Tested against the raw KEXINIT.

**Residual risks (accepted, tracked):**

| # | Residual | Why it remains | Mitigation |
|---|---|---|---|
| R1 | Whoever holds a device key can impersonate that device's services and receive the credentials operators send to it (no SSH host-key pinning yet; RDP `ignore-cert`). A local non-admin user on a user-mode install can restart the tunnel to their own listener. | Pinning needs the device's service host key captured at enrolment and passed to guacd (`host-key`), not yet built. | Prefer **personal** logins over shared admin passwords; never reuse a shared password across devices; install system-wide (admin) so only admins control the tunnel. |
| R2 | Session attribution is unattributed (not wrong) when two users click Connect on the same device+service within the token TTL. | The tunnel cannot see which Guacamole token a connection serves. | Per-token one-time listeners (planned) remove it. |
| R3 | Guacamole runs same-origin under its relaxed CSP (`unsafe-eval`, inline styles). An HTML injection in Guacamole would reach RemoteHound's API. | Guacamole's AngularJS client needs it. | Keep Guacamole patched (Dependabot on the image digest); a separate origin for `/guacamole` is planned. |
| R4 | The Windows bootstrap's ACL hardening is tested by parsing only, not on Windows. | No Windows CI runner yet. | Add a Windows job; review `client/bootstrap.ps1` changes with the `tunnel-security-reviewer` agent. |
| R5 | `guacd` (the stock `guacamole/guacd:1.6.0` image) is built on Alpine 3.18, which no longer gets security updates, so OS-level CVEs in it are unknown rather than absent. | Rebuilding guacamole-server 1.6.0 on a supported Alpine needs changes to Apache's build recipe (FreeRDP 2.11 fails under GCC 14; FreeRDP 3 fails on Alpine 3.22's cJSON CMake files). | guacd runs with no capabilities, a read-only root, `no-new-privileges` and only the internal `guac` network (no route to the internet, no published port). Move to the next guacamole-server release, or a supported rebuild, as soon as one exists. |

### Deployment hardening (2026-11-21)

- **Guacamole web app image.** `deploy/guacamole/Dockerfile` rebuilds Guacamole 1.6.0 (unchanged WAR code) on a current, digest-pinned Tomcat 9 with only `guacamole-auth-json`, and replaces Jackson 2.19.0 and Guava 32.1.3 — in the WAR and in the extension — with patched releases pinned by SHA-256. trivy: 18 critical / 120 high in the stock image → 0 / 0. Signed-in users reach Guacamole's Tomcat and REST API through the proxy, so this closes real exposure, not just scanner noise.
- **No credentials in access or error logs.** Enrolment codes in `/e/<code>` are masked by `logx.Redact` (RemoteHound's own request log). The bundled Caddy (`deploy/Caddyfile`) masks `?data=`, `?token=` and `/e/<code>` in both its access log and its default log, which records the request URI when an upstream fails; without the second filter a dropped websocket would write a live Guacamole token to the log.
- **Bundle edge:** Caddy 2.11.9 (2.10.2 carried 6 critical / 100 high CVEs).
