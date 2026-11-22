# RemoteHound — Architecture

> Browser-based remote access to Linux, macOS and Windows machines **without installing a client** and
> **without anyone approving the session at the other end**. A device joins with one short command the
> person types by hand; from then on an operator opens SSH, RDP or VNC sessions to it from any browser,
> including a phone.

Status: v0.1 design + foundation. Built to the
[engineering standard](https://github.com/jchirayath/engineering-standard) in **client** mode
(`standard.config.json`). Rule IDs (`SEC-6`, `LOG-5`, …) refer to that standard.

---

## 1. The problem and the constraints

| Requirement | What it forces |
|---|---|
| No client install on the remote machine | Use only what the OS ships: `ssh`, `curl`/`irm`, sshd, RDP, Screen Sharing, GNOME/KDE RDP. |
| No approval at the other end | Unattended access. Consent is given **once**, by the person who runs the enrolment command. |
| Machines behind NAT | The device dials **out**. `ssh -R` (built into Windows 10+, macOS, Linux) is the tunnel. |
| One short, typed command | `curl -sL <host>/e/<code> \| sh` / `irm <host>/e/<code> \| iex`. Everything else is done by the script it downloads. |
| Full desktop in the browser | Apache Guacamole renders SSH / RDP / VNC over HTML5. We do not write protocol code. |
| Fast, multi-session, mobile | Guacamole for the session canvas; RemoteHound's own UI is responsive and touch-first. |
| Self-hosted, open source | Apache-2.0. One `docker compose up` deploys RemoteHound **and** Guacamole as a bundle. |
| Install a client later (optional) | The device registry is transport-agnostic (`transport: ssh-r` today, `agent` later). |

## 2. The shape

```
              ┌──────────────────────── the bundle (docker compose) ───────────────────────┐
              │                                                                             │
 browser ──TLS──► caddy :443 ──► remotehound :8080 ──(/guacamole/* proxy)──► guacamole :8080 │
 (desktop/      │                    │   ▲                                         │        │
  phone)        │                    │   │ JSON-auth token (signed, 60 s)           │        │
                │                    │   └─────────────────────────────────────────┘        │
                │                    │                                     guacd :4822 ◄────┘
                │                    │ tunnel listeners 20000-20999  ◄──── (RDP/VNC/SSH)     │
 device ──SSH──────────────► remotehound :2222 (embedded SSH server, tunnel-only)            │
 (ssh -R)       │                                                                             │
              └─────────────────────────────────────────────────────────────────────────────┘
```

| Container | Image | Role | Networks |
|---|---|---|---|
| `caddy` | `caddy:2` (digest-pinned) | TLS, HTTP→HTTPS, security headers. Optional if you already have a proxy. | `edge` |
| `remotehound` | built from this repo (distroless, non-root) | UI + API, embedded SSH tunnel server, Guacamole broker, reverse proxy to Guacamole, jobs | `edge`, `guac` |
| `guacamole` | `guacamole/guacamole:1.6.0` | The HTML5 client web app. **JSON auth only** — it has no users and no database of its own. | `guac` (internal) |
| `guacd` | `guacamole/guacd:1.6.0` | Protocol engine (FreeRDP, libvncclient, libssh2). Connects to the tunnel listeners. Writes recordings. | `guac` (internal) |
| `vector` *(profile `logs`)* | `timberio/vector` | Optional: collects every container's stdout into one JSONL file RemoteHound shows in the UI. | — |

`guac` is an **internal** network: guacamole and guacd have no route to the internet and nothing
publishes their ports. The only published ports are 443 (caddy) and the SSH tunnel port (2222 by
default). RemoteHound is the single front door — every browser request to Guacamole passes through
RemoteHound's session check first (defence in depth on top of Guacamole's own token).

## 3. Key decisions (ADRs in `docs/adr/`)

1. **Guacamole as the protocol engine, JSON auth as the integration** ([ADR-0001](adr/0001-guacamole-json-auth.md)).
   RemoteHound is the only authority for *who can open what*. For each click it mints a signed,
   encrypted JSON blob (HMAC-SHA256 + AES-128-CBC, Guacamole's `guacamole-auth-json` format) holding one
   connection, valid for 60 s. Guacamole needs no database, no user sync and cannot drift from
   RemoteHound's permissions.
2. **Embedded SSH server instead of OpenSSH in a container** ([ADR-0002](adr/0002-embedded-ssh-tunnel-server.md)).
   `golang.org/x/crypto/ssh` lets RemoteHound decide *per device* which forwards are allowed, allocate
   the internal port itself, see presence instantly, count bytes, kick a session, and refuse everything
   that is not a remote forward (no shell, no local forwards, no agent forwarding).
3. **Server-assigned ports; the client never knows them.** The device asks for `-R 3389:localhost:3389`;
   the requested port is only the *service identity*. The server binds its own stable internal port per
   (device, service) from the configured range. The bootstrap command never changes when ports do.
4. **Go, one static binary, one external module** (`golang.org/x/crypto`). Same approach as secscan:
   stdlib HTTP, `log/slog`, embedded UI with **no build step**, JSON-file store behind an interface.
5. **JSON document store first** ([ADR-0003](adr/0003-json-store.md)). A single-writer store with atomic
   writes, last-good backup and per-record ETags is enough for hundreds of devices and keeps the bundle to
   zero databases. The `store.Store` interface is the seam for Postgres later.
6. **Two kinds of configuration.** *Infrastructure* (listeners, data dir, secrets, auth provider) is
   environment config validated at boot (CORE-1) and changes need a restart. *Behaviour* (public host
   name, enrolment TTL, recording, retention, role mapping, log level) is stored in the database and
   managed from the **Settings** screen at runtime.
7. **Short bootstrap, idempotent stage-2.** The typed command only fetches a script. The script is
   re-runnable, does its work in numbered stages, and installs a *supervisor* (systemd / launchd /
   Scheduled Task) that keeps the tunnel up. Nothing is installed — only files, a key and a service entry.
8. **Script-free enrolment for locked-down machines** ([ADR-0005](adr/0005-scriptless-enrolment.md)).
   Endpoint security often blocks the script. A code can instead be typed as the SSH username of a
   plain `ssh -R` command: *attended* codes (no key, one session, nothing installed) or *persistent*
   codes with a key the person generated (reconnects only when they rerun the printed command).

## 4. Components inside the binary

```
cmd/remotehound/            main: subcommands serve | version | healthcheck | gen-secret | enroll
internal/core/              ── platform core (§1 of the standard), the ONLY implementations ──
  config/   CORE-1          typed env config, validated at boot, documented keys
  secrets/  CORE-2          data-encryption key, AES-GCM seal/open, guac JSON key
  logx/     CORE-3          slog JSON in the OTel log data model, redaction, ring buffer, runtime level
  audit/    CORE-4          record(ctx, event, outcome, attrs) → log + append-only hash-chained audit
  authz/    CORE-5          Actor, roles, Can(actor, action, resource) — deny by default
  httpx/    CORE-6          outbound client: timeouts, retry+jitter, circuit breaker, SSRF guard, traceparent
  apierr/   CORE-7          typed errors with stable codes → RFC 9457 problem+json
  store/    CORE-8          Store interface + JSON-file implementation, ETags, atomic persist, backups
  validate/ CORE-9          field validation helpers producing apierr field errors
  jobs/     CORE-10         registry: schedule, single-flight lock, panic recovery, backoff, status for UI
  help/     CORE-16         help registry served to the UI (keys checked by test)
internal/auth/              provider registry (Entra, Google, Apple, Facebook, GitHub, OIDC) | trusted proxy | dev; identities, sessions, CSRF
internal/tunnel/            embedded SSH server: device auth, forward policy, port allocator, presence, kick, metrics
internal/guac/              JSON-auth sealer, Guacamole REST client, integration checks, connect URL builder
internal/enroll/            enrolment codes, script rendering (sh / ps1), redeem
internal/device/            device service: CRUD, services, credentials (sealed), probes
internal/api/               HTTP handlers (/api/v1), middleware (request id, logging, authz, rate limit, CSRF)
internal/web/               server assembly, security headers, static UI, Guacamole reverse proxy
web/ui/                     the SPA (vanilla ES modules, no build step), generated tokens.css, icons
client/                     bootstrap.sh, bootstrap.ps1 (templates rendered by internal/enroll)
deploy/                     compose.yml, Caddyfile, .env.example, vector.toml
docs/                       this file, ADRs, threat model, runbook, SLOs, observability, user docs
```

**Shared-seam table (§1 "This repo" column)** — enforced by semgrep (`.semgrep/standard/`) and
`ci/guards.sh`:

| Core | Module | Banned elsewhere |
|---|---|---|
| CORE-1 Config | `internal/core/config` | `os.Getenv`, `os.LookupEnv` |
| CORE-2 Secrets | `internal/core/secrets` | reading key files / env secrets directly |
| CORE-3 Logger | `internal/core/logx` | `fmt.Print*`, `log.Print*` outside `cmd/` CLI output |
| CORE-4 Audit | `internal/core/audit` | writing audit lines directly |
| CORE-5 AuthZ | `internal/core/authz` | role string comparisons in handlers |
| CORE-6 Outbound HTTP | `internal/core/httpx` | `http.Get`, `http.DefaultClient`, `&http.Client{}` |
| CORE-7 Errors | `internal/core/apierr` | `http.Error` with free text |
| CORE-8 Persistence | `internal/core/store` | `os.WriteFile` of state outside store |
| CORE-9 Validation | `internal/core/validate` | ad-hoc field checks in handlers |
| CORE-10 Jobs | `internal/core/jobs` | bare `go func()` loops / `time.Ticker` outside jobs and tunnel |
| CORE-11 UI primitives | `web/ui/lib/ui.js` (grid, page chrome, states) | hand-rolled tables |
| CORE-12 Data fetch | `web/ui/lib/api.js` | `fetch(` anywhere else in the UI |
| CORE-13 Tokens/icons | `design/` → `web/ui/tokens.css`, `web/ui/lib/icons.js` | raw hex, inline SVG outside the registry |
| CORE-14 Notifications | — (none in v0.1; webhooks planned) | |
| CORE-15 Flags | settings `features.*` in the store | `if env == "prod"` branches |
| CORE-16 Help | `web/ui/help/registry.json` + `docs/user/` | help text in screen code |

## 5. Data model

All records carry `id` (opaque, prefixed), `created_at`, `updated_at` (RFC 3339 UTC) and `etag`.

| Collection | Key fields | Notes |
|---|---|---|
| `devices` (`dev_…`) | `name`, `group_id`, `os`, `hostname`, `status` (`pending`/`active`/`disabled`), `transport` (`ssh-r`), `key_fingerprint`, `public_key`, `services[]`, `client_version`, `last_seen_at`, `last_ip`, `notes`, `tags[]`, `debug` | `online` is computed from live presence, not stored. |
| `services` (inside device) | `kind` (`ssh`/`rdp`/`vnc`), `remote_port` (port on the device, e.g. 3389), `internal_port` (server-assigned), `username`, `credential_sealed`, `options` (e.g. RDP `security`, `ignore-cert`) | `credential_sealed` is AES-GCM ciphertext; the API never returns it. |
| `enrollments` (`enr_…`) | `code_hash` (SHA-256), `code_hint` (last 2 chars), `name`, `group_id`, `expires_at`, `used_at`, `device_id`, `created_by` | The plain code is shown once at creation. |
| `groups` (`grp_…`) | `name`, `description`, `color` (domain token name) | Device scoping for operators/viewers. |
| `users` (`usr_…`) | `subject` (IdP `sub` or proxy identity), `email`, `display_name`, `role` (`admin`/`operator`/`viewer`), `group_ids[]`, `disabled`, `last_login_at` | Admin sees all groups. |
| `sessions` (`ses_…`) | `device_id`, `service`, `user_id`, `started_at`, `ended_at`, `bytes_in`, `bytes_out`, `client_address`, `recording` | Derived from tunnel-listener connections — so it is true even if the browser lies. |
| `settings` (singleton) | see §8 | ETag-protected; every change is audited. |
| audit (append-only file) | OTel-shaped record + `prev_hash`, `hash` | Hash chain verified by the `audit-verify` job. |

## 6. Flows

### 6.1 Enrolment (what the person at the device does)

```
operator UI ── POST /api/v1/enrollments {name, group}  ──► code "k7q2mx" (shown once, 15 min, single use)
                                                            command: curl -sL rh.example.com/e/k7q2mx | sh
person types command
  GET /e/k7q2mx            (User-Agent picks sh vs ps1; code is checked but NOT consumed)
  script stage 1  detect OS, admin rights, local services (22, 3389, 5900)
  script stage 2  ssh-keygen -t ed25519 (private key never leaves the device)
  script stage 3  POST /api/v1/enroll {code, public_key, hostname, os, services}   ← code consumed here
                  ← {device_id, ssh_host, ssh_port, known_hosts_line, forwards[]}
  script stage 4  enable built-in services (needs admin; skipped with a message if not)
  script stage 5  write tunnel watchdog + supervisor unit; start it
  script stage 6  wait until the server reports the tunnel online → "Connected as laptop1 ✓"
```

Script-free alternative (§3.8, [CLIENT_PROTOCOL.md §9](specs/CLIENT_PROTOCOL.md)):

```
person types   mkdir … && echo '<known_hosts line>' > ~/.remotehound/<host>-<port>/known_hosts && \
               ssh -o StrictHostKeyChecking=yes … -R 3389:localhost:3389 k7q2mx@rh.example.com hello v1 os=… host=…
tunnel server  username is a code → wrong-code limiter → none (attended) / ed25519 publickey (persistent)
               -R requests held · hello → code consumed + device created (transport ssh-attended | ssh-manual)
               → held forwards bound → "connected as …, connection code 4F7K" in the person's terminal
```

### 6.2 The tunnel (what runs forever on the device)

```
ssh -T -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<dir>/known_hosts -i <dir>/id_ed25519 \
    -R 3389:localhost:3389 -R 22:localhost:22 -p 2222 dev_xxx@rh.example.com  agent v1 <facts>
```
- The remote command `agent v1 os=… ver=… services=…` lets the server update facts on every connect.
- The client's last 50 log lines are piped on **stdin**; the server keeps them as the device's log tail
  (centralised client logging over the same authenticated channel).
- The server keeps the session channel open and writes control lines (`ok`, `reconnect`, `revoked`).
- A new connection for a device replaces the old one (half-open sessions after a network change heal
  themselves).

### 6.3 Opening a session (operator)

```
UI "Connect RDP" ─► POST /api/v1/devices/{id}/connect {service:"rdp"}
   authz.Can(actor, device.connect, device)        (group-scoped; viewer is denied)
   device online? service has an internal port?    (else 409 DEVICE_OFFLINE with help)
   guac.Seal({username: actor, expires: now+60s, connections: {"laptop1 · RDP": {rdp, hostname: remotehound,
              port: 20017, recording…}}})
   audit: session.open (success|denied|failure)
 ◄─ {url: "/guacamole/?data=<sealed>#/client/<b64(name\0c\0json)>"}
UI opens the URL in a new tab (or full-screen on mobile). Guacamole redeems the data, guacd connects to
remotehound:20017, which opens a `forwarded-tcpip` channel to the device → localhost:3389.
```

### 6.4 Multi-user sessions

- **Ownership.** A session belongs to the user whose click minted its token (matched at the tunnel, so it
  is true even if a browser lies). Each user saves **their own login** per device service (Profile → Saved
  logins, sealed with AAD `cred/<user>/<device>/<service>`), so Connect opens *their* OS session. The device's
  admin-set shared login is a fallback; with neither, Guacamole prompts.
- **Sharing is invite-only.** Each connection is minted with a Guacamole connection `id`. The owner shares a
  live session with a user for 5–480 minutes as **view** (read-only) or **control**; the grantee's Join mints a
  token whose single connection is `{"join": <id>}` — it carries no credentials.
- **Admins see and end, never join.** `authz.CanJoinSession` is ownership + live share only — no role
  bypasses it. `session.read_all` (admin) shows every session's metadata; admins (and owners) can end any
  session at the tunnel, audited with `by_admin`. Grantees can neither re-share nor end.
- **Same box, many users:** SSH and Linux xrdp/GNOME remote-login give each OS user their own session;
  Windows client editions allow one interactive session (a second login takes over); macOS Screen Sharing
  and VNC show the shared console.

### 6.5 Sign-in providers
`internal/auth` is a provider registry (Entra, Google, Apple, Facebook, GitHub, generic OIDC — any mix).
OIDC providers are verified by ID token (pinned RS256/ES256, JWKS, iss/aud/azp/exp/nonce, PKCE); OAuth-only
providers by their user API over TLS. Users may link several identities; matching is by
`provider:subject`, and only a *verified* email binds a first sign-in to a pre-authorised user. Setup:
[AUTH_PROVIDERS.md](AUTH_PROVIDERS.md).

## 7. Self-healing and recovery

| Layer | Failure | What heals it |
|---|---|---|
| Client tunnel | network drop, sleep/wake, server restart | `ServerAliveInterval` detects; watchdog loop reconnects with exponential backoff + jitter (2 s → 5 min, reset after 60 s stable). |
| Client process | watchdog killed, crash, reboot | Supervisor: systemd `Restart=always` / launchd `KeepAlive` / Scheduled Task at startup + every 5 min (`IgnoreNew`). |
| Client config | server moved / host key rotated | Server sends `reconnect`; `revoked` makes the watchdog stop and remove its unit. Re-running the bootstrap with a new code is always safe (idempotent). |
| Half-open SSH | NAT dropped the flow silently | Server keepalive every 30 s; 3 misses → close; a new login for the same device replaces the old session. |
| Port listener | port taken | Allocator skips busy ports and records the new one; the next connect uses it (connections are minted per click, so nothing stale exists in Guacamole). |
| Guacamole / guacd down | crash, OOM | Compose `restart: unless-stopped` + healthchecks; `guac-health` job probes every 30 s behind a circuit breaker; UI shows "Guacamole degraded" instead of failing per click. |
| RemoteHound crash | panic in a job or handler | Panics are recovered per request and per job run (logged as `ERROR`, job backs off); compose restarts the process; devices reconnect on their own. |
| State file | corrupt / partial write | Writes are temp-file + fsync + rename; `state.json.bak` is the last good copy; boot falls back to the newest valid backup and raises a banner. Daily snapshot job keeps 7. |
| Audit chain | tampered / truncated | `audit-verify` job recomputes the chain and reports the first bad record. |

## 8. Runtime settings (UI-managed)

`public_url`, `ssh_public_host`, `ssh_public_port`, `enrollment_ttl_minutes` (default 15),
`connect_token_ttl_seconds` (60), `recording.enabled`, `recording.retention_days` (30),
`recording.max_gb` (3), `log_level` (`info`), `session.idle_minutes` (30), `session.absolute_hours` (12),
`roles.claim` (e.g. `groups`) + `roles.map` (claim value → role), `default_group_id`,
`features.vnc_enabled`, `features.client_logs`, `retention.audit_days` (365), `retention.sessions_days` (90).

## 9. Observability and debugging

- **One logger** (`logx`): JSON on stdout in the OTel log data model (LOG-1), redacted at the logger
  (LOG-4), `event.name` on every record, `trace_id`/`span_id` from W3C `traceparent`, `app.request.id`
  echoed as `X-Request-Id`.
- **One audit call** (`audit.Record`) for every state change and privileged read (LOG-5/6). Producer ×
  sink table in [OBSERVABILITY.md](OBSERVABILITY.md).
- **Centralised**: RemoteHound logs (ring buffer + stdout), **client logs** (piped over the tunnel),
  **bundle logs** (guacamole/guacd/caddy via the optional `vector` profile) — all searchable in the
  **Logs** screen with level / event / device / request-id filters and a live tail (SSE).
- **Debug screen** (admin): build + runtime stats, live tunnels with bytes and channel counts, job table
  with *Run now*, per-device debug logging toggle, service probe (TCP + protocol banner: `SSH-2.0`,
  `RFB 003.00x`, RDP X.224 confirm), runtime log level, and a **redacted diagnostics bundle** download.
- **Services screen** (admin): one card per part — RemoteHound, tunnel server, store, Guacamole, guacd —
  with status, version, ports (public/internal), and the last hour's warnings/errors from the log ring
  and, with rh-control, from container output. The read-only Guacamole configuration lives here too
  (no Guacamole admin UI exists: JSON auth, no user database).
- **Container control (optional, ADR-0004)**: `remotehound control` runs as a separate **rh-control**
  container holding the Docker socket, reachable only by remotehound with a shared token; it can
  start/stop/restart and tail logs of **labelled** containers only, and never returns their environment.
  RemoteHound authorises (admin), audits, and can only restart itself.
- **Metrics**: Prometheus text on the internal listener (`:9090/metrics`): request duration histogram,
  tunnels online, bytes, job `last_success_timestamp`, guac probe state. `pprof` only when
  `RH_DEBUG_PPROF=true`, internal listener only.

## 10. Security summary (full model: [THREAT_MODEL.md](THREAT_MODEL.md))

- Operators authenticate with **any mix of providers** (Entra ID, Google, Apple, Facebook, GitHub, any OIDC —
  MFA is the IdP's job) or a **trusted authenticating proxy**. No local passwords exist.
- Sessions are private to their owner; joining needs the owner's invitation; admins can end but not join.
- Devices authenticate with an **ed25519 key generated on the device**; the server stores only the public key.
- Enrolment codes: 6 chars from a 31-letter unambiguous alphabet (887 M), CSPRNG, stored hashed,
  single use, 15 min, rate-limited per IP.
- The SSH server accepts **only** `tcpip-forward` for the device's declared services and a session
  channel for the `agent` command. No shell, no exec of anything else, no local forwards, no agent/X11 forwarding.
- Tunnel listeners bind on the internal `guac` network only — a device's desktop is reachable only by guacd.
- Connect tokens live 60 s, carry one connection, and are scoped to the requesting user.
- Every connect, enrol, revoke, setting change and debug action is audited with actor + role + IP.

## 11. Optional client (later)

`transport: agent` devices will use a small signed binary (Go) that keeps one outbound TLS/WebSocket
connection and can also stream its own screen (for Windows Home and Macs without Screen Sharing). It
plugs in at `internal/tunnel` behind the same `PortAllocator` and presence API; enrolment, Guacamole
connect, sessions and the UI do not change.
