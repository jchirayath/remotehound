# Changelog

All notable changes are documented here. The format follows Keep a Changelog; versions follow SemVer.
Security fixes are disclosed here once users can update (VULN-7).

## [Unreleased]

### Added
- Safari and iOS show the beagle icon: the console and the website now ship `favicon.ico` and `apple-touch-icon.png` next to the SVG favicon, which Safari ignores (`tools/brand/raster.mjs`).
- Enrolment codes can be tidied: **Edit** an open code (device name, group, machine type), **Delete** a used or expired one, or **Clear used & expired** in one go (`PATCH /api/v1/enrollments/{id}`, `POST /api/v1/enrollments/cleanup`). **Created by** shows the person, not a user ID (`created_by_name`).

### Fixed
- Remote Desktop logins written `DOMAIN\name` (`.\admin` for a local account, `AzureAD\you@company.com` for Entra) are sent with the domain separately, so Windows signs in automatically instead of failing with "no such user" and showing its sign-in screen.
- **Edit my login** showed a blank, locked Device field and could not be saved; it now shows the login's device and saves.
- Saving a user in **Users** no longer ends their sessions unless their role, groups or disabled state really changed (the form always sends the groups). Behind a proxy that also made the page's CSRF token stale, so the next change, e.g. Sign out, was refused once. The UI now also fetches a fresh token and retries once when the server reports `AUTH_CSRF_FAILED`.
- Enrolment codes show who created them only to people who may see that user (the same rules as the user directory); others see "Another user", so viewers no longer learn creators' emails.
- The macOS / Linux bootstrap script passes ShellCheck (SC2209) in CI; no change in behaviour.
- Two data races found by `go test -race`: the tunnel server's listener address and the process logger were read while another goroutine set them. Both are now atomic. CI's UI job runs the test files explicitly (Node 22 does not accept a folder).

### Security
- **Critical:** `public_url` could carry Unicode quotes (‘ ’ “ ” …) that PowerShell treats as quotes, letting whoever can change Settings inject code into the Windows bootstrap script. It is now a strict ASCII allow-list (letters, digits, `. - / _ ~`; https unless development) in Settings and in `RH_PUBLIC_URL`, and the scripts and one-liners refuse to render from a stored value that fails it (new error `SETTINGS_PUBLIC_URL_INVALID`). No longer accepted: IPv6-literal hosts (`https://[2001:db8::1]`), `%`-escapes or `+` in the path, user info, query strings and fragments. If startup or Settings now rejects your public URL, set it to the plain address, e.g. `https://rh.example.com`, or use a DNS name.
- The tunnel's limit on unauthenticated SSH handshakes counts an IPv6 /64 as one client (as the HTTP limiter does) and caps an IPv6 /48 at 64, gives each handshake 5 s instead of 15 s, holds up to 1024, and when full drops the oldest pending handshake of the client holding the most instead of refusing new ones, so a flood of slow handshakes can no longer keep devices offline. New metrics `remotehound_tunnel_preauth_refused_total` and `remotehound_tunnel_preauth_evicted_total`. Rate limits treat an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) as the IPv4 address.
- Wrong enrolment codes are limited per client (10 a minute per IPv4 address / IPv6 /64) with a ceiling of 300 a minute for everyone (new metric `remotehound_enroll_throttled_total{scope}`), instead of one global brake that paused all enrolment after 121 misses a minute (and counted each script request twice). A paused caller is told "busy, try again in a minute" rather than that their code is invalid.
- A device's stored log tail no longer keeps control characters, terminal escape sequences, bidi overrides, zero-width or other invisible format characters, line separators or invalid UTF-8 (the protocol always said control characters are stripped).
- The tunnel SSH server no longer offers SHA-1 key exchange or MACs (`diffie-hellman-group14-sha1`, `hmac-sha1`, `hmac-sha1-96`). Every supported client (OpenSSH 7.4 or later, including Windows 10's 7.7) uses curve25519 with AES-GCM or chacha20 already.
- The bundle's Guacamole web app is rebuilt from `deploy/guacamole/Dockerfile`: Guacamole 1.6.0 on a current Tomcat 9 with only the JSON-auth extension and patched Jackson / Guava (the stock image carried 18 critical and 120 high CVEs; the rebuilt one has none). `docker compose up -d --build` builds it.
- Enrolment codes (`/e/<code>`) are masked in RemoteHound's request log, and the bundled Caddy masks `?data=`, `?token=` and `/e/<code>` in both its access log and its error log.
- Bundled Caddy 2.10.2 → 2.11.9; `golang.org/x/crypto` 0.57.0 → 0.58.0; GitHub Actions pins updated (setup-go 7.0.0, setup-node 7.1.0, setup-python 7.1.0, upload-artifact 7.0.2, scorecard-action 2.5.0).
- Known residual: `guacd` stays on the stock 1.6.0 image (Alpine 3.18, end of life); see THREAT_MODEL R5.
- A live session can be shared only with a member of the device's group or an admin (`NO_ACCESS` otherwise); before, an owner could invite any active user.
- **Breaking for proxy mode:** `RH_PROXY_SECRET` is now required when `RH_AUTH_MODE=proxy`; RemoteHound refuses to start without it, and an empty value never disables the check. Configure your proxy to send it in `X-RemoteHound-Proxy-Secret`. New optional `RH_PROXY_SUBJECT_HEADER` keys proxy identities on the IdP's stable subject (email for display); unset keeps today's email-keyed behaviour, and existing users are converted on their first request after enabling it.
- Guacamole sessions are tied to the RemoteHound user. A connect link (`?data=`) is redeemed only by the user it was minted for and creates at most one Guacamole session (a reload returns to it; anyone else, or a replay after Sign out, is refused) — the threat model previously claimed single use that was not enforced. A Guacamole token is accepted only from the user it was issued to. Sign out and any change to a user's access revoke their Guacamole sessions, and the UI clears Guacamole's saved token. Disabling, demoting, regrouping or deleting a user also removes the shares they were given and closes sessions they joined, without ending the owner's session. The `/guacamole` proxy now forwards no cookies except `JSESSIONID`, strips every `X-Auth-Request-*` header and the configured identity headers, and refuses paths containing `;` (Tomcat `..;` traversal). New audit event `session.guacamole_denied` (denied).
- Proxy mode no longer rewrites `state.json` on every authenticated request (including every Guacamole asset): identities resolve from a read-only view and the store is written only when something changes (new user, role-mapping change, name fix). Public routes (`/ui/*`, `/e/*`, `/docs/*`, `/healthz`, `/readyz`, `/signed-out`, `/auth/providers`, `/api/v1/enroll`, `/api/v1/enroll/status`) ignore identity headers and cookies entirely, so they can never create or modify a user. A role change from the IdP's group mapping now also ends the user's sessions and live desktops.
- Blocking, deleting or demoting a user, or changing their groups, now closes their live remote sessions at the tunnel (audited `user.sessions_ended`). Before, only their RemoteHound cookie ended and an open desktop kept running; a demoted owner could also rejoin their own session with full control. Rejoining your own session now requires that you may still connect to its device.
- `go.mod` requires Go 1.26.11, so every build — CI, local and the image — has the standard-library fixes up to that release (govulncheck reported 20 reachable ones in Go 1.26.0, which CI used). Release images were already built with 1.26.11.

## [0.1.0] — 2026-11-21

First public release.

### Fixed
- Proxy sign-in no longer uses an ID as the display name (oauth2-proxy with Entra sends the opaque subject in `X-Auth-Request-User`); a name stored that way is cleared at the next sign-in, and the Overview greeting falls back to the email's local part.

### Added
- Release workflow: a version tag publishes a multi-arch (amd64 + arm64) image to GHCR with an SBOM and a signed build-provenance attestation, and creates the GitHub release from this changelog. Issue templates and a code of conduct for the public repository.
- Enroll offers both install types side by side (**Permanent**: sudo / Administrator, starts at boot; **Temporary**: one user, no admin rights). The script reports which it ran (`install_scope`, `install_user` on `POST /api/v1/enroll`), and Devices shows it in an **Install** column and on the device page, with **Make it permanent** for temporary installs.
- Embedded SSH tunnel server (`ssh -R`) with per-device key auth and a forward-only policy.
- One-line enrolment for macOS/Linux (`curl … | sh`) and Windows (`irm … | iex`), single-use codes.
- Guacamole integration via guacamole-auth-json: 60-second, single-connection tokens; integration checks.
- Web UI: overview, devices, enrolment, groups, users, sessions, integration, logs (live tail), debug, settings, audit; mobile-first, light/dark.
- Pluggable sign-in: Microsoft Entra ID, Google, Apple, Facebook, GitHub and any OIDC issuer (any mix),
  linked identities per user, or a trusted authenticating proxy; roles admin/operator/viewer with group scoping.
- Multi-user sessions: personal per-device logins, owner-only invite to view/control a live session
  (Guacamole connection sharing), admins see and end sessions but cannot join; user directory for pickers.
- Hash-chained audit log, OTel-shaped structured logs with redaction, client log upload, Prometheus metrics.
- Self-healing: watchdog with backoff + supervisors on devices; job registry with panic recovery and backoff;
  store fallback to backups; session reconciliation.
- Docker compose bundle: RemoteHound + Guacamole 1.6.0 + guacd + Caddy (+ optional Vector).
- Services screen (admin): status, version, ports and recent warnings/errors for RemoteHound, the tunnel
  server, the store, Guacamole and guacd, plus a read-only Guacamole configuration card (JSON-secret
  fingerprint and match, no user database). Optional `rh-control` helper (compose profile `control`,
  ADR-0004) adds Start / Stop / Restart and container logs, limited to labelled containers; audited.
- Saved SSH logins can be a private key (+ optional passphrase) for key-only servers; sealed like passwords,
  passed to Guacamole as `private-key`, refused for RDP/VNC.
- Proxy mode: `RH_PROXY_LOGOUT_URL` makes Sign out end the proxy's session too; public `/signed-out`
  page, optional `RH_IDP_LOGOUT_URL`.

- Overview opens with a short "what RemoteHound is for" blurb and a "Learn more" link, set by
  `RH_PROJECT_URL` (default: the project on GitHub).
- `website/`: the project's one-page website (static, no scripts), with `deploy.sh`, which fills in
  install-specific URLs from the git-ignored `local/website.env` and publishes it.

- Wrong-machine checks. An enrolment code can name the machine type (macOS / Linux / Windows); a
  machine reporting another OS is refused with `ENROLL_WRONG_OS` and the code stays usable. Devices carry
  `identity_warnings`: the name contradicts the reported OS (`NAME_OS_MISMATCH`, with **Rename to
  <hostname>**), or two devices in a group report the same hostname and OS (`DUPLICATE_HOST`). Shown as a
  banner on the device and **Check identity** in the list; recorded on the `enrollment.redeem` audit event.

- Enroll shows the permanent, system-wide macOS / Linux command (`… | sudo sh`, `command_unix_system`) as
  the recommended one, with the per-user command folded below and what each does. A `sudo` install now
  removes an earlier per-user install by the same person (its own `uninstall.sh`, run as that person),
  so upgrading does not leave two tunnels running.

### Fixed
- Screen Sharing to a Mac, and Remote Desktop with Network Level Authentication, opened a tab that waited
  forever ("Connected to Guacamole. Waiting for response...") when no login was saved: guacd asks the
  browser for the username and password, and Guacamole's page never shows that form. Connect now answers
  `CREDENTIALS_REQUIRED`, and the device page opens the login form with the reason, then offers Connect.
- After an upgrade, a screen could fail to load ("This screen failed to load", `INTERNAL`) for up to five
  minutes: the browser paired a new screen module with a stale cached library module. UI assets are now
  `no-cache` with a content-hash ETag, so each is revalidated (304 when unchanged).
- Clicking a link to the page already shown did nothing (e.g. "register again" on Enroll); it now
  re-renders. Enroll with a name filled in scrolls to the form, focuses it and says what to do next.
- Opening a device that no longer exists (deleted, or never finished enrolling) showed a bare
  "device not found". It now explains that the machine is not registered, shows what the install command
  looks like and links to Enroll. Sessions, saved logins and enrolment codes mark deleted devices
  (`device_deleted`) and show "<name> (removed) · register again", linking to Enroll with the name
  filled in, instead of a link that 404s. An offline device shows how to
  register the machine again, with the name filled in on Enroll.
- Proxy mode: a request the proxy passed without an identity sent the UI round /auth/login and back until
  the rate limiter answered 429. It now gets `PROXY_IDENTITY_MISSING` and an explanation page, and the UI
  stops after three sign-in redirects in a minute whatever the cause.
- Free-text redaction now masks `password=`/`secret:`/`token=`/`api_key=` pairs (container output).
- guacd gets a writable in-memory home: with a read-only root, FreeRDP warned "initialization may fail".
