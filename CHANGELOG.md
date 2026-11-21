# Changelog

All notable changes are documented here. The format follows Keep a Changelog; versions follow SemVer.
Security fixes are disclosed here once users can update (VULN-7).

## [Unreleased]

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
