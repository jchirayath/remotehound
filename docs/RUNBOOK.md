# Runbook (OPS-5, REL-3)

## Deploy

1. DNS: point `RH_DOMAIN` at the host. Open TCP 80, 443 and the SSH tunnel port (default 2222).
2. `cd deploy && cp .env.example .env && chmod 600 .env`
3. `docker run --rm ghcr.io/jchirayath/remotehound gen-secret >> .env`, then set `RH_DOMAIN`, `RH_PUBLIC_URL`,
   OIDC values and `RH_BOOTSTRAP_ADMIN`.
4. `docker compose up -d` → sign in → **Integration**: every check green → **Settings**: confirm SSH public host/port.

Behind an existing proxy (no Caddy): delete the `caddy` service, publish remotehound `8080` to your proxy,
set `RH_TRUSTED_PROXIES` to its address, and proxy WebSockets with no read timeout.

## Upgrade / roll back

```bash
docker compose pull && docker compose up -d          # upgrade
REMOTEHOUND_VERSION=<previous> docker compose up -d   # roll back (state schema is forward-checked: a newer
                                                      # schema refuses to start on an older binary — restore the
                                                      # pre-upgrade snapshot from /data/snapshots if you must)
```
Take a snapshot first: Debug → Jobs → `store-snapshot` → Run now.

## Backups and restore (OPS-3) — RPO 24 h, RTO 30 min

Back up the `rh-data` volume (`state.json`, `audit.jsonl`, `ssh_host_ed25519_key`, `snapshots/`).
**The host key matters:** devices pin it; losing it means every device must re-enroll.
```bash
docker run --rm -v remotehound_rh-data:/d -v "$PWD":/b alpine tar czf /b/rh-data-$(date +%F).tgz -C /d .
# restore
docker compose stop remotehound
docker run --rm -v remotehound_rh-data:/d -v "$PWD":/b alpine sh -c 'rm -rf /d/* && tar xzf /b/rh-data-<date>.tgz -C /d'
docker compose start remotehound
```
Restore test each quarter: restore into a scratch project (`docker compose -p rh-restore …`) and check
the device list and `audit-verify`.

## Rotate secrets

| Secret | How | Effect |
|---|---|---|
| `RH_SECRET_KEY` | New value in `.env`, `docker compose up -d remotehound` | All operators signed out; stored service passwords become unreadable — re-enter them; open enrollment codes stop working. |
| `RH_GUAC_JSON_SECRET` | New value in `.env`, `docker compose up -d remotehound guacamole` | In-flight connect links fail; nothing else. |
| OIDC client secret | IdP → new secret → `.env` → restart remotehound | None. |
| SSH host key | Delete `/data/ssh_host_ed25519_key`, restart | **Every device must re-enroll** (pinned key). Only after a host compromise. |
| A device key | Device page → Delete (or Disable) | Tunnel closed immediately; re-enroll the device. |

## Smoke test

```bash
cd deploy && docker compose -f compose.yml -f test/compose.e2e.yml --env-file test/e2e.env up -d --build
# e2e overlay = proxy auth that stamps admin@example.com — TEST ONLY
```
Then follow `.claude/commands/smoke.md`: set public URL / SSH host via the API, create a code, run the
one-liner in an Alpine container sharing Caddy's network namespace, probe, connect.

## Incidents

**Restarting a part:** Services screen → the card → **Restart** (needs the `control` profile). Without
it: `docker compose restart guacamole` (or `guacd`, `remotehound`). Every UI action is in Audit as
`service.action`. RemoteHound can only restart itself from the UI.

**Sign-in loops / "Your sign-in did not reach RemoteHound"** (proxy mode, `PROXY_IDENTITY_MISSING`):
the proxy authenticated the user but RemoteHound got no identity. Check, in order: the proxy sets the
header named by `RH_PROXY_EMAIL_HEADER`; it sends `X-RemoteHound-Proxy-Secret` matching `RH_PROXY_SECRET`
(a mismatch logs `auth.proxy_rejected` reason `secret_mismatch` at WARN); its address is inside
`RH_TRUSTED_PROXIES`; with `RH_PROXY_SUBJECT_HEADER` set, that header is present (reason `no_subject`). **Caddy:** `request_header` runs *after* `forward_auth` unless wrapped in a
`route { }` block, so header strips placed before the gate silently delete the identity the gate just
copied — wrap strip → gate → proxy in `route`.

Severities: **SEV1** outage of sign-in or connect, or any suspected unauthorized access · **SEV2**
degraded (Guacamole down, devices flapping) · **SEV3** minor. One incident lead; for SEV1/2 post a status
note to users; blameless postmortem within 5 business days (REL-4).

| Alert / symptom | First steps |
|---|---|
| Integration red | Integration screen → each failing check has a hint. `docker compose ps`, `docker compose logs guacamole guacd`. |
| Many devices offline | Is :2222 reachable from outside? `docker compose logs remotehound | grep tunnel.` — auth failures (`tunnel.auth denied`) after a restore mean the host key changed. |
| `job.*` failing repeatedly | Debug → Jobs shows the last error; Run now after fixing. |
| `audit.verify` failed | Treat as SEV1 security incident: preserve `/data`, compare with backups, rotate `RH_SECRET_KEY`. |
| `store.recovered` banner | state.json was unreadable; RemoteHound started from the backup named in Debug → Runtime. Check disk space; compare device list. |
| Suspected compromise | Disable affected users (sessions end immediately), disable devices, rotate `RH_GUAC_JSON_SECRET` and `RH_SECRET_KEY`, export the audit CSV. |

## Emergency patch (VULN-5)

Build from the fix commit (`docker compose build remotehound`), run `go test ./...` (never skipped), deploy
with `docker compose up -d remotehound`. Devices reconnect on their own within seconds.
