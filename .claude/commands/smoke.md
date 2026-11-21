---
description: Bring up the full bundle locally and enrol a real (containerised) device with the real one-liner
---
Run RemoteHound's live smoke test and report each step's result verbatim.

1. Make sure `deploy/test/e2e.env` exists; if not, create it with `RH_DOMAIN=localhost`,
   `RH_PUBLIC_URL=https://localhost:8443`, `RH_AUTH_MODE=proxy`, `RH_SSH_PUBLISH=127.0.0.1:2222`, and fresh
   `RH_SECRET_KEY` (`openssl rand -hex 32`) / `RH_GUAC_JSON_SECRET` (`openssl rand -hex 16`).
2. `cd deploy && docker compose -f compose.yml -f test/compose.e2e.yml --env-file test/e2e.env up -d --build`
   and wait until the guacamole log shows `Server startup in`.
3. `curl -sk https://localhost:8443/api/v1/integration` — every check must be `pass` (recording may be `skip`).
4. With a cookie jar: GET `/api/v1/me` for the CSRF token; PATCH `/api/v1/settings` (If-Match = etag) to
   `{"public_url":"https://localhost","ssh_public_host":"172.29.0.10","ssh_public_port":2222}`; POST
   `/api/v1/enrollments` `{"name":"alpine-box"}` and note the code.
5. Copy Caddy's root CA (`docker cp remotehound-caddy-1:/data/caddy/pki/authorities/local/root.crt`), start
   `alpine:3.20` with `--network container:remotehound-caddy-1`, that CA mounted into
   `/usr/local/share/ca-certificates/`, `apk add openssh curl ca-certificates`, `update-ca-certificates`,
   `ssh-keygen -A && /usr/sbin/sshd`, then run exactly `curl -fsSL https://localhost/e/<code> | sh`.
   Expect `Connected as alpine-box ✓`.
6. POST `/api/v1/devices/<id>/probe` → `ssh ok`; POST `/connect {"service":"ssh"}` and redeem its `data`
   at `/guacamole/api/tokens` → `authToken` with `dataSource: json`.
7. Browser proof (needs a local user on the device: in the container run
   `adduser -D -s /bin/sh rh && echo rh:rh-demo-pass | chpasswd` and enable `PasswordAuthentication yes`):
   `cd e2e && npm install && node live/session-share.mjs <dir>` — real SSH session in Guacamole, view-only
   share joined by the operator, grantee denied re-share/end, admin ends it. Look at the screenshots.
8. Tear down: `docker rm -f rh-device` and `docker compose … down -v`.

State clearly anything that failed or was skipped. Never expose the e2e overlay beyond localhost.
