# ADR-0001 — Guacamole as the protocol engine, integrated through JSON auth

Status: accepted (2026-11-20)

## Context
We need SSH, RDP and VNC rendered in the browser, fast, on phones too. Writing protocol clients is out of
scope. Apache Guacamole (Apache-2.0) is mature and maintained. Its usual deployments keep users and
connections in a database (MySQL/Postgres auth), which would duplicate RemoteHound's own users, groups
and devices and drift from them.

## Decision
Use Guacamole + guacd unmodified, with **only** the `guacamole-auth-json` extension enabled. RemoteHound
mints, per click, a signed (HMAC-SHA256) and encrypted (AES-128-CBC) document holding one connection,
valid for `connect_token_ttl_seconds` (default 60). Guacamole stores nothing. RemoteHound reverse-proxies
`/guacamole/*` behind its own session check.

## Consequences
+ One source of truth for permissions; nothing to sync; no database container.
+ Revoking a user or device in RemoteHound takes effect on the next click.
− The connect URL carries the sealed blob in `?data=`; it is replayable for its TTL by anyone who obtains
  the URL. Mitigated by short TTL, user binding, log scrubbing and no-referrer (THREAT_MODEL I5).
− Guacamole's own session history UI is unused; RemoteHound records sessions at the tunnel instead.
− The JSON secret is a powerful shared key (THREAT_MODEL E3).
