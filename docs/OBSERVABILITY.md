# Observability (LOG-6 producer × sink table)

One logger (`internal/core/logx`, OTel log data model on stdout), one audit call (`audit.Record` → log +
hash-chained `audit.jsonl`), one metrics registry (`/metrics` on the internal listener).

| Producer | Log events | Audit events | Metrics |
|---|---|---|---|
| HTTP layer | `http.request` (one per request), `http.error`, `http.denied`, `http.panic` | `auth.csrf`, `authz.denied` | `http_server_request_duration_seconds` |
| Auth | `auth.providers` | `auth.login` (attr provider), `auth.logout` (attr guacamole_sessions revoked), `auth.identity_link`, `auth.identity_unlink` | — |
| Enrolment | `enrollment.script` | `enrollment.create` (attr mode), `enrollment.redeem` (attr method: script default, `ssh-attended` / `ssh-key` for script-free enrolment, ADR-0005), `enrollment.revoke` | `remotehound_enroll_throttled_total{scope=client\|global}` (wrong-code pauses; `global` rising = guessing flood, everyone sees "busy") |
| Tunnel server | `tunnel.open/close/replace/auth/forward/exec/keepalive_lost/port_busy`, `tunnel.enrol` (code login → device, or refused; too many requests before hello) | `device.connect_tunnel`, `device.service.upsert` (attr source=tunnel: a typed device forwarded a conventional port it had not declared) | `remotehound_tunnel_*` (incl. `remotehound_tunnel_auth_total{outcome=enrol_attended\|enrol_key}` for code logins; `remotehound_tunnel_preauth_refused_total`, `remotehound_tunnel_preauth_evicted_total`: a rising rate means a handshake flood), `remotehound_tunnels_online` |
| Devices | `device.presence`, `session.start/end` | `device.update/delete/enable/disable/probe/reconnect`, `device.service.*`, `session.open` (attr credentials: personal/shared/prompt), `session.share`, `session.unshare`, `session.join`, `session.terminate` (attr by_admin), `credential.save/delete`, `recording.download` | — |
| Groups / users / settings | — | `group.*`, `user.*`, `user.preferences` (attr theme; the user's own theme change), `user.sessions_ended` (attrs reason, sessions; when a role/group/disabled change, deletion or IdP role change closes the user's live sessions), `settings.update` | — |
| Guacamole integration | `integration.state`, `guacamole.revoke_failed`, `guacamole.stale_token` (info; a token RemoteHound no longer tracks — typically a browser tab left open across a restart or sign out — was stripped before forwarding; attr `app.count`) | `integration.test`, `session.guacamole_denied` (outcome denied; attr reason: a connect link used by another user or after revocation, or a Guacamole token presented by someone it was not issued to) | `remotehound_guacamole_up` |
| Jobs | `job.<name>.finish`, `job.panic`, `store.snapshot`, `audit.verify`, `retention.run` | `audit.retention` | `remotehound_jobs_failing` |
| Debug | `debug.pprof` | `debug.log_level`, `debug.bundle`, `job.run` | — |
| Devices (client logs) | ring only, `source=client` | — | — |
| Bundle containers (vector profile) | ring only, `source=bundle` | — | — |
| System | `system.listener_failed`, `store.recovered` | `system.start`, `system.stop` | — |

**Alerts (LOG-9):** error-rate burn (SLO.md), `auth.login` failure spike, `remotehound_jobs_failing > 0`
for 30 min, `audit.write_failed` (any), `audit.verify` failure (any), `remotehound_guacamole_up == 0` for 5 min.

**Retention:** container logs 30 MB per container (json-file rotation) — ship stdout to your collector
for 30 days; audit 365 days (`audit_retention_days`); sessions 90 days; recordings 30 days.
