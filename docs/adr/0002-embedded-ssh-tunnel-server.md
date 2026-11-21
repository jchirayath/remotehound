# ADR-0002 — An embedded SSH server for device tunnels

Status: accepted (2026-11-20)

## Context
Devices are behind NAT and may not install software. Every target OS ships an OpenSSH client, so
`ssh -R` is the tunnel. The server side could be OpenSSH in a container with `authorized_keys`
`permitlisten=` restrictions, plus scripts to manage keys and detect presence.

## Decision
Embed an SSH server in RemoteHound with `golang.org/x/crypto/ssh` — the project's only external module.

## Consequences
+ Per-device policy in code: only declared forwards, server-assigned internal ports, no shell/exec/local
  forwards — enforced and unit-tested in one place (`internal/tunnel`).
+ Instant presence, byte counts, per-session termination, kick/revoke with a control message, replacement
  of half-open sessions — all of which OpenSSH would need log scraping for.
+ The bootstrap command never changes when ports do (the requested port is only the service identity).
− We own an SSH server's exposure. Mitigations: x/crypto is maintained by the Go team; public-key auth
  only; pre-auth deadline and per-IP handshake caps; fuzzed command parser; tracked by govulncheck.
