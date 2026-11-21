# ADR-0004 — Container control through a separate helper (rh-control)

Status: accepted (2026-11-21)

## Context
Admins want to see whether Guacamole, guacd and RemoteHound are running and to start, stop or restart
them from the Services screen, with their recent errors. Status needs nothing special: RemoteHound
probes its own parts and the Guacamole checker already tests every hop. **Control and container logs
need the Docker Engine API, and the Docker socket is root on the host.** RemoteHound is internet-facing
(sign-in, enrolment, the Guacamole proxy), so handing it the socket would turn any RemoteHound bug into
control of every container on the machine — on a shared host, every other service too.

## Decision
- A second process from the same image, `remotehound control` (**rh-control**), in its own container,
  is the only thing that holds the socket. It is optional (compose profile `control`, off by default).
- It has no published port and sits on an internal network shared only with remotehound. Every request
  except `/healthz` needs the shared `RH_CONTROL_TOKEN` (≥ 32 chars, constant-time compare).
- It acts **only** on containers the operator labelled `io.remotehound.control.service=<name>`, and only
  with the actions listed in `io.remotehound.control.actions` (subset of start, stop, restart, logs).
  The allowlist is enforced in the helper, not only in RemoteHound.
- It returns a fixed view of each container (state, health, restarts, image, timestamps). It never
  decodes `Config.Env`, `Cmd` or mounts, so container secrets cannot leave it.
- RemoteHound authorises the person (`services.read` / `services.control`, admins only), refuses
  anything but *restart* for itself, rate-limits, audits every action (`service.action`) and redacts
  container log lines before showing them.
- The Docker client is ~150 lines over the unix socket, not the Docker SDK (ADR-0002: one dependency).

## Consequences
+ A RemoteHound compromise yields, at most: restart/stop/start/logs of the labelled bundle containers.
  It cannot exec, create, inspect environments, or touch unlabelled containers.
+ Status works with no Docker access at all; control is a deliberate opt-in.
− A compromise of rh-control itself is a host compromise. Mitigations: tiny surface (four routes),
  no inbound network path but remotehound's, non-root user in the socket's group, read-only root,
  no capabilities. Recorded in STANDARD_EXCEPTIONS and THREAT_MODEL (TB-6).
− Operators must keep the labels in their compose file; an unlabelled container simply has no buttons.
