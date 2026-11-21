# Debug

The Debug screen shows what the running server is doing. Use it together with [Logs](/docs/logs) when something misbehaves, and to gather information for a bug report.

## Runtime

Version and commit, Go version, start time and uptime, goroutines, heap, number of tunnels online, the SSH listener address, the sign-in mode and the state file location. A warning appears if the state file had to be restored from a backup at start-up.

## Log level

Change the server's log level immediately: **DEBUG**, **INFO**, **WARN** or **ERROR**. The change lasts until the next restart; the default after a restart is set in [Settings](/docs/settings). Set DEBUG while reproducing a problem, then return to INFO.

## Live tunnels

Every connected device, where it connected from, when, its last keepalive and its forwarded services. Expand a row to see each forward's device port, server port, open connections and traffic.

## Background jobs

Jobs such as the Guacamole health probe, state backups, retention clean-up and audit-chain verification. Each shows its schedule, status, last run, last success and next run. A failing job shows its last error. Select **Run now** to start a job immediately, for example after fixing its cause.

## Diagnostics bundle

**Download diagnostics** saves a JSON file with runtime facts, configuration (secrets redacted), job status, tunnel state and recent log records. Review it before attaching it to a bug report.

Only Admins can use this screen.
