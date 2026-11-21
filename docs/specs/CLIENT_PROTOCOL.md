# Client protocol (bootstrap scripts ⇄ server)

Version: **v1**. The bootstrap scripts in `client/` and `internal/enroll` + `internal/tunnel` implement
this. Changing anything here is a breaking change for every enrolled device: bump the version and keep
v1 working (API-2).

## 1. Script delivery

- `GET /e/{code}` → the server reads `client/bootstrap.sh` or `client/bootstrap.ps1` (embedded), and
  replaces exactly two placeholders:
  - `__RH_BASE_URL__` → the public base URL from settings, e.g. `https://rh.example.com` (no trailing slash)
  - `__RH_CODE__` → the code (already validated against `^[a-hjkmnp-z2-9]{6}$`)
- PowerShell is chosen when the User-Agent contains `PowerShell` (Windows PowerShell 5.1 and pwsh both
  send it), or the path ends `.ps1`. Otherwise sh.
- Unknown or expired code → a tiny script that prints `RemoteHound: this code is not valid or has
  expired. Ask for a new one.` and exits 1. The code is **not** consumed by this GET.

## 2. Redeem

`POST {base}/api/v1/enroll` with JSON (see `api/openapi.yaml` → `EnrollRequest`):
```json
{"code":"k7q2mx","public_key":"ssh-ed25519 AAAA... rh","hostname":"laptop1","os":"macos",
 "os_version":"15.1","services":[{"kind":"ssh","remote_port":22},{"kind":"vnc","remote_port":5900}],
 "client_version":"1","install_scope":"user","install_user":"alice"}
```
`install_scope` is `system` (installed as root / Administrator: starts at boot) or `user` (one account's
logins only); `install_user` names that account and is sent only with `user`. Both are optional: an
older script omits them and the device shows the install type as not reported. Other values are dropped.
Response `201 {"data": EnrollResult}`:
```json
{"device_id":"dev_8f3k…","device_name":"laptop1","ssh_host":"rh.example.com","ssh_port":2222,
 "known_hosts_line":"[rh.example.com]:2222 ssh-ed25519 AAAA…",
 "forwards":["22:localhost:22","5900:localhost:5900"],"fingerprint":"SHA256:…"}
```
Errors are problem+json with `code`: `ENROLL_CODE_INVALID` (404), `ENROLL_CODE_USED` (410),
`ENROLL_CODE_EXPIRED` (410), `ENROLL_WRONG_OS` (400: the code is for another OS; not consumed), `ENROLL_KEY_INVALID` (400), `RATE_LIMITED` (429). Scripts print `detail`.

Service detection the scripts do before redeeming (localhost TCP connect, 1 s timeout):
`ssh` 22 · `rdp` 3389 · `vnc` 5900. Services that were just enabled by stage 4 are included even if not
yet listening. If nothing is detected, send `ssh:22` anyway (the operator can add services later).

## 3. Files written on the device (nothing else is installed)

| OS | Root / admin | Not admin |
|---|---|---|
| Linux | `/etc/remotehound/` + systemd system unit `remotehound-tunnel.service` | `~/.config/remotehound/` + systemd **user** unit (prints the `loginctl enable-linger` hint) |
| macOS | `/Library/Application Support/RemoteHound/` + LaunchDaemon `/Library/LaunchDaemons/net.remotehound.tunnel.plist` | `~/Library/Application Support/RemoteHound/` + LaunchAgent `~/Library/LaunchAgents/net.remotehound.tunnel.plist` |
| Windows | `%ProgramData%\RemoteHound\` + Scheduled Task `RemoteHound Tunnel` (SYSTEM, at startup + every 5 min, IgnoreNew) | `%LOCALAPPDATA%\RemoteHound\` + Scheduled Task for the current user at logon |

Directory contents: `id_ed25519` (+ `.pub`; private key mode 600 / Windows ACL owner+SYSTEM only —
OpenSSH refuses keys readable by others), `known_hosts` (the pinned line), `device.conf` (KEY=VALUE:
`RH_BASE_URL`, `RH_DEVICE_ID`, `RH_SSH_HOST`, `RH_SSH_PORT`, `RH_FORWARDS` space-separated,
`RH_CLIENT_VERSION`), `tunnel.sh`|`tunnel.ps1` (the watchdog), `tunnel.log` (rotated at 1 MB, keep 1),
`uninstall.sh`|`uninstall.ps1`.

## 4. The tunnel connection

```
<recent log> | ssh -T -i <dir>/id_ed25519 \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<dir>/known_hosts \
  -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o ConnectTimeout=15 \
  -p <RH_SSH_PORT> -R 22:localhost:22 -R 3389:localhost:3389 … \
  <RH_DEVICE_ID>@<RH_SSH_HOST> agent v1 os=<os> ver=<client_version> host=<hostname> services=<kind:port,…>
```
- Username = device id. Auth = public key only.
- **stdin** = the last 50 lines of `tunnel.log` (then EOF). The server stores them as the device's client
  log tail (max 200 lines, each truncated to 500 chars, control chars stripped).
- **stdout** = control lines from the server, one per line, appended to `tunnel.log`:
  - `ok <device_id>` — accepted; forwards bound.
  - `ping` — informational heartbeat (every 60 s).
  - `reconnect` — server asks the client to reconnect (session will be closed by the server).
  - `revoked` — the device was disabled or deleted. The watchdog must **stop** (exit 0 and not restart):
    it writes `revoked` into `<dir>/state` and the supervisor sees it and stays down.
- The requested remote bind port is the **service identity**, not the server port. The server binds its
  own internal port. Allowed: the ports in the device's `services`. Anything else is refused (and with
  `ExitOnForwardFailure=yes` ssh exits — the watchdog logs it and retries with backoff).
- Exec of anything other than `agent v1 …`, shell, pty, X11, agent forwarding and `direct-tcpip`
  (local forwards) are rejected.

## 5. Watchdog behaviour (self-healing)

```
backoff = 2
loop:
  if state file says revoked: exit 0
  start = now
  run the ssh command above (blocking)
  rc = exit code; log "ssh exited rc=<rc>"
  if tunnel.log's last control line is "revoked": write state=revoked; exit 0
  if now - start > 60: backoff = 2            # it was a healthy session; reconnect fast
  else: backoff = min(backoff * 2, 300)
  sleep backoff + random(0..backoff/2)        # jitter
```
Log lines: `<RFC3339 UTC> <LEVEL> <message>`, never the private key, never full environment.
The supervisor restarts the watchdog if it dies (systemd `Restart=always RestartSec=5`, launchd
`KeepAlive` + `ThrottleInterval 10`, Windows task repeats every 5 min with `MultipleInstances IgnoreNew`).

## 6. Stage 4 — enabling built-in services (needs admin; each step skips with a clear message otherwise)

- **Linux**: start/enable `sshd`/`ssh` via systemctl if installed. GNOME: `grdctl rdp enable` (+ hint
  that credentials must be set with `grdctl rdp set-credentials`, which needs the user's session). KDE: hint
  for krdp. Never install packages.
- **macOS**: `systemsetup -setremotelogin on` (may need Full Disk Access for Terminal — print how). Screen
  Sharing cannot be turned on from a script on current macOS: open
  `x-apple.systempreferences:com.apple.Sharing-Settings.extension` and print the one toggle to flip.
- **Windows**: `Set-ItemProperty HKLM:\System\CurrentControlSet\Control\Terminal Server -Name fDenyTSConnections 0`
  (Pro/Enterprise only — detect Home via `(Get-CimInstance Win32_OperatingSystem).Caption` and skip RDP with an
  explanation). Optional OpenSSH Server via `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`.
  **Do not** enable the "Remote Desktop" firewall rule: the tunnel connects to localhost, so RDP stays
  closed to the LAN.

## 7. Status poll (stage 6)

`GET {base}/api/v1/enroll/status?device_id=…&fingerprint=…` every 2 s for up to 60 s →
`{"data":{"online":true,"forwards":["22:localhost:22"]}}`. Print `Connected as <name> ✓` or, on timeout, the
last 10 lines of `tunnel.log` and where to find it.

## 8. Uninstall

`uninstall.sh|ps1` in the directory: stop + remove the supervisor entry, delete the directory. It does
not disable sshd/RDP (the person may rely on them) but says so.
