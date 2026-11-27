# RemoteHound device bootstrap

These scripts connect a computer to a RemoteHound server. Someone at the device runs one command.
The script makes a key, registers the device with a one-time code, and installs a small watchdog.
The watchdog keeps one outbound `ssh -R` tunnel to the server open. The server then reaches only the
forwarded local ports (SSH 22, RDP 3389, VNC 5900) through that tunnel. No inbound firewall port is
opened on the device.

| File | What it is |
|---|---|
| `bootstrap.sh` | Linux and macOS. POSIX `sh`: runs under dash, bash, zsh-as-sh and macOS `/bin/sh`. |
| `bootstrap.ps1` | Windows. Windows PowerShell 5.1 and PowerShell 7. Pure ASCII, safe for `irm \| iex`. |
| `test/run.sh` | Test harness (syntax, PowerShell parse, functional run against `test/fake_server.py`, watchdog tests). |
| `embed.go` | Embeds the scripts into the server binary (owned by the server, not described here). |

The server serves these files at `GET /e/{code}`. It replaces exactly two placeholders: the base URL
and the code. The contract is [`docs/specs/CLIENT_PROTOCOL.md`](../docs/specs/CLIENT_PROTOCOL.md)
(v1). If you change a script, keep it in step with that spec.

## What the person at the device runs

```sh
# Linux / macOS (add sudo for a system-wide install that starts at boot)
curl -sL https://rh.example.com/e/k7q2mx | sh
curl -sL https://rh.example.com/e/k7q2mx | sudo sh
```

```powershell
# Windows (open PowerShell with "Run as administrator" for the full install)
irm https://rh.example.com/e/k7q2mx | iex
```

### Read it before you run it

Downloading the script does **not** use up the code. Only the registration step does. So you can
read the script first:

```sh
curl -sL https://rh.example.com/e/k7q2mx | less          # or: > rh.sh, read it, then: sh rh.sh
```

```powershell
irm https://rh.example.com/e/k7q2mx.ps1                  # prints it; or save with -OutFile rh.ps1
```

Each script starts with a comment block. It says what the script does, what it writes and how to undo
it. Every stage is commented inline.

## The six stages

1. **Check.** OS and version, admin/root, hostname (cut down to `[A-Za-z0-9._-]`), and which services
   answer on `127.0.0.1` within 1 s. Missing `ssh`/`ssh-keygen` (or curl/wget) stops here with a
   clear message.
2. **Key.** `ssh-keygen -t ed25519` writes `id_ed25519.new` in the RemoteHound folder. The private key
   is never printed, logged or sent. It replaces the current key only after the server accepts it, so
   a failed or refused enrollment leaves a working install untouched.
3. **Register.** `POST /api/v1/enroll` with the code, public key, hostname, OS, OS version and
   services. Every field of the answer is validated before it is used in a file or a command:
   - `device_id` must match `^dev_[a-z0-9]{6,40}$`
   - `ssh_host` must be hostname characters and must not start with `-`
   - `ssh_port` must be 1-65535
   - each forward must match `^[0-9]{1,5}:localhost:[0-9]{1,5}$`
   - `known_hosts_line` must be `host` or `[host]:port`, a key type, and base64
   Error answers (problem+json) print their `detail`. Nothing from the server is ever passed to `eval`.
4. **Services.** These need admin. Each one is skipped with an explanation when it can't be done.
   - Linux: `systemctl enable --now ssh|sshd` if that unit is installed. For GNOME, `grdctl rdp enable`
     runs as your desktop user (it is per-user); as root it prints the commands to run instead.
     For KDE it prints a hint.
   - macOS: `systemsetup -setremotelogin on`. Then it opens System Settings → Sharing so you can turn
     on Screen Sharing (a script cannot do that).
   - Windows: sets `fDenyTSConnections=0` (not on Home editions). It can also add the OpenSSH Server:
     it asks first (default no) or reads `$env:RH_SSHD=1`. It never enables the "Remote Desktop"
     firewall rule.
   Packages are never installed.
5. **Install.** Writes the files below and the supervisor entry, then starts it.
6. **Confirm.** Polls `GET /api/v1/enroll/status` every 2 s for up to 60 s. Prints
   `Connected as <name> ✓`. On a timeout it prints the last 10 log lines; `bootstrap.sh` then exits
   with status 2.

Running the command again with a new code is safe. It reuses the folder, makes a new key, and
replaces `device.conf`, `known_hosts`, the scripts and the supervisor entry. It also clears a
`revoked` state.

## Files written

| OS | Admin / root | Not admin |
|---|---|---|
| Linux | `/etc/remotehound/` + `/etc/systemd/system/remotehound-tunnel.service` | `~/.config/remotehound/` + `~/.config/systemd/user/remotehound-tunnel.service` |
| macOS | `/Library/Application Support/RemoteHound/` + `/Library/LaunchDaemons/net.remotehound.tunnel.plist` | `~/Library/Application Support/RemoteHound/` + `~/Library/LaunchAgents/net.remotehound.tunnel.plist` |
| Windows | `%ProgramData%\RemoteHound\` + Scheduled Task `RemoteHound Tunnel` (SYSTEM, at startup + every 5 min) | `%LOCALAPPDATA%\RemoteHound\` + Scheduled Task `RemoteHound Tunnel` (your user, at logon + every 5 min) |

Contents of the folder (mode 700 on Unix; on Windows, inheritance is removed and only
SYSTEM + Administrators, or you + SYSTEM, have access):

| File | Purpose |
|---|---|
| `id_ed25519`, `id_ed25519.pub` | The device key. Private key mode 600 on Unix. On Windows: SYSTEM + Administrators (owner Administrators), or you + SYSTEM. OpenSSH refuses a key that others can read. |
| `known_hosts` | The one pinned server host key line (`StrictHostKeyChecking=yes`). |
| `device.conf` | `KEY=VALUE`: `RH_BASE_URL`, `RH_DEVICE_ID`, `RH_SSH_HOST`, `RH_SSH_PORT`, `RH_FORWARDS`, `RH_CLIENT_VERSION`, plus `RH_OS` and `RH_SERVICES` (used for the `agent v1` facts). It is parsed, never sourced. |
| `tunnel.sh` / `tunnel.ps1` | The watchdog (see below). |
| `tunnel.log` (+ `tunnel.log.1`) | `<RFC3339 UTC> <LEVEL> <message>`. Rotated at 1 MB; one old copy is kept. |
| `state` | Contains `revoked` after the server revoked the device. |
| `uninstall.sh` / `uninstall.ps1` | Removes everything listed here. |
| `ssh_config` (Windows only) | Empty file passed as `-F`, so your own ssh settings cannot change the tunnel. The Unix watchdog uses `-F /dev/null`. |
| `tunnel.pid` (Unix) | PID of the running watchdog. Used by re-enrollment and uninstall when no service manager exists. |

### The watchdog

The watchdog runs `ssh -T -R … <device_id>@<host> agent v1 os=… ver=… host=… services=…`, using
exactly the options in protocol §4. While it runs:

- **stdin**: the last 50 lines of `tunnel.log`, then EOF. Heartbeat `server: ping` lines are left
  out so they don't push real events out of the tail.
- **stdout**: the server's control lines. Each one is appended to the log as `server: <line>`.
- **revoked**: when the server's last control line in a session is `revoked`, the watchdog writes
  `revoked` to `state` and exits 0. The supervisor treats that as "stay down":
  - systemd: `Restart=always` + `RestartPreventExitStatus=0`
  - launchd: `KeepAlive.SuccessfulExit=false`
  - Windows: the task is disabled, and any later run exits at once.
- **Backoff**: starts at 2 s and doubles to a 300 s cap after each short session. A random jitter
  of 0 to backoff/2 is added. A session longer than 60 s resets the backoff to 2 s.
- **Stopping**: SIGTERM, SIGINT or SIGHUP kills ssh, logs `stopping (SIGTERM)`, and the watchdog
  then exits by that same signal. On Windows, a `finally` block kills ssh, and stale ssh processes
  using this key are killed when the watchdog starts.

## Uninstall

```sh
sh "/Library/Application Support/RemoteHound/uninstall.sh"     # macOS, installed with sudo → prefix sudo
sh ~/.config/remotehound/uninstall.sh                           # Linux, user install
sudo sh /etc/remotehound/uninstall.sh                           # Linux, root install
```

```powershell
powershell -ExecutionPolicy Bypass -File "$env:ProgramData\RemoteHound\uninstall.ps1"   # elevated
powershell -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\RemoteHound\uninstall.ps1"  # user install
```

The uninstaller stops the tunnel, removes the service entry and deletes the folder. It leaves sshd,
Remote Login, Screen Sharing, GNOME Remote Desktop, RDP and OpenSSH Server as they are, and says so.
Turn those off yourself if you don't need them. Deleting the device in the RemoteHound UI also stops
the tunnel (it is revoked), but the files stay until you run the uninstaller.

## Troubleshooting

Start with the log: `tunnel.log` in the folder above.

- **"Permission denied (publickey)"** in the log: the device was deleted, or its key changed on the
  server. Run the enroll command again with a new code.
- **"Host key verification failed"**: the server's host key changed. Re-enroll to pin the new key.
- **"remote port forwarding failed"**: the server refused a forward that is not one of the device's
  services. The watchdog retries with backoff. Add the service in the UI, or re-enroll.
- **macOS: "requires Full Disk Access"** when turning on Remote Login: open System Settings → Privacy &
  Security → Full Disk Access and turn on your terminal app. Or switch on System Settings → General →
  Sharing → Remote Login by hand.
- **macOS Screen Sharing**: a script cannot switch it on. Use System Settings → General → Sharing →
  Screen Sharing. The operator signs in with a user name and password from this Mac.
- **Windows Home**: it has no Remote Desktop server, so RDP is skipped. Use SSH (OpenSSH Server) or a
  VNC server instead, or upgrade to Pro.
- **Windows: "OpenSSH Client is not installed"**: Settings → System → Optional features → Add a feature
  → OpenSSH Client. Or, as admin: `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`.
- **Windows: old PowerShell can't download the script** (TLS error): run
  `[Net.ServicePointManager]::SecurityProtocol = 'Tls12'` first, then the command again.
- **Linux, installed without sudo**: the systemd *user* unit stops when you log out. To keep it
  running, an admin runs `sudo loginctl enable-linger <user>`. Or re-run the command with `| sudo sh`.
- **Linux without systemd** (some containers, Alpine/OpenRC): the watchdog is started with `nohup`
  and won't survive a reboot. The script prints the `@reboot` crontab line that fixes this.
- **GNOME Remote Desktop** listens only while that user's desktop session is running. Set the
  credentials with `grdctl rdp set-credentials <user> <password>`.
- **Corporate proxies / firewalls**: registration uses HTTPS (curl/wget and `Invoke-RestMethod`
  honour the usual proxy settings). The tunnel itself is plain SSH to the server's SSH port (often
  2222), and v1 does not tunnel it through an HTTP proxy. If outbound traffic to that port is
  blocked, ask for it to be allowed, or have the server's SSH listener on 443.
- **"Could not reach …"**: check DNS, the proxy, and that the server's certificate is valid. The
  scripts never disable TLS verification.

## Security notes

- The private key is created on the device and never leaves it. It is never printed, logged or sent.
  The tests check that no output, log, request or log upload contains private-key material.
- Every file is created with `umask 077`.
- Windows: ordinary users can create folders in `%ProgramData%`, so an attacker could create
  `RemoteHound` before the first install. `bootstrap.ps1` only reuses an existing folder if it already
  looks exactly like one it creates (`Test-RhTrustedDirectory`):
  - the owner is SYSTEM or Administrators (in user mode, you)
  - the DACL is protected and names no other SID
  - nothing inside it is a junction or symlink
  Any other folder is renamed to `RemoteHound.untrusted-<UTC time>`, with a warning. A new folder is
  created with its protected DACL in a single step. Every file is deleted and recreated, so it can
  only inherit that DACL. The key gets its own protected DACL. If the ACLs read back show any
  unexpected owner or SID, the install stops before the Scheduled Task is registered.
- The server's host key is pinned from the enrollment answer (`StrictHostKeyChecking=yes`, our own
  `known_hosts`, `-F /dev/null` so user and system ssh config cannot change behavior).
- Server answers are validated with strict patterns before use. JSON is parsed by a small awk parser
  (no `eval`, no `source`). On macOS, `python3` can be just a stub that pops up an installer, so it
  isn't used. Text from the server that is shown or logged has control characters removed, which
  blocks terminal escape injection.
- The SSH session can only do the `agent v1` command and the listed `-R` forwards. The server rejects
  shells, PTYs, agent and X11 forwarding, and local forwards.
- Stage 4 never opens firewall ports. RDP, SSH and VNC are reachable only through the tunnel from
  the server. (When the script installs the Windows OpenSSH Server, it disables the inbound rule that
  feature creates.)
- The `RH_TEST_*` variables exist only for `test/run.sh`. They change paths and skip system changes.
  They cannot widen what the script accepts from the server.

## Tests

```sh
sh client/test/run.sh                    # every shell found: sh, dash, bash, zsh --emulate sh
RH_SHELLS="sh dash" sh client/test/run.sh
KEEP=1 sh client/test/run.sh             # keep the temp dir for inspection
```

Needs `python3` (fake server) and `ssh-keygen`. `pwsh` is optional, for the PowerShell parse checks.
Each result line is `PASS @feature:enroll …` or `FAIL @feature:enroll …`.

The tests do not cover the real systemd/launchd/Scheduled Task registration, stage 4 service
changes, or a real SSH connection. Those need a disposable VM per OS.
