# ADR-0005 — Script-free enrollment over SSH (attended and keyed)

Status: accepted (2026-11-22)

## Context
The bootstrap scripts (`curl … | sh`, `irm … | iex`) are what endpoint security products (Defender,
EDR/XDR, MDR) react to: a download cradle, AMSI-scanned script text, a hidden PowerShell scheduled task
with `-ExecutionPolicy Bypass`, registry and firewall changes. On managed machines the script is often
blocked, or the host is isolated afterwards. Many support cases only need a session *now* and never
need the machine to start a tunnel at boot — and that boot persistence is the part that needs a script.

## Decision
Add an enrollment path that runs no script: the person types an `ssh` command (OpenSSH is built into
Windows 10 1809+ / Server 2019+, macOS and Linux) and the enrollment code is the SSH credential.

- **The code carries a mode**, chosen by the operator when creating it:
  - `persistent` (default, unchanged): the bootstrap scripts, **or** `ssh` with an ed25519 key the
    person generated with `ssh-keygen`. On first login the server binds that key to a new device
    (transport `ssh-manual`); later logins are ordinary device logins (username = device ID).
  - `attended`: `ssh` with **no key**. The device (transport `ssh-attended`) has no key, so it can
    never log in again; the session lasts while the window is open. A code is single-use, so a new
    session needs a new code. Attended codes are refused by `/e/{code}` and `POST /api/v1/enroll`.
- **Authentication.** SSH username = the code. `attended` codes authenticate with the SSH `none`
  method; `persistent` codes only with `publickey` (ed25519), and only with proof of possession
  (x/crypto verifies the signature before the login succeeds). Every code login shares the HTTP
  path's wrong-code limiter (10/min per client, 300/min overall), so SSH adds no guessing budget.
  Because a valid code is refunded, a code holder is capped separately: 3 code lookups per TCP
  connection, 2 logins per code (64 in total) waiting for hello.
  Device-ID logins keep their exact current rules; `none` is refused for anything that is not a code.
- **Nothing is created until the device says hello.** After a code login, the server waits up to
  10 s for one session channel running `hello v1 os=… host=…` (or a bare shell request, treated as
  `hello` with no facts). Forward requests that arrive first are held, in order, and answered once the
  device exists. On hello the code is consumed and the device created in one store transaction —
  `ExpectedOS` refusals happen before that, so a wrong-machine attempt does not burn the code, as on
  the script path. The services are the `-R` ports from the held requests (22, 3389, 5900 only).
- **Identification.** The device takes name, group and creator from the code. The server records
  the source IP, the SSH client banner (`SSH-2.0-OpenSSH_for_Windows_9.5`), and the `os=` / `host=`
  facts, which the person's *own shell* expands (`%COMPUTERNAME%`, `$(hostname)`, `$(uname -s)`) —
  client-reported, as with the script. Each live manual tunnel gets a 4-character **connection
  code** shown in the person's terminal and on the device page, so an operator on the phone can
  confirm they are looking at the same machine.
- **Host key pinning, not TOFU.** The command first writes the server's `known_hosts` line to
  `~/.remotehound/<host>-<port>/known_hosts` (a folder per server, so enrolling one machine on two
  servers keeps both), then runs `ssh -o StrictHostKeyChecking=yes` against it. (A TOFU
  prompt also could not work: the 5 s pre-auth budget (D1) covers key exchange, and a person reading
  a fingerprint takes longer.)
- **What a manual tunnel may do** is the existing policy plus one exec form: `hello v1 …` is accepted
  for `ssh-manual` / `ssh-attended` devices instead of `agent v1 …` (each only on its own transport);
  a bare `shell` request is accepted as `hello` but no shell runs. Still refused: pty, X11, agent
  forwarding, env, subsystems, other exec, `direct-tcpip`, undeclared forwards. stdin is not read
  (it is the person's keyboard, not a log); the server writes plain-language status lines instead
  of `ok`/`ping`.

## Consequences
+ No download, no script, no service or scheduled task, no registry or firewall change: what endpoint
  security sees is `ssh.exe`/`ssh` making an outbound connection with `-R`. That still matches some
  rules (e.g. Sigma "Port Forwarding Activity Via SSH.EXE"); it is not hidden, and must not be.
+ An `attended` code cannot create lasting access: the device has no credential once the window
  closes. Operators can hand out attended codes with less risk than persistent ones.
− The code is now a credential on a second listener. Same entropy, TTL, single use and shared
  limiter (THREAT_MODEL S5); a code login holds a connection for at most 10 s before hello.
− Nothing restarts a manual tunnel: it drops with the network or a reboot. `ssh-manual` devices
  reconnect with the command the server prints; `ssh-attended` devices need a new code (and appear as
  a new device each time).
− Services must already be on (RDP, Remote Login, Screen Sharing): there is no stage 4.
− Windows commands are `cmd` syntax; PowerShell users type `cmd` first. Windows Server 2016 and older
  have no OpenSSH client: use the PowerShell script, or Microsoft's portable Win32-OpenSSH.
