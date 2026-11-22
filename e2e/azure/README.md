# Azure end-to-end suite

`run.sh` tests RemoteHound on real machines, unattended. It builds the bundle from this
checkout's `HEAD` on an Azure VM, enrols Windows and Linux clients with the script-free
ssh commands ([ADR-0005](../../docs/adr/0005-scriptless-enrolment.md)), and checks the
result through the API, Guacamole and a browser. It creates **one** resource group and
deletes it at the end, also when a step fails or you press Ctrl+C.

```bash
az login                      # once
cd e2e && npm ci && cd ..     # once, for the browser stage (uses your installed Chrome)
e2e/azure/run.sh
```

Exit code 0 means every check passed. Results are in `e2e/azure/out/<run id>/results.txt`,
with screenshots and each device's terminal output next to it.

## What it covers

| Machine | OpenSSH | Checks |
|---|---|---|
| Ubuntu 22.04 | 8.9 | Install code with a key, reconnect command, SSH probe, Guacamole SSH token, browser session |
| Ubuntu 18.04 | 7.6 | Install code + reconnect; one-time code, session end, code used up, second session not flagged as a duplicate |
| Windows Server 2019 | 9.5 (built in) | Install code + reconnect; one-time code, RDP probe, Guacamole RDP token, browser session |
| Windows Server 2019 | 7.7 (Microsoft's portable zip, checksum pinned) | Install code + reconnect; one-time code |
| Windows Server 2019 | – | A code for another OS is refused in the person's window and not used up; the cmd line pasted into PowerShell runs nothing |

Every device check compares the server's view (transport, OS, hostname, ssh client
version, online) with what the person's terminal showed, including the connection code.
The browser stage then opens the device pages, runs **Diagnostics → Run probe**, clicks
**Connect RDP** and **Connect SSH** until Guacamole draws a picture, checks the
"session has ended" banner, and runs the whole walkthrough suite (`e2e/walk/`).

Windows commands run in `cmd.exe` as the ordinary admin user with a real profile, over
WinRM from the server VM (`winrm_hold.py`), which keeps the session open the way a
person leaves the window open. Linux commands run as a normal user in bash.

## Safety

- The UI is never exposed: the bundle's Caddy listens on the server's loopback and the
  suite reaches it through an SSH tunnel. That matters, because the bundle runs the
  TEST-ONLY e2e overlay, which signs every request in as admin.
- Firewall: SSH to the server from your public IP only; the tunnel port 2222 from the
  VNet only; the client VMs accept no inbound traffic.
- Keys and passwords are generated per run in a temporary folder, never printed, and
  deleted at exit.

## Cost and time

Four B-series VMs for about 30–40 minutes: well under USD 1 per run. Most of the time
is building the bundle's images on the server.

## Options

| Variable | Default | |
|---|---|---|
| `RH_E2E_LOCATION` | `westus2` | Azure region |
| `RH_E2E_CALLER_IP` | looked up | Your public IPv4, for the server's SSH rule |
| `RH_E2E_PORT` | `9443` | Local tunnel port for the UI (`+1` is the operator view) |
| `RH_E2E_BROWSER` | `1` | `0` skips the browser stage |
| `RH_E2E_KEEP` | `0` | `1` keeps the resource group to debug; delete it with `az group delete -n <name>` |
| `RH_E2E_OUT` | `e2e/azure/out/<run id>` | Results folder |

## Not covered

A person typing into an interactive Windows console (the line runs through `cmd.exe /c`,
which parses it the same way), Windows 10/11 desktop, macOS clients, and EDR products.
