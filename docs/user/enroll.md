# Enroll a device

Enrollment adds a machine to RemoteHound with one short command typed on that machine. The usual command downloads a script that uses the operating system's own `ssh`, creates a key on the device, and sets up a background service that keeps the tunnel open. Where scripts are blocked, a command that runs no script is offered too (see below).

## Create a code

1. Optionally type a **Device name**. If you leave it empty, the hostname the device reports is used.
2. Pick a **Group**. Only groups that exist can be picked; create one on the [Groups](/docs/groups) screen first if you need it.
3. Optionally pick the **Machine type** (macOS, Linux or Windows). A machine reporting a different OS is refused and the code stays usable, so a command pasted on the wrong machine cannot enroll it.
4. Pick the **Connection type**: **Install: stays connected** (the default) or **One-time: nothing installed** (see [No script: type an ssh command](#no-script-type-an-ssh-command)).
5. Choose how long the **Code valid for** (15 minutes by default).
6. Select **Create code**.

The six-character code is shown once. It works for one device only and expires at the time shown.

## Type the command on the device

Pick the operating system tab, then the **Install type**. Both are shown; **Permanent** is selected first.

| Install type | macOS / Linux | Windows | What you get |
|---|---|---|---|
| **Permanent** (recommended) | `curl -fsSL https://rh.example.com/e/k7q2mx \| sudo sh` in Terminal; enter your password when `sudo` asks | `irm https://rh.example.com/e/k7q2mx \| iex` in PowerShell opened with **Run as administrator** | The tunnel starts at boot and runs when nobody is logged in. The script can turn on SSH, Screen Sharing or Remote Desktop for you. |
| **Temporary** | the same command without `sudo` | the same command in an ordinary PowerShell window | No admin rights needed. The tunnel runs only while you are logged in, and the script tells you which services to switch on yourself. |

The script tells the server which one it ran, and **Devices** shows it in the **Install** column (and as **Install type** on the device page): **Permanent**, **Temporary · *user***, or **Not reported** for devices enrolled by an older script.

To make a temporary install permanent, open the device and choose **Make it permanent** (or create a new code), then run the permanent command. On macOS and Linux the script removes the per-user install; the old entry shows **Check identity** (enrolled twice) so you can delete it.

## Setup guide for the person at the machine

For a **macOS** or **Windows** code (or **Any**) with **Install: stays connected**, the code panel has a **Setup guide** button. It opens a printable guide in a new tab, already filled in with this code, the commands for your server, the device name and when the code expires. With a machine type set, it shows only that system's pages. Print it, or choose **Save as PDF** as the printer and send the file.

The guide walks the person through everything they do at the machine: the settings to change first (Screen Sharing and keeping a Mac awake; keeping a PC awake and signing in with a password rather than only a PIN), the command, what the window shows, problems and how to remove RemoteHound. It covers the **Permanent** install only.

The code is handed to the new tab inside the browser, never in its address, so it stays out of the browser history. If your browser blocks the new tab, allow pop-ups for RemoteHound. A blank copy, with a box to write the code in, is at `/ui/guide/device-setup.html` on your server.

## No script: type an ssh command

Security software (Microsoft Defender, EDR/XDR, a managed-detection service) often blocks the install script, or isolates the machine after it runs: downloading and running a script, a hidden scheduled task and registry changes look like malware. For those machines, RemoteHound also offers a command that **runs no script**: it uses the `ssh` client already on the machine, with the code as the user name.

- **Install** codes show a **No script (ssh)** tab. The command makes a key in `~/.remotehound/<server>-<port>` (a folder per RemoteHound server) and connects with it. When it connects, the window prints a **reconnect command** to use later without a new code. Nothing restarts the tunnel after a reboot or a network change: run the reconnect command again.
- **One-time** codes show only the ssh commands. No key and no file other than the server's pinned key (`known_hosts` in that same folder). The session lasts while the window stays open; closing it (or Ctrl+C) ends it, and the device cannot reconnect. A new session needs a new code, and shows as a new device you can delete afterwards. Finished one-time sessions on the same machine are not flagged as **enrolled twice**; a live one, or an installed device on that machine, still is. The install scripts refuse one-time codes.

| | macOS / Linux | Windows |
|---|---|---|
| Where to paste | Terminal | **Command Prompt**. In PowerShell, type `cmd` and press Enter first. |
| What it needs | the built-in `ssh` | the built-in `ssh`: Windows 10 1809 or later, Windows 11, Windows Server 2019 or later. Windows Server 2016 and older have no ssh client: use the PowerShell script, or Microsoft's portable Win32-OpenSSH. |
| Services | SSH (Remote Login) or Screen Sharing must already be on | Remote Desktop must already be on |

The command first saves the server's key, so ssh never asks "Are you sure you want to continue connecting?". The page shows the key's fingerprint if you want to compare it.

**Which machine is it?** The device takes its name and group from the code. RemoteHound also records the address it connects from, its ssh version (for example `OpenSSH_for_Windows_9.5`), and the hostname and OS that the person's shell fills in. Those last two are reported by the machine, not proven. While the session is live, the person's window and the device page both show a four-character **Connection code**: ask them to read it out to be sure you are on the right machine.

**Will security software still notice?** Possibly. There is no download, no script, no service and no registry change, but `ssh` opening a reverse tunnel (`-R`) matches some detection rules. Tell your security team to expect `ssh.exe` / `ssh` connecting to your RemoteHound server on port 2222.

## Wait for it to join

Keep the Enroll page open. It shows **Waiting for the device…** and checks every three seconds. When the device's tunnel connects, the page shows that it joined and links to the device.

## Managing codes

The list under the wizard shows every code: *Open* (still usable), *Used* (a device enrolled with it) or *Expired*, and who created it.

- **Edit** an open code to fix the device name, group or machine type before it is used. The code itself stays the same.
- **Revoke** an open code you no longer need: nobody can enroll with it after that.
- **Delete** a used or expired code to remove it from the list. A device it enrolled stays.
- **Clear used & expired** removes every used and expired code you can manage in one go. Open codes stay.

Used and expired codes cannot be edited; create a new code instead.

## Troubleshooting

> Codes use letters and digits that cannot be confused: there is no 0, o, 1, l or i.

- **"This code is not valid or has expired."** The code was mistyped, already used, revoked or expired. Create a new one.
- **"RemoteHound is busy … try again in a minute."** Too many wrong codes were tried recently from this network (or, during an attack, from everywhere). Your code was not checked and is still good: wait a minute and run the same command again.
- **Waiting never finishes.** The device must reach the SSH tunnel port (2222 by default). Look at the last lines the script printed, then at the device's **Client logs**.
- **macOS asks for Full Disk Access.** Turning on Remote Login from a script needs it for Terminal. The script prints where to grant it.
- **"This code is for a … machine, but this one reports …"** (`ENROLL_WRONG_OS`). The code was made for another kind of machine. Run it on the right one, or create a code for this OS. The code was not used up.
- **The ssh command says "Host key verification failed".** Run the whole command again exactly as copied (its first part saves the server's key). If it still fails, the SSH host or port in Settings does not match where the machine connects.
- **Windows prints `The ampersand (&) character is not allowed` or `The token '&&' is not a valid statement separator`.** That is PowerShell; nothing was run. Type `cmd`, press Enter, and paste again.
- **"RemoteHound could not connect this machine: …"** The ssh window shows why (wrong machine type, code used or expired). For a wrong machine type the code is still usable.
- **Re-running on an enrolled machine** with a new code is safe and replaces the old registration on the machine. RemoteHound keeps the old entry, which shows **Check identity** (enrolled twice): delete the one you no longer use.
