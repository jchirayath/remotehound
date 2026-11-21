# Enroll a device

Enrolment adds a machine to RemoteHound with one short command typed on that machine. Nothing is installed: the command downloads a script that uses the operating system's own `ssh`, creates a key on the device, and sets up a background service that keeps the tunnel open.

## Create a code

1. Optionally type a **Device name**. If you leave it empty, the hostname the device reports is used.
2. Pick a **Group**. Only groups that exist can be picked; create one on the [Groups](/docs/groups) screen first if you need it.
3. Optionally pick the **Machine type** (macOS, Linux or Windows). A machine reporting a different OS is refused and the code stays usable, so a command pasted on the wrong machine cannot enrol it.
4. Choose how long the **Code valid for** (15 minutes by default).
5. Select **Create code**.

The six-character code is shown once. It works for one device only and expires at the time shown.

## Type the command on the device

Pick the operating system tab, then the **Install type**. Both are shown; **Permanent** is selected first.

| Install type | macOS / Linux | Windows | What you get |
|---|---|---|---|
| **Permanent** (recommended) | `curl -fsSL https://rh.example.com/e/k7q2mx \| sudo sh` in Terminal; enter your password when `sudo` asks | `irm https://rh.example.com/e/k7q2mx \| iex` in PowerShell opened with **Run as administrator** | The tunnel starts at boot and runs when nobody is logged in. The script can turn on SSH, Screen Sharing or Remote Desktop for you. |
| **Temporary** | the same command without `sudo` | the same command in an ordinary PowerShell window | No admin rights needed. The tunnel runs only while you are logged in, and the script tells you which services to switch on yourself. |

The script tells the server which one it ran, and **Devices** shows it in the **Install** column (and as **Install type** on the device page): **Permanent**, **Temporary · *user***, or **Not reported** for devices enrolled by an older script.

To make a temporary install permanent, open the device and choose **Make it permanent** (or create a new code), then run the permanent command. On macOS and Linux the script removes the per-user install; the old entry shows **Check identity** (enrolled twice) so you can delete it.

## Wait for it to join

Keep the Enroll page open. It shows **Waiting for the device…** and checks every three seconds. When the device's tunnel connects, the page shows that it joined and links to the device.

## Managing codes

The list under the wizard shows every code: *Open* (still usable), *Used* (a device enrolled with it) or *Expired*. Select **Revoke** on an open code you no longer need.

## Troubleshooting

> Codes use letters and digits that cannot be confused: there is no 0, o, 1, l or i.

- **"This code is not valid or has expired."** The code was mistyped, already used, revoked or expired. Create a new one.
- **Waiting never finishes.** The device must reach the SSH tunnel port (2222 by default). Look at the last lines the script printed, then at the device's **Client logs**.
- **macOS asks for Full Disk Access.** Turning on Remote Login from a script needs it for Terminal. The script prints where to grant it.
- **"This code is for a … machine, but this one reports …"** (`ENROLL_WRONG_OS`). The code was made for another kind of machine. Run it on the right one, or create a code for this OS. The code was not used up.
- **Re-running on an enrolled machine** with a new code is safe and replaces the old registration on the machine. RemoteHound keeps the old entry, which shows **Check identity** (enrolled twice): delete the one you no longer use.
