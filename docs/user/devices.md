# Devices

The Devices screen lists every machine you can see. Open one to connect to it, change its details, manage its services or diagnose its tunnel.

## Finding a device

- **Search** matches the device name and the hostname it reported.
- **Presence**: *Online* devices have a live tunnel right now; *Offline* ones do not.
- **Status**: *Active* (normal), *Pending* (enrolled but never connected) or *Disabled* (blocked by an operator).
- **Group** and **OS** narrow the list further.

Filters are stored in the address bar, so you can bookmark or share a filtered view. Presence refreshes every 20 seconds. **CSV** and **JSON** export the rows currently loaded.

- The **Install** column shows how the enrolment script installed the tunnel: **Permanent** (starts at boot), **Temporary · *user*** (runs only while that user is logged in) or **Not reported** (older script). See [Enroll](enroll.md).

## Connecting

On the device page, each configured service has a **Connect** button: SSH, RDP or VNC.

- On a computer the session opens in a new tab; on a phone it opens in the same tab.
- A button is disabled when the device is offline, disabled, or not forwarding that service. The reason is shown on the button.
- The connection link is valid for about a minute. If a tab shows an expired link, select **Connect** again.

Viewers cannot connect; Operators and Admins can.

## Connecting as yourself

Below each Connect button, **Use my own login** opens a form for your personal username and password for that service. Once saved, Connect signs you in as yourself and the button shows *your login*. Your login is encrypted for you alone: nobody else — admins included — can read or use it. Manage all your saved logins on your [Profile](/docs/profile).

## Editing details

In the **Overview** tab, change the **Name**, **Group**, **Tags** and **Notes**, then select **Save changes**. If someone else saved a change after you opened the page, you are asked to **Reload** first, so nobody's edit is silently overwritten.

## Services

A service is a remote-access port on the device that the tunnel forwards:

- **SSH**: port 22.
- **RDP**: port 3389 (Windows Pro/Enterprise, or GNOME Remote Desktop on Linux).
- **VNC**: port 5900 (macOS Screen Sharing, or a VNC server on Linux).

For each service you can set the **Port on the device**, a shared **Username**, and optionally a shared **Password** used by everyone who has no saved login of their own. Passwords are encrypted on the server and never shown again; leave the password empty to be asked at each connection. **Options** depend on the protocol:

- **RDP security mode**: `any` works for most machines; try `nla` for modern Windows.
- **Ignore the RDP server certificate**: needed for self-signed certificates (the connection is still encrypted inside the tunnel).
- **Colour depth**: fewer colours for slow connections.
- **Enable file transfer (SFTP)**: drag files in and out of the session.
- **View only**: watch without sending keyboard or mouse input.

After adding a service, use **Diagnostics → Ask device to reconnect** so the device starts forwarding it.

## Sessions and client logs

- **Sessions** lists sessions opened to this device.
- **Client logs** shows the last lines from the tunnel script on the device, sent each time it connects. Turn on **Auto-refresh** while you watch a device reconnect.

## Diagnostics

- **Run probe** connects to each service through the tunnel and reports whether it answered, its greeting (for example `SSH-2.0` or `RFB 003.008`) and the latency, with a hint when it fails.
- **Ask device to reconnect** makes the device drop and re-open its tunnel.
- **Debug logging** records every tunnel event for this device, even when the server log level is higher. Turn it off when you are done.

## Danger zone

- **Disable** closes the tunnel immediately and refuses new logins until you **Enable** it again.
- **Delete** revokes the device's key. You must type the device name to confirm. To bring the machine back, enrol it again.

## Troubleshooting

- **Connect is disabled: service not forwarded.** Add the service, then ask the device to reconnect.
- **RDP connects then drops.** Try a different security mode and enable *Ignore the RDP server certificate*. Windows Home editions cannot accept RDP.
- **"This device isn't registered".** The device was deleted, or its enrolment never finished. Select **Register a machine**, create a code, and run the command it shows on the machine: `curl -fsSL https://<your RemoteHound>/e/<code> | sh` on macOS or Linux, `irm https://<your RemoteHound>/e/<code> | iex` in Windows PowerShell. In session history and on the Enroll page, a deleted device shows as "<name> (removed) · register again"; select it to open Enroll with the name filled in.
- **The device is offline and RemoteHound was removed from it.** Open the device and select **Get the install command**. Enroll opens with the name filled in; run the new command on the machine, then delete the old entry.
- **"Check identity" / "This may not be the machine its name says".** The machine reports a different OS than its name says (for example a code named *office-linux* run on a Mac). Select **Rename to <hostname>** to name it after the machine it really is, then enrol the intended machine with a new code. Pick a **Machine type** on Enroll to stop this happening.
- **"This machine may be enrolled twice".** Two devices in the group report the same hostname and OS. Open the other entry and delete the one you no longer use.
- **Screen Sharing to a Mac asks for a login first.** macOS only accepts Apple's own sign-in for screen sharing, so RemoteHound needs your macOS username (the short account name) and password. Connect opens the login form when none is saved; after saving, select **Connect** again. The account must be allowed under **System Settings → General → Sharing → Screen Sharing** (or *All users*). A wrong password or a user who is not allowed ends with "The remote desktop server is currently unreachable".
- **Remote Desktop asks for a login first.** Windows uses Network Level Authentication by default, which needs the username and password before the desktop starts. Save them with **Use my own login** (or ask an admin for a shared device login).
- **The device keeps going offline.** Read its client logs; repeated `ssh exited` lines usually mean the network blocks the tunnel port.
