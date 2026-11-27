# Getting started

RemoteHound lets you open SSH, Remote Desktop (RDP) and VNC sessions to Linux, macOS and Windows machines from any browser, including a phone. Nothing is installed on the machines: each one joins with one short command and keeps an outbound SSH tunnel open using the `ssh` client its operating system already ships.

## Before you begin

- RemoteHound and its Guacamole bundle are running, and you can sign in.
- The SSH tunnel port (2222 by default) is reachable from the internet, so devices behind home or office routers can dial out to it.

## Four steps to your first session

1. **Check the integration.** Open [Integration](/docs/integration) and select **Run checks**. Every check should pass.
2. **Create a group (optional).** Groups decide which devices operators and viewers can see. See [Groups](/docs/groups).
3. **Enroll a device.** Open [Enroll](/docs/enroll), select **Create code**, and type the command shown on the machine.
4. **Connect.** When the device appears, open it from [Devices](/docs/devices) and select **Connect**.

## Finding your way around

- Press **Ctrl+K** (**⌘K** on a Mac) to jump to any screen or device, or to search help.
- Press **?** on any screen to open its help panel. The panel links to the full guide for that screen.
- On a phone, the bottom bar holds Overview, Devices, Enroll and Sessions; everything else is under **More**.
- Change between light, dark and system theme at the bottom of the sidebar (or under **More** on a phone). Your choice follows you to other browsers.

## Roles at a glance

- **Admin**: everything, including users, settings, logs and debugging.
- **Operator**: connect to, enroll and manage devices in their groups.
- **Viewer**: see devices and sessions in their groups, read-only.

## If you cannot sign in

If you see **Your account is not set up in RemoteHound**, you signed in at your identity provider but no RemoteHound user matches your account. Ask an admin to add your email on the [Users](/docs/users) screen.
