# Settings

Settings change how RemoteHound behaves while it runs, without a restart. Every change is recorded in the [audit log](/docs/audit).

Listeners, secrets and the identity provider are configured with environment variables when the server starts; they do not appear here.

## Public address

- **Public URL**: the https address people and devices use, for example `https://rh.example.com`. Used in enrolment commands.
- **SSH tunnel host** and **SSH tunnel port**: where devices connect their tunnel (port 2222 by default). The port must be reachable from the internet.

## Enrolment and connections

- **Enrolment code lifetime**: default validity of new codes, 5 to 1440 minutes.
- **Connect link lifetime**: how long a Connect link stays usable, 15 to 600 seconds.
- **Default group**: group for devices whose enrolment code names none.
- **Allow VNC connections**: turn VNC off if you do not need it.

## Operator sessions

- **Sign out after inactivity** and **Maximum sign-in length** control RemoteHound sign-in sessions. Open remote sessions are not cut by these.

## Recording

- **Record sessions** records the screen of every new session. Tell your users when this is on.
- **Keep recordings for** deletes older recordings automatically.

## Logging and retention

- **Default log level** after a restart.
- **Collect device client logs** stores the log lines devices send.
- **Keep audit events for** and **Keep session history for** set retention in days.

## Sign-in roles

Map values of a claim from your identity provider to RemoteHound roles. Set **Role claim** to the claim name (for example `groups`), then add rows: a claim value on the left, a role on the right. When a user signs in, the highest matching role wins.

## Saving

A bar at the bottom shows how many changes are unsaved. Select **Save changes** to apply them, or **Discard** to return to the saved values. If someone else saved settings after you opened the page, you are asked to reload first.

Only Admins can change settings.
