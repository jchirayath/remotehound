# Services

The Services screen shows whether every part of RemoteHound is running, and lets admins restart a part that is stuck. Only admins see it.

## What each card means

| Card | What it is | If it is down |
|---|---|---|
| **RemoteHound** | The web console, the API, sign-in and the proxy to Guacamole. | You would not see this page. If it is degraded, read its recent problems. |
| **Tunnel server** | The SSH server every device keeps its tunnel to. | No device can connect or stay online. |
| **Data store** | The file holding users, devices, groups and encrypted logins. | Changes cannot be saved. |
| **Guacamole** | The remote-desktop web client in your browser tab. | Sessions cannot open. |
| **guacd** | The engine that speaks RDP, VNC and SSH to devices. | Sessions cannot open, and open ones end. |

Each card lists the **ports** the service uses. *public* ports are reachable from the internet (the console, and the SSH port devices dial); *internal* ones only inside the bundle. Below them are the service's **recent problems**: warnings and errors from the last hour, newest first, with secrets masked.

## Restart, stop and start

When container control is enabled (see below), cards show **Start**, **Restart** and **Stop**:

- **Restart** is the usual fix for a service that is running but stuck. Restarting Guacamole or guacd ends open remote sessions; people can reconnect a few seconds later.
- **Stop** keeps the service stopped until someone starts it. You type the service name to confirm.
- **RemoteHound can only restart itself.** Stopping it from here would leave no console to start it again. During its restart the page shows *RemoteHound is restarting* and reconnects by itself in about ten seconds; devices reconnect on their own too.

Every action is recorded in the [audit log](/docs/audit) as `service.action`.

You rarely need these buttons: Docker already restarts a crashed container by itself.

## View logs

**View logs** opens the last 500 lines of that container's output, with tokens and passwords masked. Turn on **Warnings and errors only** to filter. RemoteHound's own, richer logs are on the [Logs](/docs/logs) screen.

## Guacamole configuration

The card at the bottom shows how Guacamole is set up, read-only. There is no Guacamole admin screen: Guacamole runs with only the encrypted-JSON sign-in extension and **no user database**. It keeps no users or connections; RemoteHound holds them and hands Guacamole a 60-second sealed token for each session.

The **shared JSON secret** appears only as a short fingerprint. The badge next to it says whether Guacamole accepted a test token signed with that secret in the last [integration check](/docs/integration). If it says *DOES NOT match*, set the same value in `RH_GUAC_JSON_SECRET` (RemoteHound) and `JSON_SECRET_KEY` (Guacamole), then restart both.

## Enabling container control

Without it the screen is *status only*: everything above except the buttons and container logs.

Control needs the Docker socket, and the Docker socket gives full control of the host. So RemoteHound never holds it. A separate small helper, **rh-control**, does:

1. Generate a token: `docker compose run --rm remotehound gen-secret` prints `RH_CONTROL_TOKEN`. Put it in `.env`.
2. Start the bundle with the control profile: `docker compose --profile control up -d`.
3. Set `RH_CONTROL_URL=http://rh-control:9091` for RemoteHound (the bundle does this when the profile is on).

The helper acts **only** on containers labeled `io.remotehound.control.service=<name>`, and only with the actions listed in `io.remotehound.control.actions` (any of `start,stop,restart,logs`). It never returns a container's environment, so secrets stay put. It has no published port and refuses any request without the token. See the architecture decision `docs/adr/0004-rh-control.md`.
