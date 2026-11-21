# Guacamole integration

RemoteHound draws remote sessions with Apache Guacamole. The Integration screen proves that every hop between your browser and a device works, and tells you how to fix the ones that do not.

## Run the checks

Select **Run checks**. Each card shows a check's result, what it found, a **How to fix** hint when it is not passing, and how long it took.

- `guacamole.reachable`: RemoteHound can reach the Guacamole web app on the internal network.
- `guacamole.version`: Guacamole runs a supported version.
- `guacd.reachable`: the guacd protocol engine answers.
- `json_auth.roundtrip`: Guacamole accepts a signed, encrypted test login from RemoteHound.
- `json_auth.clock`: the clocks agree closely enough for short-lived connect links.
- `tunnel.listener`: the per-device tunnel ports are bound and reachable from guacd.
- `recording.path`: the recording directory is writable (only when recording is on).
- `proxy.websocket`: WebSocket upgrades reach Guacamole through RemoteHound.

## How a session travels

The diagram at the bottom of the screen shows the path: **Browser → RemoteHound → Guacamole → guacd → tunnel listener → device**. Each box turns green, yellow or red from the checks that cover it. The browser and the device are outside what the server can test.

## Common fixes

- **json_auth.roundtrip fails**: the shared secret differs. Set the same value for `RH_GUAC_JSON_SECRET` in RemoteHound and `JSON_SECRET_KEY` in Guacamole, then restart both.
- **guacd.reachable fails**: the guacd container is not running or not on the internal network. Check `docker compose ps`.
- **proxy.websocket fails**: a reverse proxy in front of RemoteHound blocks WebSocket upgrades. Allow them for `/guacamole/`.
- **json_auth.clock warns**: enable time synchronisation (NTP) on the host.

Checks also run automatically every 30 seconds to drive the Guacamole status on the [Overview](/docs/overview).
