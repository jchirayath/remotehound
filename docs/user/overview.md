# Overview

The overview answers one question: is everything reachable, and does anything need my attention?

## What you see

- **About RemoteHound**: one paragraph on what RemoteHound is for, and **Learn more about RemoteHound**, which opens the project site in a new tab (your administrator can point it elsewhere with `RH_PROJECT_URL`).
- **Fleet**: how many devices are online out of all devices, with a bar showing the proportion. Select **online**, **offline** or **pending** to open the device list filtered to those devices.
- **Active sessions**: remote sessions open right now, and how many were opened in the last 24 hours.
- **Open enrollment codes**: codes that are still waiting for a device.
- **Guacamole**: the latest result of the automatic health probe (every 30 seconds). *Healthy* means sessions can open; *Degraded* or *Down* means they may fail.
- **Failing jobs**: background jobs whose last run failed. Open [Debug](/docs/debug) to see why.
- **Recent activity**: the latest entries from the [audit log](/docs/audit), newest first.

The numbers refresh every 30 seconds while the screen is open.

## Getting started checklist

While no devices exist, a checklist walks you through checking the integration, creating a group, enrolling a device and opening a session. Steps tick themselves off as you complete them.

## Quick actions

- **Enroll a device** opens [Enroll](/docs/enroll). Needs the Operator or Admin role.
- **Run integration checks** runs every Guacamole check now and tells you the result. Needs the Admin role.

## Troubleshooting

- **All devices are offline after a restart.** Devices reconnect by themselves with a short backoff; allow up to a minute. If they stay offline, confirm the SSH tunnel port is reachable from the internet.
- **Guacamole shows Down.** Open [Integration](/docs/integration) and run the checks; each failing check explains the fix.
