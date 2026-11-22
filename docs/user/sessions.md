# Sessions

A session is one remote connection from a browser to a device. RemoteHound records sessions from the tunnel side, so the list is accurate even if a browser tab is closed abruptly.

## Mine

Your live sessions, refreshing every five seconds (turn **Live** off to stop). For each you see the device, protocol, start time, duration, traffic and who you shared it with.

- **Share** invites one person at a time. Pick them from the list of RemoteHound users, choose **View only** (they watch) or **Control** (they can also type and use the mouse), and how long the invitation lasts — 15 minutes to 8 hours. People with the Viewer role can only be given view-only access. You can share only with people in the device's group, or with an admin.
- The drawer also lists who the session is currently shared with; select the remove button next to a person to stop sharing with them. Shares also end by themselves when their time runs out.
- **End** closes the session for you and everyone joined to it.
- **Join** on your own live session reopens it, as long as you may still connect to that device. If an admin changed your role or groups, your open sessions were closed and cannot be rejoined.

## Shared with me

Sessions other people invited you to, with a badge showing your access (*view only* or *control*). Select **Join** to open the session in a new tab (in the same tab on a phone).

## All sessions (view only)

Admins see every live session here. They can **End** any session — the confirmation names the owner, and ending someone else's session is recorded in the [audit log](/docs/audit) — but they cannot join or watch it.

> Joining needs the owner's invitation; admins can see and end sessions but not watch them.

## History

Finished sessions with their duration and traffic. Admins can switch between **Mine** and **Everyone**. If recording was on, a **Download** link fetches the recording.

## Recordings

When **Record sessions** is on in [Settings](/docs/settings), guacd records the screen of every new session. The **Recordings** tab lists the files with their size and date; they are deleted automatically after the retention period. Recordings can be played back with Guacamole's `guacenc` tool.

## Who can see what

- Everyone sees their own sessions and sessions shared with them.
- Admins also see all sessions (view only), can end any session, and can download recordings.
- Buttons appear only when you are allowed to use them: Join when you were invited, Share on your own live sessions, End when you own the session or are an admin.
