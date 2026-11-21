# Logs

The Logs screen brings three sources together:

- **Server**: RemoteHound itself.
- **Devices**: the log lines each device sends over its tunnel when it connects.
- **Guacamole bundle**: Guacamole, guacd and caddy, when the optional log collector is running.

## Searching

Combine **Search** (text in the message or event name), **Source**, **Level**, **Device** and **Request ID**. Filters are kept in the address bar so you can share a view.

Every error message in RemoteHound shows a **request ID**. Paste it into **Request ID** to see every record written while handling that request, across components.

Expand a row to see all its attributes as JSON. **Show this request only** filters to that record's request.

## Live tail

Turn on **Live tail** to stream new records as they are written. **Pause** stops the list moving while you read; new records are counted and added when you resume. The view keeps the latest 1000 records. **Clear** empties the view without affecting stored logs.

## Notes

- Secrets, keys and credentials are redacted before anything is logged.
- The server keeps recent records in memory. Longer history lives in your container logs or the log collector's file.
- DEBUG records only exist while the log level is DEBUG; change it on the [Debug](/docs/debug) screen.

Only Admins can read logs.
