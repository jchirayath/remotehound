# Audit log

The audit log records every change and every privileged read: sign-ins, enrollments, connections, edits, deletions, setting changes and debug actions. Each record is chained to the previous one with a hash, so records cannot be altered or removed without detection. The `audit-verify` job checks the chain every day.

## Reading a record

- **Time**: when it happened.
- **Event**: what happened, such as `session.open` or `device.delete`.
- **Outcome**: *success*, *failure* (allowed but it did not work) or *denied* (not permitted).
- **User**: who did it, with their role at the time. *system* means a background job.
- **Resource**: the affected object's ID.
- **IP address**: where the request came from.

Expand a row to see its details. Select its request ID to open the matching [log records](/docs/logs).

## Filtering and exporting

Filter by **Event** name and **Outcome**. **Download CSV** gets the full filtered log from the server. The grid's **CSV** and **JSON** buttons export only the rows loaded on screen.

Audit events are kept for the period set in [Settings](/docs/settings) (365 days by default). Only Admins can read the audit log.
