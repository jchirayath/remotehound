# Error codes

Every error RemoteHound returns has a stable **code** and a **request ID**. Quote both if you ask for
help — the request ID finds the exact log lines on the **Logs** screen (filter *Request ID*).

| Code | What happened | How to fix it |
|---|---|---|
| `VALIDATION_FAILED` | One or more fields are invalid. | Each field shows what is wrong; correct it and save again. |
| `REQUEST_MALFORMED` | The request body was not valid JSON. | A client bug — reload the page. |
| `AUTH_REQUIRED` | You are not signed in, or your session expired. | Sign in again. Sessions end after the idle and absolute limits in Settings. |
| `AUTH_FORBIDDEN` | Your role cannot do this. | Ask an admin to change your role or add you to the device's group. |
| `AUTH_CSRF_FAILED` | The page's security token is stale. | Reload the page and try again. |
| `NOT_FOUND` | The item does not exist (or you cannot see it). | Check the link; it may have been deleted. |
| `PRECONDITION_FAILED` | Someone changed this item after you opened it. | Reload to see their change, then make yours again. |
| `PRECONDITION_REQUIRED` | The edit was sent without a version check. | A client bug — reload the page. |
| `RATE_LIMITED` | Too many requests in a short time. | Wait 30 seconds. |
| `INTERNAL` | Something failed on the server. | Retry. If it persists, send the request ID to your admin. |
| `SERVICE_UNAVAILABLE` | A dependency (e.g. the identity provider) did not answer. | Retry shortly; check the Integration screen. |
| `DEVICE_NOT_FOUND` | No such device, or it is in a group you are not in. | Check the device list; ask an admin for group access. |
| `DEVICE_OFFLINE` | The device has no live tunnel. | It reconnects on its own within minutes. If not, check the device's client log and that it has network. Re-running the enrolment command is always safe. |
| `DEVICE_DISABLED` | The device is disabled. | Enable it on the device page (Danger zone). |
| `SERVICE_NOT_CONFIGURED` | The device has no such service (SSH/RDP/VNC). | Add it on the device's **Services** tab. |
| `SERVICE_NOT_FORWARDED` | The device is online but not forwarding that port. | Turn the service on at the device (Remote Login, Screen Sharing, Remote Desktop) and use **Reconnect**. |
| `GUAC_UNAVAILABLE` | Guacamole is not answering. | Open **Integration** and run the checks; each failing check says how to fix it. |
| `ENROLL_CODE_INVALID` | The enrolment code does not exist. | Check for typos or create a new code. |
| `ENROLL_CODE_USED` | The code was already used. | Codes are single use — create a new one. |
| `CREDENTIALS_REQUIRED` | Mac Screen Sharing, or Remote Desktop with Network Level Authentication, needs a username and password before it starts. | Save them with **Use my own login** on the device page, then connect. |
| `ENROLL_WRONG_OS` | The code was made for another kind of machine (macOS, Linux or Windows). | Run it on the machine it was made for, or create a code for this OS. The code is still usable. |
| `ENROLL_CODE_EXPIRED` | The code expired. | Create a new one (the lifetime is set in Settings). |
| `ENROLL_KEY_INVALID` | The device sent an unusable key. | Re-run the command; it generates a fresh key. |
| `GROUP_NOT_EMPTY` | The group still has devices. | Move or delete them first. |
| `GROUP_NOT_FOUND` | The group does not exist. | Pick an existing group. |
| `USER_NOT_FOUND` / `USER_EXISTS` | No such user / the email is already a user. | Check the Users list. |
| `LAST_ADMIN` | The change would leave no admin, or targets yourself. | Make someone else admin first. |
| `SESSION_NOT_FOUND` | The session already ended. | Refresh the Sessions list. |
| `JOB_NOT_FOUND` | No such background job. | Refresh the Debug screen. |
| `RECORDING_NOT_FOUND` | The recording is gone (retention) or storage is not mounted. | See Integration → *Session recording storage*. |
| `PROXY_IDENTITY_MISSING` | RemoteHound runs behind a sign-in proxy, and this request arrived without the proxy's identity (or not from the proxy). | Sign in again. If it keeps happening, an admin should check the proxy passes the email header and the proxy secret — see Services and the runbook. |
| `CONTROL_UNAVAILABLE` | Container control is not set up, or the rh-control helper is not answering. | Status still works. An admin sets `RH_CONTROL_URL` and runs rh-control, or checks that the helper container is running. |
| `CONTROL_ACTION_NOT_ALLOWED` | That action is not allowed for this service — by its container label, or because RemoteHound can only restart itself (stopping it would leave no console to start it again). | Use an allowed action, or change the container's `io.remotehound.control.actions` label. |
| `CONTROL_TARGET_NOT_FOUND` | No container is labelled for that service. | Add `io.remotehound.control.service=<name>` to the container in compose and recreate it. |
