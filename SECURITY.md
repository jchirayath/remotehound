# Security policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- GitHub: **Security → Report a vulnerability** (private vulnerability reporting) on
  https://github.com/jchirayath/remotehound.

RemoteHound grants remote access to other people's computers, so treat anything that could bypass
authentication, group scoping, the tunnel policy or the Guacamole token as **Critical**.

Include what you found, how to reproduce it, and the impact you expect. We acknowledge reports within
**3 business days** and send a first assessment within **7 days**.

## Our commitments (ENGINEERING_STANDARD VULN-1…7)

| Severity | Fixed within |
|---|---|
| Critical (or actively exploited) | 7 days |
| High | 30 days |
| Medium | 90 days |
| Low | next planned release |

Fixed vulnerabilities are disclosed in the release notes once users can update. We will credit you if
you wish.

## Supported versions

Only the latest release receives security fixes. Devices need no update: the bootstrap scripts are served by the server.
