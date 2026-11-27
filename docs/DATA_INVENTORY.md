# Data inventory (SEC-13)

| Data | Classification | Where | Retention | Deletion path |
|---|---|---|---|---|
| Operator email, display name, IdP subject | Personal | state.json `users` | Until the user is deleted | Users → Delete |
| Operator IP + user agent | Personal | audit.jsonl, logs | Audit 365 d (setting), logs per collector (30 d) | Ages out; audit records identify actors by user ID |
| Device hostname, OS, last IP | Personal (device of a person) | state.json `devices` | Until the device is deleted | Device → Delete |
| Device client logs | May contain personal data | memory only (200 lines/device) | Until restart or device delete | Device → Delete |
| Service usernames/passwords | Secret | state.json, AES-256-GCM sealed | Until changed/cleared | Services → clear password |
| Session records | Personal | state.json `sessions` | 90 d after end (setting) | Retention job |
| Session recordings | Sensitive personal (screen contents) | recordings volume | 30 d (setting); off by default | Retention job; delete files |
| Enrollment codes | Secret (short-lived) | state.json, HMAC only | 7 d after expiry/use | Retention job / Revoke |
