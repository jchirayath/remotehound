# Service level objectives (REL-1)

| SLI | Measure | Target (monthly) |
|---|---|---|
| Sign-in and UI availability | `http_server_request_duration_seconds_count` for `GET /api/v1/me`, non-5xx ratio | 99.5 % |
| Connect success | `POST /api/v1/devices/{id}/connect` non-5xx ratio (409 offline excluded — that is the device) | 99 % |
| Connect latency | p95 of the same route | < 300 ms |
| Tunnel freshness | devices online / devices seen in the last 24 h | ≥ 95 % |

Alerts fire on **error-budget burn rate** (fast: 14× over 1 h; slow: 6× over 6 h), never on single errors.
When the monthly budget is spent, reliability work takes priority (REL-2).
