---
description: Add an API endpoint through the platform core (contract first)
argument-hint: <METHOD /api/v1/path> <purpose>
---
Add `$ARGUMENTS`:
1. Contract first: `api/openapi.yaml` (snake_case, `{data, meta}`, problem+json, cursor paging, If-Match for PATCH).
2. Handler in `internal/api`: `decode` (strict) → `validate.Collector` → `s.can` / `authz.Can` with the
   right resource (group-scoped → 404 for other groups) → domain service → `writeJSON`.
3. New error codes go in `internal/core/apierr` (never renamed) + `docs/user/errors.md` + the UI help
   registry `errors` map.
4. `audit.Record` for every state change; add the producer to `docs/OBSERVABILITY.md`.
5. Integration test in `internal/integration` covering success and the denied path; run `go test ./...`.
