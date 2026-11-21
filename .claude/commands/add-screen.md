---
description: Add a new UI screen the RemoteHound way (route, help, docs, tests, tokens)
argument-hint: <screen-key> <one-line purpose>
---
Add the screen `$ARGUMENTS` to the RemoteHound UI following `web/ui/README.md`:

1. `web/ui/screens/<key>.js` using `lib/ui.js` page chrome and the four states (loading/empty/error with
   request ID/data); data only through `lib/api.js`; icons only through `lib/icons.js`; no raw colours.
2. Register the route in `web/ui/app.js` (and nav, gated by permissions from `/api/v1/me`).
3. Help: a registry entry in `web/ui/help/registry.json` (purpose, how-to, fields, columns, roles,
   troubleshooting, doc link) and `docs/user/<key>.md`.
4. If it needs new endpoints: add them to `api/openapi.yaml` first, then handlers in `internal/api`
   (decode → validate → authz → service → respond), audit every mutation, integration test incl. denied path.
5. Tests tagged `@feature:<key>`: UI module tests (`web/ui/tests/`), integration, and add the key to
   `standard.config.json` → `tests.features`.
6. Run `node --test web/ui/tests/ && go test ./... && ./ci/guards.sh && tools/standard/check.sh`.
