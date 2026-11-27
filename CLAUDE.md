# CLAUDE.md

This repo follows the engineering standard (https://github.com/jchirayath/engineering-standard): mode in `standard.config.json`, deviations in `docs/STANDARD_EXCEPTIONS.md`. The `engineering-standard` plugin supplies the rules (MCP `rules_for` / `rule`) and the agent loop; run `tools/standard/check.sh` before saying done.

## What this is
RemoteHound — open-source (Apache-2.0) browser remote access with no client install. Devices enroll with a
typed one-liner that sets up an `ssh -R` tunnel to RemoteHound's embedded SSH server; sessions render in
Apache Guacamole, which RemoteHound drives through guacamole-auth-json. Start with
`docs/ARCHITECTURE.md`; the API contract is `api/openapi.yaml`; the device protocol is
`docs/specs/CLIENT_PROTOCOL.md`; threats are `docs/THREAT_MODEL.md`.

## Rules that are specific to this repo
- **One module per concern** (`internal/core/*`): config, secrets, logx, audit, authz, httpx, apierr, store,
  validate, jobs, metrics, ids. Never call `os.Getenv`, `fmt.Print*`, `http.Client{}`, `math/rand` for
  secrets, or write state files outside them. `./ci/guards.sh` fails otherwise — keep its allow-lists empty.
- **One external Go module** (`golang.org/x/crypto`). Adding one needs an ADR in `docs/adr/`.
- **The tunnel policy lives only in `internal/tunnel/server.go`.** Anything that widens what a device key
  can do (new channel types, exec commands, forwards) is a security change: update THREAT_MODEL.md and add
  a denied-path test in `internal/tunnel/server_test.go`. Ask the `tunnel-security-reviewer` agent.
- **Authz:** handlers call `authz.Can` (or `s.can`) — group-scoped resources return 404 for other groups,
  never 403. Every mutation gets a denied-path test (`internal/integration`).
- **Audit:** every state change calls `audit.Record` once. Update `docs/OBSERVABILITY.md` when you add a producer.
- **Client protocol is a contract** with every enrolled device. Changing `client/*` or the `agent v1`
  command/control lines means updating `docs/specs/CLIENT_PROTOCOL.md` and `client/test/run.sh` together.
- **UI:** no build step, no npm deps. Only `web/ui/lib/api.js` calls `fetch`. Colors/spacing via tokens
  from `design/` (regenerate `web/ui/tokens.css` with `tools/standard/design-tokens/scripts/build.mjs`),
  icons via `web/ui/lib/icons.js`, copy via `web/ui/help/registry.json` + `docs/user/<page>.md`. Every
  screen: loading / empty / error (with request ID) / data, light + dark, ≥ 44 px targets.
- **Config:** new env keys go in `internal/core/config.Keys` (documented), then regenerate
  `docs/CONFIG.md` (`go run ./cmd/remotehound config-doc`) and add them to `deploy/.env.example`
  (a test checks). Runtime-tunable behavior belongs in `model.Settings` + the Settings screen instead.

## Commands
```bash
go test ./...                       # unit + in-process integration (real SSH + HTTP)
node --test web/ui/tests/           # UI module tests
sh client/test/run.sh               # bootstrap scripts
./ci/guards.sh                      # architecture guards
tools/standard/check.sh             # standard gates
```
Slash commands: `/smoke` (live bundle + real device container), `/add-screen`, `/add-endpoint`.
Never point the e2e overlay (`deploy/test/`) at anything reachable from a network — it signs everyone in as admin.

## Before saying "done"
Run the commands above, and say explicitly what you did **not** verify (e.g. Windows, a real IdP, a browser session).
