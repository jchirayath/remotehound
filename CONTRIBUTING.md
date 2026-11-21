# Contributing to RemoteHound

Thanks for helping. RemoteHound is remote-access software: correctness and security come first.

## Ground rules
- Read [CLAUDE.md](CLAUDE.md) (it applies to humans too) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- Each cross-cutting concern has one module in `internal/core/` — use it; `ci/guards.sh` enforces this.
- No new Go dependencies without an ADR (`go.mod` holds exactly `golang.org/x/crypto`).
- The UI has no build step and no npm dependencies. Colours/sizes come from `design/` tokens; icons from `web/ui/lib/icons.js`; help text from `web/ui/help/registry.json`.
- Every change ships with tests in the same PR, including the denied path for anything authorised.
  Tag tests with `@feature:<key>`.
- Security issues: report privately (SECURITY.md), not as issues.

## Secrets and private data
Run `git config core.hooksPath .githooks` once per clone. The pre-commit hook runs gitleaks
(`.gitleaks.toml`: default rules + RemoteHound key formats) and `ci/check-public.mjs` (secret-shaped files
such as `.env`, `state.json`, `*.p8`, host keys, plus your private terms in the git-ignored
`local/denylist.txt`). CI repeats both over the whole history. A secret that reaches git is rotated
immediately (docs/RUNBOOK.md → Rotate secrets); rewriting history does not un-leak it.

## Workflow
```bash
go test ./... && node --test web/ui/tests/ && sh client/test/run.sh && ./ci/guards.sh && tools/standard/check.sh
```
Conventional commits (`feat:`, `fix:`, `docs:` …). By contributing you agree your contribution is licensed
under Apache-2.0 (inbound = outbound); sign off your commits (`git commit -s`, DCO).

## Releasing (maintainers)
1. Rename `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] — YYYY-MM-DD` and start a new `[Unreleased]`.
2. Tag and push: `git tag -s vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
3. `.github/workflows/release.yml` publishes `ghcr.io/jchirayath/remotehound:X.Y.Z` (amd64 + arm64,
   SBOM, signed provenance) and creates the GitHub release from that CHANGELOG section. It fails if the
   section is missing. A tag with a suffix (`v0.2.0-rc.1`) is a pre-release and does not move `latest`.

## Code of conduct
Be kind and constructive. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) (Contributor Covenant 2.1);
report conduct issues privately to the maintainers via GitHub.
