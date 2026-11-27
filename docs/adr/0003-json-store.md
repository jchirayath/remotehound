# ADR-0003 — JSON document store behind an interface

Status: accepted (2026-11-20)

## Context
Self-hosters value a small bundle. State is small (devices, users, groups, enrollments, sessions,
settings) and write rates are low (presence updates, clicks).

## Decision
`internal/core/store` defines `Store`; `FileStore` keeps the state in memory and in one JSON file with
transactional updates (copy → mutate → atomic write → swap), a `.bak` of the previous good file, and daily
snapshots (7 kept). Audit is a separate append-only, hash-chained JSONL file.

## Consequences
+ Zero databases to run, back up, or upgrade; backup = one volume.
+ Corruption recovery is automatic and visible (RecoveredFrom → UI banner).
− Single writer: one RemoteHound replica. Horizontal scaling (and OPS-8 statelessness) needs a Postgres
  `Store` implementation — the interface is the seam; recorded in STANDARD_EXCEPTIONS.
− Whole-file rewrite per update; fine to thousands of devices, not to hundreds of thousands.
