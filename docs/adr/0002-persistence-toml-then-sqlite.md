# ADR 0002: The TOML file is M1 persistence; SQLite comes with the daemon

Status: accepted (M1), revisit in M2/M3

## Decision

`parallax.toml` is the single source of truth in M1. Commands that change it
(`keygen --write-config`, `peer add/remove/allocate`) edit it in place with
`toml_edit` so operator comments survive. Nothing else is persisted except the
server private key file and the generated artifacts.

## Why not SQLite now

M1 has no long-running process and no concurrent writers. A file the operator
can read, diff and back up is the better interface for a CLI harness, and the
`serde` model is exactly what a database layer would map to.

## Plan

M2 or M3 (whichever brings the reconcile daemon) adds SQLite with a TOML
import command. `parallax-core` types stay storage-agnostic: no ORM
attributes, no ids beyond names, no file paths outside `ServerConfig`.
