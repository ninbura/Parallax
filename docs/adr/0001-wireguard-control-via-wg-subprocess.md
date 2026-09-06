# ADR 0001: Control WireGuard through `wg`/`ip` subprocesses, not netlink

Status: accepted (M1)

## Context

The gateway must create `wg0`, assign its address, load peers and keep them in
sync as the configuration changes. Options: a netlink crate
(`wireguard-control`, `neli`-based bindings, `defguard_wireguard_rs`) or the
`wireguard-tools` binaries.

## Decision

Drive `ip(8)` and `wg(8)` through the `ProcessRunner` trait. The server
config is rendered in `wg(8)` format and applied with `wg syncconf`, which
computes the peer delta itself and never drops live sessions of unchanged
peers.

## Consequences

- No unsafe code, no netlink struct maintenance; `wireguard-tools` is in the
  image anyway for operators.
- `wg syncconf` gives idempotent reconciliation for free.
- The trait boundary means a netlink implementation can replace the runner
  later without touching generators or the CLI.
- Tests use `RecordingRunner` and assert the exact command sequence
  (`tests/golden/apply/commands.txt`).
