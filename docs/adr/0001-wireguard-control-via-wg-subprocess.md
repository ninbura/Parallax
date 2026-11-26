# ADR 0001: Control WireGuard through `wg`/`ip` subprocesses, not netlink

Status: accepted (M1). ADR 0012 makes a scoped exception: the activity
collector reads its event streams from netlink directly.

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

## Update (step 8.1)

The config reaches `wg syncconf` on stdin (`/dev/stdin`), not as a path.
Ubuntu 25.10 and later confine `wg` with AppArmor, which lets it open files
only under `/etc/wireguard`; a pipe from the caller isn't a file `wg` opens.
`wg-quick` feeds `wg` the same way. The file under the output directory stays
for `parallax plan`.
