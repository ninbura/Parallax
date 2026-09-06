# Parallax

A Dockerized WireGuard + Headscale gateway with a Rust engine that uses subnet
remapping, DNS rewriting and template-based access policies to make split
tunnels and scoped guest access just work, from any client.

**Status: Milestone 1** (shared engine + WireGuard transport + CLI harness).
Both transports are part of the product; the Headscale transport is defined
by the `Transport` trait and implemented in M2. M1 is an incomplete product by
design, not a "WireGuard-only" mode.

## Why

- Most home LANs are `192.168.1.0/24`, so a roaming split tunnel cannot address
  home. Parallax NETMAPs each LAN to a collision-free virtual prefix
  (`192.168.1.5` ⇄ `192.168.240.5`) and rewrites DNS answers to match, from
  the same single mapping.
- Access is a **template** (policy class) with grants; every WireGuard peer of
  a template draws from a dedicated pool, so the address *is* the tier and the
  gateway's nftables FORWARD chain enforces the policy regardless of what the
  client puts in `AllowedIPs`.
- nginx `allow/deny` snippets extend the same identity to virtual hosts.

## Try it

```sh
cargo build
cp example/parallax.toml /tmp/parallax.toml
sed -i 's#/etc/parallax/wg-server.key#/tmp/wg-server.key#' /tmp/parallax.toml
parallax=target/debug/parallax
$parallax -c /tmp/parallax.toml keygen --write-config
$parallax -c /tmp/parallax.toml validate
$parallax -c /tmp/parallax.toml generate -o /tmp/parallax-out
$parallax -c /tmp/parallax.toml peer add tablet --template family --platform mobile
$parallax -c /tmp/parallax.toml peer show
```

`apply` needs Linux with `nft`, `wg`, `ip` and `dnsmasq`; use the container
(`docker/`) or read `docs/setup.md`.

## Layout

- `crates/parallax-core`: model, validation, allocation, transports,
  generators, plan/apply. UI-agnostic; all I/O behind traits.
- `crates/parallax-cli`: `validate`, `plan`, `generate`, `apply`, `keygen`,
  `peer add|remove|show|allocate`, `export`.
- `docker/`: image, entrypoint, compose with `parallax` + `headscale`.
- `example/parallax.toml`: the canonical scenario, fully commented.
- `tests/integration/netns.sh`: Linux namespace test of the six M1 assertions.
- `docs/`: design and ADRs (`docs/design.md` is the review artifact).

## Tests

```sh
cargo test --workspace            # unit, property, golden, CLI end-to-end
UPDATE_GOLDEN=1 cargo test -p parallax-core --test golden   # refresh goldens after an intended change
sudo ./tests/integration/netns.sh # Linux only, needs root
```
