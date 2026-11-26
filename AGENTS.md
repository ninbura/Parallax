# Working on Parallax

For humans and agents (Claude Code, Codex and Antigravity all read this file).
Design lives in `docs/design.md` and `docs/adr/`; read those before changing
the model or a generator.

## Before you push

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
sudo ./tests/integration/netns.sh   # after changes to generate/ or apply
```

The netns test needs Linux, root, and `nft`, `wg`, `ip`, `dnsmasq`, `dig`,
`curl`, `openssl`, `ping` and `python3`. CI runs all of these. Each run makes
its own namespaces, so two can share a machine. The toolchain is pinned in
`rust-toolchain.toml`.

Golden files: after an intended generator change, run
`UPDATE_GOLDEN=1 cargo test -p parallax-core --test golden` and review the diff.

## How the code is shaped

- `parallax-core` is a pure library: no global state, no direct I/O. Files,
  processes and key generation go through the traits in `io.rs`, so tests
  run against in-memory fakes.
- `parallax-cli` is a thin harness over core. Keep logic in core.
- Errors: `thiserror` in core (`error.rs`), `anyhow` in the CLI. Messages
  name the offending thing and say what's wrong ("peer 'sister-phone':
  unknown grant 'familly'"), never just "invalid config".
- Config types are `serde` with `deny_unknown_fields`. Typos must fail loudly.
- Generated output is deterministic: same input, byte-identical output.
- Secrets (private and preshared keys, API keys) use the types in
  `secret.rs`, whose `Debug` is redacted. Never log or print them. Public
  keys are fine to show.
- `crates/parallax-core/src/testing.rs` holds the canonical scenario.
  Prefer it over ad hoc fixtures.

## Style

- Simple beats clever. No trait, generic or builder until there's a second
  real use. A plain function is fine.
- No `unwrap`/`expect`/`todo!`/`unimplemented!`/`dbg!` outside tests
  (clippy enforces it). Return an error, or make the invalid state
  impossible. For values known valid at compile time, use a const
  (`Ipv4Net::new_assert`) or an infallible conversion (`Ipv4Net::from(addr)`
  for a /32).
- Don't `.clone()` just to quiet the borrow checker; borrow or restructure.
- Async only where it's needed (the daemon, the Headscale client), not in
  generators or validation.
- New dependency: only if it clearly pays for itself. Add it to
  `[workspace.dependencies]` and give a one-line reason in the PR.
- Comments explain why, not what. Doc comments on public items.
- Tests: unit tests next to the code, golden tests for every generator,
  netns integration tests for packet behaviour.
- `unsafe` is forbidden.

## Commits and PRs

- Commit subjects: `area: what changed`, lower case (`validate: reject ...`).
- One PR per change. Keep descriptions short: what, why, how it was tested.
- The repo is public. Never commit hostnames, IPs, domains or anything else
  about a real deployment. Use the example scenario's values.

## References

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Effective Rust](https://www.lurklurk.org/effective-rust/)
- [Clippy lints](https://rust-lang.github.io/rust-clippy/master/)
