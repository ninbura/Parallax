# ADR 0012: The activity collector reads netlink directly

Status: accepted (step 7c.3). A scoped exception to ADR 0001.

## Context

Activity logging (docs/logging.md) needs two feeds from the kernel:
connection tracking's events (a flow starts, a flow ends with its byte
counts) and the firewall's nflog group (blocked packets). ADR 0001 drives
WireGuard and the network through the `wg` and `ip` tools rather than
netlink, because those are one-shot configuration calls the tools already
do well. These feeds are the opposite: long-running event streams. For them
the tools are poor fits: `conntrack -E` prints text to parse and is another
package in the image and on native installs; nflog has no tool besides
`ulogd`, a daemon of its own.

## Decision

- **The daemon reads both feeds from netlink sockets itself.** The sockets
  come from `rustix` (already a dependency, `net` feature); no `unsafe` in
  Parallax's code. Each feed runs on its own thread with its own connection
  to `logs.db`, and commits its records in batches (every second, or 2000
  records) with `BEGIN CONCURRENT` (ADR 0011).
- **The messages are parsed by hand**, in `parallax-core`'s `netlink.rs`:
  pure functions from bytes to events, tested with byte fixtures and with
  truncated and garbled input. The fields needed are few (two tuples, the
  connection mark, the flow id, two byte counters; a blocked packet's
  addresses, ports and prefix), so the parser is small, and no crate typed
  the counters or the id anyway.
- **Only marked flows are kept.** The firewall sets a connection-mark bit on
  logged peers' new flows; the collector drops every event without it, then
  attributes the rest to a peer by tunnel address against the configuration
  as it is now. Blocked packets come only from logged peers' rules.
- **A feed runs only while someone needs it.** The collector subscribes to
  connection tracking while some peer logs `connections` or more, and binds
  the nflog group while some peer logs `denied`. With nobody logged it opens
  no socket, so the kernel sends nothing.
- **Losses are counted, not hidden.** The receive buffer is 8 MiB; when the
  kernel still drops events (`ENOBUFS`), the daemon says so in its log.

## Consequences

- `CAP_NET_ADMIN`, which the gateway already has, covers both subscriptions;
  no new package, capability or tool.
- A flow's end is reported when connection tracking's periodic sweep removes
  the entry, seconds after the connection closes (about 11 s after TIME_WAIT
  on a 7.2 kernel), so `closed` records lag.
- If another program holds nflog group 20568, blocked attempts aren't
  recorded and the daemon names the group.

## Rejected

- **`conntrack -E` as a subprocess.** Text parsing of a format meant for
  people, an extra package, and still nothing for nflog.
- **`netlink-packet-netfilter`.** It doesn't type the byte counters or the
  flow id, so those would be parsed by hand regardless, and it brings
  `derive_more` and an older `netlink-packet-core` for a few dozen lines of
  framing.
- **Logging each packet (`log` without nflog, or `nft monitor trace`).**
  Per-packet cost on the forwarding path, which `off` must never pay and
  `connections` doesn't need.
