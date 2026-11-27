# ADR 0003: One nftables table, replaced atomically; iptables-nft as fallback

Status: accepted (M1)

## Decision

All gateway rules live in `table inet parallax`. The generated file declares
the table, deletes it and redefines it in a single `nft -f` transaction, so
apply is atomic and idempotent and never leaves half a ruleset behind.
Parallax never emits imperative insert/delete pairs (the wg-easy
`PostUp`/`PostDown` `|| true` pattern).

NETMAP uses `dnat/snat ip prefix to ip daddr/saddr map { virt : real }`, the
nftables form of 1:1 prefix translation (nftables >= 0.9.4). Rules are built
as a small IR (`generate::firewall::Rule`) and rendered by the chosen backend;
the `iptables-nft` renderer produces an `iptables-restore --noflush` file
with dedicated `PARALLAX_*` chains and uses `ipset` for the Tailscale node
sets. That restore is atomic per table, not across `filter` and `nat`; why
that's safe is in `docs/design.md` (issue #56).

## The gateway host is not a destination

The gateway runs host-networked next to whatever else the Docker host
serves. INPUT from a tunnel interface therefore accepts only the DNS shim and
ICMP echo and then drops, so a guest peer cannot reach a published container
port or the host's SSH through the tunnel. LAN-side access to the host is
untouched (INPUT policy stays `accept`).

## Docker coexistence

Docker's own `FORWARD` policy is `DROP` and its hook runs alongside ours.
With `firewall.docker_coexistence = true` Parallax emits accepts for the
tunnel interfaces into `DOCKER-USER`; apply removes rules commented
`parallax` before inserting them, so it stays idempotent without flushing
Docker's chain.

With the `iptables-nft` backend, Parallax's jumps share the built-in chains
with Docker's, and order decides: an accept in a chain that comes first ends
`FORWARD` before Parallax's tiers see the packet. Docker puts its
`DOCKER-USER` jump back on top whenever it starts (issue #74). So
`DOCKER-USER` starts with a jump to `PARALLAX_FORWARD`, followed only by the
accepts toward a tunnel (that chain gives every packet from a tunnel its
verdict). Apply makes each `PARALLAX_*` jump the first rule of its built-in
chain (a hold aside), moving it back up when something got above it; each
such change, and the refill of `DOCKER-USER`, is one `iptables-restore`
transaction, so no packet finds a jump missing. Either `FORWARD` order,
Parallax's or Docker's after a restart, has Parallax decide first, so the
two don't keep reordering each other. While a restore's holds are up they
sit at the top of `DOCKER-USER` too. Drift detection treats any rule above
Parallax's as drift, so it's repaired at the next check (a minute by
default). Until then, what Docker's own chains accept (published container
ports) comes first: that window, from Docker starting to the next check, is
left open.

## Rejected

- Per-peer rules: the template pool already encodes the tier; a per-peer rule
  would have to be added and removed with the peer.
- Masquerading tunnel traffic by default: it destroys the L7 identity that
  nginx snippets rely on. It stays an explicit per-network toggle.
