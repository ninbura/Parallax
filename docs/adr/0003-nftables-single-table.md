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
sets.

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

## Rejected

- Per-peer rules: the template pool already encodes the tier; a per-peer rule
  would have to be added and removed with the peer.
- Masquerading tunnel traffic by default: it destroys the L7 identity that
  nginx snippets rely on. It stays an explicit per-network toggle.
