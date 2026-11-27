# ADR 0010: Named grants replace templates

Status: accepted (step 7b).

## Context

A template was a policy class that held everything at once: what its peers
reach (grants), a WireGuard address pool, a Headscale user or tag, DNS
policy and client defaults. A peer had exactly one, and its address came
from the template's pool, so the address *was* the tier. That made common
things awkward: a device that needs two kinds of access needed a third
template that repeats both; moving a device to other access meant a new
address and a new client config; and Headscale users (M2) would have been
tied to templates rather than given access directly.

## Decision

Access is a set of **named grants**, attached to principals.

- A **grant** has a name, any number of **rules** (`all_networks`,
  `network`, `host` with optional ports, `service`, `internet`,
  `public_dns`), and an `everyone` switch. It may exist with nothing
  attached.
- A **peer** has a list of grants (none is allowed: it reaches nothing).
  What it reaches is the **union** of its grants and every `everyone`
  grant. Rules only add; there is no deny. In M2, Headscale users get
  grants the same way.
- **Addresses say nothing about access.** WireGuard peers get the lowest
  free address of `server.wireguard.supernet` and keep it whatever their
  grants become. Existing addresses stay as they are.
- **Template settings move where they belong.** DNS mode, `allowed_ips`,
  MTU, keepalive and `visible_networks` are per peer (`[peer.wireguard]`),
  with `server.wireguard.peer_defaults` for new ones; changing grants never
  changes a peer's config, except the routes of an `allowed_ips =
  grants_only` peer, which follow what its grants reach. `dns.public` is the `public_dns` rule.
  `dns.tailscale` is `server.headscale.dns` (Headscale's split DNS is
  tailnet-wide). Pools and the Headscale identity are gone.

### Tiers

Peers with the same effective set of grants form a **tier**
(`parallax_core::tier`), and the generators work per tier, as they did per
template: one firewall chain, one DNS entry and one proxy entry per tier,
built from the union of its rules. Tiers come from the configuration alone
(every peer, active or not), ordered by their grants' positions, so the same
configuration always numbers them alike.

- **Firewall.** FORWARD picks a tier's chain with one verdict-map lookup on
  the source address, now per peer:
  `iifname "wg0" ip saddr vmap { 10.8.1.1 : jump tier_0, ... }`. Chains are
  numbered (`tier_<n>`, `PARALLAX_T<n>`); a tier's name can be several
  grants long, and the rules' comments say which (`family+photos: ...`).
  INPUT and the proxy redirect match the tier's member set (`wg_<key>`,
  `ts_<key>`), so they stay one rule per tier however many peers. Sets are
  named by content, not position: `iptables-nft` refills sets before it
  restores the rules, and a set whose name moved to other access would
  briefly give old rules' access to new members. *(Amended, issue #35: the
  key first hashed the grants' names, which missed a grant whose rules
  changed under the same name. It now hashes the tier's label and every
  rule that uses the set or sits in the tier's chain, so a tier whose access
  changes gets a fresh set and the restore switches to it in one step.)*
- **Addresses change hands.** Since an address no longer implies access, a
  save can give a removed peer's address to someone with other grants.
  Apply first takes any live WireGuard peer off the interface that holds an
  address the new configuration gives another key, then replaces the
  firewall, then re-syncs WireGuard. The old key never holds the address under the new
  owner's rules, even if a later step fails.
- **DNS and proxy** routes list each tier's member addresses.
- **Validation** runs per tier on the union: the hostname-bypass warning,
  `full_tunnel` without `internet`, the home's public IP rules (ADR 0008,
  0009: the exemption is `all_networks` and `internet` together, now in the
  union). A grant for everyone with anything beyond `public_dns` gets a
  warning, since it can't be taken away from anyone.

### Conversion

Existing configurations convert automatically, keeping the same access:
each template becomes a grant of its name with its rules (plus
`public_dns` when it had `dns.public`), and each peer gets that grant and
the template's client settings. The database does it in migration 0006;
TOML files with `[[template]]` and `peer.template` still import, converted
the same way, and export writes the new format.

## Consequences

- One rule per peer in the FORWARD verdict map instead of one per pool. nft
  looks it up in one step either way; the `iptables-nft` fallback has no
  verdict maps and jumps once per peer address.
- A peer added after the conversion gets an address outside the old pools;
  nothing depends on pools any more.
- A peer without grants is in no tier and falls to the transport's
  catch-all drop. Validation warns.
- `dns.tailscale` set differently per template collapses to `split`. It had
  no effect before M2.

## Alternatives

- **Several templates per peer.** Keeps the bundle of access and settings,
  but two templates disagree on DNS and client settings, and the address
  still couldn't encode a combination.
- **Tags per access set** (the earlier M2 plan). One tag per combination is
  the third-template problem again.
- **Deny rules.** Union-only keeps "who can reach X" a simple question and
  avoids ordering; nothing needs a deny yet.
