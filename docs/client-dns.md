# Name resolution across colliding subnets

Raw mapped addresses always work without DNS: `198.18.1.1` reaches the
home router through routing plus the PREROUTING NETMAP rule and nothing else.
This is the foundational guarantee and has its own integration test (DNS
server stopped, mapped access still works).

Names need two pieces:

1. **The shim** (Parallax's built-in DNS server, part of `parallax daemon` on the
   gateway address) forwards the operator's zones (`Network.domains`) to the
   real home resolvers and rewrites their A answers into virtual space with
   the same `Mapping` as the NETMAP rule. Both come from the one `mapped_to`
   field. The rewrite is safe *because* only home zones get it: rewriting
   answers about the client's local network would misroute them. It answers
   each tier only the names that tier may reach (see `docs/design.md`, "DNS
   server").
2. **The client routes only the home zones to the shim.** On a foreign
   192.168.1.0/24 an answer of `192.168.1.5` is inherently ambiguous; the
   domain name is the only unambiguous routing key.

## What each platform can do

| Transport / platform            | Split DNS | What the export contains |
|---------------------------------|-----------|--------------------------|
| WireGuard, Linux systemd-resolved | native  | `PostUp = resolvectl dns %i <shim>; resolvectl domain %i ~zone`, `PreDown = resolvectl revert %i` |
| WireGuard, macOS                | via OS    | comment recipe: `/etc/resolver/<zone>` with `nameserver <shim>` |
| WireGuard, Windows              | via OS    | comment recipe: `Add-DnsClientNrptRule -Namespace ".zone" -NameServers "<shim>"` |
| WireGuard, iOS/Android official app | **no** | `DNS = <shim>` tunnel-wide; the shim answers other names only with `dns.public` |
| Tailscale (M2)                  | native    | Headscale pushes per-zone restricted nameservers; the client resolver does the split on every OS (Android through its on-device resolver) |

The macOS and Windows recipes change system-wide settings that outlive the
tunnel: while it is down, home names go to an unreachable shim and fail, even
on the home LAN. Each export says so and gives the command that removes them.

A peer's `dns = "split"` on a mobile export falls back to tunnel-wide
with a warning. A tunnel-wide device sends every query to the shim, which
forwards names outside the home zones to `server.dns.public_resolver` only
for peers with a `public_dns` rule. Without it, the device resolves only
its granted home names while connected, and the export says so. Split
clients on other platforms only send the home zones to the shim, so the
setting doesn't matter to them.

Honest caveats for tunnel-wide devices: unicast names on the visited network
do not resolve while connected; mDNS/Bonjour (casting, AirPlay) is multicast
and unaffected; raw IPs always work; Android allows per-app VPN exemptions.

## Limits (documented, not hidden)

- Only A records are rewritten. AAAA answers for home names are dropped (no
  IPv6 mapping in this release, and peers can't send IPv6), and so are
  SVCB/HTTPS records, whose address hints would carry real addresses.
- PTR lookups for virtual addresses are not rewritten.
- Home answers lose private and reserved addresses outside every configured
  network, such as a VLAN Parallax doesn't know: off-site they would point at
  a host on the visited network. This holds even for a tier that reaches
  such a VLAN through `internet`. To get its names, configure that subnet as
  a network with `mapped_to` (and `masquerade = true` if the router has no
  route back to the tunnel range).
- Public answers lose addresses in private, reserved or mapped space, on
  purpose (DNS rebinding).
- Mapping covers the home side only. The tunnel addresses and the shim
  (`10.8.0.0/16` in the examples) can still clash with a visited network
  that uses the shim's address for its own router. A split-tunnel export
  routes the shim's `/32` into the tunnel and hides that router; a
  full-tunnel export lets the visited LAN's route win, so DNS goes to that
  router instead of the shim. Pick a tunnel range you're unlikely to visit. The
  same goes for `198.18.0.0/15` on a device running a proxy app that hands
  out fake addresses from it (Clash, Surge).
- A `host` grant gives a name only when it's written with one
  (`host = "nas.mydomain.com"`); one written with an address gives none.
