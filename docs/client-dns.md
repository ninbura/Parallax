# Name resolution across colliding subnets

Raw mapped addresses always work without DNS: `192.168.240.1` reaches the
home router through routing plus the PREROUTING NETMAP rule and nothing else.
This is the foundational guarantee and has its own integration test (shim
stopped, mapped access still works).

Names need two pieces:

1. **The shim** (dnsmasq in the gateway) forwards only the operator's zones
   (`Network.domains`) to the real home resolvers and rewrites their A answers
   with `alias=real,virtual,mask`, the DNS mirror of the NETMAP rule. Both come
   from the one `mapped_to` field. It is safe as a blanket rewrite *because*
   only home zones transit the shim. A forward-everything shim with `alias`
   would rewrite answers about the client's local network and misroute them;
   Parallax never generates that.
2. **The client routes only the home zones to the shim.** On a foreign
   192.168.1.0/24 an answer of `192.168.1.5` is inherently ambiguous; the
   domain name is the only unambiguous routing key.

## What each platform can do

| Transport / platform            | Split DNS | What the export contains |
|---------------------------------|-----------|--------------------------|
| WireGuard, Linux systemd-resolved | native  | `PostUp = resolvectl dns %i <shim>; resolvectl domain %i ~zone` |
| WireGuard, macOS                | via OS    | comment recipe: `/etc/resolver/<zone>` with `nameserver <shim>` |
| WireGuard, Windows              | via OS    | comment recipe: `Add-DnsClientNrptRule -Namespace ".zone" -NameServers "<shim>"` |
| WireGuard, iOS/Android official app | **no** | `DNS = <shim>` tunnel-wide; shim forwards other zones to `public_resolver` |
| Tailscale (M2)                  | native    | Headscale pushes per-zone restricted nameservers; the client resolver does the split on every OS |

Template `dns.wireguard = "split"` on a mobile export falls back to tunnel-wide
with a warning. The shim therefore gets a catch-all resolver whenever any
template configures WireGuard DNS (`split` or `tunnel_wide`), since any of its
peers may be exported for a phone. Split clients on other platforms only send
the home zones to the shim, so they never use it.

Honest caveats for tunnel-wide devices: unicast names on the visited network
do not resolve while connected; mDNS/Bonjour (casting, AirPlay) is multicast
and unaffected; raw IPs always work; Android allows per-app VPN exemptions.

## Limits (documented, not hidden)

- `alias=` rewrites A records only. AAAA answers pass through untranslated
  (no IPv6 mapping in this release).
- PTR lookups for virtual addresses are not rewritten.
- `stop-dns-rebind` blocks private answers from non-home zones on purpose.
