# Parallax M1 design: workspace, core types, `Transport` trait

This is the review artifact the handoff asked for: the workspace layout, the
data model as it exists in `parallax-core`, and the transport abstraction.
Everything below is implemented; file paths are clickable.

## Workspace layout

```
Cargo.toml                      workspace (resolver 2), shared dependency versions
crates/parallax-core/           pure library, no I/O of its own
  src/lib.rs                    module tree, TAILSCALE_CGNAT
  src/model/                    serde types: Config, ServerConfig, Network, Service,
                                Template, Grant, Peer (+ Platform)
  src/secret.rs                 PublicKey / PrivateKey / PresharedKey / Secret (Debug-redacted)
  src/date.rs                   dependency-free civil date for peer expiry
  src/netmap.rs                 Mapping: 1:1 prefix translation (+ property test)
  src/validate.rs               check() + Model (validated view every generator uses)
  src/alloc.rs                  WireGuard pool allocation
  src/io.rs                     FileSystem / ProcessRunner / KeyGenerator traits,
                                memory + real implementations
  src/transport/{mod,wireguard,tailscale}.rs
  src/generate/{firewall,dnsmasq,client,nginx,wg_server}.rs
  src/plan.rs, src/apply.rs
  src/doctor.rs                 host checks run before apply (`parallax doctor`)
  src/testing.rs                canonical fixture shared by all tests
  tests/golden.rs + tests/golden/   frozen outputs for every generator
  tests/example.rs              example/parallax.toml == canonical fixture
crates/parallax-cli/            `parallax` binary (validate, plan, generate, apply,
                                keygen, peer add/remove/show/allocate, export, doctor)
docker/                         Dockerfile, entrypoint, compose (parallax + headscale)
example/parallax.toml           fully commented canonical scenario
tests/integration/netns.sh      Linux network-namespace integration test (CI)
docs/adr/                       decisions
```

## Core types (all `serde`, `deny_unknown_fields`)

```rust
pub struct Config {
    pub server: ServerConfig,
    pub networks: Vec<Network>,     // [[network]]
    pub services: Vec<Service>,     // [[service]]
    pub templates: Vec<Template>,   // [[template]]
    pub peers: Vec<Peer>,           // [[peer]]
}

pub struct ServerConfig {
    pub wireguard: WireGuardServer,   // interface, listen_port, supernet, endpoint,
                                      // public_key, private_key_file
    pub headscale: HeadscaleServer,   // interface, server_url, api_key_file, derp, subnet_router_node
    pub dns: DnsServer,               // listen (default: WG gateway addr), port, public_resolver
    pub firewall: FirewallServer,     // backend (nftables | iptables-nft), docker_coexistence
    pub wan_interface: Option<String>,
}

pub struct Network {
    pub name: String,
    pub interface: String,
    pub gateway_address: Option<Ipv4Addr>, // the gateway host's own LAN address
    pub subnet: Ipv4Net,              // real
    pub mapped_to: Option<Ipv4Net>,   // virtual, same prefix length
    pub upstream_dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,         // zones that live here
    pub masquerade: bool,
}

pub struct Service { name, host: Ipv4Addr, proto: Proto, port: u16, nginx_vhost: bool,
                     hostnames: Vec<String> }

pub struct Template {
    pub name: String,
    pub wireguard: WireGuardTemplate,   // pool: Ipv4Net  (the range IS the tier)
    pub headscale: HeadscaleIdentity,   // user and/or tag
    pub grants: Vec<Grant>,
    pub visible_networks: Option<Vec<String>>,
    pub dns: DnsPolicy,                 // { wireguard: DnsMode, tailscale: DnsMode }
    pub client: ClientDefaults,         // allowed_ips strategy, mtu, persistent_keepalive
}

#[serde(tag = "kind")]
pub enum Grant { AllNetworks, Network{name}, Host{ip}, HostPort{ip,proto,port}, Service{name}, Internet }
pub enum DnsMode { Split, TunnelWide, None }
pub enum AllowedIpsStrategy { MappedSubnets, GrantsOnly, FullTunnel }

pub struct Peer {
    pub name: String,
    pub template: String,
    pub transport: TransportKind,        // WireGuard | Tailscale (a device fact)
    pub enabled: bool,
    pub expires: Option<Date>,
    pub wireguard: Option<WireGuardPeer>, // public_key, address, private_key?, preshared_key?
    pub tailscale: Option<TailscalePeer>, // node_id?, address?  (M2)
}
```

Two additions relative to the handoff, both small and flagged:

- `Grant::Internet` and `server.wan_interface`. Without an egress grant the
  `full_tunnel` AllowedIPs strategy has no meaning (all non-LAN traffic would be
  dropped by the trailing deny). Validation refuses `full_tunnel` without it.
- `Template.dns` is per transport (`wireguard` / `tailscale`) because the
  canonical scenario wants tunnel-wide DNS on plain WireGuard for the family
  tier but split DNS through the Tailscale client.

Grants are written against real addresses. `Model::reaches(template)` resolves
them to `Reach { label, kind: Lan { network, real, port, proxied } | Internet }` and
`Reach::client_net()` translates to virtual space for clients, nginx and (M2)
Headscale ACLs. The nftables FORWARD chain matches real addresses because it
runs after PREROUTING NETMAP.

## The `Transport` trait

```rust
pub trait Transport {
    fn kind(&self) -> TransportKind;
    fn ingress_interface(&self, server: &ServerConfig) -> String;      // wg0 / tailscale0
    fn source_range(&self, server: &ServerConfig) -> Ipv4Net;          // WG supernet / 100.64.0.0/10
    fn tier_source(&self, server: &ServerConfig, t: &Template) -> TierSource; // Cidr(pool) / Set("ts_<t>")
    fn tier_members(&self, model: &Model, t: &Template) -> Vec<Ipv4Net>;     // pool / one /32 per node
    fn provision(&self, model: &Model, t: &Template, name: &str,
                 keys: &dyn KeyGenerator, opts: &ProvisionOptions) -> Result<Peer>;
    fn generate(&self, model: &Model, fs: &dyn FileSystem) -> Result<Vec<Artifact>>;
    fn export(&self, model: &Model, peer: &Peer, platform: Platform) -> Result<Export>;
    fn apply(&self, model: &Model, artifacts: &[Artifact], sys: System) -> Result<Vec<String>>;
}
pub fn all() -> Vec<Box<dyn Transport>>   // always [WireGuard, Tailscale]
```

The shared generators (`firewall`, `dnsmasq`, `nginx`) iterate `transport::all()`
and only use the first five methods. That is why the M1 nftables table already
has its final shape: NETMAP matches `{ "wg0", "tailscale0" }`, every template
gets a WireGuard rule block keyed on its pool and a Tailscale block keyed on
the `ts_<template>` set (empty until M2 syncs it), and both transports end
with a catch-all deny. `TailscaleTransport` implements those five methods
today and returns `NotImplemented` for provision/export.

The INPUT chain is locked down too: from a tunnel interface only the shim
(UDP/TCP 53 to the shim address), ICMP echo, grants that cover a network's
`gateway_address`, and the HTTPS proxy for tiers with a proxied grant are
accepted, then drop. A host-networked gateway otherwise
exposes every published container port and its SSH to guest peers. With
`gateway_address` set, services on the gateway box itself are reachable
through the mapping exactly like any other LAN host, tier by tier. LAN-side
INPUT is untouched (policy accept).

Every packet a tunnel peer sends is checked against its tier's grants, not
only the first packet of a flow. Only reply-direction packets (`ct direction
reply`) and related ones (ICMP errors) skip the check, and invalid ones are
dropped, in both INPUT and FORWARD. So removing a grant cuts already-open
connections on their next packet, with no conntrack flush on apply (which
would drop everyone's sessions, or need a diff of what changed).

Checking every packet is only cheap if a packet doesn't walk past every
other template's rules first (with 200 rules ahead of it, small-packet UDP
through WireGuard ran at a quarter of the speed; `dev/bench/firewall.sh`
measures this). So each template's FORWARD rules live in their own chain
(`tier_<template>`, ending in its default deny), and FORWARD picks the
chain with one verdict-map lookup on the source address:
`iifname "wg0" ip saddr vmap { 10.8.1.0/24 : jump tier_personal, ... }`.
Tailscale tiers are sets of node addresses, so they get one `jump` rule per
template for now. The `iptables-nft` backend has no verdict maps: it jumps
to numbered chains (`PARALLAX_T<n>`) with one rule per template.

`internet` reaches public addresses only: FORWARD to the WAN interface
excludes private, shared (CGNAT), loopback, link-local, multicast, reserved,
documentation and benchmarking ranges as well as the configured networks
(the `not_public` set). Otherwise a guest with full tunnel could reach
subnets the router knows but Parallax doesn't, such as other VLANs. A
template that also has `all_networks` is the owner's own and keeps
"everything outside the configured networks" (`lan_real`).

Tunnel peers are IPv4-only: WireGuard's AllowedIPs already refuses IPv6, and
an explicit drop for IPv6 from a tunnel interface in INPUT and FORWARD keeps
it that way for transports that might carry it (Tailscale). The
`iptables-nft` backend renders IPv4 tables only, so it has no such rule.

## Proxied HTTPS services

One address and port often serves many sites (an nginx with several
virtual hosts), so a firewall rule on `host:443` lets a template reach all
of them. A service with `hostnames` closes that gap: `service` grants reach
it only through Parallax's own HTTPS proxy, which terminates TLS, checks
SNI, `Host` and HTTP/2 `:authority` on every request, and forwards only the
listed names to the service. The firewall gives such grants no direct
accept (`ReachKind::Lan { proxied: true }`). Instead, for each tier with a
`service` grant on a proxied service, PREROUTING sends its `tcp/443` to that
service's address, as clients see it (virtual where mapped), to the proxy
(`server.proxy`, `10.8.0.1:8443` by default). The rule comes before NETMAP,
since NAT takes the first match. A tier that already reaches that host's 443
directly (`all_networks`, its network, `host`, a matching `host_port`) gets
no redirect: the proxy would add nothing. Only tiers with a redirect may
reach the proxy port in INPUT. The firewall works per tier and the proxy per
hostname: when a tier loses one of several proxied hostnames, its other
redirects keep the proxy port open to it, and the proxy closes the revoked
hostname's connections when it reloads. So whatever runs `apply` also sends
the proxy SIGHUP (the Docker entrypoint does).

Validation keeps it honest: hostnames are lower-case DNS names, unique
across services, inside a `domains` zone of the service's network (or
clients couldn't resolve them through the shim), and only on `tcp/443`. A
template with another grant that reaches the same host's web ports directly
(`all_networks`, its network, `host`, tcp/80, or 443 on either protocol)
gets a warning naming that grant, since it can bypass the hostname check.
Proxied reaches also don't count toward nginx `allow` snippets: the proxy
connects from the gateway, and sibling sites on the same address mustn't
inherit the tier.

Parallax never issues certificates. The proxy reads PEM certificates
and keys from one folder the operator mounts (certbot's layout works) and
uses whichever certificate covers each hostname.

### The proxy (`parallax proxy`, crate `parallax-proxy`)

`apply` writes `proxy/routes.toml`: the listen address, the certificate
folder, the upstream CA bundle, and one site per hostname with its upstream
(the service's real `host:port`) and the tier members allowed to use it.
A site exists only when some template has a `service` grant on it, and
only that template's members are allowed: every proxied tier lands on the
same proxy, so the source address is what keeps one tier off another
tier's hostnames. The proxy reads nothing else from the configuration.

Per connection, before any certificate is sent: the SNI must name a site,
the tunnel source address must be in that site's `allowed` list, and a
certificate must cover the name. Anything else gets no handshake. Then, on
every request (HTTP/1.1 or HTTP/2): `Host` and `:authority` must name the
SNI hostname (port 443 or none), or `421`; `CONNECT` gets `405`; HTTP/1
absolute-form targets get `400`. Checked requests go to the site's
upstream over HTTP/1.1 and TLS, verified against the hostname; the
upstream address comes from the routes, never from a client-supplied name.
Forwarding headers are replaced, not appended (`X-Forwarded-For` is the
tunnel address). WebSocket upgrades pass through; other upgrades (`h2c`)
are dropped, since after a switch the proxy only relays bytes. HTTP/1 vs
HTTP/2 comes from ALPN, so the header timeout runs from the first byte, and
one tunnel address may hold at most 64 connections.

Reloads (SIGHUP) swap the routes whole. Every request looks its site up in
the current routes, and open connections and WebSocket relays are closed
when a reload takes their hostname away from their address. A reload that
fails (unreadable routes or CA bundle) refuses everything until one
succeeds: the old routes may grant what the new configuration took away.

Certificates: every directory under the folder holding `fullchain.pem` and
`privkey.pem` is one certificate. An exact name beats a wildcard; ties go to
path order. The folder is re-checked every minute, so renewals need no
restart. A certificate whose key is missing or doesn't match is skipped.
`plan` and `apply` make the same choice and fail, naming the hostname, when
a site has no usable certificate or the upstream CA bundle doesn't load, so
the proxy isn't handed routes it would refuse. In Docker, the container
stops if the proxy does, and the restart policy takes over.

Docker note: a Docker-published port on the gateway host is reached through
`docker-proxy` listening on the host address, because the NETMAP DNAT and
Docker's DNAT cannot both apply to one connection. That is Docker's default
(`userland-proxy: true`); with it disabled, published ports are not reachable
via the virtual address. Parallax's prerouting chain runs at `dstnat - 10`,
ahead of Docker's DNAT: the first NAT binding wins, so a tier's redirect to
the proxy can't lose to a port Docker publishes on the gateway.

## Generated artifacts (output directory layout)

```
wireguard/wg0.conf                 wg(8) format for `wg syncconf`   (0600)
nftables/parallax.nft              table inet parallax, atomic replace
nftables/docker-user.nft           DOCKER-USER accepts (docker_coexistence)
dnsmasq/parallax.conf              domain-scoped shim
nginx/snippets/parallax-<t>.conf   allow lines per tier
nginx/snippets/parallax-service-<s>.conf   allow lines + deny all per vhost
proxy/routes.toml                  sites for `parallax proxy`
clients/<peer>/<platform>.conf     only for peers that retain their private key (0600)
```

`iptables-nft` backend writes `iptables/parallax.rules` (iptables-restore
format, PARALLAX_* chains) and `iptables/docker-user.rules` instead.

## Apply order and idempotency

firewall (`nft -c -f` then `nft -f`) → WireGuard (`ip link add` if missing,
`ip address replace`, `wg syncconf`, `ip link set up`) → dnsmasq (`--test`,
kill previous pid, start). Every step is a replace, never an insert/delete
pair, so re-applying an unchanged bundle is a no-op (asserted by
`apply_runs_expected_commands_and_is_idempotent`).
