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
  src/testing.rs                canonical fixture shared by all tests
  tests/golden.rs + tests/golden/   frozen outputs for every generator
  tests/example.rs              example/parallax.toml == canonical fixture
crates/parallax-cli/            `parallax` binary (validate, plan, generate, apply,
                                keygen, peer add/remove/show/allocate, export)
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
    pub subnet: Ipv4Net,              // real
    pub mapped_to: Option<Ipv4Net>,   // virtual, same prefix length
    pub upstream_dns: Vec<Ipv4Addr>,
    pub domains: Vec<String>,         // zones that live here
    pub masquerade: bool,
}

pub struct Service { name, host: Ipv4Addr, proto: Proto, port: u16, nginx_vhost: bool }

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
them to `Reach { label, kind: Lan { network, real, port } | Internet }` and
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
(UDP/TCP 53 to the shim address) and ICMP echo are accepted, then drop. A
host-networked gateway otherwise exposes every published container port and
its SSH to guest peers. LAN-side INPUT is untouched (policy accept).

## Generated artifacts (output directory layout)

```
wireguard/wg0.conf                 wg(8) format for `wg syncconf`   (0600)
nftables/parallax.nft              table inet parallax, atomic replace
nftables/docker-user.nft           DOCKER-USER accepts (docker_coexistence)
dnsmasq/parallax.conf              domain-scoped shim
nginx/snippets/parallax-<t>.conf   allow lines per tier
nginx/snippets/parallax-service-<s>.conf   allow lines + deny all per vhost
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
