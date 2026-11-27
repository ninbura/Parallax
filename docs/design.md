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
                                Grant, Rule, Peer (+ Platform); legacy.rs reads
                                template-era TOML
  src/tier.rs                   peers with the same grants form a tier
  src/grants.rs                 changing grants and who has them (CLI, later GUI)
  src/headscale.rs              Headscale's users and nodes, read through its API (ADR 0014)
  src/secret.rs                 PublicKey / PrivateKey / PresharedKey / Secret (Debug-redacted)
  src/date.rs                   dependency-free civil date for peer expiry
  src/netmap.rs                 Mapping: 1:1 prefix translation (+ property test)
  src/validate.rs               check() + Model (validated view every generator uses)
  src/alloc.rs                  WireGuard address allocation (from the supernet)
  src/io.rs                     FileSystem / ProcessRunner / KeyGenerator traits,
                                memory + real implementations
  src/transport/{mod,wireguard,tailscale}.rs
  src/generate/{firewall,dns,proxy,client,nginx,wg_server}.rs
  src/plan.rs, src/apply.rs
  src/doctor.rs                 host checks run before apply (`parallax doctor`)
  src/testing.rs                canonical fixture shared by all tests
  tests/golden.rs + tests/golden/   frozen outputs for every generator
  tests/example.rs              example/parallax.toml == canonical fixture
crates/parallax-store/          the database (Turso, SQLite's file format): Config in, Config out; backups
  migrations/                   schema, one numbered SQL file per change
crates/parallax-core/src/reconcile.rs   the daemon's apply triggers, drift listing, teardown
crates/parallax-proxy/          the HTTPS proxy (a task in the daemon)
crates/parallax-dns/            the DNS server (a task in the daemon)
crates/parallax-cli/            `parallax` binary (daemon, status, validate, plan,
                                generate, apply, keygen, config import/export/edit,
                                backup, grant, peer add/remove/show/grants,
                                export, doctor);
                                src/daemon.rs and src/protocol.rs: the daemon and
                                its socket protocol
docker/                         Dockerfile, entrypoint, compose (parallax + headscale)
packaging/                      the native install (ADR 0013, docs/native.md): the
                                systemd unit, sysusers.d, tmpfiles.d, modules-load.d,
                                sysctl.d, nfpm.yaml (the .deb and Arch package)
example/parallax.toml           fully commented canonical scenario
tests/integration/netns.sh      Linux network-namespace integration test (CI), with
                                the daemon as root or as the native unit
docs/adr/                       decisions
```

## Core types (all `serde`, `deny_unknown_fields`)

```rust
pub struct Config {
    pub server: ServerConfig,
    pub networks: Vec<Network>,     // [[network]]
    pub services: Vec<Service>,     // [[service]]
    pub grants: Vec<Grant>,         // [[grant]]
    pub peers: Vec<Peer>,           // [[peer]]
}

pub struct ServerConfig {
    pub wireguard: WireGuardServer,   // interface, listen_port, supernet, endpoint,
                                      // public_key, private_key_file, peer_defaults
    pub headscale: HeadscaleServer,   // interface, server_url, api_key_file, derp,
                                      // subnet_router_node, dns (tailnet-wide)
    pub dns: DnsServer,               // listen (default: WG gateway addr), port, public_resolver
    pub firewall: FirewallServer,     // backend (nftables | iptables-nft), docker_coexistence
    pub logs: LogsServer,             // level, path, keep, max_size (docs/logging.md)
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

pub struct Service { name, host: Host, ports: Vec<PortSpec>, nginx_vhost: bool,
                     hostnames: Vec<String> }
pub struct PortSpec { first: u16, last: u16, proto: Option<Proto> }   // "445/tcp", "137-138/udp", "25565" (both)
pub enum Host { Ip(Ipv4Addr), Name(String) }   // TOML: a string either way

pub struct Grant {
    pub name: String,
    pub everyone: bool,                 // every peer has it, unattached
    pub log: Option<LogLevel>,          // sets its peers' log level (docs/logging.md)
    pub rules: Vec<Rule>,
}

#[serde(tag = "kind")]
pub enum Rule { AllNetworks, Network{name}, Host{host, ports}, Service{name}, Internet, PublicDns }
pub enum DnsMode { Split, TunnelWide, None }
pub enum AllowedIpsStrategy { MappedSubnets, GrantsOnly, FullTunnel }

pub struct Peer {
    pub name: String,
    pub grants: Vec<String>,             // besides every `everyone` grant
    pub log: Option<LogLevel>,           // its own log level, over its grants'
    pub transport: TransportKind,        // WireGuard | Tailscale (a device fact)
    pub enabled: bool,
    pub expires: Option<Date>,
    pub wireguard: Option<WireGuardPeer>, // public_key, address, private_key?, preshared_key?,
                                          // dns, allowed_ips, mtu?, persistent_keepalive?,
                                          // visible_networks?
    pub tailscale: Option<TailscalePeer>, // node_id?, address?  (M2)
}
```

Access is named grants (ADR 0010). A peer has any number of them and
reaches the union of their rules plus every `everyone` grant; rules only
add. Peers with the same effective grants form a **tier** (`tier.rs`), and
every generator works per tier: one firewall chain, one DNS and one proxy
entry each, built from the union. A WireGuard peer's address is the lowest
free one of the supernet and says nothing about access, so changing its
grants changes neither the address nor its client config (except
`AllowedIPs` under `grants_only`). How the client is set up (DNS mode,
`allowed_ips`, MTU, keepalive, visible networks) is per peer, copied from
`server.wireguard.peer_defaults` when it's added. Files written with
`[[template]]` still import (`model/legacy.rs`), each template becoming a
grant of its name.

Activity logging (`logging.rs`, docs/logging.md) is per peer, not per tier:
a peer's own `log` wins, then the most detailed `log` among its grants, then
`server.logs.level`. The firewall keeps two address sets, `log_flows` and
`log_denied` (each name followed by a hash of its members), marks the new flows of the first (connection mark bit
`0x20000000`) and hands the blocked attempts of the second to nflog group
20568, rate-limited, before each drop they can reach (a tier's default deny,
the unknown-source drop, the gateway host's). With nobody logged none of it
is generated: the canonical goldens have no logging rule or set.

The daemon's collector (`daemon/collector.rs`, ADR 0012) reads connection
tracking's events and that nflog group from netlink sockets, only while some
peer needs them. `netlink.rs` parses the bytes into events,
`logging::attribute` turns each into a record (peer and grant names as they
are now, the destination as addressed and as real), and each feed commits
its batches to `logs.db` (`parallax_store::logs`) with `BEGIN CONCURRENT`.
The daemon purges by age and size every 10 minutes and answers `parallax log
show` from the same database.

Ports are lists, written the way ufw writes them: `445/tcp`, `137-138/udp`,
or a bare `25565` for TCP and UDP. A service is a named host and its ports
(SMB is one service with four ports), used by any number of grants. A
`host` rule is the inline form for one-offs: with `ports` it opens those,
without them every port. The firewall matches one set of ports per protocol
per rule (`tcp dport { 139, 445 }`). Older configurations still import: a
service's single `port`/`proto`, and `host_port` rules (now a `host` rule
with one port).

Two additions relative to the handoff, both small and flagged:

- `Rule::Internet` and `server.wan_interface`. Without an egress rule a
  `full_tunnel` device reaches only what it's granted (the trailing deny drops
  the rest); validation warns, since that's usually a mistake but can be a
  locked-down device on purpose.
- The DNS mode differs per transport: a WireGuard peer has its own
  (`peer.wireguard.dns`; the canonical guest phone is tunnel-wide), while
  Tailscale nodes share `server.headscale.dns`, since the Tailscale client
  does split DNS natively. A `public_dns` rule lets a tier look up public
  names through the gateway; see "DNS server".

Rules are written against real addresses, or DNS names that resolve to
them (ADR 0009): a name is looked up through the resolvers of the network
whose zone holds it, and grants what it resolved to when every address is
inside a configured network or is the home's public IP. The public IP is
port forwards: a tier that doesn't reach everything gets one port at
a time there, and web ports only through the HTTPS proxy
(`ReachKind::HomePublic`). Those addresses are an input to generation
(`Model::with_names`), like the date. `Model::reaches(tier)` resolves
them to `Reach { label, kind: Lan { network, real, port, proxied } | HomePublic { address, port, proxied } | Internet }` and
`Reach::client_net()` translates to virtual space for clients, nginx and (M2)
Headscale ACLs. The nftables FORWARD chain matches real addresses because it
runs after PREROUTING NETMAP.

## The `Transport` trait

```rust
pub trait Transport {
    fn kind(&self) -> TransportKind;
    fn ingress_interface(&self, server: &ServerConfig) -> String;      // wg0 / tailscale0
    fn source_range(&self, server: &ServerConfig) -> Ipv4Net;          // WG supernet / 100.64.0.0/10
    fn set_name(&self, tier: &Tier) -> String;                          // wg_<key> / ts_<key>
    fn members_known(&self) -> bool;                                    // WG: yes; TS: synced (M2)
    fn tier_members(&self, model: &Model, tier: &Tier) -> Vec<Ipv4Net>; // one /32 per active member
    fn provision(&self, model: &Model, grants: &[String], name: &str,
                 keys: &dyn KeyGenerator, opts: &ProvisionOptions) -> Result<Peer>;
    fn generate(&self, model: &Model, fs: &dyn FileSystem) -> Result<Vec<Artifact>>;
    fn export(&self, model: &Model, peer: &Peer, platform: Platform) -> Result<Export>;
    fn apply(&self, model: &Model, artifacts: &[Artifact], sys: System) -> Result<Vec<String>>;
}
pub fn all() -> Vec<Box<dyn Transport>>   // always [WireGuard, Tailscale]
```

The shared generators (`firewall`, `dns`, `proxy`, `nginx`) iterate `transport::all()`
and only use the methods above `provision`. That is why the M1 nftables table
already has its final shape: NETMAP matches `{ "wg0", "tailscale0" }`, every
tier has a member set per transport (`wg_<key>`, and `ts_<key>`, the
addresses Headscale gave the tier's Tailscale peers' nodes, ADR 0014; the key
is a hash of the set's members and every rule that uses it or sits in the
tier's chain, so a set name never changes meaning between applies), and both
transports end with a catch-all deny.
`TailscaleTransport` implements those today and returns `NotImplemented` for
provision/export.

The INPUT chain is locked down too: from a tunnel interface only DNS
(UDP/TCP 53 to the DNS server's address), ICMP echo, grants that cover a network's
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
other tier's rules first (with 200 rules ahead of it, small-packet UDP
through WireGuard ran at a quarter of the speed; `dev/bench/firewall.sh`
measures this). So each tier's FORWARD rules live in their own chain
(`tier_<n>`, ending in its default deny; numbered, since a tier may be
several grants, which the rules' comments name), and FORWARD picks the
chain with one verdict-map lookup on the peer's source address:
`iifname "wg0" ip saddr vmap { 10.8.1.1 : jump tier_0, 10.8.2.1 : jump tier_1, ... }`.
Tailscale tiers are sets of node addresses, so they get one `jump` rule per
tier. INPUT and the proxy
redirect match a tier's member set, one rule per tier. The `iptables-nft`
backend has no verdict maps: it jumps to numbered chains (`PARALLAX_T<n>`)
with one rule per peer address.

`internet` reaches public addresses only: FORWARD to the WAN interface
excludes private, shared (CGNAT), loopback, link-local, multicast, reserved,
documentation and benchmarking ranges as well as the configured networks
(the `not_public` set). Otherwise a guest with full tunnel could reach
subnets the router knows but Parallax doesn't, such as other VLANs. A
tier that also has `all_networks` is the owner's own and keeps
"everything outside the configured networks" (`lan_real`).

Tunnel peers are IPv4-only: WireGuard's AllowedIPs already refuses IPv6, and
an explicit drop for IPv6 from a tunnel interface in INPUT and FORWARD keeps
it that way for transports that might carry it (Tailscale). The
`iptables-nft` backend renders IPv4 tables only, so it has no such rule.

## Proxied HTTPS services

One address and port often serves many sites (an nginx with several
virtual hosts), so a firewall rule on `host:443` lets a peer reach all
of them. A service with `hostnames` closes that gap: `service` rules reach
it only through Parallax's own HTTPS proxy, which terminates TLS, checks
SNI, `Host` and HTTP/2 `:authority` on every request, and forwards only the
listed names to the service. The firewall gives such rules no direct
accept (`ReachKind::Lan { proxied: true }`). Instead, for each tier with a
`service` rule on a proxied service, PREROUTING sends its `tcp/443` to that
service's address, as clients see it (virtual where mapped), to the proxy
(`server.proxy`, `10.8.0.1:8443` by default). The rule comes before NETMAP,
since NAT takes the first match. A tier that already reaches that host's 443
directly (`all_networks`, its network, a `host` rule covering tcp/443) gets
no redirect: the proxy would add nothing. Only tiers with a redirect may
reach the proxy port in INPUT. The firewall works per tier and the proxy per
hostname: when a tier loses one of several proxied hostnames, its other
redirects keep the proxy port open to it, and the proxy closes the revoked
hostname's connections when it reloads. So the daemon has the proxy re-read
its routes after every apply.

Validation keeps it honest: hostnames are lower-case DNS names, unique
across services, inside a `domains` zone of the service's network (or
clients couldn't resolve them through the DNS server), and only on `tcp/443`. A
tier with another rule that reaches the same host's web ports directly
(`all_networks`, its network, `host`, tcp/80, or 443 on either protocol)
gets a warning naming that rule and its grant, since it can bypass the
hostname check.
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
A site exists only when some tier has a `service` rule on it, and
only that tier's members are allowed: every proxied tier lands on the
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

Reloads (after each apply) swap the routes whole. Every request looks its site up in
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

## DNS server

Every tier asks the same address (`server.dns.listen`, by default the
WireGuard gateway address), and the answer depends on who asks. The DNS
server (crate `parallax-dns`, built on hickory, a task in the daemon) reads
`dns/routes.toml`, which `apply` writes, and re-reads it after each apply:

- **Who asks.** The source address picks the tier: its peers' WireGuard
  addresses, or (M2) its Tailscale nodes. WireGuard ties the source address
  to the peer's key. A source outside every tier is refused.
- **What it may ask.** A network rule (or `all_networks`) gives the
  network's `domains`; a `service` rule gives the service's `hostnames`.
  A `host` rule on a name gives that name (one by address gives none), and
  so does a granted service whose host is a name. Names outside every zone
  go to `server.dns.public_resolver`, only for tiers with `public_dns`.
  Everything else is `REFUSED`. A name inside a zone is never sent to the
  public resolver, even for a public tier: it would leak the operator's
  names, and the public answer is the home's public address.
- **Home zones** go to the owning network's `upstream_dns` (the most specific
  zone wins). A records inside a mapped network are rewritten into its
  virtual prefix by the same `Mapping` the NETMAP rules come from, so DNS
  and the firewall can't drift. Public addresses, those in an unmapped
  network and those already in a virtual prefix pass unchanged; any other
  private or reserved address is dropped, because on a visited network with
  the same prefix it would lead to a stranger's host. When that leaves no
  address, the CNAMEs go too. AAAA, SVCB and HTTPS records are dropped:
  peers can't send IPv6, and address hints would carry real addresses. A tier
  that may see a single name (a service hostname) gets only records of the
  asked type, under the asked name: a CNAME would name the sibling it points
  at.
- **Public answers** lose A/AAAA records, and SVCB/HTTPS records with address
  hints, in private, reserved or mapped space (DNS rebinding).
- Names are compared in ASCII (punycode), as zones are written.
- It holds no records and doesn't recurse. One caching resolver per zone,
  2-second upstream timeout, TCP fallback; `SERVFAIL` when the upstream fails.
  UDP answers follow the client's EDNS size, and anything larger is
  truncated so the client retries over TCP. One tunnel address may have 64
  lookups in flight.
- A reload that fails refuses every query until one succeeds, like the
  proxy: answering by grants that may have been revoked is worse than not
  answering.

DNS is convenience, never enforcement: the firewall and the proxy are the
gate. The DNS server only keeps a guest from using the gateway's resolver for
names it has no business with (and from sending its lookups out through the
home connection). Why not dnsmasq or another server: ADR 0004.

## Storage (`parallax-store`)

The configuration lives in a database file, `/var/lib/parallax/parallax.db`
by default (`--db`, `PARALLAX_DB`), mode 0600 together with its write-ahead
log. `Store::load` returns a whole `Config`; `Store::save` writes one back in
a single transaction. `parallax-core` never sees the database. Decisions and
alternatives: ADR 0005.

- One table per part of the model, child tables with a `position` for lists
  (`network_domains`, `grant_rules`, `peer_grants`, ...). Values are TEXT in their TOML
  spelling.
- Every row has a hidden integer id beside its unique name; references between
  tables use the id. `save` matches rows by name, so a kept name keeps its id.
- Migrations: `crates/parallax-store/migrations/NNNN_*.sql`, applied in order
  when the database opens. A newer database than the binary knows is refused.
- One process at a time (Turso's default lock): the daemon while it runs,
  otherwise each CLI command while it needs it. Every change is one write
  transaction (`Store::update`). With the daemon, changes queue in its one
  writer (ADR 0007).
- MVCC mode (`BEGIN CONCURRENT`, ADR 0011): opening a database switches it once,
  before migrating. `sqlite3` can't open the live file; a backup's copy it can.
- The database and its logs (`-wal`, MVCC's `-log`) are 0600.

The CLI validates before every save, so the database only ever holds a valid
configuration. `config import` and `config edit` also give WireGuard peers
without an address the next free one.

Backups (`parallax_store::backup`, ADR 0006): `parallax-backup-<time>.tar`
holds a plaintext `manifest.toml` and `payload.tar.age`, which is `age`
passphrase-encrypted and holds a copy of the database, rebuilt from its rows
in WAL mode (the live one runs in MVCC mode, ADR 0011), and the
server key. Restore stages the backup's database next to the live one,
migrates and checks it, then replaces every row of the live database with
its rows in one write transaction. Operator guide: `docs/backup.md`.

## Generated artifacts (output directory layout)

```
wireguard/wg0.conf                 wg(8) format for `wg syncconf`   (0600)
nftables/parallax.nft              table inet parallax, atomic replace
nftables/docker-user.nft           DOCKER-USER accepts (docker_coexistence)
dns/routes.toml                    zones, mappings and tiers for the DNS server
nginx/snippets/parallax-<g>.conf   allow lines for every peer with grant <g>
nginx/snippets/parallax-service-<s>.conf   allow lines + deny all per vhost
proxy/routes.toml                  sites for the HTTPS proxy
clients/<peer>/<platform>.conf     only for peers that retain their private key (0600)
```

`iptables-nft` backend writes `iptables/parallax.rules` (iptables-restore
format, PARALLAX_* chains) and `iptables/docker-user.rules` instead.
Its sets live in the host's one ipset namespace, so apply removes only
stale sets named as Parallax names them (`wg_`, `ts_`, `lan_real_`,
`not_public_`, `log_flows_` or `log_denied_` and a 16-digit hex hash, or
plain `log_flows` and `log_denied`) and leaves every other set alone. Builds
before named grants made empty `ts_<template>` sets, and builds before
hashed names plain `lan_real` and `not_public` ones; those stay, unused,
until removed with `ipset destroy`.
Every set is named after what it means: its members and the rules that use
it. apply fills sets before `iptables-restore` swaps the rules, so a set
the old rules use must not change: a changed set gets a new name and is
filled beside the old one, the restore moves every rule to the new sets in
one step, and the old ones are destroyed after it. A failed restore leaves
the old rules with exactly the sets they had (issue #35).

## Apply order and idempotency

firewall (`nft -c -f` then `nft -f`) → WireGuard (`ip link add` if missing,
`ip address replace`, `wg syncconf`, `ip link set up`). Every step is a
replace, never an insert/delete pair, so re-applying an unchanged bundle is a
no-op (asserted by `apply_runs_expected_commands_and_is_idempotent`). The DNS
server and the HTTPS proxy are tasks in the daemon that read the routes
`apply` wrote; the daemon starts them after the first apply and has them
re-read after each one.

## The daemon

`parallax daemon` (ADR 0007) holds the database, keeps the configuration in
memory and keeps the gateway applied: at startup, after every saved change,
on SIGHUP, when the UTC date changes, and when the live table or WireGuard
interface differs from the listing taken after the last apply (checked every
60 s). A failed apply is retried every tick. It serves DNS and the proxy,
runs automatic backups and the activity collector, and listens on
`/run/parallax/parallax.sock` for the CLI: one JSON request and one JSON
reply per connection, with a `protocol` number both sides must match
(`PROTOCOL` in `protocol.rs`). Saves
carry the revision they were based on; an older one is refused and the CLI
retries against the latest. With no daemon answering, the CLI opens the
database itself. SIGTERM deletes the table and the interface.

When a guest tier has `internet`, the daemon also keeps the home's
public IP (ADR 0008): it looks it up at startup, every 5 minutes and when a
saved change alters what the lookup depends on, re-applies when it changes,
and keeps the last one found in the `daemon_state` table. The address is an
input to generation (`Model::with_public_ip`), like the date; it joins the
`not_public` set those tiers' `internet` accept excludes, because the router
would hairpin it back into the home. The lookup logic is `parallax_core::public_ip`,
behind the `Resolver` trait in `io.rs`; `parallax_dns::Lookup` is the real
one (plain DNS, and DNS over HTTPS by IP address).

Hosts named by DNS name (ADR 0009) are looked up the same way, through their
zone's `upstream_dns`: right after startup, every 5 minutes and when a saved
change alters the names or the networks. Only the latest answer counts: a
name whose lookup fails or is refused grants nothing until it resolves
again, and answers aren't stored. A save that adds a name looks
it up first and is refused if it doesn't resolve to addresses inside the
configured networks.

When a Tailscale peer names a Headscale node (`peer.tailscale.node_id`), the
daemon asks Headscale's admin API for its nodes (ADR 0014): before the
first apply, every 10 seconds and when a saved change alters where Headscale
is. The addresses are an input to generation (`Model::with_tailnet`), and a
change applies again. Such a peer has only its node's address: none before
Headscale first answers or once the node is gone. When Headscale stops
answering, the last answer stays. The
logic is `parallax_core::headscale`, behind the `HeadscaleApi` trait in
`io.rs`; the real client is `parallax-cli`'s `headscale.rs`, and Headscale
itself is built from a pinned commit (`docker/headscale.Dockerfile`).

Tailscale traffic enters through the subnet router, a `tailscaled` on the
gateway (ADR 0015). While any peer is on Tailscale, the daemon looks at it
every 30 seconds and after each saved change, through the `tailscale` CLI
(`--tailscale-socket`) and Headscale's API. Logged out, it gets logged in as
`subnet_router_node` under the Headscale user `parallax` with a single-use
pre-auth key. As Parallax's own node, it's kept advertising exactly
`subnet_router::routes` (each network's client subnet, the DNS and proxy
addresses) with its filtering, SNAT, DNS and route acceptance off, and
exactly those routes are approved. As anyone else's node (the machine's own
Tailscale), it's left alone and the operator is told what to run. The
logic is `parallax_core::subnet_router`, pure apart from the
`ProcessRunner` and `HeadscaleApi` it's given.
