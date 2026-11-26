//! The gateway firewall: one complete table owned by Parallax, replaced
//! atomically. Rules are built as a small IR and rendered by the selected
//! backend (`nftables` default, `iptables-nft` fallback), so both backends
//! carry identical semantics.
//!
//! Design invariants:
//! - Access control is FORWARD-chain only, keyed on the tunnel source address
//!   (WireGuard: cryptographically bound to the peer key; Tailscale: node IP
//!   set mirrored from Headscale).
//! - NETMAP rules key on the destination prefix and match both ingress
//!   interfaces; return traffic is unambiguous because the transports' source
//!   ranges are disjoint.
//! - Peers with the same grants form a tier ([`crate::tier`]). Every tier
//!   ends with a default deny; every transport ends with a catch-all deny
//!   for unknown sources (peers without grants among them).
//! - The gateway host itself is not a destination unless a network declares
//!   `gateway_address`: grants covering that address become INPUT accepts with
//!   the same source and port constraints. Everything else from a tunnel
//!   interface to the host (beyond the DNS shim and ICMP echo) is dropped, so
//!   a host-networked gateway does not expose its other services to peers.
//! - Services with `hostnames` get no direct accept: they're reached only
//!   through the HTTPS proxy, which checks the hostname on every request.
//!   Prerouting sends a granted tier's `tcp/443` for that address to the
//!   proxy (before NETMAP), and INPUT lets only those tiers reach the proxy.
//! - Every packet a tunnel peer sends is checked against its grants, not just
//!   the first of a flow: only reply-direction and related packets skip the
//!   check. Removing a grant cuts open connections on their next packet.
//!   To keep that cheap, each tier's forward rules are their own chain,
//!   picked by one source-address lookup (a verdict map of every peer's
//!   address), so a packet never walks past other tiers' rules.
//! - `internet` reaches public addresses only, unless the tier also has
//!   `all_networks` (then it's everything outside the configured networks).
//!   Public-only tiers also exclude the home's own public IP, which the
//!   router would hairpin back into the home ([`crate::public_ip`]).
//! - Tunnel peers are IPv4-only: IPv6 from a tunnel interface is dropped.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddrV4};

use ipnet::Ipv4Net;

use super::{Artifact, ArtifactKind};
use crate::model::{FirewallBackend, PortRange, Proto};
use crate::tier::Tier;
use crate::transport;
use crate::validate::{Model, ReachKind};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Input,
    Forward,
    Prerouting,
    Postrouting,
    /// One tier's forward rules, by index into [`Ruleset::tiers`].
    Tier(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    Any,
    Cidr(Ipv4Net),
    Cidrs(Vec<Ipv4Net>),
    Set(String),
    NotSet(String),
}

/// A connection-tracking condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ct {
    /// A packet travelling in the reply direction of a tracked flow.
    Reply,
    /// The first packet of a flow related to a tracked one (ICMP errors).
    Related,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    /// Rewrite the destination to one address and port.
    Dnat {
        to: SocketAddrV4,
    },
    /// Continue in a tier's chain (index into [`Ruleset::tiers`]).
    Jump(usize),
    /// Jump to the tier chain of the source address: one lookup, however
    /// many peers and tiers there are.
    SourceVmap(Vec<(Ipv4Net, usize)>),
    /// 1:1 prefix translation of the destination.
    NetmapDst {
        from: Ipv4Net,
        to: Ipv4Net,
    },
    /// 1:1 prefix translation of the source.
    NetmapSrc {
        from: Ipv4Net,
        to: Ipv4Net,
    },
    Masquerade,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub chain: Chain,
    pub iif: Vec<String>,
    pub oif: Vec<String>,
    pub src: Match,
    pub dst: Match,
    pub ct: Option<Ct>,
    /// Match IPv6 packets only (all other matches here are IPv4).
    pub ipv6: bool,
    pub icmp_echo: bool,
    pub l4: Option<L4>,
    pub action: Action,
    pub comment: String,
}

impl Rule {
    fn new(chain: Chain, action: Action, comment: impl Into<String>) -> Self {
        Rule {
            chain,
            iif: Vec::new(),
            oif: Vec::new(),
            src: Match::Any,
            dst: Match::Any,
            ct: None,
            ipv6: false,
            icmp_echo: false,
            l4: None,
            action,
            comment: comment.into(),
        }
    }
    fn iif(mut self, i: impl Into<String>) -> Self {
        self.iif.push(i.into());
        self
    }
    fn iifs(mut self, i: &[String]) -> Self {
        self.iif.extend(i.iter().cloned());
        self
    }
    fn oif(mut self, o: impl Into<String>) -> Self {
        self.oif.push(o.into());
        self
    }
    fn oifs(mut self, o: &[String]) -> Self {
        self.oif.extend(o.iter().cloned());
        self
    }
    fn src(mut self, m: Match) -> Self {
        self.src = m;
        self
    }
    fn dst(mut self, m: Match) -> Self {
        self.dst = m;
        self
    }
    /// One port on one protocol.
    fn l4(mut self, l4: Option<(Proto, u16)>) -> Self {
        self.l4 = l4.map(|(proto, port)| L4 {
            proto,
            ports: vec![(port, port)],
        });
        self
    }
    fn ports(mut self, l4: Option<L4>) -> Self {
        self.l4 = l4;
        self
    }
    fn ct(mut self, ct: Ct) -> Self {
        self.ct = Some(ct);
        self
    }
    fn ipv6(mut self) -> Self {
        self.ipv6 = true;
        self
    }
}

/// Destination ports on one protocol: single ports and ranges (`first`
/// to `last`), matched as one set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L4 {
    pub proto: Proto,
    pub ports: Vec<(u16, u16)>,
}

/// iptables' `multiport` takes at most 15 ports per rule, a range counting
/// as two; longer lists become several rules (in both backends, so they
/// render alike).
const MULTIPORT_MAX: usize = 15;

/// The port matches for `ports` (`None`: every port, so one rule without a
/// port match): per protocol, TCP first, each at most [`MULTIPORT_MAX`].
fn port_matches(ports: Option<&[PortRange]>) -> Vec<Option<L4>> {
    let Some(ports) = ports else {
        return vec![None];
    };
    let mut out = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        // Sorted, with overlapping and adjacent ranges merged: nft refuses
        // overlapping elements in a set.
        let mut wanted: Vec<(u16, u16)> = ports
            .iter()
            .filter(|r| r.proto == proto)
            .map(|r| (r.first, r.last))
            .collect();
        wanted.sort_unstable();
        let mut set: Vec<(u16, u16)> = Vec::new();
        for (first, last) in wanted {
            match set.last_mut() {
                Some(prev) if first <= prev.1.saturating_add(1) => prev.1 = prev.1.max(last),
                _ => set.push((first, last)),
            }
        }
        let mut chunk: Vec<(u16, u16)> = Vec::new();
        let mut weight = 0;
        for p in set {
            let w = if p.0 == p.1 { 1 } else { 2 };
            if weight + w > MULTIPORT_MAX {
                out.push(Some(L4 {
                    proto,
                    ports: std::mem::take(&mut chunk),
                }));
                weight = 0;
            }
            chunk.push(p);
            weight += w;
        }
        if !chunk.is_empty() {
            out.push(Some(L4 {
                proto,
                ports: chunk,
            }));
        }
    }
    out
}

/// A named address set: Tailscale tiers, configured networks, non-public space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSet {
    pub name: String,
    pub elements: Vec<Ipv4Net>,
    pub comment: String,
}

/// The whole ruleset before rendering.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ruleset {
    pub sets: Vec<AddressSet>,
    pub rules: Vec<Rule>,
    /// Tier labels, one chain each ([`Chain::Tier`]).
    pub tiers: Vec<String>,
    /// DOCKER-USER accepts, if Docker coexistence is on.
    pub docker_user: Vec<Rule>,
}

pub const TABLE: &str = "parallax";
pub const LAN_SET: &str = "lan_real";
pub const NOT_PUBLIC_SET: &str = "not_public";

const fn net(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(a, b, c, d), len)
}

/// Destinations that aren't the public internet (RFC 6890 and friends): an
/// `internet` grant never reaches these, so a guest with full tunnel can't
/// use the gateway's router to reach private subnets Parallax doesn't know
/// about.
pub const NOT_PUBLIC: [Ipv4Net; 15] = [
    net(0, 0, 0, 0, 8),       // "this network"
    net(10, 0, 0, 0, 8),      // private
    net(100, 64, 0, 0, 10),   // shared address space (CGNAT, Tailscale)
    net(127, 0, 0, 0, 8),     // loopback
    net(169, 254, 0, 0, 16),  // link-local
    net(172, 16, 0, 0, 12),   // private
    net(192, 0, 0, 0, 24),    // IETF protocol assignments
    net(192, 0, 2, 0, 24),    // documentation (TEST-NET-1)
    net(192, 88, 99, 0, 24),  // deprecated 6to4 relay anycast
    net(192, 168, 0, 0, 16),  // private
    net(198, 18, 0, 0, 15),   // benchmarking, and Parallax's mapped space
    net(198, 51, 100, 0, 24), // documentation (TEST-NET-2)
    net(203, 0, 113, 0, 24),  // documentation (TEST-NET-3)
    net(224, 0, 0, 0, 4),     // multicast
    net(240, 0, 0, 0, 4),     // reserved, broadcast
];

/// `internet` for a tier that also has `all_networks` keeps reaching
/// private space through the router (other VLANs): it already reaches every
/// configured network, so it's the owner's own devices.
fn internet_is_public_only(tier: &Tier<'_>) -> bool {
    !tier.has(&crate::model::Rule::AllNetworks)
}

/// Client-side addresses (virtual where mapped) whose `tcp/443` this
/// tier sends to the HTTPS proxy: each proxied service it's granted,
/// unless another rule already reaches that host's 443 directly. A service
/// on the home's public IP likewise, unless the owner's `internet` reaches
/// it anyway.
fn proxy_redirects(model: &Model<'_>, tier: &Tier<'_>) -> Vec<ProxyRedirect> {
    let mut out: Vec<ProxyRedirect> = Vec::new();
    for r in model.reaches(tier) {
        // Proxied services are validated to be exactly tcp/443.
        let client = match r.kind {
            ReachKind::Lan {
                real,
                proxied: true,
                ..
            } => {
                if model.reaches_directly(tier, real.addr(), Proto::Tcp, HTTPS) {
                    continue;
                }
                let Some(client) = r.client_net() else {
                    continue;
                };
                client
            }
            ReachKind::HomePublic {
                address,
                proxied: true,
                ..
            } => {
                if model.reaches_directly(tier, address, Proto::Tcp, HTTPS) {
                    continue;
                }
                Ipv4Net::from(address)
            }
            _ => continue,
        };
        if !out.iter().any(|p| p.client == client) {
            out.push(ProxyRedirect {
                client,
                label: r.label,
            });
        }
    }
    out
}

/// Some tier reaches a port forward on the home's public IP directly:
/// that goes out the WAN interface, masqueraded like internet traffic.
fn any_home_public(model: &Model<'_>) -> bool {
    model.tiers().iter().any(|t| {
        model
            .reaches(t)
            .iter()
            .any(|r| matches!(r.kind, ReachKind::HomePublic { proxied: false, .. }))
    })
}

/// The port proxied services are on.
const HTTPS: u16 = 443;

struct ProxyRedirect {
    client: Ipv4Net,
    label: String,
}

/// Build the backend-independent ruleset.
pub fn build(model: &Model<'_>) -> Result<Ruleset> {
    let cfg = model.config();
    let server = model.server();
    let transports = transport::all();
    let ingress: Vec<String> = transports
        .iter()
        .map(|t| t.ingress_interface(server))
        .collect();
    let source_ranges: Vec<Ipv4Net> = transports.iter().map(|t| t.source_range(server)).collect();
    let shim = model.shim_address();
    let proxy = SocketAddrV4::new(model.proxy_address(), server.proxy.port);
    let tier_src = |tr: &dyn transport::Transport, t: &Tier<'_>| Match::Set(tr.set_name(t));
    let tiers = model.tiers();
    let mut rs = Ruleset::default();

    // Sets: each tier's members on each transport.
    for t in tiers {
        for tr in &transports {
            rs.sets.push(AddressSet {
                name: tr.set_name(t),
                elements: tr.tier_members(model, t),
                comment: if tr.members_known() {
                    format!("{} peers of tier {}", tr.kind(), t.label())
                } else {
                    format!(
                        "{} nodes of tier {} (synced from Headscale)",
                        tr.kind(),
                        t.label()
                    )
                },
            });
        }
    }
    let configured: Vec<Ipv4Net> = cfg.networks.iter().map(|n| n.subnet.trunc()).collect();
    // Traffic out the WAN interface: `internet`, or a port forward on the
    // home's public IP. Both are masqueraded, and both need `lan_real`.
    let internet = model.any_internet() || any_home_public(model);
    if internet {
        rs.sets.push(AddressSet {
            name: LAN_SET.into(),
            elements: configured.clone(),
            comment: "real prefixes of every configured network".into(),
        });
    }
    if tiers
        .iter()
        .any(|t| t.has(&crate::model::Rule::Internet) && internet_is_public_only(t))
    {
        // The home's public IP too: the router would hairpin it back into
        // the home. A set member, not a drop rule, so a grant listed after
        // `internet` that covers it still works. nft rejects overlapping
        // intervals, so merge first.
        let home = model.public_ip().map(Ipv4Net::from);
        let all: Vec<Ipv4Net> = NOT_PUBLIC
            .iter()
            .chain(&configured)
            .chain(&home)
            .copied()
            .collect();
        rs.sets.push(AddressSet {
            name: NOT_PUBLIC_SET.into(),
            elements: Ipv4Net::aggregate(&all),
            comment: match home {
                Some(_) => "private, reserved and configured prefixes, and the home's public IP: not the internet",
                None => "private, reserved and configured prefixes: not the internet",
            }
            .into(),
        });
    }

    // Input: the WireGuard port from anywhere; from tunnels only the shim,
    // ping, granted services on the gateway host and the proxy.
    rs.rules.push(
        Rule::new(Chain::Input, Action::Drop, "tunnel peers are IPv4-only")
            .iifs(&ingress)
            .ipv6(),
    );
    rs.rules.push(
        Rule::new(Chain::Input, Action::Drop, "invalid state")
            .iifs(&ingress)
            .ct(Ct::Invalid),
    );
    rs.rules
        .push(Rule::new(Chain::Input, Action::Accept, "replies").ct(Ct::Reply));
    rs.rules
        .push(Rule::new(Chain::Input, Action::Accept, "related (ICMP errors)").ct(Ct::Related));
    rs.rules.push(
        Rule::new(Chain::Input, Action::Accept, "wireguard listen port")
            .l4(Some((Proto::Udp, server.wireguard.listen_port))),
    );
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.rules.push(
            Rule::new(Chain::Input, Action::Accept, "dns shim")
                .iifs(&ingress)
                .dst(Match::Cidr(Ipv4Net::from(shim)))
                .l4(Some((proto, server.dns.port))),
        );
    }
    let mut ping = Rule::new(Chain::Input, Action::Accept, "ping the gateway").iifs(&ingress);
    ping.icmp_echo = true;
    rs.rules.push(ping);
    for t in tiers {
        for r in model.reaches(t) {
            let ReachKind::Lan {
                network,
                real,
                ports,
                proxied: false,
            } = &r.kind
            else {
                continue;
            };
            let Some(g) = network.gateway_address.filter(|g| real.contains(g)) else {
                continue;
            };
            for tr in &transports {
                for l4 in port_matches(ports.as_deref()) {
                    rs.rules.push(
                        Rule::new(
                            Chain::Input,
                            Action::Accept,
                            format!(
                                "{}/{}: {} (on the gateway host)",
                                t.label(),
                                tr.kind(),
                                r.label
                            ),
                        )
                        .iif(tr.ingress_interface(server))
                        .src(tier_src(tr.as_ref(), t))
                        .dst(Match::Cidr(Ipv4Net::from(g)))
                        .ports(l4),
                    );
                }
            }
        }
    }
    for t in tiers {
        if proxy_redirects(model, t).is_empty() {
            continue;
        }
        for tr in &transports {
            rs.rules.push(
                Rule::new(
                    Chain::Input,
                    Action::Accept,
                    format!("{}/{}: https proxy", t.label(), tr.kind()),
                )
                .iif(tr.ingress_interface(server))
                .src(tier_src(tr.as_ref(), t))
                .dst(Match::Cidr(Ipv4Net::from(*proxy.ip())))
                .l4(Some((Proto::Tcp, proxy.port()))),
            );
        }
    }
    rs.rules.push(
        Rule::new(
            Chain::Input,
            Action::Drop,
            "tunnel peers may not reach anything else on the gateway host",
        )
        .iifs(&ingress),
    );

    // Forward
    rs.rules.push(
        Rule::new(Chain::Forward, Action::Drop, "tunnel peers are IPv4-only")
            .iifs(&ingress)
            .ipv6(),
    );
    rs.rules
        .push(Rule::new(Chain::Forward, Action::Drop, "invalid state").ct(Ct::Invalid));
    rs.rules
        .push(Rule::new(Chain::Forward, Action::Accept, "replies").ct(Ct::Reply));
    rs.rules
        .push(Rule::new(Chain::Forward, Action::Accept, "related (ICMP errors)").ct(Ct::Related));

    // Each tier's rules live in its own chain, entered by source address,
    // so a packet is checked against its own rules only, not walked past
    // every other tier's.
    for t in tiers {
        let i = t.index;
        let label = t.label();
        rs.tiers.push(label.clone());
        for r in model.reaches(t) {
            match &r.kind {
                // The proxy checks the hostname and connects from the
                // gateway itself; a direct accept would skip that check.
                ReachKind::Lan { proxied: true, .. } => {}
                ReachKind::Lan {
                    network,
                    real,
                    ports,
                    proxied: false,
                } => {
                    for l4 in port_matches(ports.as_deref()) {
                        rs.rules.push(
                            Rule::new(
                                Chain::Tier(i),
                                Action::Accept,
                                format!("{label}: {}", r.label),
                            )
                            .oif(&network.interface)
                            .dst(Match::Cidr(*real))
                            .ports(l4),
                        );
                    }
                }
                // Like the proxy, a port forward reached through it gets no
                // direct accept.
                ReachKind::HomePublic { proxied: true, .. } => {}
                ReachKind::HomePublic {
                    address,
                    ports,
                    proxied: false,
                } => {
                    if let Some(wan) = model.wan_interface() {
                        // Never `None`: a port forward always has its ports.
                        for l4 in port_matches(Some(ports)).into_iter().flatten() {
                            rs.rules.push(
                                Rule::new(
                                    Chain::Tier(i),
                                    Action::Accept,
                                    format!(
                                        "{label}: {} (a port forward on the home's public IP)",
                                        r.label
                                    ),
                                )
                                .oif(wan)
                                .dst(Match::Cidr(Ipv4Net::from(*address)))
                                .ports(Some(l4)),
                            );
                        }
                    }
                }
                ReachKind::Internet => {
                    if let Some(wan) = model.wan_interface() {
                        let (not, what) = if internet_is_public_only(t) {
                            (NOT_PUBLIC_SET, "internet (public addresses)")
                        } else {
                            (LAN_SET, "internet")
                        };
                        rs.rules.push(
                            Rule::new(Chain::Tier(i), Action::Accept, format!("{label}: {what}"))
                                .oif(wan)
                                .dst(Match::NotSet(not.into())),
                        );
                    }
                }
            }
        }
        rs.rules.push(Rule::new(
            Chain::Tier(i),
            Action::Drop,
            format!("{label}: default deny"),
        ));
    }
    for tr in &transports {
        let iif = tr.ingress_interface(server);
        let mut members = Vec::new();
        for t in tiers {
            if tr.members_known() {
                members.extend(tr.tier_members(model, t).into_iter().map(|m| (m, t.index)));
            } else {
                rs.rules.push(
                    Rule::new(
                        Chain::Forward,
                        Action::Jump(t.index),
                        format!("{}/{}", t.label(), tr.kind()),
                    )
                    .iif(&iif)
                    .src(tier_src(tr.as_ref(), t)),
                );
            }
        }
        if !members.is_empty() {
            // Sorted by address, so the map reads in address order.
            members.sort();
            rs.rules.push(
                Rule::new(
                    Chain::Forward,
                    Action::SourceVmap(members),
                    format!("{}: each peer's tier chain, by source address", tr.kind()),
                )
                .iif(&iif),
            );
        }
    }
    for tr in &transports {
        rs.rules.push(
            Rule::new(
                Chain::Forward,
                Action::Drop,
                format!("{}: unknown source", tr.kind()),
            )
            .iif(tr.ingress_interface(server)),
        );
    }

    // NAT: granted tiers' HTTPS to proxied services goes to the proxy. NAT
    // takes the first matching rule, so these precede NETMAP.
    for t in tiers {
        let redirects = proxy_redirects(model, t);
        for tr in &transports {
            for p in &redirects {
                rs.rules.push(
                    Rule::new(
                        Chain::Prerouting,
                        Action::Dnat { to: proxy },
                        format!(
                            "{}/{}: {} via the https proxy",
                            t.label(),
                            tr.kind(),
                            p.label
                        ),
                    )
                    .iif(tr.ingress_interface(server))
                    .src(tier_src(tr.as_ref(), t))
                    .dst(Match::Cidr(p.client))
                    .l4(Some((Proto::Tcp, HTTPS))),
                );
            }
        }
    }

    // NETMAP per mapped network, both directions.
    for n in &cfg.networks {
        if let Some(m) = n.mapping() {
            rs.rules.push(
                Rule::new(
                    Chain::Prerouting,
                    Action::NetmapDst {
                        from: m.virt(),
                        to: m.real(),
                    },
                    format!("netmap {}: virtual -> real", n.name),
                )
                .iifs(&ingress)
                .dst(Match::Cidr(m.virt())),
            );
            rs.rules.push(
                Rule::new(
                    Chain::Postrouting,
                    Action::NetmapSrc {
                        from: m.real(),
                        to: m.virt(),
                    },
                    format!("netmap {}: real -> virtual (LAN-initiated)", n.name),
                )
                .oifs(&ingress)
                .src(Match::Cidr(m.real())),
            );
        }
    }
    for n in &cfg.networks {
        if n.masquerade {
            rs.rules.push(
                Rule::new(
                    Chain::Postrouting,
                    Action::Masquerade,
                    format!(
                        "network {}: masquerade (opt-in, hides peer identity)",
                        n.name
                    ),
                )
                .oif(&n.interface)
                .src(Match::Cidrs(source_ranges.clone()))
                .dst(Match::Cidr(n.subnet.trunc())),
            );
        }
    }
    if internet {
        if let Some(wan) = model.wan_interface() {
            rs.rules.push(
                Rule::new(Chain::Postrouting, Action::Masquerade, "internet egress")
                    .oif(wan)
                    .src(Match::Cidrs(source_ranges.clone()))
                    .dst(Match::NotSet(LAN_SET.into())),
            );
        }
    }

    // Docker coexistence: let tunnel traffic through Docker's FORWARD policy.
    if server.firewall.docker_coexistence {
        for tr in &transports {
            let iface = tr.ingress_interface(server);
            rs.docker_user
                .push(Rule::new(Chain::Forward, Action::Accept, "parallax").iif(iface.clone()));
            rs.docker_user
                .push(Rule::new(Chain::Forward, Action::Accept, "parallax").oif(iface));
        }
    }
    name_tier_sets(&mut rs, tiers, &transports);
    Ok(rs)
}

/// Name each tier's sets after the access they give, not only the tier's
/// grants: its label and every rule that uses the set or sits in the
/// tier's chain. On iptables, apply fills sets before `iptables-restore`
/// swaps the rules, so a set whose rules changed under the same name would
/// put its new members under the old rules until the restore, or for good
/// if it failed (issue #35). With a new name, the new set is filled while
/// the old rules still use the old one, and the restore moves to it in one
/// step. An unchanged tier keeps its name, so a peer joining it gets
/// exactly its rules early. nftables loads sets and rules in one
/// transaction and is indifferent.
fn name_tier_sets(
    rs: &mut Ruleset,
    tiers: &[Tier<'_>],
    transports: &[Box<dyn transport::Transport>],
) {
    for t in tiers {
        for tr in transports {
            let old = tr.set_name(t);
            let uses = |m: &Match| matches!(m, Match::Set(s) | Match::NotSet(s) if *s == old);
            let mut access = t.label();
            for r in rs
                .rules
                .iter()
                .filter(|r| r.chain == Chain::Tier(t.index) || uses(&r.src) || uses(&r.dst))
            {
                access.push('\n');
                access.push_str(&nft::rule(r));
            }
            let new = format!("{}_{}", tr.set_prefix(), crate::tier::fnv64(&access));
            for set in rs.sets.iter_mut().filter(|s| s.name == old) {
                set.name.clone_from(&new);
            }
            for r in &mut rs.rules {
                for m in [&mut r.src, &mut r.dst] {
                    if let Match::Set(s) | Match::NotSet(s) = m {
                        if *s == old {
                            s.clone_from(&new);
                        }
                    }
                }
            }
        }
    }
}

/// Render the artifacts for the configured backend.
pub fn render(model: &Model<'_>) -> Result<Vec<Artifact>> {
    let rs = build(model)?;
    let mut out = Vec::new();
    match model.server().firewall.backend {
        FirewallBackend::Nftables => {
            out.push(Artifact::public(
                ArtifactKind::Firewall,
                "nftables/parallax.nft",
                nft::render(&rs),
            ));
            if !rs.docker_user.is_empty() {
                out.push(Artifact::public(
                    ArtifactKind::FirewallDockerUser,
                    "nftables/docker-user.nft",
                    nft::render_docker_user(&rs),
                ));
            }
        }
        FirewallBackend::IptablesNft => {
            out.push(Artifact::public(
                ArtifactKind::Firewall,
                "iptables/parallax.rules",
                iptables::render(&rs),
            ));
            if !rs.docker_user.is_empty() {
                out.push(Artifact::public(
                    ArtifactKind::FirewallDockerUser,
                    "iptables/docker-user.rules",
                    iptables::render_docker_user(&rs),
                ));
            }
        }
    }
    Ok(out)
}

/// Quoted, and at most [`COMMENT_MAX`] bytes: nftables refuses a comment
/// over 128, and a name can be long.
fn quote(s: &str) -> String {
    let s = s.replace('"', "");
    if s.len() <= COMMENT_MAX {
        return format!("\"{s}\"");
    }
    let mut end = COMMENT_MAX - 3;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("\"{}...\"", &s[..end])
}

const COMMENT_MAX: usize = 120;

/// nftables renderer.
pub mod nft {
    use super::*;

    fn iface_list(names: &[String]) -> String {
        if names.len() == 1 {
            quote(&names[0])
        } else {
            format!(
                "{{ {} }}",
                names
                    .iter()
                    .map(|n| quote(n))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }

    fn cidr(n: &Ipv4Net) -> String {
        if n.prefix_len() == 32 {
            n.addr().to_string()
        } else {
            n.to_string()
        }
    }

    fn matcher(field: &str, m: &Match) -> Option<String> {
        match m {
            Match::Any => None,
            Match::Cidr(c) => Some(format!("ip {field} {}", cidr(c))),
            Match::Cidrs(cs) => Some(format!(
                "ip {field} {{ {} }}",
                cs.iter().map(cidr).collect::<Vec<_>>().join(", ")
            )),
            Match::Set(s) => Some(format!("ip {field} @{s}")),
            Match::NotSet(s) => Some(format!("ip {field} != @{s}")),
        }
    }

    /// Numbered: a tier is named by several grants, and the rules'
    /// comments say which.
    fn tier_chain(i: usize) -> String {
        format!("tier_{i}")
    }

    pub fn rule(r: &Rule) -> String {
        let mut parts: Vec<String> = Vec::new();
        if r.ipv6 {
            parts.push("meta nfproto ipv6".into());
        }
        match r.ct {
            Some(Ct::Reply) => parts.push("ct direction reply".into()),
            Some(Ct::Related) => parts.push("ct state related".into()),
            Some(Ct::Invalid) => parts.push("ct state invalid".into()),
            None => {}
        }
        if !r.iif.is_empty() {
            parts.push(format!("iifname {}", iface_list(&r.iif)));
        }
        if !r.oif.is_empty() {
            parts.push(format!("oifname {}", iface_list(&r.oif)));
        }
        if let Some(m) = matcher("saddr", &r.src) {
            parts.push(m);
        }
        if let Some(m) = matcher("daddr", &r.dst) {
            parts.push(m);
        }
        if r.icmp_echo {
            parts.push("icmp type echo-request".into());
        }
        if let Some(l4) = &r.l4 {
            let one = |(a, b): (u16, u16)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}-{b}")
                }
            };
            let ports = match l4.ports[..] {
                [single] => one(single),
                _ => format!(
                    "{{ {} }}",
                    l4.ports
                        .iter()
                        .map(|p| one(*p))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            parts.push(format!("{} dport {ports}", l4.proto.as_str()));
        }
        parts.push(match &r.action {
            Action::Accept => "accept".into(),
            Action::Drop => "drop".into(),
            Action::Dnat { to } => format!("dnat ip to {to}"),
            Action::Jump(i) => format!("jump {}", tier_chain(*i)),
            Action::SourceVmap(entries) => format!(
                "ip saddr vmap {{ {} }}",
                entries
                    .iter()
                    .map(|(net, i)| format!("{} : jump {}", cidr(net), tier_chain(*i)))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Action::NetmapDst { from, to } => {
                format!("dnat ip prefix to ip daddr map {{ {from} : {to} }}")
            }
            Action::NetmapSrc { from, to } => {
                format!("snat ip prefix to ip saddr map {{ {from} : {to} }}")
            }
            Action::Masquerade => "masquerade".into(),
        });
        if !r.comment.is_empty() {
            parts.push(format!("comment {}", quote(&r.comment)));
        }
        parts.join(" ")
    }

    /// Name and base-chain header (none for a tier's regular chain).
    fn chain_header(c: Chain) -> (String, Option<&'static str>) {
        match c {
            Chain::Input => (
                "input".into(),
                Some("type filter hook input priority filter; policy accept;"),
            ),
            Chain::Forward => (
                "forward".into(),
                Some("type filter hook forward priority filter; policy accept;"),
            ),
            Chain::Prerouting => (
                "prerouting".into(),
                // Ahead of Docker's DNAT (plain dstnat): the first NAT binding
                // wins, so a tier's redirect to the proxy can't lose to a port
                // Docker publishes on the gateway.
                Some("type nat hook prerouting priority dstnat - 10; policy accept;"),
            ),
            Chain::Postrouting => (
                "postrouting".into(),
                Some("type nat hook postrouting priority srcnat; policy accept;"),
            ),
            Chain::Tier(i) => (tier_chain(i), None),
        }
    }

    pub fn render(rs: &Ruleset) -> String {
        let mut s = String::new();
        s.push_str("#!/usr/sbin/nft -f\n");
        s.push_str("# Generated by Parallax. Do not edit: every rule derives from the Parallax configuration.\n");
        s.push_str("# The table is declared, deleted and redefined in one transaction, so apply is atomic and idempotent.\n\n");
        let _ = writeln!(s, "table inet {TABLE} {{}}");
        let _ = writeln!(s, "delete table inet {TABLE}\n");
        let _ = writeln!(s, "table inet {TABLE} {{");
        for set in &rs.sets {
            let _ = writeln!(s, "\tset {} {{", set.name);
            s.push_str("\t\ttype ipv4_addr\n\t\tflags interval\n");
            if !set.comment.is_empty() {
                let _ = writeln!(s, "\t\tcomment {}", quote(&set.comment));
            }
            if !set.elements.is_empty() {
                let _ = writeln!(
                    s,
                    "\t\telements = {{ {} }}",
                    set.elements.iter().map(cidr).collect::<Vec<_>>().join(", ")
                );
            }
            s.push_str("\t}\n\n");
        }
        let chains = [Chain::Input, Chain::Forward]
            .into_iter()
            .chain((0..rs.tiers.len()).map(Chain::Tier))
            .chain([Chain::Prerouting, Chain::Postrouting]);
        for chain in chains {
            let (name, header) = chain_header(chain);
            let _ = writeln!(s, "\tchain {name} {{");
            if let Some(header) = header {
                let _ = writeln!(s, "\t\t{header}");
            }
            for r in rs.rules.iter().filter(|r| r.chain == chain) {
                let _ = writeln!(s, "\t\t{}", rule(r));
            }
            s.push_str("\t}\n\n");
        }
        if s.ends_with("\n\n") {
            s.pop();
        }
        s.push_str("}\n");
        s
    }

    /// Rules for Docker's `DOCKER-USER` chain (table `ip filter`, created by
    /// Docker). Applied separately and idempotently: apply first deletes every
    /// rule carrying the `parallax` comment, then inserts these.
    pub fn render_docker_user(rs: &Ruleset) -> String {
        let mut s = String::new();
        s.push_str("# Generated by Parallax. Rules for Docker's DOCKER-USER chain (only when Docker runs on the gateway host).\n");
        s.push_str("# Apply removes previous rules commented \"parallax\" before inserting these, so re-applying is idempotent.\n");
        for r in &rs.docker_user {
            let _ = writeln!(s, "insert rule ip filter DOCKER-USER {}", rule(r));
        }
        s
    }
}

/// iptables-restore renderer for hosts without a usable `nft` binary. Uses
/// dedicated PARALLAX_* chains, refilled in one restore transaction.
pub mod iptables {
    use super::*;

    pub const CHAINS: [(&str, &str, &str); 4] = [
        ("filter", "INPUT", "PARALLAX_INPUT"),
        ("filter", "FORWARD", "PARALLAX_FORWARD"),
        ("nat", "PREROUTING", "PARALLAX_PREROUTING"),
        ("nat", "POSTROUTING", "PARALLAX_POSTROUTING"),
    ];

    /// Tier chains are numbered, as in nftables. The restore file declares
    /// them, which creates or flushes each one.
    fn own_chain(c: Chain) -> String {
        match c {
            Chain::Input => "PARALLAX_INPUT".into(),
            Chain::Forward => "PARALLAX_FORWARD".into(),
            Chain::Prerouting => "PARALLAX_PREROUTING".into(),
            Chain::Postrouting => "PARALLAX_POSTROUTING".into(),
            Chain::Tier(i) => format!("PARALLAX_T{i}"),
        }
    }

    fn expand(r: &Rule) -> Vec<String> {
        // These tables are IPv4-only: an IPv6 rule has nothing to match.
        if r.ipv6 {
            return Vec::new();
        }
        // No verdict maps: one jump per prefix.
        if let Action::SourceVmap(entries) = &r.action {
            return entries
                .iter()
                .flat_map(|(net, i)| {
                    let mut one = r.clone();
                    one.src = Match::Cidr(*net);
                    one.action = Action::Jump(*i);
                    expand(&one)
                })
                .collect();
        }
        // iptables has no interface lists or anonymous sets: expand to one rule each.
        let iifs: Vec<Option<&String>> = if r.iif.is_empty() {
            vec![None]
        } else {
            r.iif.iter().map(Some).collect()
        };
        let oifs: Vec<Option<&String>> = if r.oif.is_empty() {
            vec![None]
        } else {
            r.oif.iter().map(Some).collect()
        };
        let srcs: Vec<Option<String>> = match &r.src {
            Match::Any => vec![None],
            Match::Cidr(c) => vec![Some(format!("-s {c}"))],
            Match::Cidrs(cs) => cs.iter().map(|c| Some(format!("-s {c}"))).collect(),
            Match::Set(s) => vec![Some(format!("-m set --match-set {s} src"))],
            Match::NotSet(s) => vec![Some(format!("-m set ! --match-set {s} src"))],
        };
        let dsts: Vec<Option<String>> = match &r.dst {
            Match::Any => vec![None],
            Match::Cidr(c) => vec![Some(format!("-d {c}"))],
            Match::Cidrs(cs) => cs.iter().map(|c| Some(format!("-d {c}"))).collect(),
            Match::Set(s) => vec![Some(format!("-m set --match-set {s} dst"))],
            Match::NotSet(s) => vec![Some(format!("-m set ! --match-set {s} dst"))],
        };
        let mut out = Vec::new();
        for iif in &iifs {
            for oif in &oifs {
                for src in &srcs {
                    for dst in &dsts {
                        let mut parts = vec![format!("-A {}", own_chain(r.chain))];
                        if let Some(i) = iif {
                            parts.push(format!("-i {i}"));
                        }
                        if let Some(o) = oif {
                            parts.push(format!("-o {o}"));
                        }
                        if let Some(s) = src {
                            parts.push(s.clone());
                        }
                        if let Some(d) = dst {
                            parts.push(d.clone());
                        }
                        match r.ct {
                            Some(Ct::Reply) => parts.push("-m conntrack --ctdir REPLY".into()),
                            Some(Ct::Related) => {
                                parts.push("-m conntrack --ctstate RELATED".into())
                            }
                            Some(Ct::Invalid) => {
                                parts.push("-m conntrack --ctstate INVALID".into())
                            }
                            None => {}
                        }
                        if r.icmp_echo {
                            parts.push("-p icmp --icmp-type echo-request".into());
                        }
                        if let Some(l4) = &r.l4 {
                            let one = |(a, b): (u16, u16)| {
                                if a == b {
                                    a.to_string()
                                } else {
                                    format!("{a}:{b}")
                                }
                            };
                            let proto = l4.proto.as_str();
                            parts.push(match l4.ports[..] {
                                [single] => format!("-p {proto} --dport {}", one(single)),
                                _ => format!(
                                    "-p {proto} -m multiport --dports {}",
                                    l4.ports
                                        .iter()
                                        .map(|p| one(*p))
                                        .collect::<Vec<_>>()
                                        .join(",")
                                ),
                            });
                        }
                        if !r.comment.is_empty() {
                            parts.push(format!("-m comment --comment {}", quote(&r.comment)));
                        }
                        parts.push(match &r.action {
                            Action::Accept => "-j ACCEPT".into(),
                            Action::Drop => "-j DROP".into(),
                            Action::Dnat { to } => format!("-j DNAT --to-destination {to}"),
                            Action::Jump(i) => format!("-j {}", own_chain(Chain::Tier(*i))),
                            // Expanded into jumps above.
                            Action::SourceVmap(_) => String::new(),
                            Action::NetmapDst { to, .. } | Action::NetmapSrc { to, .. } => {
                                format!("-j NETMAP --to {to}")
                            }
                            Action::Masquerade => "-j MASQUERADE".into(),
                        });
                        out.push(parts.join(" "));
                    }
                }
            }
        }
        out
    }

    pub fn render(rs: &Ruleset) -> String {
        let mut s = String::new();
        s.push_str("# Generated by Parallax for iptables-restore --noflush. Do not edit.\n");
        s.push_str("# Declaring each PARALLAX_* chain creates or flushes it within the restore; apply then ensures the jumps from the built-in chains exist.\n");
        if !rs.sets.is_empty() {
            s.push_str("# Named sets are ipsets created by apply:\n");
            for set in &rs.sets {
                let _ = writeln!(
                    s,
                    "#   ipset create -exist {} hash:net comment ; elements: {}",
                    set.name,
                    set.elements
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        let filter: Vec<Chain> = [Chain::Input, Chain::Forward]
            .into_iter()
            .chain((0..rs.tiers.len()).map(Chain::Tier))
            .collect();
        for (table, chains) in [
            ("filter", filter.as_slice()),
            ("nat", [Chain::Prerouting, Chain::Postrouting].as_slice()),
        ] {
            let _ = writeln!(s, "*{table}");
            for c in chains {
                let _ = writeln!(s, ":{} - [0:0]", own_chain(*c));
            }
            for c in chains {
                for r in rs.rules.iter().filter(|r| r.chain == *c) {
                    for line in expand(r) {
                        let _ = writeln!(s, "{line}");
                    }
                }
            }
            s.push_str("COMMIT\n");
        }
        s
    }

    pub fn render_docker_user(rs: &Ruleset) -> String {
        let mut s = String::new();
        s.push_str("# Generated by Parallax. Inserted into DOCKER-USER by apply after removing rules commented \"parallax\".\n");
        for r in &rs.docker_user {
            for line in expand(r) {
                let _ = writeln!(
                    s,
                    "{}",
                    line.replace("-A PARALLAX_FORWARD", "-I DOCKER-USER")
                );
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(proto: Proto, first: u16, last: u16) -> PortRange {
        PortRange { proto, first, last }
    }

    /// The WireGuard set of the tier labelled `label`.
    fn tier_set(cfg: &crate::Config, label: &str) -> String {
        let model = Model::resolve(cfg, crate::testing::today()).unwrap();
        let rs = build(&model).unwrap();
        rs.sets
            .into_iter()
            .find(|s| s.name.starts_with("wg_") && s.comment.ends_with(&format!("tier {label}")))
            .unwrap()
            .name
    }

    /// Issue #35: on iptables, sets are filled before the rules change, so a
    /// tier whose access changes gets a set of another name; one whose
    /// members change keeps its own.
    #[test]
    fn a_tier_set_is_renamed_when_its_access_changes_not_its_members() {
        use crate::model::Rule as Grant;
        let cfg = crate::testing::canonical_config();
        let personal = tier_set(&cfg, "personal");

        let mut joined = cfg.clone();
        joined.peers[2].grants = vec!["personal".into()];
        assert_eq!(tier_set(&joined, "personal"), personal, "a member joined");

        // The issue's case: personal shrinks to public_dns, and sister-phone
        // moves into it, in one save.
        let mut shrunk = joined.clone();
        let p = shrunk
            .grants
            .iter()
            .position(|g| g.name == "personal")
            .unwrap();
        shrunk.grants[p].rules = vec![Grant::PublicDns];
        assert_ne!(tier_set(&shrunk, "personal"), personal, "its rules changed");

        // What a rule means can change under the same rule: the service's
        // ports.
        let family = tier_set(&cfg, "family");
        let mut moved = cfg.clone();
        moved.services[0].ports = vec!["2283/tcp".parse().unwrap()];
        assert_ne!(tier_set(&moved, "family"), family, "its service changed");
        assert_eq!(
            tier_set(&cfg, "family"),
            family,
            "the same input, the same name"
        );
    }

    #[test]
    fn long_comments_are_cut() {
        let long = "x".repeat(300);
        let q = quote(&long);
        assert_eq!(q.len(), COMMENT_MAX + 2);
        assert!(q.ends_with("...\""));
        assert_eq!(
            quote("family: service immich"),
            "\"family: service immich\""
        );
    }

    #[test]
    fn overlapping_ranges_merge() {
        let ports = [
            r(Proto::Tcp, 80, 90),
            r(Proto::Tcp, 80, 80),
            r(Proto::Tcp, 91, 95),
            r(Proto::Tcp, 22, 22),
            r(Proto::Udp, 80, 80),
        ];
        let m = port_matches(Some(&ports));
        let sets: Vec<(Proto, Vec<(u16, u16)>)> = m
            .into_iter()
            .flatten()
            .map(|l| (l.proto, l.ports))
            .collect();
        assert_eq!(
            sets,
            [
                (Proto::Tcp, vec![(22, 22), (80, 95)]),
                (Proto::Udp, vec![(80, 80)])
            ]
        );
    }

    #[test]
    fn port_lists_split_at_fifteen_ports() {
        // 14 single ports (not adjacent, so nothing merges) and a range:
        // 16, so the range starts a second rule.
        let mut ports: Vec<PortRange> = (1..=14).map(|p| r(Proto::Tcp, p * 2, p * 2)).collect();
        ports.push(r(Proto::Tcp, 100, 110));
        ports.push(r(Proto::Udp, 53, 53));
        let m = port_matches(Some(&ports));
        let sizes: Vec<(Proto, usize)> = m
            .iter()
            .flatten()
            .map(|l| (l.proto, l.ports.len()))
            .collect();
        assert_eq!(sizes, [(Proto::Tcp, 14), (Proto::Tcp, 1), (Proto::Udp, 1)]);
        assert_eq!(port_matches(None), [None]);
    }
}
