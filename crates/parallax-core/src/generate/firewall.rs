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
//! - Every template ends with a per-source default deny; every transport
//!   ends with a catch-all deny for unknown sources.
//! - The gateway host itself is not a destination: INPUT from a tunnel
//!   interface accepts only the DNS shim and ICMP echo, then drops. Anything
//!   else bound on the (host-networked) gateway stays unreachable from peers.

use std::fmt::Write as _;

use ipnet::Ipv4Net;

use super::{Artifact, ArtifactKind};
use crate::model::{FirewallBackend, Proto};
use crate::transport::{self, TierSource};
use crate::validate::{Model, ReachKind};
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Input,
    Forward,
    Prerouting,
    Postrouting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    Any,
    Cidr(Ipv4Net),
    Cidrs(Vec<Ipv4Net>),
    Set(String),
    NotSet(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
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
    pub ct_established: bool,
    pub ct_invalid: bool,
    pub icmp_echo: bool,
    pub l4: Option<(Proto, u16)>,
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
            ct_established: false,
            ct_invalid: false,
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
    fn l4(mut self, l4: Option<(Proto, u16)>) -> Self {
        self.l4 = l4;
        self
    }
}

/// A named address set (only Tailscale tiers and the LAN set in M1).
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
    /// DOCKER-USER accepts, if Docker coexistence is on.
    pub docker_user: Vec<Rule>,
}

pub const TABLE: &str = "parallax";
pub const LAN_SET: &str = "lan_real";

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
    let mut rs = Ruleset::default();

    // Sets
    for t in &cfg.templates {
        for tr in &transports {
            if let TierSource::Set(name) = tr.tier_source(server, t) {
                rs.sets.push(AddressSet {
                    name,
                    elements: tr.tier_members(model, t),
                    comment: format!(
                        "{} nodes of template {} (synced from Headscale)",
                        tr.kind(),
                        t.name
                    ),
                });
            }
        }
    }
    let internet = model.any_internet_grant();
    if internet {
        rs.sets.push(AddressSet {
            name: LAN_SET.into(),
            elements: cfg.networks.iter().map(|n| n.subnet.trunc()).collect(),
            comment: "real prefixes of every configured network".into(),
        });
    }

    // Input: the WireGuard port from anywhere; from tunnels only the shim and ping.
    let mut est_in = Rule::new(Chain::Input, Action::Accept, "established flows");
    est_in.ct_established = true;
    rs.rules.push(est_in);
    rs.rules.push(
        Rule::new(Chain::Input, Action::Accept, "wireguard listen port")
            .l4(Some((Proto::Udp, server.wireguard.listen_port))),
    );
    for proto in [Proto::Udp, Proto::Tcp] {
        rs.rules.push(
            Rule::new(Chain::Input, Action::Accept, "dns shim")
                .iifs(&ingress)
                .dst(Match::Cidr(Ipv4Net::new(shim, 32).expect("/32")))
                .l4(Some((proto, server.dns.port))),
        );
    }
    let mut ping = Rule::new(Chain::Input, Action::Accept, "ping the gateway").iifs(&ingress);
    ping.icmp_echo = true;
    rs.rules.push(ping);
    rs.rules.push(
        Rule::new(
            Chain::Input,
            Action::Drop,
            "tunnel peers may not reach anything else on the gateway host",
        )
        .iifs(&ingress),
    );

    // Forward
    let mut est = Rule::new(Chain::Forward, Action::Accept, "established flows");
    est.ct_established = true;
    rs.rules.push(est);
    let mut inv = Rule::new(Chain::Forward, Action::Drop, "invalid state");
    inv.ct_invalid = true;
    rs.rules.push(inv);

    for t in &cfg.templates {
        let reaches = model.reaches(t);
        for tr in &transports {
            let iif = tr.ingress_interface(server);
            let src = match tr.tier_source(server, t) {
                TierSource::Cidr(c) => Match::Cidr(c),
                TierSource::Set(s) => Match::Set(s),
            };
            let tag = format!("{}/{}", t.name, tr.kind());
            for r in &reaches {
                match &r.kind {
                    ReachKind::Lan {
                        network,
                        real,
                        port,
                    } => rs.rules.push(
                        Rule::new(
                            Chain::Forward,
                            Action::Accept,
                            format!("{tag}: {}", r.label),
                        )
                        .iif(&iif)
                        .src(src.clone())
                        .oif(&network.interface)
                        .dst(Match::Cidr(*real))
                        .l4(*port),
                    ),
                    ReachKind::Internet => {
                        if let Some(wan) = model.wan_interface() {
                            rs.rules.push(
                                Rule::new(
                                    Chain::Forward,
                                    Action::Accept,
                                    format!("{tag}: internet"),
                                )
                                .iif(&iif)
                                .src(src.clone())
                                .oif(wan)
                                .dst(Match::NotSet(LAN_SET.into())),
                            );
                        }
                    }
                }
            }
            rs.rules.push(
                Rule::new(Chain::Forward, Action::Drop, format!("{tag}: default deny"))
                    .iif(&iif)
                    .src(src),
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

    // NAT: NETMAP per mapped network, both directions.
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
    Ok(rs)
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

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('"', ""))
}

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

    pub fn rule(r: &Rule) -> String {
        let mut parts: Vec<String> = Vec::new();
        if r.ct_established {
            parts.push("ct state established,related".into());
        }
        if r.ct_invalid {
            parts.push("ct state invalid".into());
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
        if let Some((proto, port)) = r.l4 {
            parts.push(format!("{} dport {port}", proto.as_str()));
        }
        parts.push(match &r.action {
            Action::Accept => "accept".into(),
            Action::Drop => "drop".into(),
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

    fn chain_header(c: Chain) -> (&'static str, &'static str) {
        match c {
            Chain::Input => (
                "input",
                "type filter hook input priority filter; policy accept;",
            ),
            Chain::Forward => (
                "forward",
                "type filter hook forward priority filter; policy accept;",
            ),
            Chain::Prerouting => (
                "prerouting",
                "type nat hook prerouting priority dstnat; policy accept;",
            ),
            Chain::Postrouting => (
                "postrouting",
                "type nat hook postrouting priority srcnat; policy accept;",
            ),
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
        for chain in [
            Chain::Input,
            Chain::Forward,
            Chain::Prerouting,
            Chain::Postrouting,
        ] {
            let (name, header) = chain_header(chain);
            let _ = writeln!(s, "\tchain {name} {{");
            let _ = writeln!(s, "\t\t{header}");
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
/// dedicated PARALLAX_* chains that apply flushes and re-jumps to.
pub mod iptables {
    use super::*;

    pub const CHAINS: [(&str, &str, &str); 4] = [
        ("filter", "INPUT", "PARALLAX_INPUT"),
        ("filter", "FORWARD", "PARALLAX_FORWARD"),
        ("nat", "PREROUTING", "PARALLAX_PREROUTING"),
        ("nat", "POSTROUTING", "PARALLAX_POSTROUTING"),
    ];

    fn own_chain(c: Chain) -> &'static str {
        match c {
            Chain::Input => "PARALLAX_INPUT",
            Chain::Forward => "PARALLAX_FORWARD",
            Chain::Prerouting => "PARALLAX_PREROUTING",
            Chain::Postrouting => "PARALLAX_POSTROUTING",
        }
    }

    fn expand(r: &Rule) -> Vec<String> {
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
                        if r.ct_established {
                            parts.push("-m conntrack --ctstate ESTABLISHED,RELATED".into());
                        }
                        if r.ct_invalid {
                            parts.push("-m conntrack --ctstate INVALID".into());
                        }
                        if r.icmp_echo {
                            parts.push("-p icmp --icmp-type echo-request".into());
                        }
                        if let Some((proto, port)) = r.l4 {
                            parts.push(format!("-p {} --dport {port}", proto.as_str()));
                        }
                        if !r.comment.is_empty() {
                            parts.push(format!("-m comment --comment {}", quote(&r.comment)));
                        }
                        parts.push(match &r.action {
                            Action::Accept => "-j ACCEPT".into(),
                            Action::Drop => "-j DROP".into(),
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
        s.push_str("# Apply flushes the PARALLAX_* chains, restores this file, and ensures the jumps from the built-in chains exist.\n");
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
        for (table, chains) in [
            ("filter", [Chain::Input, Chain::Forward].as_slice()),
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
