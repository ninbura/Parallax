//! Validation and the resolved [`Model`] every generator works from.
//!
//! Validation is loud and specific: each problem is one sentence naming the
//! object and what to change. Generators only ever see a [`Model`], so they
//! can assume every reference resolves and every prefix is sane.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::date::Date;
use crate::model::*;
use crate::netmap::Mapping;
use crate::{Error, Result, TAILSCALE_CGNAT};

/// A validated configuration plus the evaluation date (for peer expiry).
#[derive(Debug, Clone)]
pub struct Model<'a> {
    config: &'a Config,
    today: Date,
    warnings: Vec<String>,
}

/// One destination a template's members may reach, with the network it sits on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reach<'a> {
    /// Human label for comments (`service immich`, `network home`).
    pub label: String,
    pub kind: ReachKind<'a>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReachKind<'a> {
    Lan {
        network: &'a Network,
        /// Real-space destination prefix (a /32 for hosts).
        real: Ipv4Net,
        port: Option<(Proto, u16)>,
    },
    Internet,
}

impl Reach<'_> {
    /// The destination as clients address it (virtual where mapped).
    pub fn client_net(&self) -> Option<Ipv4Net> {
        match &self.kind {
            ReachKind::Lan { network, real, .. } => Some(match network.mapping() {
                Some(m) => m.net_to_virtual(*real).unwrap_or(*real),
                None => *real,
            }),
            ReachKind::Internet => None,
        }
    }
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn valid_zone(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn overlaps(a: Ipv4Net, b: Ipv4Net) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

impl<'a> Model<'a> {
    /// Validate `config` and build the model. `today` decides which peers are expired.
    pub fn resolve(config: &'a Config, today: Date) -> Result<Self> {
        let (errors, warnings) = check(config);
        if errors.is_empty() {
            Ok(Model {
                config,
                today,
                warnings,
            })
        } else {
            Err(Error::Invalid(errors))
        }
    }

    pub fn config(&self) -> &'a Config {
        self.config
    }
    pub fn today(&self) -> Date {
        self.today
    }
    /// Non-fatal observations worth showing the operator.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub fn server(&self) -> &'a ServerConfig {
        &self.config.server
    }

    pub fn template(&self, name: &str) -> Result<&'a Template> {
        self.config.template(name).ok_or_else(|| Error::NotFound {
            kind: "template",
            name: name.to_string(),
        })
    }

    pub fn peer(&self, name: &str) -> Result<&'a Peer> {
        self.config.peer(name).ok_or_else(|| Error::NotFound {
            kind: "peer",
            name: name.to_string(),
        })
    }

    /// Enabled, unexpired peers.
    pub fn active_peers(&self) -> impl Iterator<Item = &'a Peer> + '_ {
        self.config.peers.iter().filter(|p| p.is_active(self.today))
    }

    /// Active peers on `transport` belonging to `template` (any template if `None`).
    pub fn peers_on(
        &self,
        transport: TransportKind,
        template: Option<&'a str>,
    ) -> impl Iterator<Item = &'a Peer> + '_ {
        self.active_peers()
            .filter(move |p| p.transport == transport && template.is_none_or(|t| p.template == t))
    }

    /// Networks whose routes this template's clients receive.
    pub fn visible_networks(&self, template: &Template) -> Vec<&'a Network> {
        match &template.visible_networks {
            None => self.config.networks.iter().collect(),
            Some(names) => names
                .iter()
                .filter_map(|n| self.config.network(n))
                .collect(),
        }
    }

    pub fn network_containing(&self, ip: Ipv4Addr) -> Option<&'a Network> {
        self.config.networks.iter().find(|n| n.subnet.contains(&ip))
    }

    /// Every destination the template's grants resolve to, in grant order, deduplicated.
    pub fn reaches(&self, template: &Template) -> Vec<Reach<'a>> {
        let mut out: Vec<Reach<'a>> = Vec::new();
        let mut push = |r: Reach<'a>| {
            if !out.contains(&r) {
                out.push(r);
            }
        };
        for grant in &template.grants {
            match grant {
                Grant::AllNetworks => {
                    for n in &self.config.networks {
                        push(Reach {
                            label: format!("network {}", n.name),
                            kind: ReachKind::Lan {
                                network: n,
                                real: n.subnet.trunc(),
                                port: None,
                            },
                        });
                    }
                }
                Grant::Network { name } => {
                    if let Some(n) = self.config.network(name) {
                        push(Reach {
                            label: format!("network {}", n.name),
                            kind: ReachKind::Lan {
                                network: n,
                                real: n.subnet.trunc(),
                                port: None,
                            },
                        });
                    }
                }
                Grant::Host { ip } => {
                    if let Some(n) = self.network_containing(*ip) {
                        push(Reach {
                            label: format!("host {ip}"),
                            kind: ReachKind::Lan {
                                network: n,
                                real: Ipv4Net::new(*ip, 32).expect("/32"),
                                port: None,
                            },
                        });
                    }
                }
                Grant::HostPort { ip, proto, port } => {
                    if let Some(n) = self.network_containing(*ip) {
                        push(Reach {
                            label: format!("host {ip} {}/{port}", proto.as_str()),
                            kind: ReachKind::Lan {
                                network: n,
                                real: Ipv4Net::new(*ip, 32).expect("/32"),
                                port: Some((*proto, *port)),
                            },
                        });
                    }
                }
                Grant::Service { name } => {
                    if let Some(s) = self.config.service(name) {
                        if let Some(n) = self.network_containing(s.host) {
                            push(Reach {
                                label: format!("service {}", s.name),
                                kind: ReachKind::Lan {
                                    network: n,
                                    real: Ipv4Net::new(s.host, 32).expect("/32"),
                                    port: Some((s.proto, s.port)),
                                },
                            });
                        }
                    }
                }
                Grant::Internet => push(Reach {
                    label: "internet".to_string(),
                    kind: ReachKind::Internet,
                }),
            }
        }
        out
    }

    /// Does `template` reach `service` (directly or through a wider grant)?
    pub fn reaches_service(&self, template: &Template, service: &Service) -> bool {
        self.reaches(template).iter().any(|r| match &r.kind {
            ReachKind::Lan { real, port, .. } => {
                real.contains(&service.host)
                    && port.is_none_or(|(pr, po)| pr == service.proto && po == service.port)
            }
            ReachKind::Internet => false,
        })
    }

    /// Address the DNS shim listens on.
    pub fn shim_address(&self) -> Ipv4Addr {
        self.config
            .server
            .dns
            .listen
            .unwrap_or_else(|| self.config.server.wireguard.gateway_address())
    }

    /// Interface carrying the default route.
    pub fn wan_interface(&self) -> Option<&'a str> {
        self.config
            .server
            .wan_interface
            .as_deref()
            .or_else(|| self.config.networks.first().map(|n| n.interface.as_str()))
    }

    /// Some client may send all DNS to the shim, so it needs a catch-all resolver.
    /// A WireGuard `split` template counts: its mobile export falls back to
    /// tunnel-wide, because the official mobile apps cannot split DNS.
    pub fn needs_catch_all_resolver(&self) -> bool {
        self.config
            .templates
            .iter()
            .any(|t| t.dns.wireguard != DnsMode::None || t.dns.tailscale == DnsMode::TunnelWide)
    }

    /// Any template grants internet egress.
    pub fn any_internet_grant(&self) -> bool {
        self.config
            .templates
            .iter()
            .any(|t| t.grants.contains(&Grant::Internet))
    }

    /// Every (zone, network) pair, in configuration order.
    pub fn zones(&self) -> Vec<(&'a str, &'a Network)> {
        self.config
            .networks
            .iter()
            .flat_map(|n| n.domains.iter().map(move |d| (d.as_str(), n)))
            .collect()
    }

    /// Routing domains for a template's clients: zones of its visible networks.
    pub fn routing_domains(&self, template: &Template) -> Vec<&'a str> {
        let mut out = Vec::new();
        for n in self.visible_networks(template) {
            for d in &n.domains {
                if !out.contains(&d.as_str()) {
                    out.push(d.as_str());
                }
            }
        }
        out
    }
}

/// Run every check. Returns `(errors, warnings)`.
/// Ranges a virtual prefix may live in: RFC 1918 private space, or the RFC 2544
/// benchmarking block that no home or office LAN hands out.
fn is_virtual_space(net: Ipv4Net) -> bool {
    const ALLOWED: [&str; 4] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "198.18.0.0/15",
    ];
    ALLOWED
        .iter()
        .any(|r| r.parse::<Ipv4Net>().is_ok_and(|r| r.contains(&net)))
}

pub fn check(config: &Config) -> (Vec<String>, Vec<String>) {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let server = &config.server;
    let wg = &server.wireguard;

    // --- server ---------------------------------------------------------
    if wg.supernet.prefix_len() > 30 {
        errors.push(format!(
            "server.wireguard.supernet {} is too small; use a prefix of /30 or larger",
            wg.supernet
        ));
    }
    if wg.supernet.trunc() != wg.supernet {
        errors.push(format!(
            "server.wireguard.supernet {} has host bits set; write it as {}",
            wg.supernet,
            wg.supernet.trunc()
        ));
    }
    if overlaps(wg.supernet, TAILSCALE_CGNAT) {
        errors.push(format!(
            "server.wireguard.supernet {} overlaps the Tailscale range {TAILSCALE_CGNAT}",
            wg.supernet
        ));
    }
    if !valid_ident(&wg.interface) || !valid_ident(&server.headscale.interface) {
        errors.push("interface names must be plain identifiers (letters, digits, '-', '_')".into());
    }
    if wg.interface == server.headscale.interface {
        errors.push(format!(
            "server.wireguard.interface and server.headscale.interface are both '{}'",
            wg.interface
        ));
    }
    match wg.endpoint.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {}
        _ => errors.push(format!(
            "server.wireguard.endpoint '{}' must be host:port",
            wg.endpoint
        )),
    }
    if wg.listen_port == 0 {
        errors.push("server.wireguard.listen_port must not be 0".into());
    }
    if let Some(tag_iface) = &server.wan_interface {
        if !valid_ident(tag_iface) {
            errors.push(format!(
                "server.wan_interface '{tag_iface}' is not a valid interface name"
            ));
        }
    }
    if let Some(listen) = server.dns.listen {
        for t in &config.templates {
            if t.wireguard.pool.contains(&listen) {
                errors.push(format!(
                    "server.dns.listen {listen} lies inside the pool {} of template '{}'; pick an address outside every pool",
                    t.wireguard.pool, t.name
                ));
            }
        }
    }
    let shim = server.dns.listen.unwrap_or_else(|| wg.gateway_address());

    // --- networks -------------------------------------------------------
    let mut seen_names: BTreeSet<&str> = BTreeSet::new();
    let mut client_prefixes: Vec<(String, Ipv4Net)> = Vec::new(); // what tunnel clients route
    for n in &config.networks {
        let ctx = format!("network '{}'", n.name);
        if !valid_ident(&n.name) {
            errors.push(format!("{ctx}: name must be a plain identifier"));
        }
        if !seen_names.insert(&n.name) {
            errors.push(format!("{ctx}: duplicate name"));
        }
        if !valid_ident(&n.interface) {
            errors.push(format!(
                "{ctx}: interface '{}' is not a valid interface name",
                n.interface
            ));
        }
        if n.subnet.trunc() != n.subnet {
            errors.push(format!(
                "{ctx}: subnet {} has host bits set; write it as {}",
                n.subnet,
                n.subnet.trunc()
            ));
        }
        if overlaps(n.subnet, wg.supernet) {
            errors.push(format!(
                "{ctx}: subnet {} overlaps the WireGuard supernet {}",
                n.subnet, wg.supernet
            ));
        }
        if overlaps(n.subnet, TAILSCALE_CGNAT) {
            errors.push(format!(
                "{ctx}: subnet {} overlaps the Tailscale range {TAILSCALE_CGNAT}",
                n.subnet
            ));
        }
        if let Some(v) = n.mapped_to {
            match Mapping::new(n.subnet, v) {
                Err(_) => errors.push(format!(
                    "{ctx}: mapped_to {v} must have the same prefix length as subnet {} (/{})",
                    n.subnet,
                    n.subnet.prefix_len()
                )),
                Ok(_) => {
                    if v.trunc() != v {
                        errors.push(format!(
                            "{ctx}: mapped_to {v} has host bits set; write it as {}",
                            v.trunc()
                        ));
                    }
                    if overlaps(v, wg.supernet) {
                        errors.push(format!(
                            "{ctx}: mapped_to {v} overlaps the WireGuard supernet {}",
                            wg.supernet
                        ));
                    }
                    if overlaps(v, TAILSCALE_CGNAT) {
                        errors.push(format!(
                            "{ctx}: mapped_to {v} overlaps the Tailscale range {TAILSCALE_CGNAT}"
                        ));
                    }
                    if !is_virtual_space(v) {
                        errors.push(format!(
                            "{ctx}: mapped_to {v} is public address space; clients would lose the real hosts there. Use 198.18.0.0/15 (reserved, recommended) or a private range"
                        ));
                    }
                    for other in &config.networks {
                        if overlaps(v, other.subnet) {
                            errors.push(format!(
                                "{ctx}: mapped_to {v} overlaps the real subnet {} of network '{}'",
                                other.subnet, other.name
                            ));
                        }
                    }
                }
            }
        } else if !n.domains.is_empty() {
            warnings.push(format!(
                "{ctx}: has domains but no mapped_to; names resolve to real addresses, which collide on foreign networks using {}",
                n.subnet
            ));
        }
        if let Some(g) = n.gateway_address {
            if !n.subnet.contains(&g) {
                errors.push(format!(
                    "{ctx}: gateway_address {g} is not inside subnet {}",
                    n.subnet
                ));
            }
        }
        if !n.domains.is_empty() && n.upstream_dns.is_empty() {
            errors.push(format!(
                "{ctx}: domains {:?} need at least one upstream_dns resolver",
                n.domains
            ));
        }
        for d in &n.domains {
            if !valid_zone(d) {
                errors.push(format!("{ctx}: '{d}' is not a valid DNS zone"));
            }
        }
        for dns in &n.upstream_dns {
            if !n.subnet.contains(dns) {
                warnings.push(format!(
                    "{ctx}: upstream_dns {dns} is outside {}; make sure the gateway can reach it",
                    n.subnet
                ));
            }
        }
        if n.masquerade {
            warnings.push(format!(
                "{ctx}: masquerade is on; nginx and other LAN services will see the gateway address instead of the peer (no L7 identity)"
            ));
        }
        client_prefixes.push((n.name.clone(), n.client_subnet()));
    }
    for (i, a) in config.networks.iter().enumerate() {
        for b in config.networks.iter().skip(i + 1) {
            if overlaps(a.subnet, b.subnet) {
                errors.push(format!(
                    "networks '{}' and '{}' have overlapping real subnets ({} and {}); one gateway cannot route both",
                    a.name, b.name, a.subnet, b.subnet
                ));
            }
        }
    }
    for (i, (an, a)) in client_prefixes.iter().enumerate() {
        for (bn, b) in client_prefixes.iter().skip(i + 1) {
            if overlaps(*a, *b) {
                errors.push(format!(
                    "networks '{an}' and '{bn}' present overlapping prefixes to clients ({a} and {b})"
                ));
            }
        }
    }

    // --- services -------------------------------------------------------
    let mut seen_services: BTreeSet<&str> = BTreeSet::new();
    for s in &config.services {
        let ctx = format!("service '{}'", s.name);
        if !valid_ident(&s.name) {
            errors.push(format!("{ctx}: name must be a plain identifier"));
        }
        if !seen_services.insert(&s.name) {
            errors.push(format!("{ctx}: duplicate name"));
        }
        if !config.networks.iter().any(|n| n.subnet.contains(&s.host)) {
            errors.push(format!(
                "{ctx}: host {} is not inside any configured network",
                s.host
            ));
        }
        if s.port == 0 {
            errors.push(format!("{ctx}: port must not be 0"));
        }
    }

    // --- templates ------------------------------------------------------
    let mut seen_templates: BTreeSet<&str> = BTreeSet::new();
    let wan = config
        .server
        .wan_interface
        .as_deref()
        .or_else(|| config.networks.first().map(|n| n.interface.as_str()));
    for t in &config.templates {
        let ctx = format!("template '{}'", t.name);
        if !valid_ident(&t.name) {
            errors.push(format!("{ctx}: name must be a plain identifier"));
        }
        if !seen_templates.insert(&t.name) {
            errors.push(format!("{ctx}: duplicate name"));
        }
        let pool = t.wireguard.pool;
        if pool.trunc() != pool {
            errors.push(format!(
                "{ctx}: wireguard.pool {pool} has host bits set; write it as {}",
                pool.trunc()
            ));
        }
        if !wg.supernet.contains(&pool) {
            errors.push(format!(
                "{ctx}: wireguard.pool {pool} is not inside the supernet {}",
                wg.supernet
            ));
        }
        if pool.prefix_len() > 30 {
            errors.push(format!(
                "{ctx}: wireguard.pool {pool} is too small for peers; use /30 or larger"
            ));
        }
        if pool.contains(&wg.gateway_address()) {
            warnings.push(format!(
                "{ctx}: wireguard.pool {pool} contains the gateway address {}; it will be skipped",
                wg.gateway_address()
            ));
        }
        if t.headscale.user.is_none() && t.headscale.tag.is_none() {
            errors.push(format!(
                "{ctx}: headscale needs a user and/or a tag so Tailscale devices can be placed in this tier"
            ));
        }
        if let Some(tag) = &t.headscale.tag {
            if !tag.starts_with("tag:") || tag.len() <= 4 {
                errors.push(format!(
                    "{ctx}: headscale.tag '{tag}' must look like 'tag:name'"
                ));
            }
        }
        if let Some(user) = &t.headscale.user {
            if user.is_empty() {
                errors.push(format!("{ctx}: headscale.user must not be empty"));
            }
        }
        if let Some(vis) = &t.visible_networks {
            for v in vis {
                if config.network(v).is_none() {
                    errors.push(format!(
                        "{ctx}: visible_networks mentions unknown network '{v}'"
                    ));
                }
            }
        }
        if t.grants.is_empty() {
            warnings.push(format!("{ctx}: has no grants; its peers can reach nothing"));
        }
        for g in &t.grants {
            match g {
                Grant::AllNetworks => {}
                Grant::Network { name } => {
                    if config.network(name).is_none() {
                        errors.push(format!("{ctx}: grant refers to unknown network '{name}'"));
                    }
                }
                Grant::Host { ip } | Grant::HostPort { ip, .. } => {
                    if !config.networks.iter().any(|n| n.subnet.contains(ip)) {
                        errors.push(format!(
                            "{ctx}: grant host {ip} is not inside any configured network (grants use real addresses)"
                        ));
                    }
                    if let Grant::HostPort { port: 0, .. } = g {
                        errors.push(format!("{ctx}: grant for {ip} has port 0"));
                    }
                }
                Grant::Service { name } => {
                    if config.service(name).is_none() {
                        errors.push(format!("{ctx}: grant refers to unknown service '{name}'"));
                    }
                }
                Grant::Internet => {
                    if wan.is_none() {
                        errors.push(format!(
                            "{ctx}: internet grant needs server.wan_interface (or at least one network)"
                        ));
                    }
                }
            }
        }
        if t.client.allowed_ips == AllowedIpsStrategy::FullTunnel
            && !t.grants.contains(&Grant::Internet)
        {
            errors.push(format!(
                "{ctx}: client.allowed_ips = full_tunnel routes everything through the gateway but there is no internet grant, so all non-LAN traffic would be dropped"
            ));
        }
        if let Some(mtu) = t.client.mtu {
            if !(1280..=1500).contains(&mtu) {
                errors.push(format!("{ctx}: client.mtu {mtu} is outside 1280..=1500"));
            }
        }
        if t.dns.wireguard == DnsMode::Split
            && !config.networks.iter().any(|n| !n.domains.is_empty())
        {
            warnings.push(format!(
                "{ctx}: split DNS is selected but no network declares domains; clients get no routing domains"
            ));
        }
    }
    for (i, a) in config.templates.iter().enumerate() {
        for b in config.templates.iter().skip(i + 1) {
            if overlaps(a.wireguard.pool, b.wireguard.pool) {
                errors.push(format!(
                    "templates '{}' and '{}' have overlapping pools ({} and {})",
                    a.name, b.name, a.wireguard.pool, b.wireguard.pool
                ));
            }
        }
    }

    // --- peers ----------------------------------------------------------
    let mut seen_peers: BTreeSet<&str> = BTreeSet::new();
    let mut addresses: BTreeMap<Ipv4Addr, &str> = BTreeMap::new();
    let mut pubkeys: BTreeMap<String, &str> = BTreeMap::new();
    for p in &config.peers {
        let ctx = format!("peer '{}'", p.name);
        if !valid_ident(&p.name) {
            errors.push(format!("{ctx}: name must be a plain identifier"));
        }
        if !seen_peers.insert(&p.name) {
            errors.push(format!("{ctx}: duplicate name"));
        }
        let template = config.template(&p.template);
        if template.is_none() {
            errors.push(format!("{ctx}: unknown template '{}'", p.template));
        }
        match p.transport {
            TransportKind::WireGuard => {
                if p.tailscale.is_some() {
                    errors.push(format!(
                        "{ctx}: transport is wireguard but a [peer.tailscale] block is present"
                    ));
                }
                match &p.wireguard {
                    None => errors.push(format!(
                        "{ctx}: transport is wireguard but there is no [peer.wireguard] block with a public_key"
                    )),
                    Some(w) => {
                        let key = w.public_key.to_base64();
                        if let Some(other) = pubkeys.insert(key, &p.name) {
                            errors.push(format!("{ctx}: public_key is already used by peer '{other}'"));
                        }
                        if let Some(pk) = &w.private_key {
                            if pk.public_key() != w.public_key {
                                errors.push(format!(
                                    "{ctx}: private_key does not correspond to public_key"
                                ));
                            }
                        }
                        match w.address {
                            None => errors.push(format!(
                                "{ctx}: has no address yet; run `parallax peer allocate` to assign one from the template pool"
                            )),
                            Some(addr) => {
                                if let Some(t) = template {
                                    if !t.wireguard.pool.contains(&addr) {
                                        errors.push(format!(
                                            "{ctx}: address {addr} is outside the pool {} of template '{}'",
                                            t.wireguard.pool, t.name
                                        ));
                                    }
                                }
                                if addr == wg.gateway_address() || addr == shim {
                                    errors.push(format!(
                                        "{ctx}: address {addr} is reserved for the gateway"
                                    ));
                                }
                                if let Some(other) = addresses.insert(addr, &p.name) {
                                    errors.push(format!(
                                        "{ctx}: address {addr} is already used by peer '{other}'"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            TransportKind::Tailscale => {
                if p.wireguard.is_some() {
                    errors.push(format!(
                        "{ctx}: transport is tailscale but a [peer.wireguard] block is present"
                    ));
                }
                if let Some(addr) = p.tailscale.as_ref().and_then(|t| t.address) {
                    if !TAILSCALE_CGNAT.contains(&addr) {
                        errors.push(format!(
                            "{ctx}: tailscale address {addr} is outside {TAILSCALE_CGNAT}"
                        ));
                    }
                }
            }
        }
    }

    (errors, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::canonical_config;

    #[test]
    fn canonical_config_is_valid() {
        let cfg = canonical_config();
        let (errors, _) = check(&cfg);
        assert!(errors.is_empty(), "{errors:#?}");
    }

    fn errors_of(mutate: impl FnOnce(&mut Config)) -> Vec<String> {
        let mut cfg = canonical_config();
        mutate(&mut cfg);
        check(&cfg).0
    }

    fn has(errors: &[String], needle: &str) -> bool {
        errors.iter().any(|e| e.contains(needle))
    }

    #[test]
    fn detects_prefix_length_mismatch() {
        let e = errors_of(|c| c.networks[0].mapped_to = Some("198.18.1.0/25".parse().unwrap()));
        assert!(has(&e, "same prefix length"), "{e:?}");
    }

    #[test]
    fn detects_overlaps() {
        let e = errors_of(|c| c.networks[0].mapped_to = Some("10.8.5.0/24".parse().unwrap()));
        assert!(has(&e, "overlaps the WireGuard supernet"), "{e:?}");
        let e = errors_of(|c| c.networks[0].mapped_to = Some("100.100.0.0/24".parse().unwrap()));
        assert!(has(&e, "overlaps the Tailscale range"), "{e:?}");
        let e = errors_of(|c| c.templates[1].wireguard.pool = "10.8.1.0/24".parse().unwrap());
        assert!(has(&e, "overlapping pools"), "{e:?}");
        let e = errors_of(|c| c.templates[1].wireguard.pool = "10.9.1.0/24".parse().unwrap());
        assert!(has(&e, "not inside the supernet"), "{e:?}");
    }

    #[test]
    fn detects_unknown_references() {
        let e = errors_of(|c| {
            c.templates[1].grants = vec![Grant::Service {
                name: "nope".into(),
            }]
        });
        assert!(has(&e, "unknown service 'nope'"), "{e:?}");
        let e = errors_of(|c| c.peers[0].template = "ghost".into());
        assert!(has(&e, "unknown template 'ghost'"), "{e:?}");
        let e = errors_of(|c| {
            c.templates[0].grants = vec![Grant::Host {
                ip: "10.99.0.1".parse().unwrap(),
            }]
        });
        assert!(has(&e, "not inside any configured network"), "{e:?}");
    }

    #[test]
    fn detects_missing_headscale_identity_and_bad_tag() {
        let e = errors_of(|c| c.templates[0].headscale = HeadscaleIdentity::default());
        assert!(has(&e, "headscale needs a user and/or a tag"), "{e:?}");
        let e = errors_of(|c| c.templates[1].headscale.tag = Some("family".into()));
        assert!(has(&e, "must look like 'tag:name'"), "{e:?}");
    }

    #[test]
    fn detects_peer_problems() {
        let e = errors_of(|c| c.peers[0].wireguard.as_mut().unwrap().address = None);
        assert!(has(&e, "has no address yet"), "{e:?}");
        let e = errors_of(|c| {
            let a = c.peers[0].wireguard.as_ref().unwrap().address;
            c.peers[1].wireguard.as_mut().unwrap().address = a;
        });
        assert!(has(&e, "already used by peer"), "{e:?}");
        let e = errors_of(|c| {
            c.peers[2].wireguard.as_mut().unwrap().address = Some("10.8.1.9".parse().unwrap())
        });
        assert!(has(&e, "outside the pool"), "{e:?}");
        let e = errors_of(|c| {
            let k = c.peers[0].wireguard.as_ref().unwrap().public_key.clone();
            c.peers[1].wireguard.as_mut().unwrap().public_key = k;
        });
        assert!(has(&e, "public_key is already used"), "{e:?}");
    }

    #[test]
    fn full_tunnel_needs_internet_grant() {
        let e = errors_of(|c| c.templates[0].client.allowed_ips = AllowedIpsStrategy::FullTunnel);
        assert!(has(&e, "no internet grant"), "{e:?}");
        let e = errors_of(|c| {
            c.templates[0].client.allowed_ips = AllowedIpsStrategy::FullTunnel;
            c.templates[0].grants.push(Grant::Internet);
        });
        assert!(e.is_empty(), "{e:?}");
    }

    #[test]
    fn reaches_resolve_grants_and_dedupe() {
        let cfg = canonical_config();
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        let family = m.template("family").unwrap();
        let r = m.reaches(family);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].client_net(), Some("198.18.1.5/32".parse().unwrap()));
        let personal = m.template("personal").unwrap();
        let immich = cfg.service("immich").unwrap();
        assert!(m.reaches_service(personal, immich));
        assert!(m.reaches_service(family, immich));
    }

    #[test]
    fn expired_peers_are_inactive() {
        let mut cfg = canonical_config();
        cfg.peers[2].expires = Some(Date::new(2026, 1, 1).unwrap());
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        assert_eq!(m.active_peers().count(), 2);
        let m = Model::resolve(&cfg, Date::new(2025, 12, 31).unwrap()).unwrap();
        assert_eq!(m.active_peers().count(), 3);
    }

    #[test]
    fn split_templates_need_catch_all_for_mobile_exports() {
        let mut cfg = canonical_config();
        for t in &mut cfg.templates {
            t.dns.wireguard = DnsMode::Split;
            t.dns.tailscale = DnsMode::Split;
        }
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        assert!(m.needs_catch_all_resolver());
        for t in &mut cfg.templates {
            t.dns.wireguard = DnsMode::None;
        }
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        assert!(!m.needs_catch_all_resolver());
    }

    #[test]
    fn mapped_to_must_avoid_public_space() {
        let e = errors_of(|c| c.networks[0].mapped_to = Some("192.18.1.0/24".parse().unwrap()));
        assert!(has(&e, "public address space"), "{e:?}");
        let e = errors_of(|c| c.networks[0].mapped_to = Some("198.19.1.0/24".parse().unwrap()));
        assert!(!has(&e, "public address space"), "{e:?}");
    }
}
