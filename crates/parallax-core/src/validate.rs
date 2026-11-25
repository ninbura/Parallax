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
use crate::names::{self, in_zone, Resolved};
use crate::netmap::Mapping;
use crate::{Error, Result, TAILSCALE_CGNAT};

/// A validated configuration plus what generation needs from outside it:
/// the evaluation date (for peer expiry), the home's public IP (for the
/// guest hairpin drop) and what hosts named by DNS name resolved to.
#[derive(Debug, Clone)]
pub struct Model<'a> {
    config: &'a Config,
    today: Date,
    public_ip: Option<Ipv4Addr>,
    names: Resolved,
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
        /// `None`: every port.
        ports: Option<Vec<PortRange>>,
        /// Reached only through the HTTPS proxy (a service with hostnames),
        /// never forwarded directly.
        proxied: bool,
    },
    /// A port forward on the home's public IP, granted by a name that
    /// resolves there: out the WAN interface, which the router hairpins
    /// back in. Always named ports ([`crate::names::public_ip_refusal`]).
    HomePublic {
        address: Ipv4Addr,
        ports: Vec<PortRange>,
        /// Through the HTTPS proxy, which connects to it itself.
        proxied: bool,
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
            // Clients reach the public IP over their own internet unless
            // they send everything through the tunnel.
            ReachKind::HomePublic { .. } | ReachKind::Internet => None,
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

/// A lower-case DNS host name. Stricter than a zone: certificates and the
/// proxy's `Host` check compare names exactly, so no upper case or `_`.
/// The last label needs a letter, so an IP address never passes as a name
/// (SNI forbids literal addresses).
fn valid_hostname(s: &str) -> bool {
    s.len() <= 253
        && s.rsplit('.')
            .next()
            .is_some_and(|tld| tld.chars().any(|c| c.is_ascii_lowercase()))
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

/// The network a host lives on: the one whose subnet holds its address,
/// or whose zone holds its name.
fn network_of_host<'a>(config: &'a Config, host: &Host) -> Option<&'a Network> {
    match host {
        Host::Ip(ip) => config.networks.iter().find(|n| n.subnet.contains(ip)),
        Host::Name(name) => names::network_of(config, name),
    }
}

/// Would `grant` let a template reach web ports on `host` directly, past the
/// proxy? Plain HTTP on tcp/80 and HTTP/3 on udp/443 often serve every site
/// on the box too. Hosts compare as written: a name and an address for the
/// same machine don't match.
fn reaches_web_directly(config: &Config, grant: &Grant, host: &Host) -> bool {
    let web = |ports: &[PortSpec]| ranges(ports).into_iter().any(names::covers_web);
    match grant {
        Grant::AllNetworks => true,
        Grant::Network { name } => network_of_host(config, host).is_some_and(|n| &n.name == name),
        Grant::Host { host: h, ports } => h == host && (ports.is_empty() || web(ports)),
        Grant::Service { name } => config
            .service(name)
            .is_some_and(|s| !s.is_proxied() && &s.host == host && web(&s.ports)),
        Grant::Internet => false,
    }
}

/// `139/tcp, 445/tcp`, for messages and labels.
fn port_list(ports: &[PortSpec]) -> String {
    ports
        .iter()
        .map(PortSpec::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// A grant as written in the config, for messages.
fn describe_grant(grant: &Grant) -> String {
    match grant {
        Grant::AllNetworks => "all_networks".into(),
        Grant::Network { name } => format!("network '{name}'"),
        Grant::Host { host, ports } if ports.is_empty() => format!("host {host}"),
        Grant::Host { host, ports } => format!("host {host} {}", port_list(ports)),
        Grant::Service { name } => format!("service '{name}'"),
        Grant::Internet => "internet".into(),
    }
}

/// The label for a reach on `host`: the name with the address it resolved
/// to. Not its ports: a rule shows those in its match, and a long list
/// would overrun a firewall comment.
fn host_label(host: &Host, ip: Ipv4Addr) -> String {
    match host {
        Host::Ip(_) => format!("host {ip}"),
        Host::Name(name) => format!("host {name} ({ip})"),
    }
}

/// What's wrong with `host` as written, beginning with the host itself. An
/// address must be on a configured network (grants use real addresses); a
/// name must be under one's domains, whose resolvers are asked for it.
fn host_problem(config: &Config, host: &Host) -> Option<String> {
    match host {
        Host::Ip(ip) => (!config.networks.iter().any(|n| n.subnet.contains(ip))).then(|| {
            format!("{ip} is not inside any configured network (grants use real addresses)")
        }),
        Host::Name(name) if !valid_hostname(name) => Some(format!(
            "'{name}' is neither an IPv4 address nor a valid lower-case DNS name"
        )),
        Host::Name(name) => names::network_of(config, name).is_none().then(|| {
            format!(
                "{name} is not under any network's domains, so there's no resolver to ask for it; add its zone to the network it lives on, or use its address"
            )
        }),
    }
}

/// A port list built in code (an older `port = 0`, the GUI) rather than
/// parsed: port 0, or a range that runs backwards.
fn ports_problem(ports: &[PortSpec]) -> Option<String> {
    ports
        .iter()
        .find(|p| p.first == 0 || p.first > p.last)
        .map(|p| format!("'{p}' is not a port or range of ports (1-65535)"))
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
                public_ip: None,
                names: Resolved::new(),
                warnings,
            })
        } else {
            Err(Error::Invalid(errors))
        }
    }

    /// The home's public IP, as last found ([`crate::public_ip`]). Guest
    /// tiers with `internet` drop traffic to it; `None` adds no rule.
    pub fn with_public_ip(mut self, public_ip: Option<Ipv4Addr>) -> Self {
        self.public_ip = public_ip;
        self
    }

    pub fn public_ip(&self) -> Option<Ipv4Addr> {
        self.public_ip
    }

    /// What hosts named by DNS name resolved to ([`crate::names`]). A name
    /// missing here, or whose answer isn't allowed, grants nothing.
    pub fn with_names(mut self, mut names: Resolved) -> Self {
        // Sorted, so output is the same however the caller built them.
        for addresses in names.values_mut() {
            addresses.sort();
            addresses.dedup();
        }
        self.names = names;
        self
    }

    pub fn names(&self) -> &Resolved {
        &self.names
    }

    /// Hosts named by DNS name that grant nothing right now, and why.
    pub fn name_problems(&self) -> Vec<String> {
        names::problems(self.config, self.public_ip, &self.names)
    }

    /// The real addresses `host` stands for: itself, or what its name
    /// resolved to when that answer is allowed (inside a configured network,
    /// or the home's public IP).
    pub fn addresses(&self, host: &Host) -> Vec<Ipv4Addr> {
        match host {
            Host::Ip(ip) => vec![*ip],
            Host::Name(name) => match self.names.get(name) {
                Some(found)
                    if names::refused(self.config, self.public_ip, name, found).is_none() =>
                {
                    found.clone()
                }
                _ => Vec::new(),
            },
        }
    }

    /// The reach for `port` on `ip`, an address `host` stands for: on the
    /// network that holds it, or a port forward on the home's public IP
    /// when `template` may have that one.
    fn reach_at(
        &self,
        template: &Template,
        label: String,
        ip: Ipv4Addr,
        ports: Option<Vec<PortRange>>,
        proxied: bool,
    ) -> Option<Reach<'a>> {
        // First, even where a configured network holds it: the public IP's
        // rules must apply wherever it is.
        if Some(ip) == self.public_ip {
            // Every port of it is never a reach.
            let ports = ports?;
            return names::public_ip_refusal(template, Some(&ports), proxied)
                .is_none()
                .then_some(Reach {
                    label,
                    kind: ReachKind::HomePublic {
                        address: ip,
                        ports,
                        proxied,
                    },
                });
        }
        self.network_containing(ip).map(|network| Reach {
            label,
            kind: ReachKind::Lan {
                network,
                real: Ipv4Net::from(ip),
                ports,
                proxied,
            },
        })
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

    /// The network `host` lives on: where its address (or the first one its
    /// name resolved to) is, else the network whose zone holds the name.
    pub fn network_of_host(&self, host: &Host) -> Option<&'a Network> {
        self.addresses(host)
            .first()
            .and_then(|ip| self.network_containing(*ip))
            .or_else(|| network_of_host(self.config, host))
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
                                ports: None,
                                proxied: false,
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
                                ports: None,
                                proxied: false,
                            },
                        });
                    }
                }
                // Never every port of the home's public IP: `reach_at`
                // gives a port forward named ports only.
                Grant::Host { host, ports } => {
                    let ranges = (!ports.is_empty()).then(|| ranges(ports));
                    for ip in self.addresses(host) {
                        let label = host_label(host, ip);
                        if let Some(r) = self.reach_at(template, label, ip, ranges.clone(), false) {
                            push(r);
                        }
                    }
                }
                Grant::Service { name } => {
                    if let Some(s) = self.config.service(name) {
                        for ip in self.addresses(&s.host) {
                            let label = format!("service {}", s.name);
                            let ports = Some(ranges(&s.ports));
                            if let Some(r) =
                                self.reach_at(template, label, ip, ports, s.is_proxied())
                            {
                                push(r);
                            }
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

    /// Does `template` reach `service` directly (or through a wider grant)?
    /// Proxied reaches don't count: the proxy connects from the gateway, and
    /// sibling sites on the same address and port must not inherit them.
    pub fn reaches_service(&self, template: &Template, service: &Service) -> bool {
        let ranges = ranges(&service.ports);
        self.addresses(&service.host)
            .into_iter()
            .any(|ip| ranges.iter().any(|r| self.reaches_range(template, ip, *r)))
    }

    /// Does `template` reach `proto/port` on `host` directly, without the
    /// proxy? See [`Model::reaches_range`].
    pub fn reaches_directly(
        &self,
        template: &Template,
        host: Ipv4Addr,
        proto: Proto,
        port: u16,
    ) -> bool {
        self.reaches_range(
            template,
            host,
            PortRange {
                proto,
                first: port,
                last: port,
            },
        )
    }

    /// Does `template` reach any of `range` on `host` directly, without the
    /// proxy? Only LAN grants and port forwards count; `internet` never
    /// covers a configured network.
    pub fn reaches_range(&self, template: &Template, host: Ipv4Addr, range: PortRange) -> bool {
        // The owner's `internet` (with `all_networks`) reaches the home's
        // public IP like any public address.
        if Some(host) == self.public_ip
            && template.grants.contains(&Grant::AllNetworks)
            && template.grants.contains(&Grant::Internet)
        {
            return true;
        }
        self.reaches(template).iter().any(|r| match &r.kind {
            ReachKind::Lan { proxied: true, .. } | ReachKind::HomePublic { proxied: true, .. } => {
                false
            }
            ReachKind::Lan { real, ports, .. } => {
                real.contains(&host)
                    && ports
                        .as_ref()
                        .is_none_or(|ports| ports.iter().any(|r| r.overlaps(range)))
            }
            ReachKind::HomePublic { address, ports, .. } => {
                *address == host && ports.iter().any(|r| r.overlaps(range))
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

    /// Address the HTTPS proxy listens on.
    pub fn proxy_address(&self) -> Ipv4Addr {
        self.config
            .server
            .proxy
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
    let proxy = server.proxy.listen.unwrap_or_else(|| wg.gateway_address());
    if server.proxy.port == 0 {
        errors.push("server.proxy.port must not be 0".into());
    }
    if proxy == shim && server.proxy.port == server.dns.port {
        errors.push(format!(
            "server.proxy and the DNS shim both listen on {proxy}:{}; change server.proxy.port",
            server.proxy.port
        ));
    }
    if let Some(listen) = server.proxy.listen {
        // Tunnel tiers' HTTPS is DNATed to this address, so it must be a
        // real unicast address on the gateway (loopback would be dropped as
        // martian after the DNAT).
        if listen.is_unspecified()
            || listen.is_loopback()
            || listen.is_multicast()
            || listen.is_broadcast()
        {
            errors.push(format!(
                "server.proxy.listen {listen} is not a unicast address the gateway's tunnel peers can be redirected to; leave it unset (the WireGuard gateway address) or use one of the gateway's own addresses"
            ));
        }
        for t in &config.templates {
            if t.wireguard.pool.contains(&listen) {
                errors.push(format!(
                    "server.proxy.listen {listen} lies inside the pool {} of template '{}'; pick an address outside every pool",
                    t.wireguard.pool, t.name
                ));
            }
        }
    }

    let backup = &server.backup;
    if backup.keep == 0 {
        errors.push(
            "server.backup.keep must be at least 1; turn automatic backups off with server.backup.automatic = false".into(),
        );
    }
    for (field, path) in [
        ("directory", &backup.directory),
        ("passphrase_file", &backup.passphrase_file),
    ] {
        if !path.is_absolute() {
            errors.push(format!(
                "server.backup.{field} {} must be an absolute path",
                path.display()
            ));
        }
    }

    let public_ip = &server.public_ip;
    if let Some(address) = public_ip.address {
        if !crate::public_ip::is_public(address) {
            errors.push(format!(
                "server.public_ip.address {address} is not a public address; give the home's public IPv4 address, or leave it out to look it up"
            ));
        }
    }
    let mut seen_providers = BTreeSet::new();
    for p in &public_ip.encrypted_dns {
        if !seen_providers.insert(p) {
            errors.push(format!("server.public_ip.encrypted_dns lists '{p}' twice"));
        }
    }

    // --- networks -------------------------------------------------------
    let mut seen_names: BTreeSet<&str> = BTreeSet::new();
    let mut client_prefixes: Vec<(String, Ipv4Net)> = Vec::new(); // what tunnel clients route
                                                                  // Lower-cased zone -> the network that declared it. The DNS server sends
                                                                  // a zone to one network's resolvers, so two can't share it.
    let mut seen_zones: BTreeMap<String, &str> = BTreeMap::new();
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
            if let Some(other) = seen_zones.insert(d.to_ascii_lowercase(), &n.name) {
                errors.push(if other == n.name {
                    format!("{ctx}: domain '{d}' is listed twice")
                } else {
                    format!("{ctx}: domain '{d}' is already declared by network '{other}'")
                });
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
    let mut seen_hostnames: BTreeMap<&str, &str> = BTreeMap::new();
    for s in &config.services {
        let ctx = format!("service '{}'", s.name);
        if !valid_ident(&s.name) {
            errors.push(format!("{ctx}: name must be a plain identifier"));
        }
        if !seen_services.insert(&s.name) {
            errors.push(format!("{ctx}: duplicate name"));
        }
        if let Some(problem) = host_problem(config, &s.host) {
            errors.push(format!("{ctx}: host {problem}"));
        }
        if s.ports.is_empty() {
            errors.push(format!(
                "{ctx}: has no ports; give ports = [\"445/tcp\", ...]"
            ));
        }
        if let Some(problem) = ports_problem(&s.ports) {
            errors.push(format!("{ctx}: {problem}"));
        }
        if s.is_proxied() && s.single_port() != Some((Proto::Tcp, 443)) {
            errors.push(format!(
                "{ctx}: hostnames are for HTTPS services; set ports = [\"443/tcp\"]"
            ));
        }
        let network = network_of_host(config, &s.host);
        for h in &s.hostnames {
            if !valid_hostname(h) {
                errors.push(format!(
                    "{ctx}: hostname '{h}' is not a valid lower-case DNS name"
                ));
                continue;
            }
            match seen_hostnames.insert(h, &s.name) {
                Some(other) if other == s.name => {
                    errors.push(format!("{ctx}: hostname '{h}' is listed twice"));
                }
                Some(other) => errors.push(format!(
                    "{ctx}: hostname '{h}' is already used by service '{other}'"
                )),
                None => {}
            }
            if let Some(n) = network {
                if !n.domains.iter().any(|z| in_zone(h, z)) {
                    errors.push(format!(
                        "{ctx}: hostname '{h}' is not under any domain of network '{}' ({:?}), so clients can't resolve it through the DNS shim",
                        n.name, n.domains
                    ));
                }
            }
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
                Grant::Host { host, ports } => {
                    if let Some(problem) = host_problem(config, host) {
                        errors.push(format!("{ctx}: grant host {problem}"));
                    }
                    if let Some(problem) = ports_problem(ports) {
                        errors.push(format!("{ctx}: grant for {host}: {problem}"));
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
        for g in &t.grants {
            let Grant::Service { name } = g else { continue };
            let Some(s) = config.service(name).filter(|s| s.is_proxied()) else {
                continue;
            };
            for o in t
                .grants
                .iter()
                .filter(|o| reaches_web_directly(config, o, &s.host))
            {
                warnings.push(format!(
                    "{ctx}: grant {} reaches {} directly, which can bypass the hostname check for service '{}': other sites on that host may answer there",
                    describe_grant(o),
                    s.host,
                    s.name
                ));
            }
        }
        // Allowed: a locked-down device that reaches only what it's granted.
        if t.client.allowed_ips == AllowedIpsStrategy::FullTunnel
            && !t.grants.contains(&Grant::Internet)
        {
            warnings.push(format!(
                "{ctx}: client.allowed_ips = full_tunnel routes everything through the gateway but there is no internet grant, so its devices reach only what's granted"
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
                                "{ctx}: has no address yet; `parallax config import` or `config edit` assigns one from the template pool"
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

    #[test]
    fn public_ip_must_be_public_and_providers_unique() {
        let errors =
            errors_of(|c| c.server.public_ip.address = Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(
            has(
                &errors,
                "server.public_ip.address 192.168.1.1 is not a public address"
            ),
            "{errors:?}"
        );
        let errors = errors_of(|c| c.server.public_ip.address = Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(errors.is_empty(), "{errors:?}");
        let errors = errors_of(|c| {
            c.server.public_ip.encrypted_dns = vec![EncryptedDns::Quad9, EncryptedDns::Quad9]
        });
        assert!(has(&errors, "lists 'quad9' twice"), "{errors:?}");
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
    fn backup_settings_are_checked() {
        let e = errors_of(|c| c.server.backup.keep = 0);
        assert!(has(&e, "server.backup.keep must be at least 1"), "{e:?}");
        let e = errors_of(|c| c.server.backup.directory = "backups".into());
        assert!(
            has(
                &e,
                "server.backup.directory backups must be an absolute path"
            ),
            "{e:?}"
        );
        let e = errors_of(|c| c.server.backup.passphrase_file = "pass".into());
        assert!(has(&e, "server.backup.passphrase_file pass"), "{e:?}");
    }

    #[test]
    fn a_zone_belongs_to_one_network() {
        let e = errors_of(|c| {
            let mut lab = c.networks[0].clone();
            lab.name = "lab".into();
            lab.subnet = "192.168.50.0/24".parse().unwrap();
            lab.mapped_to = Some("198.18.50.0/24".parse().unwrap());
            lab.domains = vec!["MyDomain.com".into()];
            c.networks.push(lab);
        });
        assert!(
            has(
                &e,
                "network 'lab': domain 'MyDomain.com' is already declared by network 'home'"
            ),
            "{e:?}"
        );
        let e = errors_of(|c| c.networks[0].domains.push("mydomain.com".into()));
        assert!(has(&e, "domain 'mydomain.com' is listed twice"), "{e:?}");
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
    fn proxy_must_not_collide_with_the_shim_or_a_pool() {
        let e = errors_of(|c| c.server.proxy.port = 53);
        assert!(has(&e, "both listen on 10.8.0.1:53"), "{e:?}");
        let e = errors_of(|c| c.server.proxy.port = 0);
        assert!(has(&e, "server.proxy.port must not be 0"), "{e:?}");
        for bad in ["0.0.0.0", "127.0.0.1", "224.0.0.5", "255.255.255.255"] {
            let e = errors_of(|c| c.server.proxy.listen = Some(bad.parse().unwrap()));
            assert!(
                has(&e, &format!("server.proxy.listen {bad} is not a unicast")),
                "{e:?}"
            );
        }
        let e = errors_of(|c| c.server.proxy.listen = Some("10.8.2.9".parse().unwrap()));
        assert!(
            has(&e, "lies inside the pool 10.8.2.0/24 of template 'family'"),
            "{e:?}"
        );
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
                host: "10.99.0.1".parse().unwrap(),
                ports: Vec::new(),
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
    fn full_tunnel_without_internet_is_a_warning() {
        let mut cfg = canonical_config();
        cfg.templates[0].client.allowed_ips = AllowedIpsStrategy::FullTunnel;
        let (errors, warnings) = check(&cfg);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(has(&warnings, "reach only what's granted"), "{warnings:?}");
        cfg.templates[0].grants.push(Grant::Internet);
        assert!(!has(&check(&cfg).1, "full_tunnel"));
    }

    #[test]
    fn port_lists_are_checked() {
        let e = errors_of(|c| c.services[0].ports.clear());
        assert!(has(&e, "service 'immich': has no ports"), "{e:?}");
        // An older `port = 0` comes in as a port list with port 0.
        let e = errors_of(|c| {
            c.templates[1].grants.push(Grant::Host {
                host: "192.168.1.9".parse().unwrap(),
                ports: vec![PortSpec::one(Proto::Tcp, 0)],
            })
        });
        assert!(
            has(
                &e,
                "template 'family': grant for 192.168.1.9: '0/tcp' is not a port"
            ),
            "{e:?}"
        );
        let e = errors_of(|c| {
            c.services[0].ports = vec![PortSpec {
                first: 200,
                last: 100,
                proto: None,
            }]
        });
        assert!(has(&e, "'200-100' is not a port or range"), "{e:?}");
        // A proxied service is exactly 443/tcp: a bare 443 (TCP and UDP) isn't.
        let e = errors_of(|c| {
            c.services[0].hostnames = vec!["immich.mydomain.com".into()];
            c.services[0].ports = vec!["443".parse().unwrap()];
        });
        assert!(has(&e, "set ports = [\"443/tcp\"]"), "{e:?}");
    }

    #[test]
    fn named_hosts_must_be_names_under_a_zone() {
        let e = errors_of(|c| c.services[0].host = Host::Name("immich.mydomain.com".into()));
        assert!(e.is_empty(), "{e:?}");
        let e = errors_of(|c| {
            c.templates[1].grants.push(Grant::Host {
                host: Host::Name("game.otherdomain.com".into()),
                ports: vec![PortSpec::one(Proto::Udp, 25565)],
            })
        });
        assert!(
            has(&e, "template 'family': grant host game.otherdomain.com is not under any network's domains"),
            "{e:?}"
        );
        for bad in ["192.168.1.300", "Nas.mydomain.com", "nas_1.mydomain.com"] {
            let e = errors_of(|c| c.services[0].host = Host::Name(bad.into()));
            assert!(
                has(&e, &format!("service 'immich': host '{bad}' is neither an IPv4 address nor a valid lower-case DNS name")),
                "{bad}: {e:?}"
            );
        }
    }

    #[test]
    fn a_name_reaches_what_it_resolved_to() {
        let mut cfg = canonical_config();
        cfg.templates[1].grants.push(Grant::Host {
            host: Host::Name("nas.mydomain.com".into()),
            ports: vec![PortSpec::one(Proto::Tcp, 445)],
        });
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        let family = m.template("family").unwrap();
        // Not looked up yet: nothing beyond the service.
        assert_eq!(m.reaches(family).len(), 1);
        assert!(has(&m.name_problems(), "nas.mydomain.com didn't resolve"));
        let found: Resolved = [(
            "nas.mydomain.com".to_string(),
            vec![
                Ipv4Addr::new(192, 168, 1, 9),
                Ipv4Addr::new(192, 168, 1, 10),
            ],
        )]
        .into();
        let m = m.with_names(found);
        let r = m.reaches(family);
        assert_eq!(
            r.iter().map(|r| r.label.as_str()).collect::<Vec<_>>(),
            [
                "service immich",
                "host nas.mydomain.com (192.168.1.9)",
                "host nas.mydomain.com (192.168.1.10)"
            ]
        );
        assert_eq!(r[1].client_net(), Some("198.18.1.9/32".parse().unwrap()));
        assert!(m.name_problems().is_empty());
        // An answer outside every network grants nothing.
        let m = m.with_names(
            [(
                "nas.mydomain.com".to_string(),
                vec![Ipv4Addr::new(8, 8, 8, 8)],
            )]
            .into(),
        );
        assert_eq!(m.reaches(family).len(), 1);
        assert!(has(&m.name_problems(), "outside every configured network"));
    }

    #[test]
    fn a_service_by_name_is_reached_where_it_resolved() {
        let mut cfg = canonical_config();
        cfg.services[0].host = Host::Name("immich.mydomain.com".into());
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap())
            .unwrap()
            .with_names(
                [(
                    "immich.mydomain.com".to_string(),
                    vec![Ipv4Addr::new(192, 168, 1, 5)],
                )]
                .into(),
            );
        let family = m.template("family").unwrap();
        assert_eq!(
            m.reaches(family)[0].client_net(),
            Some("198.18.1.5/32".parse().unwrap())
        );
        assert!(m.reaches_service(family, &cfg.services[0]));
        assert_eq!(
            m.network_of_host(&cfg.services[0].host)
                .map(|n| n.name.as_str()),
            Some("home")
        );
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

    fn proxy_immich(c: &mut Config) {
        c.services[0].hostnames = vec!["immich.mydomain.com".into()];
    }

    #[test]
    fn proxied_service_is_valid_and_reached_through_the_proxy() {
        let mut cfg = canonical_config();
        proxy_immich(&mut cfg);
        let (errors, warnings) = check(&cfg);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!has(&warnings, "proxy"), "{warnings:?}");
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        let family = m.reaches(m.template("family").unwrap());
        assert!(
            matches!(family[0].kind, ReachKind::Lan { proxied: true, .. }),
            "{family:?}"
        );
        let personal = m.reaches(m.template("personal").unwrap());
        assert!(
            matches!(personal[0].kind, ReachKind::Lan { proxied: false, .. }),
            "{personal:?}"
        );
    }

    #[test]
    fn proxied_reach_does_not_count_as_direct_for_siblings() {
        let mut cfg = canonical_config();
        proxy_immich(&mut cfg);
        let mut photos = cfg.services[0].clone();
        photos.name = "photos".into();
        photos.hostnames = Vec::new();
        cfg.services.push(photos);
        let m = Model::resolve(&cfg, Date::new(2026, 9, 6).unwrap()).unwrap();
        let family = m.template("family").unwrap();
        let personal = m.template("personal").unwrap();
        for s in &cfg.services {
            assert!(!m.reaches_service(family, s), "{}", s.name);
            assert!(m.reaches_service(personal, s), "{}", s.name);
        }
    }

    #[test]
    fn hostnames_must_be_valid_unique_and_under_a_domain() {
        let e = errors_of(|c| {
            c.services[0].hostnames =
                vec!["immich.mydomain.com".into(), "immich.mydomain.com".into()]
        });
        assert!(
            has(&e, "hostname 'immich.mydomain.com' is listed twice"),
            "{e:?}"
        );
        for bad in [
            "192.168.1.5",
            "Immich.mydomain.com",
            "imm_ich.mydomain.com",
            "-x.mydomain.com",
            "a..mydomain.com",
        ] {
            let e = errors_of(|c| c.services[0].hostnames = vec![bad.into()]);
            assert!(has(&e, "not a valid lower-case DNS name"), "{bad}: {e:?}");
        }
        for outside in ["immich.otherdomain.com", "notmydomain.com"] {
            let e = errors_of(|c| c.services[0].hostnames = vec![outside.into()]);
            assert!(
                has(&e, "is not under any domain of network 'home'"),
                "{outside}: {e:?}"
            );
        }
        let e = errors_of(|c| c.services[0].hostnames = vec!["mydomain.com".into()]);
        assert!(e.is_empty(), "{e:?}");
        let e = errors_of(|c| {
            proxy_immich(c);
            let mut other = c.services[0].clone();
            other.name = "photos".into();
            c.services.push(other);
        });
        assert!(
            has(
                &e,
                "hostname 'immich.mydomain.com' is already used by service 'immich'"
            ),
            "{e:?}"
        );
    }

    #[test]
    fn hostnames_need_https() {
        let e = errors_of(|c| {
            proxy_immich(c);
            c.services[0].ports = vec![PortSpec::one(Proto::Tcp, 8443)];
        });
        assert!(has(&e, "hostnames are for HTTPS services"), "{e:?}");
        let e = errors_of(|c| {
            proxy_immich(c);
            c.services[0].ports = vec![PortSpec::one(Proto::Udp, 443)];
        });
        assert!(has(&e, "hostnames are for HTTPS services"), "{e:?}");
    }

    #[test]
    fn warns_when_another_grant_bypasses_the_proxy() {
        let host: Host = "192.168.1.5".parse().unwrap();
        let bypasses = [
            Grant::AllNetworks,
            Grant::Network {
                name: "home".into(),
            },
            Grant::Host {
                host: host.clone(),
                ports: Vec::new(),
            },
            Grant::Host {
                host: host.clone(),
                ports: vec![PortSpec::one(Proto::Tcp, 80)],
            },
            Grant::Host {
                host: host.clone(),
                ports: vec![PortSpec::one(Proto::Udp, 443)],
            },
            Grant::Host {
                host: host.clone(),
                ports: vec![PortSpec::one(Proto::Tcp, 443)],
            },
            Grant::Service {
                name: "plain-web".into(),
            },
        ];
        let with_services = || {
            let mut cfg = canonical_config();
            proxy_immich(&mut cfg);
            let mut plain = cfg.services[0].clone();
            plain.name = "plain-web".into();
            plain.ports = vec![PortSpec::one(Proto::Tcp, 80)];
            plain.hostnames = Vec::new();
            let mut photos = cfg.services[0].clone();
            photos.name = "photos".into();
            photos.hostnames = vec!["photos.mydomain.com".into()];
            cfg.services.extend([plain, photos]);
            cfg
        };
        for g in bypasses {
            let mut cfg = with_services();
            cfg.templates[1].grants.push(g.clone());
            let (errors, warnings) = check(&cfg);
            assert!(errors.is_empty(), "{errors:?}");
            assert!(
                has(
                    &warnings,
                    &format!(
                        "template 'family': grant {} reaches 192.168.1.5 directly",
                        describe_grant(&g)
                    )
                ),
                "{g:?}: {warnings:?}"
            );
        }
        // Neither another port nor a second proxied site on the same box bypasses.
        let mut cfg = with_services();
        cfg.templates[1].grants.push(Grant::Host {
            host,
            ports: vec![PortSpec::one(Proto::Tcp, 22)],
        });
        cfg.templates[1].grants.push(Grant::Service {
            name: "photos".into(),
        });
        let (errors, warnings) = check(&cfg);
        assert!(errors.is_empty(), "{errors:?}");
        assert!(!has(&warnings, "directly"), "{warnings:?}");
    }

    #[test]
    fn mapped_to_must_avoid_public_space() {
        let e = errors_of(|c| c.networks[0].mapped_to = Some("192.18.1.0/24".parse().unwrap()));
        assert!(has(&e, "public address space"), "{e:?}");
        let e = errors_of(|c| c.networks[0].mapped_to = Some("198.19.1.0/24".parse().unwrap()));
        assert!(!has(&e, "public address space"), "{e:?}");
    }
}
