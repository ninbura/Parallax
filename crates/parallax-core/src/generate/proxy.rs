//! The HTTPS proxy's routes: which hostnames it serves, where each one goes,
//! and which tunnel addresses may use it. The proxy process reads this file
//! and nothing else from the configuration.
//!
//! A site is listed only when some tier has a `service` rule on it and
//! doesn't already reach the service directly, so the proxy holds no
//! certificate nobody comes through it for. Its `allowed` list is the
//! members of exactly those tiers: every proxied tier lands on the
//! same proxy, and the source address is what keeps one tier off another
//! tier's hostnames.

use std::net::SocketAddrV4;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use super::{Artifact, ArtifactKind};
use crate::model::{Proto, Rule};
use crate::transport;
use crate::validate::Model;
use crate::{Error, Result};

/// The port of every proxied service: validated to be exactly `443/tcp`.
pub const HTTPS: u16 = 443;

/// Where the routes file lives, relative to the output directory.
pub const PATH: &str = "proxy/routes.toml";

/// Everything the proxy process needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyRoutes {
    pub listen: SocketAddrV4,
    /// Folder of PEM certificates (see [`crate::model::ProxyServer`]).
    pub certificates: PathBuf,
    /// CA bundle upstream certificates are verified against.
    pub upstream_ca: PathBuf,
    #[serde(default, rename = "site")]
    pub sites: Vec<ProxySite>,
}

/// One hostname the proxy answers for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxySite {
    pub hostname: String,
    /// The service it belongs to, for logs.
    pub service: String,
    /// Real address and port of the service. The proxy connects here and
    /// checks the upstream certificate against `hostname`.
    pub upstream: SocketAddrV4,
    /// Tunnel source prefixes allowed to use this hostname.
    pub allowed: Vec<Ipv4Net>,
}

impl ProxyRoutes {
    pub fn from_toml(text: &str) -> Result<Self> {
        toml::from_str(text).map_err(|e| Error::Malformed {
            what: "proxy routes",
            detail: e.message().trim().to_string(),
        })
    }

    /// The site for `hostname`, if the proxy serves it.
    pub fn site(&self, hostname: &str) -> Option<&ProxySite> {
        self.sites.iter().find(|s| s.hostname == hostname)
    }
}

impl ProxySite {
    pub fn allows(&self, addr: std::net::Ipv4Addr) -> bool {
        self.allowed.iter().any(|net| net.contains(&addr))
    }
}

/// Derive the routes from the model.
pub fn build(model: &Model<'_>) -> ProxyRoutes {
    let cfg = model.config();
    let proxy = &model.server().proxy;
    let transports = transport::all();
    let mut sites = Vec::new();
    for svc in cfg.services.iter().filter(|s| s.is_proxied()) {
        // A name that hasn't resolved (or not to an allowed address) has
        // nowhere to send the proxy; when it has several addresses, the
        // lowest is the upstream.
        let Some(upstream) = model.addresses(&svc.host).first().copied() else {
            continue;
        };
        let rule = Rule::Service {
            name: svc.name.clone(),
        };
        let mut allowed: Vec<Ipv4Net> = Vec::new();
        // A tier that reaches the service directly gets no redirect (see
        // the firewall), so it never comes through the proxy. With several
        // addresses, it's redirected for those it doesn't reach.
        let addresses = model.addresses(&svc.host);
        for t in model.tiers().iter().filter(|t| {
            t.has(&rule)
                && addresses
                    .iter()
                    .any(|ip| !model.reaches_directly(t, *ip, Proto::Tcp, HTTPS))
        }) {
            for tr in &transports {
                for m in tr.tier_members(model, t) {
                    if !allowed.contains(&m) {
                        allowed.push(m);
                    }
                }
            }
        }
        if allowed.is_empty() {
            continue;
        }
        for hostname in &svc.hostnames {
            sites.push(ProxySite {
                hostname: hostname.clone(),
                service: svc.name.clone(),
                upstream: SocketAddrV4::new(upstream, HTTPS),
                allowed: allowed.clone(),
            });
        }
    }
    ProxyRoutes {
        listen: SocketAddrV4::new(model.proxy_address(), proxy.port),
        certificates: proxy.certificates.clone(),
        upstream_ca: proxy.upstream_ca.clone(),
        sites,
    }
}

/// The routes with every granted proxied hostname, also those whose service
/// is named by a DNS name that hasn't resolved (no upstream yet) and those
/// no granted peer has an address for yet (a Tailscale node not seen yet),
/// for checking certificates: whether one is there mustn't depend on DNS or
/// Headscale, or an answer arriving later could start failing every apply.
pub fn certificate_check(model: &Model<'_>) -> ProxyRoutes {
    let mut routes = build(model);
    for svc in model.config().services.iter().filter(|s| s.is_proxied()) {
        let rule = Rule::Service {
            name: svc.name.clone(),
        };
        // As `build` decides, members aside: some tier with the grant that
        // doesn't reach it directly (unresolved: can't tell, so any tier).
        let addresses = model.addresses(&svc.host);
        let through_proxy = model.tiers().iter().any(|t| {
            t.has(&rule)
                && (addresses.is_empty()
                    || addresses
                        .iter()
                        .any(|ip| !model.reaches_directly(t, *ip, Proto::Tcp, HTTPS)))
        });
        if !through_proxy {
            continue;
        }
        for hostname in &svc.hostnames {
            if routes.sites.iter().any(|s| s.hostname == *hostname) {
                continue;
            }
            routes.sites.push(ProxySite {
                hostname: hostname.clone(),
                service: svc.name.clone(),
                upstream: SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, HTTPS),
                allowed: Vec::new(),
            });
        }
    }
    routes
}

pub fn render(model: &Model<'_>) -> Result<Artifact> {
    let text = to_text(&build(model), false)?;
    Ok(Artifact::public(ArtifactKind::ProxyRoutes, PATH, text))
}

/// The routes file for `routes`. `interim` marks the overlap an apply
/// serves until it has finished ([`overlap`]).
pub fn to_text(routes: &ProxyRoutes, interim: bool) -> Result<String> {
    let body = toml::to_string(routes).map_err(|e| Error::Parse(e.to_string()))?;
    let mut s = String::from(
        "# Generated by Parallax. Do not edit.\n# Routes for `parallax proxy`: each site is a hostname, its upstream, and the tunnel\n# addresses allowed to use it. The proxy re-reads this file on SIGHUP.\n",
    );
    if interim {
        s.push_str(
            "# An apply hasn't finished: only what both the last and the new configuration grant\n# is served until one does.\n",
        );
    }
    if routes.sites.is_empty() {
        s.push_str(
            "# No proxied hostnames are granted to anyone: the proxy refuses every connection.\n",
        );
    }
    s.push('\n');
    s.push_str(&body);
    Ok(s)
}

/// What both `served` and `new` grant: the sites they have alike (apart
/// from who may use them), each for the addresses both allow, and `new`'s
/// listener and certificates. While an apply is under way, or after it
/// failed partway, the live firewall may be the old one, the new one, or
/// (iptables) a mix (issue #71), so the proxy serves only this.
pub fn overlap(served: &ProxyRoutes, new: &ProxyRoutes) -> ProxyRoutes {
    let sites = new
        .sites
        .iter()
        .filter_map(|site| {
            let before = served.sites.iter().find(|s| {
                s.hostname == site.hostname
                    && s.service == site.service
                    && s.upstream == site.upstream
            })?;
            // Two IPv4 prefixes either nest or don't meet, so what both
            // allow is the narrower of each nesting pair.
            let mut allowed: Vec<Ipv4Net> = Vec::new();
            for b in &site.allowed {
                for a in &before.allowed {
                    let both = if a.contains(b) {
                        *b
                    } else if b.contains(a) {
                        *a
                    } else {
                        continue;
                    };
                    if !allowed.contains(&both) {
                        allowed.push(both);
                    }
                }
            }
            (!allowed.is_empty()).then(|| ProxySite {
                allowed,
                ..site.clone()
            })
        })
        .collect();
    ProxyRoutes {
        listen: new.listen,
        certificates: new.certificates.clone(),
        upstream_ca: new.upstream_ca.clone(),
        sites,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{canonical_config, today};

    fn proxied() -> crate::Config {
        let mut cfg = canonical_config();
        cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
        cfg
    }

    #[test]
    fn only_granted_tiers_are_allowed() {
        let cfg = proxied();
        let model = Model::resolve(&cfg, today()).unwrap();
        let routes = build(&model);
        assert_eq!(routes.listen.to_string(), "10.8.0.1:8443");
        assert_eq!(routes.sites.len(), 1);
        let site = &routes.sites[0];
        assert_eq!(site.upstream.to_string(), "192.168.1.5:443");
        // `personal` reaches everything directly and isn't listed; `family` is.
        assert_eq!(
            site.allowed,
            vec!["10.8.2.1/32".parse::<Ipv4Net>().unwrap()]
        );
        assert!(site.allows("10.8.2.1".parse().unwrap()));
        assert!(!site.allows("10.8.2.7".parse().unwrap()));
        assert!(!site.allows("10.8.1.2".parse().unwrap()));
    }

    #[test]
    fn ungranted_services_get_no_site() {
        let mut cfg = proxied();
        cfg.grants[1].rules.clear();
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(build(&model).sites.is_empty());
    }

    #[test]
    fn several_addresses_keep_a_tier_that_reaches_only_some() {
        let mut cfg = proxied();
        cfg.services[0].host = crate::model::Host::Name("immich.mydomain.com".into());
        cfg.grants[1].rules.push(Rule::Host {
            host: "192.168.1.5".parse().unwrap(),
            ports: Vec::new(),
        });
        let found = [(
            "immich.mydomain.com".to_string(),
            vec![
                "192.168.1.5".parse().unwrap(),
                "192.168.1.6".parse().unwrap(),
            ],
        )]
        .into();
        let model = Model::resolve(&cfg, today()).unwrap().with_names(found);
        let routes = build(&model);
        // `family` reaches .5 directly, but .6 still goes through the proxy.
        assert_eq!(
            routes.sites[0].allowed,
            vec!["10.8.2.1/32".parse::<Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn certificates_are_checked_for_names_not_resolved_yet() {
        let mut cfg = proxied();
        cfg.services[0].host = crate::model::Host::Name("immich.mydomain.com".into());
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(build(&model).sites.is_empty());
        let check = certificate_check(&model);
        assert_eq!(check.sites.len(), 1);
        assert_eq!(check.sites[0].hostname, "immich.mydomain.com");
        cfg.grants[1].rules.clear();
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(
            certificate_check(&model).sites.is_empty(),
            "not granted: no certificate needed"
        );
    }

    #[test]
    fn certificates_are_checked_before_any_member_has_an_address() {
        let mut cfg = proxied();
        // family's only peer is on Tailscale, and Headscale hasn't answered.
        let peer = cfg
            .peers
            .iter_mut()
            .find(|p| p.grants == ["family"])
            .unwrap();
        peer.transport = crate::model::TransportKind::Tailscale;
        peer.wireguard = None;
        peer.tailscale = Some(crate::model::TailscalePeer {
            node_id: Some(1),
            address: None,
        });
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(build(&model).site("immich.mydomain.com").is_none());
        assert!(certificate_check(&model)
            .site("immich.mydomain.com")
            .is_some());
    }

    #[test]
    fn rendered_routes_parse_back() {
        let cfg = proxied();
        let model = Model::resolve(&cfg, today()).unwrap();
        let artifact = render(&model).unwrap();
        let parsed = ProxyRoutes::from_toml(&artifact.contents).unwrap();
        assert_eq!(parsed, build(&model));
        assert!(parsed.site("immich.mydomain.com").is_some());
        assert!(parsed.site("photos.mydomain.com").is_none());
    }

    fn site(hostname: &str, upstream: &str, allowed: &[&str]) -> ProxySite {
        ProxySite {
            hostname: hostname.into(),
            service: hostname.split('.').next().unwrap_or_default().into(),
            upstream: upstream.parse().unwrap(),
            allowed: allowed.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    fn routes(listen: &str, sites: Vec<ProxySite>) -> ProxyRoutes {
        ProxyRoutes {
            listen: listen.parse().unwrap(),
            certificates: "/etc/parallax/certs".into(),
            upstream_ca: "/etc/ssl/certs/ca-certificates.crt".into(),
            sites,
        }
    }

    /// #71: a site stays only if both have it alike, for the addresses
    /// both allow; the listener is the new one's.
    #[test]
    fn the_overlap_is_what_both_grant() {
        let served = routes(
            "10.8.0.1:8443",
            vec![
                site(
                    "immich.mydomain.com",
                    "192.168.1.5:443",
                    &["10.8.2.1/32", "10.8.3.0/24"],
                ),
                site("photos.mydomain.com", "192.168.1.6:443", &["10.8.2.1/32"]),
                site("wiki.mydomain.com", "192.168.1.7:443", &["10.8.2.1/32"]),
            ],
        );
        let new = routes(
            "10.8.0.1:9443",
            vec![
                // Someone else's now, and narrower inside the /24.
                site(
                    "immich.mydomain.com",
                    "192.168.1.5:443",
                    &["10.8.1.2/32", "10.8.3.4/32"],
                ),
                // Moved to another upstream.
                site("photos.mydomain.com", "192.168.1.9:443", &["10.8.2.1/32"]),
                // New.
                site("jellyfin.mydomain.com", "192.168.1.8:443", &["10.8.2.1/32"]),
            ],
        );
        let both = overlap(&served, &new);
        assert_eq!(
            both,
            routes(
                "10.8.0.1:9443",
                vec![site(
                    "immich.mydomain.com",
                    "192.168.1.5:443",
                    &["10.8.3.4/32"]
                )]
            )
        );
        // The other way round, the /24 inside the new one's /16 is kept.
        let wide = routes(
            "10.8.0.1:8443",
            vec![site(
                "immich.mydomain.com",
                "192.168.1.5:443",
                &["10.8.0.0/16"],
            )],
        );
        assert_eq!(
            overlap(&wide, &served).sites[0].allowed,
            served.sites[0].allowed
        );
        // Same routes: nothing changes.
        assert_eq!(overlap(&new, &new), new);
    }

    #[test]
    fn interim_routes_say_so_and_parse_back() {
        let r = routes(
            "10.8.0.1:8443",
            vec![site(
                "immich.mydomain.com",
                "192.168.1.5:443",
                &["10.8.2.1/32"],
            )],
        );
        let text = to_text(&r, true).unwrap();
        assert!(text.contains("An apply hasn't finished"), "{text}");
        assert_eq!(ProxyRoutes::from_toml(&text).unwrap(), r);
        assert!(!to_text(&r, false).unwrap().contains("An apply"));
    }
}
