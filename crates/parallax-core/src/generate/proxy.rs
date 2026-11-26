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
const HTTPS: u16 = 443;

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
/// is named by a DNS name that hasn't resolved (no upstream yet), for
/// checking certificates: whether one is there mustn't depend on DNS, or a
/// name resolving later could start failing every apply.
pub fn certificate_check(model: &Model<'_>) -> ProxyRoutes {
    let mut routes = build(model);
    let granted = |name: &str| {
        model.tiers().iter().any(|t| {
            t.rules
                .iter()
                .any(|r| matches!(r, Rule::Service { name: n } if n == name))
        })
    };
    for svc in model.config().services.iter().filter(|s| s.is_proxied()) {
        if !model.addresses(&svc.host).is_empty() || !granted(&svc.name) {
            continue;
        }
        for hostname in &svc.hostnames {
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
    let routes = build(model);
    let body = toml::to_string(&routes).map_err(|e| Error::Parse(e.to_string()))?;
    let mut s = String::from(
        "# Generated by Parallax. Do not edit.\n# Routes for `parallax proxy`: each site is a hostname, its upstream, and the tunnel\n# addresses allowed to use it. The proxy re-reads this file on SIGHUP.\n",
    );
    if routes.sites.is_empty() {
        s.push_str(
            "# No proxied hostnames are granted to anyone: the proxy refuses every connection.\n",
        );
    }
    s.push('\n');
    s.push_str(&body);
    Ok(Artifact::public(ArtifactKind::ProxyRoutes, PATH, s))
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
    fn rendered_routes_parse_back() {
        let cfg = proxied();
        let model = Model::resolve(&cfg, today()).unwrap();
        let artifact = render(&model).unwrap();
        let parsed = ProxyRoutes::from_toml(&artifact.contents).unwrap();
        assert_eq!(parsed, build(&model));
        assert!(parsed.site("immich.mydomain.com").is_some());
        assert!(parsed.site("photos.mydomain.com").is_none());
    }
}
