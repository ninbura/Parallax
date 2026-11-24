//! The DNS server's routes: which zones exist and who answers them, how
//! answers are rewritten into mapped space, and which names each tier may
//! look up. The DNS server reads this file and nothing else from the
//! configuration.
//!
//! The server holds no records. It forwards the operator's zones to the home
//! resolvers and rewrites their answers with the same [`Mapping`] the NETMAP
//! rules come from, so DNS and the firewall can't drift. Every query is
//! checked against the tier the source address belongs to: a tier gets the
//! zones of the networks it's granted and the hostnames of the services it's
//! granted, and public names only with `dns.public`. Everything else is
//! refused. DNS is convenience, never enforcement: the firewall and the proxy
//! are the gate, this only keeps a guest from using the gateway's resolver
//! for names it has no business with.

use std::net::{Ipv4Addr, SocketAddrV4};

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use super::{Artifact, ArtifactKind};
use crate::model::Grant;
use crate::netmap::Mapping;
use crate::transport;
use crate::validate::Model;
use crate::{Error, Result};

/// Where the routes file lives, relative to the output directory.
pub const PATH: &str = "dns/routes.toml";

/// Everything the DNS server needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRoutes {
    pub listen: SocketAddrV4,
    /// Where public names go, for tiers with `public`.
    pub public_resolver: Ipv4Addr,
    #[serde(default, rename = "zone")]
    pub zones: Vec<DnsZone>,
    #[serde(default, rename = "mapping")]
    pub mappings: Vec<DnsMapping>,
    #[serde(default, rename = "tier")]
    pub tiers: Vec<DnsTier>,
}

/// One of the operator's zones and the home resolvers that answer it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsZone {
    /// Lower case, no trailing dot.
    pub name: String,
    /// The network it belongs to, for logs.
    pub network: String,
    pub upstream: Vec<Ipv4Addr>,
}

/// A mapped network: A records in `real` are rewritten into `virtual`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsMapping {
    pub real: Ipv4Net,
    #[serde(rename = "virtual")]
    pub virt: Ipv4Net,
}

/// What one template's members may look up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsTier {
    pub template: String,
    /// Tunnel source prefixes of the template's members.
    pub members: Vec<Ipv4Net>,
    /// Whole zones (every name in them).
    #[serde(default)]
    pub zones: Vec<String>,
    /// Single names inside a zone (a service's hostnames).
    #[serde(default)]
    pub names: Vec<String>,
    /// Names outside every zone go to the public resolver.
    #[serde(default)]
    pub public: bool,
}

/// Where a query goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route<'a> {
    /// A name in one of the operator's zones: ask its home resolvers and
    /// rewrite the answer into mapped space. `whole_zone` is false when the
    /// tier may see just this name (a service hostname): the answer must
    /// not reveal other names in the zone, such as a CNAME's target.
    Home { zone: &'a DnsZone, whole_zone: bool },
    /// A public name: ask the public resolver, drop non-public answers.
    Public,
    /// Not this tier's business, or not a tier at all.
    Refused,
}

/// `name` is `zone` or inside it. Both lower case, no trailing dot.
fn in_zone(name: &str, zone: &str) -> bool {
    name == zone
        || name
            .strip_suffix(zone)
            .is_some_and(|rest| rest.ends_with('.'))
}

impl DnsRoutes {
    pub fn from_toml(text: &str) -> Result<Self> {
        let routes: DnsRoutes = toml::from_str(text).map_err(|e| Error::Malformed {
            what: "DNS routes",
            detail: e.message().trim().to_string(),
        })?;
        routes.mapping_list()?;
        Ok(routes)
    }

    /// The mappings, checked.
    pub fn mapping_list(&self) -> Result<Vec<Mapping>> {
        self.mappings
            .iter()
            .map(|m| Mapping::new(m.real, m.virt))
            .collect()
    }

    /// The tier `client` belongs to.
    pub fn tier(&self, client: Ipv4Addr) -> Option<&DnsTier> {
        self.tiers
            .iter()
            .find(|t| t.members.iter().any(|m| m.contains(&client)))
    }

    /// The most specific zone `name` is in.
    pub fn zone_of(&self, name: &str) -> Option<&DnsZone> {
        self.zones
            .iter()
            .filter(|z| in_zone(name, &z.name))
            .max_by_key(|z| z.name.len())
    }

    /// Where `client`'s query for `name` goes. `name` may carry a trailing
    /// dot and any case.
    pub fn route(&self, client: Ipv4Addr, name: &str) -> Route<'_> {
        let Some(tier) = self.tier(client) else {
            return Route::Refused;
        };
        // A backslash is an escaped character inside a label (`a\.b` is one
        // label): text matching would misread its labels, and no host name
        // has one.
        if name.contains('\\') {
            return Route::Refused;
        }
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        match self.zone_of(&name) {
            // A name in a zone never goes to the public resolver, even when
            // the tier may not see it: that would leak the operator's names
            // and could return the home's public address.
            Some(zone) if tier.zones.contains(&zone.name) => Route::Home {
                zone,
                whole_zone: true,
            },
            Some(zone) if tier.names.contains(&name) => Route::Home {
                zone,
                whole_zone: false,
            },
            Some(_) => Route::Refused,
            None if tier.public => Route::Public,
            None => Route::Refused,
        }
    }
}

/// Derive the routes from the model.
pub fn build(model: &Model<'_>) -> DnsRoutes {
    let cfg = model.config();
    let dns = &model.server().dns;
    let zones: Vec<DnsZone> = cfg
        .networks
        .iter()
        .flat_map(|n| {
            n.domains.iter().map(move |d| DnsZone {
                name: d.to_ascii_lowercase(),
                network: n.name.clone(),
                upstream: n.upstream_dns.clone(),
            })
        })
        .collect();
    let mappings = cfg
        .networks
        .iter()
        .filter_map(|n| n.mapping())
        .map(|m| DnsMapping {
            real: m.real(),
            virt: m.virt(),
        })
        .collect();
    let transports = transport::all();
    let mut tiers = Vec::new();
    for t in &cfg.templates {
        let mut members: Vec<Ipv4Net> = Vec::new();
        for tr in &transports {
            for m in tr.tier_members(model, t) {
                if !members.contains(&m) {
                    members.push(m);
                }
            }
        }
        let mut tier_zones: Vec<String> = Vec::new();
        let mut names: Vec<String> = Vec::new();
        for g in &t.grants {
            let granted: Vec<&str> = match g {
                Grant::AllNetworks => cfg.networks.iter().map(|n| n.name.as_str()).collect(),
                Grant::Network { name } => vec![name.as_str()],
                Grant::Service { name } => {
                    if let Some(svc) = cfg.services.iter().find(|s| &s.name == name) {
                        for h in &svc.hostnames {
                            if !names.contains(h) {
                                names.push(h.clone());
                            }
                        }
                    }
                    Vec::new()
                }
                // A host or port has no name of its own (yet: DNS-resolved
                // hostname grants come later).
                Grant::Host { .. } | Grant::HostPort { .. } | Grant::Internet => Vec::new(),
            };
            for z in zones
                .iter()
                .filter(|z| granted.contains(&z.network.as_str()))
            {
                if !tier_zones.contains(&z.name) {
                    tier_zones.push(z.name.clone());
                }
            }
        }
        if members.is_empty() {
            continue;
        }
        tiers.push(DnsTier {
            template: t.name.clone(),
            members,
            zones: tier_zones,
            names,
            public: t.dns.public,
        });
    }
    DnsRoutes {
        listen: SocketAddrV4::new(model.shim_address(), dns.port),
        public_resolver: dns.public_resolver,
        zones,
        mappings,
        tiers,
    }
}

pub fn render(model: &Model<'_>) -> Result<Artifact> {
    let routes = build(model);
    let body = toml::to_string(&routes).map_err(|e| Error::Parse(e.to_string()))?;
    let s = format!(
        "# Generated by Parallax. Do not edit.\n# Routes for `parallax dns`: the operator's zones and their home resolvers, the\n# rewrite into mapped space, and the names each tier may look up. Everything else\n# is refused. The DNS server re-reads this file on SIGHUP.\n\n{body}"
    );
    Ok(Artifact::public(ArtifactKind::DnsRoutes, PATH, s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Network, Service};
    use crate::testing::{canonical_config, today};

    fn addr(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn proxied() -> crate::Config {
        let mut cfg = canonical_config();
        cfg.services[0].hostnames = vec!["immich.mydomain.com".into()];
        cfg
    }

    #[test]
    fn tiers_get_their_zones_and_names() {
        let cfg = proxied();
        let model = Model::resolve(&cfg, today()).unwrap();
        let routes = build(&model);
        assert_eq!(routes.listen.to_string(), "10.8.0.1:53");
        assert_eq!(routes.zones.len(), 1);
        assert_eq!(
            routes.mappings,
            vec![DnsMapping {
                real: "192.168.1.0/24".parse().unwrap(),
                virt: "198.18.1.0/24".parse().unwrap(),
            }]
        );
        let personal = &routes.tiers[0];
        assert_eq!(personal.zones, vec!["mydomain.com"]);
        assert!(personal.names.is_empty());
        assert!(personal.public);
        let family = &routes.tiers[1];
        assert_eq!(
            family.members,
            vec!["10.8.2.0/24".parse::<Ipv4Net>().unwrap()]
        );
        assert!(family.zones.is_empty());
        assert_eq!(family.names, vec!["immich.mydomain.com"]);
        assert!(!family.public);
    }

    #[test]
    fn routes_by_tier_and_name() {
        let cfg = proxied();
        let model = Model::resolve(&cfg, today()).unwrap();
        let routes = build(&model);
        let (laptop, sister, stranger) = (addr("10.8.1.2"), addr("10.8.2.1"), addr("10.8.9.9"));
        let zone = &routes.zones[0];
        let whole = Route::Home {
            zone,
            whole_zone: true,
        };
        assert_eq!(routes.route(laptop, "nas.mydomain.com."), whole);
        assert_eq!(routes.route(laptop, "MyDomain.com"), whole);
        assert_eq!(routes.route(laptop, "example.org."), Route::Public);
        assert_eq!(
            routes.route(sister, "Immich.MyDomain.com."),
            Route::Home {
                zone,
                whole_zone: false
            }
        );
        assert_eq!(routes.route(sister, "other.mydomain.com."), Route::Refused);
        assert_eq!(routes.route(sister, "mydomain.com."), Route::Refused);
        assert_eq!(routes.route(sister, "example.org."), Route::Refused);
        // An escaped dot makes one label of `evil.mydomain`: not in the zone.
        assert_eq!(routes.route(laptop, "evil\\.mydomain.com."), Route::Refused);
        // Not a zone, though it ends in one's letters.
        assert_eq!(routes.route(laptop, "notmydomain.com."), Route::Public);
        assert_eq!(routes.route(sister, "notmydomain.com."), Route::Refused);
        assert_eq!(
            routes.route(stranger, "immich.mydomain.com."),
            Route::Refused
        );
        assert_eq!(
            routes.route(addr("192.168.1.10"), "example.org."),
            Route::Refused
        );
    }

    #[test]
    fn a_public_tier_never_sends_hidden_zone_names_out() {
        let mut cfg = proxied();
        cfg.templates[1].dns.public = true;
        let model = Model::resolve(&cfg, today()).unwrap();
        let routes = build(&model);
        assert_eq!(routes.route(addr("10.8.2.1"), "example.org"), Route::Public);
        assert_eq!(
            routes.route(addr("10.8.2.1"), "other.mydomain.com"),
            Route::Refused
        );
    }

    #[test]
    fn the_most_specific_zone_owns_a_name() {
        let mut cfg = proxied();
        cfg.networks.push(Network {
            name: "lab".into(),
            interface: "eth1".into(),
            gateway_address: None,
            subnet: "192.168.50.0/24".parse().unwrap(),
            mapped_to: Some("198.18.50.0/24".parse().unwrap()),
            upstream_dns: vec![addr("192.168.50.1")],
            domains: vec!["lab.mydomain.com".into()],
            masquerade: false,
        });
        cfg.templates[0].grants = vec![Grant::Network {
            name: "home".into(),
        }];
        let model = Model::resolve(&cfg, today()).unwrap();
        let routes = build(&model);
        let laptop = addr("10.8.1.2");
        assert_eq!(
            routes.zone_of("pi.lab.mydomain.com").unwrap().network,
            "lab"
        );
        assert!(
            matches!(routes.route(laptop, "nas.mydomain.com"), Route::Home { zone, .. } if zone.network == "home")
        );
        // Granted home, not lab: lab's names stay hidden.
        assert_eq!(routes.route(laptop, "pi.lab.mydomain.com"), Route::Refused);
    }

    #[test]
    fn a_service_hostname_survives_a_grant_on_an_enclosing_zone() {
        // The service lives in lab.mydomain.com; the tier also gets the home
        // network (mydomain.com) but not lab. Its hostname must still resolve.
        let mut cfg = proxied();
        cfg.networks.push(Network {
            name: "lab".into(),
            interface: "eth1".into(),
            gateway_address: None,
            subnet: "192.168.50.0/24".parse().unwrap(),
            mapped_to: Some("198.18.50.0/24".parse().unwrap()),
            upstream_dns: vec![addr("192.168.50.1")],
            domains: vec!["lab.mydomain.com".into()],
            masquerade: false,
        });
        cfg.services[0].host = addr("192.168.50.5");
        cfg.services[0].hostnames = vec!["immich.lab.mydomain.com".into()];
        cfg.templates[1].grants.push(Grant::Network {
            name: "home".into(),
        });
        let model = Model::resolve(&cfg, today()).unwrap();
        let routes = build(&model);
        let sister = addr("10.8.2.1");
        assert!(matches!(
            routes.route(sister, "immich.lab.mydomain.com"),
            Route::Home { zone, whole_zone: false } if zone.network == "lab"
        ));
        assert_eq!(routes.route(sister, "pi.lab.mydomain.com"), Route::Refused);
        assert!(matches!(
            routes.route(sister, "nas.mydomain.com"),
            Route::Home {
                whole_zone: true,
                ..
            }
        ));
    }

    #[test]
    fn services_without_hostnames_give_no_names() {
        let mut cfg = canonical_config();
        cfg.services.push(Service {
            name: "printer".into(),
            host: addr("192.168.1.9"),
            proto: crate::model::Proto::Tcp,
            port: 631,
            nginx_vhost: false,
            hostnames: Vec::new(),
        });
        cfg.templates[1].grants = vec![Grant::Service {
            name: "printer".into(),
        }];
        let model = Model::resolve(&cfg, today()).unwrap();
        let family = &build(&model).tiers[1];
        assert!(family.zones.is_empty() && family.names.is_empty());
    }

    #[test]
    fn rendered_routes_parse_back() {
        let cfg = proxied();
        let model = Model::resolve(&cfg, today()).unwrap();
        let artifact = render(&model).unwrap();
        let parsed = DnsRoutes::from_toml(&artifact.contents).unwrap();
        assert_eq!(parsed, build(&model));
        assert_eq!(parsed.mapping_list().unwrap().len(), 1);
    }

    #[test]
    fn a_broken_mapping_is_refused_at_load() {
        let text = "listen = \"10.8.0.1:53\"\npublic_resolver = \"1.1.1.1\"\n[[mapping]]\nreal = \"192.168.1.0/24\"\nvirtual = \"198.18.1.0/25\"\n";
        let e = DnsRoutes::from_toml(text).unwrap_err().to_string();
        assert!(e.contains("different prefix lengths"), "{e}");
    }
}
