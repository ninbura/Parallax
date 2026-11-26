use serde::{Deserialize, Serialize};

use super::{Host, PortSpec};

/// L4 protocol for port-scoped grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    #[default]
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// A named bundle of rules. Peers (and, in M2, Headscale users) are tied
/// to any number of grants; what one reaches is the union of their rules,
/// plus every grant marked `everyone`. Rules only add: there is no deny.
/// A grant may exist with nothing attached.
///
/// TOML form: `[[grant]] name = "family", rules = [{ kind = "service", name = "immich" }]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub name: String,
    /// Applies to every peer, current and future, without being attached.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub everyone: bool,
    /// How much to log for the peers that have it (docs/logging.md). Unset:
    /// the grant doesn't raise its peers' level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<super::LogLevel>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// One thing a grant reaches. Expressed against **real** addresses
/// (or names that resolve to them);
/// the engine translates to virtual space for clients, Headscale ACLs and
/// nginx, and to real space for the post-NETMAP FORWARD chain.
///
/// TOML form: `rules = [{ kind = "service", name = "immich" }]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "RuleToml")]
pub enum Rule {
    /// Every configured network.
    AllNetworks,
    /// One network by name.
    Network { name: String },
    /// One host: `ports` (`["139/tcp", "445/tcp"]`), or every port when
    /// there are none. `host` is an address or a DNS name. For a host used
    /// by several grants, a named [`super::Service`] says it once.
    Host {
        host: Host,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ports: Vec<PortSpec>,
    },
    /// A named [`super::Service`].
    Service { name: String },
    /// Egress to the internet through the gateway's WAN interface
    /// (masqueraded): public addresses only, so private subnets the router
    /// knows but Parallax doesn't stay out of reach. With `all_networks` it
    /// covers everything outside the configured networks. Required for the
    /// `full_tunnel` AllowedIPs strategy to be useful.
    Internet,
    /// Parallax's DNS server answers public lookups (names outside the
    /// operator's zones) through `server.dns.public_resolver`. Without it a
    /// guest's lookups don't leave through the home connection; mobile
    /// WireGuard apps send every query to the gateway, so they then resolve
    /// only the home names they're granted. Opens no firewall access.
    PublicDns,
}

/// The command-line form: `all_networks`, `internet`, `public_dns`,
/// `network:home`, `service:immich`, `host:192.168.1.5`,
/// `host:nas.mydomain.com:139/tcp,445/tcp`. Kinds are the TOML `kind`s;
/// hosts and port lists hold no `:`, so it splits unambiguously.
impl std::fmt::Display for Rule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rule::AllNetworks => f.write_str("all_networks"),
            Rule::Network { name } => write!(f, "network:{name}"),
            Rule::Host { host, ports } => {
                write!(f, "host:{host}")?;
                for (i, port) in ports.iter().enumerate() {
                    write!(f, "{}{port}", if i == 0 { ':' } else { ',' })?;
                }
                Ok(())
            }
            Rule::Service { name } => write!(f, "service:{name}"),
            Rule::Internet => f.write_str("internet"),
            Rule::PublicDns => f.write_str("public_dns"),
        }
    }
}

impl std::str::FromStr for Rule {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        let malformed = |detail: String| crate::Error::Malformed {
            what: "rule",
            detail,
        };
        let mut parts = s.splitn(3, ':');
        let kind = parts.next().unwrap_or_default();
        let value = parts.next();
        let ports = parts.next();
        let named = |what: &str| match value {
            Some(v) if !v.is_empty() && ports.is_none() => Ok(v.to_string()),
            _ => Err(malformed(format!("'{s}': write it {kind}:<{what}>"))),
        };
        let bare = |rule: Rule| match value {
            None => Ok(rule),
            Some(_) => Err(malformed(format!("'{s}': {kind} takes nothing after it"))),
        };
        match kind {
            "all_networks" => bare(Rule::AllNetworks),
            "internet" => bare(Rule::Internet),
            "public_dns" => bare(Rule::PublicDns),
            "network" => Ok(Rule::Network {
                name: named("network")?,
            }),
            "service" => Ok(Rule::Service {
                name: named("service")?,
            }),
            "host" => {
                let host = match value {
                    Some(h) if !h.is_empty() => h,
                    _ => {
                        return Err(malformed(format!(
                            "'{s}': write it host:<address or name>[:<ports>]"
                        )))
                    }
                };
                let ports = match ports {
                    None => Vec::new(),
                    Some(list) => list
                        .split(',')
                        .map(str::parse)
                        .collect::<Result<_, _>>()
                        .map_err(|e: String| malformed(format!("'{s}': {e}")))?,
                };
                Ok(Rule::Host {
                    host: host.parse().unwrap_or_else(|never| match never {}),
                    ports,
                })
            }
            _ => Err(malformed(format!(
                "'{s}': '{kind}' is not one of all_networks, network, host, service, internet, public_dns"
            ))),
        }
    }
}

/// What a rule may look like in TOML, older spellings included: `ip` for
/// `host`, and `host_port` rules with one `proto` and `port`.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RuleToml {
    AllNetworks,
    Network {
        name: String,
    },
    Host {
        #[serde(alias = "ip")]
        host: Host,
        ports: Option<Vec<PortSpec>>,
    },
    HostPort {
        #[serde(alias = "ip")]
        host: Host,
        #[serde(default)]
        proto: Proto,
        port: u16,
    },
    Service {
        name: String,
    },
    Internet,
    PublicDns,
}

impl TryFrom<RuleToml> for Rule {
    type Error = String;
    fn try_from(g: RuleToml) -> Result<Self, String> {
        Ok(match g {
            RuleToml::AllNetworks => Rule::AllNetworks,
            RuleToml::Network { name } => Rule::Network { name },
            // An empty list would mean every port: a list that ended up
            // empty mustn't open everything.
            RuleToml::Host {
                host,
                ports: Some(ports),
            } if ports.is_empty() => {
                return Err(format!(
                    "host rule for {host}: ports = [] lists no port; leave ports out to reach every port"
                ))
            }
            RuleToml::Host { host, ports } => Rule::Host {
                host,
                ports: ports.unwrap_or_default(),
            },
            // Port 0 is refused by validation, as before.
            RuleToml::HostPort { host, proto, port } => Rule::Host {
                host,
                ports: vec![PortSpec {
                    first: port,
                    last: port,
                    proto: Some(proto),
                }],
            },
            RuleToml::Service { name } => Rule::Service { name },
            RuleToml::Internet => Rule::Internet,
            RuleToml::PublicDns => Rule::PublicDns,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct T {
        g: Rule,
    }

    fn rule(text: &str) -> Result<Rule, String> {
        toml::from_str::<T>(&format!("g = {text}"))
            .map(|t| t.g)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn older_spellings_still_read() {
        let one = Rule::Host {
            host: "192.168.1.9".parse().unwrap(),
            ports: vec![PortSpec::one(Proto::Udp, 53)],
        };
        assert_eq!(
            rule(r#"{ kind = "host_port", ip = "192.168.1.9", proto = "udp", port = 53 }"#),
            Ok(one.clone())
        );
        assert_eq!(
            rule(r#"{ kind = "host", host = "192.168.1.9", ports = ["53/udp"] }"#),
            Ok(one)
        );
        let e = rule(r#"{ kind = "host", host = "192.168.1.9", port = 53 }"#).unwrap_err();
        assert!(e.contains("unknown field `port`"), "{e}");
        let e = rule(r#"{ kind = "host", host = "192.168.1.9", ports = [] }"#).unwrap_err();
        assert!(e.contains("lists no port; leave ports out"), "{e}");
    }

    #[test]
    fn the_command_line_form_reads_back() {
        for text in [
            "all_networks",
            "internet",
            "public_dns",
            "network:home",
            "service:immich",
            "host:192.168.1.5",
            "host:nas.mydomain.com:139/tcp,445/tcp,25565",
        ] {
            let rule: Rule = text.parse().unwrap();
            assert_eq!(rule.to_string(), text);
        }
        assert_eq!(
            "host:192.168.1.9:53/udp".parse::<Rule>().unwrap(),
            Rule::Host {
                host: "192.168.1.9".parse().unwrap(),
                ports: vec![PortSpec::one(Proto::Udp, 53)],
            }
        );
        for (bad, why) in [
            ("services:immich", "'services' is not one of"),
            ("service", "write it service:<service>"),
            ("service:", "write it service:<service>"),
            ("network:home:80", "write it network:<network>"),
            ("internet:yes", "internet takes nothing after it"),
            ("host:", "write it host:<address or name>"),
            ("host:192.168.1.9:", "is not a port"),
            ("host:192.168.1.9:53/sctp", "neither tcp nor udp"),
        ] {
            let e = bad.parse::<Rule>().unwrap_err().to_string();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn written_with_ports_or_without() {
        let all = Rule::Host {
            host: Host::Name("nas.mydomain.com".into()),
            ports: Vec::new(),
        };
        let text = toml::to_string(&T { g: all.clone() }).unwrap();
        assert!(!text.contains("ports"), "{text}");
        assert_eq!(
            rule(r#"{ kind = "host", host = "nas.mydomain.com" }"#),
            Ok(all)
        );
    }
}
