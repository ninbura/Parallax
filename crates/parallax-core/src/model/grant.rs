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

/// What a template's members may reach. Expressed against **real** addresses
/// (or names that resolve to them);
/// the engine translates to virtual space for clients, Headscale ACLs and
/// nginx, and to real space for the post-NETMAP FORWARD chain.
///
/// TOML form: `grants = [{ kind = "service", name = "immich" }]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", try_from = "GrantToml")]
pub enum Grant {
    /// Every configured network.
    AllNetworks,
    /// One network by name.
    Network { name: String },
    /// One host: `ports` (`["139/tcp", "445/tcp"]`), or every port when
    /// there are none. `host` is an address or a DNS name. For a host used
    /// by several templates, a named [`super::Service`] says it once.
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
}

/// What a grant may look like in TOML, older spellings included: `ip` for
/// `host`, and `host_port` grants with one `proto` and `port`.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum GrantToml {
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
}

impl TryFrom<GrantToml> for Grant {
    type Error = String;
    fn try_from(g: GrantToml) -> Result<Self, String> {
        Ok(match g {
            GrantToml::AllNetworks => Grant::AllNetworks,
            GrantToml::Network { name } => Grant::Network { name },
            // An empty list would mean every port: a list that ended up
            // empty mustn't open everything.
            GrantToml::Host {
                host,
                ports: Some(ports),
            } if ports.is_empty() => {
                return Err(format!(
                    "host grant for {host}: ports = [] lists no port; leave ports out to reach every port"
                ))
            }
            GrantToml::Host { host, ports } => Grant::Host {
                host,
                ports: ports.unwrap_or_default(),
            },
            // Port 0 is refused by validation, as before.
            GrantToml::HostPort { host, proto, port } => Grant::Host {
                host,
                ports: vec![PortSpec {
                    first: port,
                    last: port,
                    proto: Some(proto),
                }],
            },
            GrantToml::Service { name } => Grant::Service { name },
            GrantToml::Internet => Grant::Internet,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize)]
    struct T {
        g: Grant,
    }

    fn grant(text: &str) -> Result<Grant, String> {
        toml::from_str::<T>(&format!("g = {text}"))
            .map(|t| t.g)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn older_spellings_still_read() {
        let one = Grant::Host {
            host: "192.168.1.9".parse().unwrap(),
            ports: vec![PortSpec::one(Proto::Udp, 53)],
        };
        assert_eq!(
            grant(r#"{ kind = "host_port", ip = "192.168.1.9", proto = "udp", port = 53 }"#),
            Ok(one.clone())
        );
        assert_eq!(
            grant(r#"{ kind = "host", host = "192.168.1.9", ports = ["53/udp"] }"#),
            Ok(one)
        );
        let e = grant(r#"{ kind = "host", host = "192.168.1.9", port = 53 }"#).unwrap_err();
        assert!(e.contains("unknown field `port`"), "{e}");
        let e = grant(r#"{ kind = "host", host = "192.168.1.9", ports = [] }"#).unwrap_err();
        assert!(e.contains("lists no port; leave ports out"), "{e}");
    }

    #[test]
    fn written_with_ports_or_without() {
        let all = Grant::Host {
            host: Host::Name("nas.mydomain.com".into()),
            ports: Vec::new(),
        };
        let text = toml::to_string(&T { g: all.clone() }).unwrap();
        assert!(!text.contains("ports"), "{text}");
        assert_eq!(
            grant(r#"{ kind = "host", host = "nas.mydomain.com" }"#),
            Ok(all)
        );
    }
}
