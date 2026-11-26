use serde::{Deserialize, Serialize};

use super::{Host, PortSpec, Proto};

/// A named host and its ports, referenced by [`super::Rule::Service`]:
/// defined once, used by any number of grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ServiceToml")]
pub struct Service {
    pub name: String,
    /// Real address of the host (the engine translates to virtual space
    /// where mapped), or a DNS name that resolves to it.
    pub host: Host,
    /// `["137-138/udp", "139/tcp", "445/tcp"]`; a bare port is TCP and UDP.
    pub ports: Vec<PortSpec>,
    /// The service is a virtual host multiplexed behind nginx: emit a
    /// per-service `allow/deny` snippet for the operator to `include`.
    #[serde(default)]
    pub nginx_vhost: bool,
    /// HTTPS names this service answers to. When set, a `service` rule
    /// reaches it only through Parallax's HTTPS proxy, which lets these names
    /// through and nothing else. One address and port often serves many
    /// sites, so the firewall alone can't limit a peer to one of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
}

impl Service {
    /// Reached through the HTTPS proxy rather than forwarded directly.
    pub fn is_proxied(&self) -> bool {
        !self.hostnames.is_empty()
    }

    /// The one port on one protocol, if that's all it has (a proxied
    /// service is validated to be exactly `443/tcp`).
    pub fn single_port(&self) -> Option<(Proto, u16)> {
        match self.ports[..] {
            [PortSpec {
                first,
                last,
                proto: Some(proto),
            }] if first == last => Some((proto, first)),
            _ => None,
        }
    }
}

/// What a service may look like in TOML: `ports`, or the older single
/// `port` with an optional `proto` (TCP by default).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceToml {
    name: String,
    host: Host,
    ports: Option<Vec<PortSpec>>,
    port: Option<u16>,
    proto: Option<Proto>,
    #[serde(default)]
    nginx_vhost: bool,
    #[serde(default)]
    hostnames: Vec<String>,
}

impl TryFrom<ServiceToml> for Service {
    type Error = String;
    fn try_from(s: ServiceToml) -> Result<Self, String> {
        let ports = match (s.ports, s.port, s.proto) {
            (Some(ports), None, None) if !ports.is_empty() => ports,
            (None, Some(port), proto) => vec![PortSpec {
                first: port,
                last: port,
                proto: Some(proto.unwrap_or_default()),
            }],
            (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                return Err(format!(
                    "service '{}': give ports, or the older port and proto, not both",
                    s.name
                ))
            }
            (None, None, Some(_)) => {
                return Err(format!(
                    "service '{}': proto needs a port; or list ports, like 445/tcp",
                    s.name
                ))
            }
            // No double quotes in these: the parser hides quoted text.
            _ => {
                return Err(format!(
                    "service '{}' has no ports; list them in ports, like 445/tcp or 137-138/udp",
                    s.name
                ))
            }
        };
        Ok(Service {
            name: s.name,
            host: s.host,
            ports,
            nginx_vhost: s.nginx_vhost,
            hostnames: s.hostnames,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Config;
    use crate::testing::canonical_config;

    /// The canonical configuration with its one service written as `service`.
    fn with_service(service: &str) -> crate::Result<Config> {
        let text = canonical_config().to_toml()?;
        let start = text.find("[[service]]").unwrap_or(0);
        let end = text[start..].find("\n\n").map_or(text.len(), |e| start + e);
        Config::from_toml(&format!("{}{}{}", &text[..start], service, &text[end..]))
    }

    #[test]
    fn older_single_ports_still_read() {
        let c = with_service("[[service]]\nname = \"immich\"\nhost = \"192.168.1.5\"\nport = 443")
            .unwrap();
        assert_eq!(c.services[0].ports, [PortSpec::one(Proto::Tcp, 443)]);
        let c = with_service(
            "[[service]]\nname = \"immich\"\nhost = \"192.168.1.5\"\nproto = \"udp\"\nport = 53",
        )
        .unwrap();
        assert_eq!(c.services[0].ports, [PortSpec::one(Proto::Udp, 53)]);
    }

    #[test]
    fn ports_and_the_older_spelling_dont_mix() {
        for (service, why) in [
            ("ports = [\"443/tcp\"]\nport = 443", "not both"),
            ("ports = []\nport = 443", "not both"),
            ("proto = \"tcp\"", "proto needs a port"),
            (
                "ports = []",
                "has no ports; list them in ports, like 445/tcp",
            ),
            ("", "has no ports; list them in ports, like 445/tcp"),
        ] {
            let e = with_service(&format!(
                "[[service]]\nname = \"immich\"\nhost = \"192.168.1.5\"\n{service}"
            ))
            .unwrap_err()
            .to_string();
            assert!(e.contains(why), "{service}: {e}");
        }
    }
}
