use serde::{Deserialize, Serialize};

use super::{Host, PortSpec, Proto};

/// A named host and its ports, referenced by [`super::Grant::Service`]:
/// defined once, granted to any number of templates.
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
    /// HTTPS names this service answers to. When set, a `service` grant
    /// reaches it only through Parallax's HTTPS proxy, which lets these names
    /// through and nothing else. One address and port often serves many
    /// sites, so the firewall alone can't limit a template to one of them.
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
    #[serde(default)]
    ports: Vec<PortSpec>,
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
        let ports = match (s.ports.is_empty(), s.port, s.proto) {
            (false, None, None) => s.ports,
            (true, Some(port), proto) => vec![PortSpec {
                first: port,
                last: port,
                proto: Some(proto.unwrap_or_default()),
            }],
            (true, None, None) => {
                return Err(format!(
                    "service '{}' has no ports; give ports = [\"445/tcp\", ...]",
                    s.name
                ))
            }
            _ => {
                return Err(format!(
                    "service '{}': give ports, or the older port and proto, not both",
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
