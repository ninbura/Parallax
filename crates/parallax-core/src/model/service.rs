use serde::{Deserialize, Serialize};

use super::{Host, Proto};

/// A named `host:port` on a network, referenced by [`super::Grant::Service`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    /// Real address of the host (the engine translates to virtual space
    /// where mapped), or a DNS name that resolves to it.
    pub host: Host,
    #[serde(default)]
    pub proto: Proto,
    pub port: u16,
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
}
