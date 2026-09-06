use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::Proto;

/// A named `host:port` on a network, referenced by [`super::Grant::Service`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Service {
    pub name: String,
    /// Real address of the host (the engine translates to virtual space where mapped).
    pub host: Ipv4Addr,
    #[serde(default)]
    pub proto: Proto,
    pub port: u16,
    /// The service is a virtual host multiplexed behind nginx: emit a
    /// per-service `allow/deny` snippet for the operator to `include`.
    #[serde(default)]
    pub nginx_vhost: bool,
}
