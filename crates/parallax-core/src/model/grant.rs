use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

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

/// What a template's members may reach. Expressed against **real** addresses;
/// the engine translates to virtual space for clients, Headscale ACLs and
/// nginx, and to real space for the post-NETMAP FORWARD chain.
///
/// TOML form: `grants = [{ kind = "service", name = "immich" }]`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Grant {
    /// Every configured network.
    AllNetworks,
    /// One network by name.
    Network { name: String },
    /// One host, all ports.
    Host { ip: Ipv4Addr },
    /// One host, one port.
    HostPort {
        ip: Ipv4Addr,
        #[serde(default)]
        proto: Proto,
        port: u16,
    },
    /// A named [`super::Service`].
    Service { name: String },
    /// Egress to the internet through the gateway's WAN interface
    /// (masqueraded). Required for the `full_tunnel` AllowedIPs strategy to be
    /// useful.
    Internet,
}
