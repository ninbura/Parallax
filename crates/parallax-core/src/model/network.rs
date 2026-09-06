use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

/// A physical network the gateway can reach directly.
///
/// A mapped network (one with `mapped_to`) is presented to every VPN client
/// under the virtual prefix instead of its real one, on both transports. The
/// single mapping drives the NETMAP rules, the dnsmasq `alias=` rewrite, the
/// client routes and (M2) the Tailscale advertised route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Unique name, referenced by grants and templates.
    pub name: String,
    /// Gateway interface attached to this network (e.g. `eth0`).
    pub interface: String,
    /// The real prefix as configured on the LAN.
    pub subnet: Ipv4Net,
    /// Collision-free virtual prefix presented to clients. Same prefix length
    /// as `subnet`; host bits are preserved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mapped_to: Option<Ipv4Net>,
    /// Authoritative resolvers for `domains` (the existing source of truth).
    #[serde(default)]
    pub upstream_dns: Vec<Ipv4Addr>,
    /// DNS zones whose names live on this network. They scope the shim
    /// (`server=/zone/`), the clients' routing domains, and (M2) Headscale
    /// split DNS.
    #[serde(default)]
    pub domains: Vec<String>,
    /// SNAT tunnel traffic toward this LAN behind the gateway's address.
    /// Destroys L7 identity (nginx sees the gateway, not the peer). Only for
    /// routers that cannot hold a static route back to the tunnel ranges.
    #[serde(default)]
    pub masquerade: bool,
}

impl Network {
    /// The prefix clients use to address this network (virtual if mapped).
    pub fn client_subnet(&self) -> Ipv4Net {
        self.mapped_to.unwrap_or(self.subnet)
    }

    /// The mapping, if any, as a translation helper.
    pub fn mapping(&self) -> Option<crate::netmap::Mapping> {
        self.mapped_to
            .map(|v| crate::netmap::Mapping::new(self.subnet, v))
            .transpose()
            .ok()
            .flatten()
    }

    /// Translate a real address on this network to what clients see.
    pub fn to_client_addr(&self, real: Ipv4Addr) -> Ipv4Addr {
        match self.mapping() {
            Some(m) => m.to_virtual(real).unwrap_or(real),
            None => real,
        }
    }
}
