use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use super::Grant;

/// A policy class. Every template applies to both transports: WireGuard peers
/// get an address from `wireguard.pool` (the range *is* the trust tier), and
/// Tailscale nodes are placed under the Headscale user/tag in `headscale`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub name: String,
    pub wireguard: WireGuardTemplate,
    pub headscale: HeadscaleIdentity,
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// Networks whose mappings this template's clients receive routes for.
    /// `None` means every network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_networks: Option<Vec<String>>,
    #[serde(default)]
    pub dns: DnsPolicy,
    #[serde(default)]
    pub client: ClientDefaults,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardTemplate {
    /// Dedicated CIDR carved from the WireGuard supernet. Firewall and nginx
    /// rules match this prefix, so adding a peer needs zero new rules.
    pub pool: Ipv4Net,
}

/// How this template's members appear to Headscale (M2). At least one of
/// `user` or `tag` must be set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadscaleIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

/// DNS behaviour of a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Route only the operator's zones to the shim; everything else stays on
    /// the local network's resolver. The only correct posture on colliding LANs.
    #[default]
    Split,
    /// Send all DNS to the shim, which forwards non-home zones to a public
    /// resolver. The only option on the official mobile WireGuard apps.
    TunnelWide,
    /// Do not configure DNS. Raw mapped IPs still work.
    None,
}

impl DnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsMode::Split => "split",
            DnsMode::TunnelWide => "tunnel_wide",
            DnsMode::None => "none",
        }
    }
}

/// DNS mode per transport. Differs because the Tailscale client implements
/// split DNS natively on every platform while plain WireGuard cannot on mobile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsPolicy {
    #[serde(default)]
    pub wireguard: DnsMode,
    #[serde(default)]
    pub tailscale: DnsMode,
}

/// What the courtesy `AllowedIPs` in an exported client config contains.
/// Never an enforcement point: the gateway's FORWARD chain is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowedIpsStrategy {
    /// The visible networks' client prefixes (virtual where mapped) plus the shim.
    #[default]
    MappedSubnets,
    /// Only the granted destinations, in virtual space, plus the shim.
    GrantsOnly,
    /// `0.0.0.0/0`. Explicit opt-in; pair with an `internet` grant.
    FullTunnel,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientDefaults {
    #[serde(default)]
    pub allowed_ips: AllowedIpsStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}
