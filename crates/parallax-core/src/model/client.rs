//! How a WireGuard client is set up: its DNS mode and what its exported
//! `AllowedIPs` hold. Per peer, with server-wide defaults for new peers.

use serde::{Deserialize, Serialize};

/// DNS behaviour of a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Route only the operator's zones to the shim; everything else stays on
    /// the local network's resolver. The only correct posture on colliding LANs.
    #[default]
    Split,
    /// Send all DNS to the gateway, which answers public names only for
    /// peers granted `public_dns`. The only option on the official mobile
    /// WireGuard apps.
    TunnelWide,
    /// Do not configure DNS. Raw mapped IPs still work.
    None,
}

impl DnsMode {
    pub const ALL: [DnsMode; 3] = [DnsMode::Split, DnsMode::TunnelWide, DnsMode::None];

    pub fn as_str(self) -> &'static str {
        match self {
            DnsMode::Split => "split",
            DnsMode::TunnelWide => "tunnel_wide",
            DnsMode::None => "none",
        }
    }
}

impl std::str::FromStr for DnsMode {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        one_of("DNS mode", s, &DnsMode::ALL, |m| m.as_str())
    }
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
    /// `0.0.0.0/0`. Explicit opt-in; pair with an `internet` rule.
    FullTunnel,
}

impl AllowedIpsStrategy {
    pub const ALL: [AllowedIpsStrategy; 3] = [
        AllowedIpsStrategy::MappedSubnets,
        AllowedIpsStrategy::GrantsOnly,
        AllowedIpsStrategy::FullTunnel,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            AllowedIpsStrategy::MappedSubnets => "mapped_subnets",
            AllowedIpsStrategy::GrantsOnly => "grants_only",
            AllowedIpsStrategy::FullTunnel => "full_tunnel",
        }
    }
}

impl std::str::FromStr for AllowedIpsStrategy {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        one_of("allowed_ips", s, &AllowedIpsStrategy::ALL, |a| a.as_str())
    }
}

/// The value of `all` spelled `s`, or an error listing the spellings.
fn one_of<T: Copy>(
    what: &'static str,
    s: &str,
    all: &[T],
    name: fn(T) -> &'static str,
) -> crate::Result<T> {
    all.iter()
        .copied()
        .find(|v| name(*v) == s)
        .ok_or_else(|| crate::Error::Malformed {
            what,
            detail: format!(
                "'{s}' is not one of {}",
                all.iter().map(|v| name(*v)).collect::<Vec<_>>().join(", ")
            ),
        })
}

/// Client settings `peer add` gives a new WireGuard peer unless told
/// otherwise (`[server.wireguard.peer_defaults]`). Each peer keeps its own
/// copy, so changing these never changes an existing peer's config.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerDefaults {
    #[serde(default)]
    pub dns: DnsMode,
    #[serde(default)]
    pub allowed_ips: AllowedIpsStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}
