use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::secret::{PresharedKey, PrivateKey, PublicKey};

/// Which of the two transports a device uses. A per-device fact, not policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    WireGuard,
    Tailscale,
}

impl TransportKind {
    pub const ALL: [TransportKind; 2] = [TransportKind::WireGuard, TransportKind::Tailscale];

    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::WireGuard => "wireguard",
            TransportKind::Tailscale => "tailscale",
        }
    }
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for TransportKind {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "wireguard" | "wg" => Ok(TransportKind::WireGuard),
            "tailscale" | "ts" | "headscale" => Ok(TransportKind::Tailscale),
            other => Err(crate::Error::Malformed {
                what: "transport",
                detail: format!("'{other}' is not one of wireguard, tailscale"),
            }),
        }
    }
}

/// A device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub template: String,
    pub transport: TransportKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Last day the peer is valid (inclusive). Expired peers are treated as disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Date>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireGuardPeer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailscale: Option<TailscalePeer>,
}

fn default_true() -> bool {
    true
}

impl Peer {
    /// Enabled and not expired as of `today`.
    pub fn is_active(&self, today: Date) -> bool {
        self.enabled && self.expires.is_none_or(|e| today <= e)
    }
}

/// WireGuard identity of a peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardPeer {
    pub public_key: PublicKey,
    /// Address from the template pool, allocated by `peer add`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv4Addr>,
    /// Retained only when the operator opted into config regeneration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<PrivateKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<PresharedKey>,
}

/// Tailscale identity of a peer (M2: driven through the Headscale API).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TailscalePeer {
    /// Headscale node id once the device has registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<u64>,
    /// Tailscale address as assigned by Headscale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Ipv4Addr>,
}
