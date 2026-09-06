use std::net::Ipv4Addr;
use std::path::PathBuf;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::secret::PublicKey;

/// Gateway-wide settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub wireguard: WireGuardServer,
    #[serde(default)]
    pub headscale: HeadscaleServer,
    #[serde(default)]
    pub dns: DnsServer,
    #[serde(default)]
    pub firewall: FirewallServer,
    /// Interface with the default route, used by `internet` grants. Defaults
    /// to the first network's interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wan_interface: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuardServer {
    #[serde(default = "default_wg_interface")]
    pub interface: String,
    #[serde(default = "default_wg_port")]
    pub listen_port: u16,
    /// All template pools are carved from here. The gateway takes its first host.
    pub supernet: Ipv4Net,
    /// `host:port` clients connect to.
    pub endpoint: String,
    /// The gateway's WireGuard public key (derived from `private_key_file`).
    pub public_key: PublicKey,
    /// 0600 file holding the gateway's private key. Never stored in this model.
    #[serde(default = "default_wg_key_file")]
    pub private_key_file: PathBuf,
}

fn default_wg_interface() -> String {
    "wg0".into()
}
fn default_wg_port() -> u16 {
    51820
}
fn default_wg_key_file() -> PathBuf {
    PathBuf::from("/etc/parallax/wg-server.key")
}

impl WireGuardServer {
    /// The gateway's own tunnel address: first host of the supernet.
    pub fn gateway_address(&self) -> Ipv4Addr {
        self.supernet
            .hosts()
            .next()
            .unwrap_or_else(|| self.supernet.addr())
    }
}

/// Headscale control-plane settings (driven in M2; validated now so the model is final).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadscaleServer {
    #[serde(default = "default_ts_interface")]
    pub interface: String,
    #[serde(default = "default_hs_url")]
    pub server_url: String,
    #[serde(default = "default_hs_key_file")]
    pub api_key_file: PathBuf,
    #[serde(default)]
    pub derp: DerpMode,
    #[serde(default = "default_router_name")]
    pub subnet_router_node: String,
}

impl Default for HeadscaleServer {
    fn default() -> Self {
        HeadscaleServer {
            interface: default_ts_interface(),
            server_url: default_hs_url(),
            api_key_file: default_hs_key_file(),
            derp: DerpMode::default(),
            subnet_router_node: default_router_name(),
        }
    }
}

fn default_ts_interface() -> String {
    "tailscale0".into()
}
fn default_hs_url() -> String {
    "http://headscale:8080".into()
}
fn default_hs_key_file() -> PathBuf {
    PathBuf::from("/etc/parallax/headscale-api.key")
}
fn default_router_name() -> String {
    "parallax-gateway".into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerpMode {
    /// Headscale's built-in DERP relay.
    #[default]
    Embedded,
    /// Tailscale's public relay map.
    Tailscale,
}

/// The DNS shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
    /// Address the shim listens on. Defaults to the WireGuard gateway address,
    /// which the M2 subnet router also advertises so Tailscale nodes reach it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<Ipv4Addr>,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    /// Catch-all resolver for tunnel-wide-fallback templates.
    #[serde(default = "default_public_resolver")]
    pub public_resolver: Ipv4Addr,
}

impl Default for DnsServer {
    fn default() -> Self {
        DnsServer {
            listen: None,
            port: default_dns_port(),
            public_resolver: default_public_resolver(),
        }
    }
}

fn default_dns_port() -> u16 {
    53
}
fn default_public_resolver() -> Ipv4Addr {
    Ipv4Addr::new(1, 1, 1, 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallServer {
    #[serde(default)]
    pub backend: FirewallBackend,
    /// The gateway runs host-networked next to Docker's own rules: emit
    /// DOCKER-USER accepts so Docker's FORWARD policy does not eat tunnel traffic.
    #[serde(default)]
    pub docker_coexistence: bool,
}

impl Default for FirewallServer {
    fn default() -> Self {
        FirewallServer {
            backend: FirewallBackend::Nftables,
            docker_coexistence: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallBackend {
    #[default]
    Nftables,
    /// Rendered through `iptables-nft` for hosts without a usable `nft` binary.
    IptablesNft,
}
