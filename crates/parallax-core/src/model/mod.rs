//! The policy model. `parallax-store` keeps it in the database, these serde
//! types are its TOML import/export form, and they will back the API and GUI
//! unchanged. Everything here is plain data; behaviour lives in
//! [`crate::validate`], [`crate::tier`], [`crate::alloc`], [`crate::transport`] and
//! [`crate::generate`].

mod client;
mod config;
mod grant;
mod host;
mod layout;
mod legacy;
mod logs;
mod network;
mod peer;
mod ports;
mod server;
mod service;

pub use client::{AllowedIpsStrategy, DnsMode, PeerDefaults};
pub use config::Config;
pub use grant::{Grant, Proto, Rule};
pub use host::Host;
pub use logs::{ByteSize, LogLevel, LogsServer};
pub use network::Network;
pub use peer::{Peer, TailscalePeer, TransportKind, WireGuardPeer};
pub use ports::{ranges, PortRange, PortSpec};
pub use server::{
    BackupServer, DerpMode, DnsServer, EncryptedDns, FirewallBackend, FirewallServer,
    HeadscaleServer, Interval, ProxyServer, PublicIpServer, ServerConfig, WireGuardServer,
};
pub use service::Service;

/// Client platform a WireGuard config is exported for. Drives the DNS flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// systemd-resolved: native per-domain routing via `resolvectl`.
    Linux,
    /// `/etc/resolver/<zone>` files.
    Macos,
    /// Name Resolution Policy Table rule.
    Windows,
    /// Official iOS/Android apps: no split DNS; tunnel-wide fallback only.
    Mobile,
}

impl Platform {
    pub const ALL: [Platform; 4] = [
        Platform::Linux,
        Platform::Macos,
        Platform::Windows,
        Platform::Mobile,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Macos => "macos",
            Platform::Windows => "windows",
            Platform::Mobile => "mobile",
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "linux" => Ok(Platform::Linux),
            "macos" | "mac" | "darwin" => Ok(Platform::Macos),
            "windows" | "win" => Ok(Platform::Windows),
            "mobile" | "ios" | "android" => Ok(Platform::Mobile),
            other => Err(crate::Error::Malformed {
                what: "platform",
                detail: format!("'{other}' is not one of linux, macos, windows, mobile"),
            }),
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
