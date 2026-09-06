//! The policy model. These serde types are the M1 TOML interface and will back
//! the API and GUI unchanged. Everything here is plain data; behaviour lives in
//! [`crate::validate`], [`crate::alloc`], [`crate::transport`] and
//! [`crate::generate`].

mod config;
mod grant;
mod network;
mod peer;
mod server;
mod service;
mod template;

pub use config::Config;
pub use grant::{Grant, Proto};
pub use network::Network;
pub use peer::{Peer, TailscalePeer, TransportKind, WireGuardPeer};
pub use server::{
    DerpMode, DnsServer, FirewallBackend, FirewallServer, HeadscaleServer, ServerConfig,
    WireGuardServer,
};
pub use service::Service;
pub use template::{
    AllowedIpsStrategy, ClientDefaults, DnsMode, DnsPolicy, HeadscaleIdentity, Template,
    WireGuardTemplate,
};

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
