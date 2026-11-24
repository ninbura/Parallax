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
    #[serde(default)]
    pub proxy: ProxyServer,
    #[serde(default)]
    pub backup: BackupServer,
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

/// The DNS shim: Parallax's built-in DNS server (`parallax dns`), which
/// answers each tier only the names it may reach.
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

/// The HTTPS proxy that services with `hostnames` are reached through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyServer {
    /// Address the proxy listens on. Defaults to the WireGuard gateway
    /// address, like the DNS shim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<Ipv4Addr>,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
    /// Folder of PEM certificates the operator keeps current (Parallax never
    /// issues any). Every directory under it holding `fullchain.pem` and
    /// `privkey.pem` is one certificate, so certbot's `live/<name>` works.
    #[serde(default = "default_proxy_certificates")]
    pub certificates: PathBuf,
    /// CA bundle that upstream certificates are verified against.
    #[serde(default = "default_upstream_ca")]
    pub upstream_ca: PathBuf,
}

impl Default for ProxyServer {
    fn default() -> Self {
        ProxyServer {
            listen: None,
            port: default_proxy_port(),
            certificates: default_proxy_certificates(),
            upstream_ca: default_upstream_ca(),
        }
    }
}

fn default_proxy_port() -> u16 {
    8443
}
fn default_proxy_certificates() -> PathBuf {
    PathBuf::from("/etc/parallax/certs")
}
fn default_upstream_ca() -> PathBuf {
    PathBuf::from("/etc/ssl/certs/ca-certificates.crt")
}

/// Backups of everything Parallax keeps (`parallax backup`): the database and
/// the server's private key, in one file per backup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupServer {
    /// Where backups are written. Best on another disk than the database.
    #[serde(default = "default_backup_directory")]
    pub directory: PathBuf,
    /// Back up every `interval` when something changed. `parallax backup
    /// create` works either way.
    #[serde(default = "default_true")]
    pub automatic: bool,
    #[serde(default = "default_backup_interval")]
    pub interval: Interval,
    /// How many backups to keep; the oldest are deleted first.
    #[serde(default = "default_backup_keep")]
    pub keep: u32,
    /// Encrypt backups with the passphrase in `passphrase_file`.
    #[serde(default = "default_true")]
    pub encrypt: bool,
    /// 0600 file holding the backup passphrase (`parallax backup
    /// passphrase`). Never stored in the database, so no backup carries it.
    #[serde(default = "default_passphrase_file")]
    pub passphrase_file: PathBuf,
}

impl Default for BackupServer {
    fn default() -> Self {
        BackupServer {
            directory: default_backup_directory(),
            automatic: true,
            interval: default_backup_interval(),
            keep: default_backup_keep(),
            encrypt: true,
            passphrase_file: default_passphrase_file(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_backup_directory() -> PathBuf {
    PathBuf::from("/var/lib/parallax/backups")
}
fn default_backup_interval() -> Interval {
    Interval::from_secs(Interval::DAY)
}
fn default_backup_keep() -> u32 {
    14
}
fn default_passphrase_file() -> PathBuf {
    PathBuf::from("/etc/parallax/backup.passphrase")
}

/// A period of whole minutes, written `30m`, `6h` or `1d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Interval(u64);

impl Interval {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * Interval::MINUTE;
    const DAY: u64 = 24 * Interval::HOUR;

    /// `secs` should be a whole number of minutes, or it prints as seconds rounded down.
    pub const fn from_secs(secs: u64) -> Self {
        Interval(secs)
    }
    pub fn as_secs(self) -> u64 {
        self.0
    }
}

impl std::str::FromStr for Interval {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        let malformed = || crate::Error::Malformed {
            what: "interval",
            detail: format!("'{s}' is not a period like 30m, 6h or 1d"),
        };
        let s = s.trim();
        let (number, unit) = s.split_at(s.len().saturating_sub(1));
        let unit = match unit {
            "m" => Interval::MINUTE,
            "h" => Interval::HOUR,
            "d" => Interval::DAY,
            _ => return Err(malformed()),
        };
        let n: u64 = number.parse().map_err(|_| malformed())?;
        match n.checked_mul(unit) {
            Some(secs) if secs > 0 => Ok(Interval(secs)),
            _ => Err(malformed()),
        }
    }
}

impl TryFrom<String> for Interval {
    type Error = crate::Error;
    fn try_from(s: String) -> crate::Result<Self> {
        s.parse()
    }
}

impl From<Interval> for String {
    fn from(i: Interval) -> String {
        i.to_string()
    }
}

impl std::fmt::Display for Interval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.0;
        if secs.is_multiple_of(Interval::DAY) {
            write!(f, "{}d", secs / Interval::DAY)
        } else if secs.is_multiple_of(Interval::HOUR) {
            write!(f, "{}h", secs / Interval::HOUR)
        } else {
            write!(f, "{}m", secs / Interval::MINUTE)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_parse_and_print_in_their_largest_unit() {
        for (text, secs, shown) in [
            ("30m", 1800, "30m"),
            ("90m", 5400, "90m"),
            ("120m", 7200, "2h"),
            ("6h", 21_600, "6h"),
            ("48h", 172_800, "2d"),
            ("1d", 86_400, "1d"),
        ] {
            let i: Interval = text.parse().unwrap();
            assert_eq!(i.as_secs(), secs, "{text}");
            assert_eq!(i.to_string(), shown, "{text}");
        }
        for bad in [
            "",
            "0d",
            "1",
            "d",
            "1w",
            "-1h",
            "1.5h",
            "99999999999999999999d",
        ] {
            assert!(bad.parse::<Interval>().is_err(), "{bad}");
        }
    }
}
