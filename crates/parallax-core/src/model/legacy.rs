//! The configuration as TOML may still spell it: `[[template]]` entries and
//! `peer.template`, from before grants replaced templates (ADR 0010). They
//! convert on read, keeping the same access:
//!
//! - each template becomes a grant of the same name with its rules, plus
//!   `public_dns` when it had `dns.public`;
//! - each of its peers gets that grant and copies the template's client
//!   settings (`dns.wireguard`, `client`, `visible_networks`). Addresses stay
//!   as they are; pools and the Headscale identity are dropped;
//! - `dns.tailscale` becomes `server.headscale.dns` when every template
//!   agrees, `split` otherwise.
//!
//! Export always writes the current format.

use ipnet::Ipv4Net;
use serde::Deserialize;

use super::{
    AllowedIpsStrategy, Config, DnsMode, Grant, Network, Peer, Rule, ServerConfig, Service,
    TailscalePeer, TransportKind, WireGuardPeer,
};
use crate::date::Date;

/// Everything a configuration file may hold, old spellings included.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConfigToml {
    server: ServerConfig,
    #[serde(default)]
    network: Vec<Network>,
    #[serde(default)]
    service: Vec<Service>,
    #[serde(default)]
    grant: Vec<Grant>,
    #[serde(default)]
    template: Vec<Template>,
    #[serde(default)]
    peer: Vec<PeerToml>,
}

/// A template as it was written.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Template {
    name: String,
    #[allow(dead_code, reason = "read so old files parse; pools are gone")]
    wireguard: WireGuardTemplate,
    #[allow(dead_code, reason = "read so old files parse; unused before M2")]
    headscale: HeadscaleIdentity,
    #[serde(default)]
    grants: Vec<Rule>,
    #[serde(default)]
    visible_networks: Option<Vec<String>>,
    #[serde(default)]
    dns: DnsPolicy,
    #[serde(default)]
    client: ClientDefaults,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGuardTemplate {
    #[allow(dead_code, reason = "read so old files parse")]
    pool: Ipv4Net,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeadscaleIdentity {
    #[allow(dead_code, reason = "read so old files parse")]
    user: Option<String>,
    #[allow(dead_code, reason = "read so old files parse")]
    tag: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DnsPolicy {
    #[serde(default)]
    wireguard: DnsMode,
    #[serde(default)]
    tailscale: DnsMode,
    #[serde(default)]
    public: bool,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientDefaults {
    #[serde(default)]
    allowed_ips: AllowedIpsStrategy,
    mtu: Option<u16>,
    persistent_keepalive: Option<u16>,
}

/// A peer, with `template` or `grants`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerToml {
    name: String,
    template: Option<String>,
    grants: Option<Vec<String>>,
    log: Option<super::LogLevel>,
    log_dns: Option<bool>,
    transport: TransportKind,
    #[serde(default = "default_true")]
    enabled: bool,
    expires: Option<Date>,
    wireguard: Option<WireGuardPeer>,
    tailscale: Option<TailscalePeer>,
}

fn default_true() -> bool {
    true
}

impl TryFrom<ConfigToml> for Config {
    type Error = String;
    fn try_from(c: ConfigToml) -> Result<Self, String> {
        let mut server = c.server;
        let mut grants = c.grant;
        for t in &c.template {
            if grants.iter().any(|g| g.name == t.name) {
                return Err(format!(
                    "template '{}' converts to a grant of the same name, which already exists; rename one",
                    t.name
                ));
            }
            let mut rules = t.grants.clone();
            if t.dns.public {
                rules.push(Rule::PublicDns);
            }
            grants.push(Grant {
                name: t.name.clone(),
                everyone: false,
                log: None,
                log_dns: None,
                rules,
            });
        }
        if let Some(first) = c.template.first() {
            let mode = first.dns.tailscale;
            server.headscale.dns = if c.template.iter().all(|t| t.dns.tailscale == mode) {
                mode
            } else {
                DnsMode::Split
            };
        }
        let mut peers = Vec::with_capacity(c.peer.len());
        for p in c.peer {
            let mut wireguard = p.wireguard;
            let grants = match (p.template, p.grants) {
                (Some(_), Some(_)) => {
                    return Err(format!(
                        "peer '{}' has both template and grants; templates are now grants, so give only grants",
                        p.name
                    ))
                }
                (None, grants) => grants.unwrap_or_default(),
                (Some(name), None) => {
                    // Not a grant of that name: it would bind silently,
                    // with none of the template's client settings.
                    let t = c.template.iter().find(|t| t.name == name).ok_or_else(|| {
                        format!(
                            "peer '{}' has template '{name}', which isn't defined; give it grants = [...] instead",
                            p.name
                        )
                    })?;
                    if let Some(w) = wireguard.as_mut() {
                        w.dns = t.dns.wireguard;
                        w.allowed_ips = t.client.allowed_ips;
                        w.mtu = t.client.mtu;
                        w.persistent_keepalive = t.client.persistent_keepalive;
                        w.visible_networks = t.visible_networks.clone();
                    }
                    vec![name]
                }
            };
            peers.push(Peer {
                name: p.name,
                grants,
                log: p.log,
                log_dns: p.log_dns,
                transport: p.transport,
                enabled: p.enabled,
                expires: p.expires,
                wireguard,
                tailscale: p.tailscale,
            });
        }
        Ok(Config {
            server,
            networks: c.network,
            services: c.service,
            grants,
            peers,
        })
    }
}
