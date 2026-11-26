//! Which peers' traffic the gateway logs, and how much (docs/logging.md).
//! The firewall marks the flows of logged peers and hands their blocked
//! attempts to the collector; nothing is marked or handed over for peers
//! at `off`, so logging nobody costs nothing.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::{LogLevel, Peer, TransportKind};
use crate::{Config, Error, Model, Result};

/// Whose level `parallax log level` sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `server.logs.level`.
    Global,
    Peer(String),
    Grant(String),
}

/// Set a level, or with `None` clear a peer's or grant's own so it follows
/// the rest again. True when something changed.
pub fn set_level(config: &mut Config, target: &Target, level: Option<LogLevel>) -> Result<bool> {
    let not_found = |kind: &'static str, name: &str| Error::NotFound {
        kind,
        name: name.to_string(),
    };
    let slot = match target {
        Target::Global => {
            let Some(level) = level else {
                return Err(Error::Malformed {
                    what: "log level",
                    detail: "the global level (server.logs.level) has nothing to inherit from; \
                             set off, connections, bytes or denied"
                        .into(),
                });
            };
            let changed = config.server.logs.level != level;
            config.server.logs.level = level;
            return Ok(changed);
        }
        Target::Peer(name) => {
            &mut config
                .peers
                .iter_mut()
                .find(|p| &p.name == name)
                .ok_or_else(|| not_found("peer", name))?
                .log
        }
        Target::Grant(name) => {
            &mut config
                .grants
                .iter_mut()
                .find(|g| &g.name == name)
                .ok_or_else(|| not_found("grant", name))?
                .log
        }
    };
    let changed = *slot != level;
    *slot = level;
    Ok(changed)
}

/// The level that applies to `peer`: its own `log` if set, otherwise the
/// most detailed `log` among its grants (grants for everyone included),
/// otherwise `server.logs.level`.
pub fn level(config: &Config, peer: &Peer) -> LogLevel {
    if let Some(own) = peer.log {
        return own;
    }
    config
        .grants
        .iter()
        .filter(|g| g.everyone || peer.grants.contains(&g.name))
        .filter_map(|g| g.log)
        .max()
        .unwrap_or(config.server.logs.level)
}

/// Tunnel addresses of the active WireGuard peers logged at `at_least` or
/// more, sorted. Tailscale nodes join in M2, when their addresses come from
/// Headscale.
pub fn addresses(model: &Model<'_>, at_least: LogLevel) -> Vec<Ipv4Net> {
    let mut out: Vec<Ipv4Net> = model
        .peers_on(TransportKind::WireGuard)
        .filter(|p| level(model.config(), p) >= at_least)
        .filter_map(|p| p.wireguard.as_ref().and_then(|w| w.address))
        .map(Ipv4Net::from)
        .collect();
    out.sort();
    out
}

/// Whether some enabled WireGuard peer with an address is logged at
/// `at_least` or more: what the collector reads for. From the
/// configuration alone; expired peers count, which only means reading
/// events nobody's marked.
pub fn configured(config: &Config, at_least: LogLevel) -> bool {
    config.peers.iter().any(|p| {
        p.enabled
            && p.transport == TransportKind::WireGuard
            && p.wireguard.as_ref().and_then(|w| w.address).is_some()
            && level(config, p) >= at_least
    })
}

/// Whether some peer the firewall can mark is logged at `at_least` or
/// more (the same peers as [`addresses`]).
pub fn any(model: &Model<'_>, at_least: LogLevel) -> bool {
    !addresses(model, at_least).is_empty()
}

/// A connection as the kernel's connection tracking reports it, as the
/// peer sent it (`src` to `dst`) and as it was answered (`answered_by`:
/// the real address after the gateway's NETMAP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flow {
    /// Connection tracking's id: the same for a flow's start and end.
    pub id: u32,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub answered_by: Ipv4Addr,
    /// Destination port (TCP, UDP, SCTP); none for ICMP and the like.
    pub port: Option<u16>,
    pub mark: u32,
    /// Bytes from the peer and to it, when the kernel counts them.
    pub bytes: Option<(u64, u64)>,
}

/// A packet the firewall blocked, as nflog hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub port: Option<u16>,
    /// Bound for the gateway host itself, not forwarded.
    pub to_gateway: bool,
}

/// What the collector hears from the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Opened(Flow),
    Closed(Flow),
    Blocked(Blocked),
}

/// One stored activity record. Names are kept as they were, so the
/// history survives renames and removals.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Unix milliseconds.
    pub time: u64,
    pub kind: RecordKind,
    pub peer: String,
    /// The grants the peer had then, comma-separated.
    pub grants: String,
    pub source: Ipv4Addr,
    /// As the peer addressed it (a mapped address for a home host).
    pub destination: Ipv4Addr,
    /// The real address, when the gateway translated it.
    pub real_destination: Option<Ipv4Addr>,
    /// The configured network the real destination is on.
    pub network: Option<String>,
    pub protocol: String,
    pub port: Option<u16>,
    /// Connection tracking's id, joining a flow's start and end.
    pub flow: Option<u32>,
    pub bytes_out: Option<u64>,
    pub bytes_in: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Opened,
    Closed,
    /// Blocked on its way through the gateway.
    Denied,
    /// Blocked on its way to the gateway host itself.
    DeniedGateway,
}

impl RecordKind {
    pub const ALL: [RecordKind; 4] = [
        RecordKind::Opened,
        RecordKind::Closed,
        RecordKind::Denied,
        RecordKind::DeniedGateway,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Opened => "opened",
            RecordKind::Closed => "closed",
            RecordKind::Denied => "denied",
            RecordKind::DeniedGateway => "denied_gateway",
        }
    }
}

impl std::str::FromStr for RecordKind {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        RecordKind::ALL
            .into_iter()
            .find(|k| k.as_str() == s)
            .ok_or_else(|| Error::Malformed {
                what: "record kind",
                detail: format!("'{s}' is not one of opened, closed, denied, denied_gateway"),
            })
    }
}

/// `6` → `tcp`; others by number.
pub fn protocol_name(protocol: u8) -> String {
    match protocol {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        132 => "sctp".into(),
        n => n.to_string(),
    }
}

/// The record for `event` at `time`, or none when it isn't one to keep:
/// not from a peer, or more than the peer's level covers. The firewall
/// already marks only logged peers' flows; this checks again against the
/// configuration now, which may have changed since.
pub fn attribute(config: &Config, event: &Event, time: u64) -> Option<Record> {
    let (src, needed) = match event {
        Event::Opened(f) | Event::Closed(f) => {
            if f.mark & crate::generate::firewall::FLOW_MARK == 0 {
                return None;
            }
            (f.src, LogLevel::Connections)
        }
        Event::Blocked(b) => (b.src, LogLevel::Denied),
    };
    let peer = config
        .peers
        .iter()
        .find(|p| p.wireguard.as_ref().and_then(|w| w.address) == Some(src))?;
    let level = level(config, peer);
    if level < needed {
        return None;
    }
    let grants = crate::tier::grant_names(config, peer).join(",");
    let network_of = |ip: Ipv4Addr| {
        config
            .networks
            .iter()
            .find(|n| n.subnet.contains(&ip))
            .map(|n| n.name.clone())
    };
    let record = |kind, destination, real: Option<Ipv4Addr>, protocol: u8, port| Record {
        time,
        kind,
        peer: peer.name.clone(),
        grants: grants.clone(),
        source: src,
        destination,
        network: network_of(real.unwrap_or(destination)),
        real_destination: real,
        protocol: protocol_name(protocol),
        port,
        flow: None,
        bytes_out: None,
        bytes_in: None,
    };
    Some(match event {
        Event::Opened(f) | Event::Closed(f) => {
            let real = (f.answered_by != f.dst).then_some(f.answered_by);
            let closed = matches!(event, Event::Closed(_));
            let kind = if closed {
                RecordKind::Closed
            } else {
                RecordKind::Opened
            };
            let mut r = record(kind, f.dst, real, f.protocol, f.port);
            r.flow = Some(f.id);
            if closed && level >= LogLevel::Bytes {
                if let Some((out, back)) = f.bytes {
                    r.bytes_out = Some(out);
                    r.bytes_in = Some(back);
                }
            }
            r
        }
        // The firewall sees a blocked packet after NETMAP, so its
        // destination is already the real one: map it back to what the peer
        // addressed.
        Event::Blocked(b) => {
            let kind = if b.to_gateway {
                RecordKind::DeniedGateway
            } else {
                RecordKind::Denied
            };
            let addressed = config
                .networks
                .iter()
                .find(|n| n.subnet.contains(&b.dst))
                .map(|n| n.to_client_addr(b.dst))
                .unwrap_or(b.dst);
            let real = (addressed != b.dst).then_some(b.dst);
            record(kind, addressed, real, b.protocol, b.port)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Grant;
    use crate::testing::{canonical_config, today};

    #[test]
    fn a_peer_s_own_level_wins_then_its_grants_then_the_global_one() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        let peer = cfg.peers[1].clone();
        assert_eq!(level(&cfg, &peer), LogLevel::Connections, "global");

        // The most detailed of its grants', even below the global level.
        let family = cfg
            .grants
            .iter_mut()
            .position(|g| g.name == "family")
            .unwrap();
        cfg.grants[family].log = Some(LogLevel::Off);
        let mut peer = cfg.peers[1].clone();
        peer.grants = vec!["family".into()];
        assert_eq!(level(&cfg, &peer), LogLevel::Off, "its grant");
        cfg.grants.push(Grant {
            name: "watched".into(),
            everyone: true,
            log: Some(LogLevel::Denied),
            rules: Vec::new(),
        });
        assert_eq!(level(&cfg, &peer), LogLevel::Denied, "grant for everyone");

        peer.log = Some(LogLevel::Bytes);
        assert_eq!(level(&cfg, &peer), LogLevel::Bytes, "its own");
    }

    #[test]
    fn levels_are_set_and_cleared_by_name() {
        let mut cfg = canonical_config();
        let peer = Target::Peer("sister-phone".into());
        assert!(set_level(&mut cfg, &peer, Some(LogLevel::Bytes)).unwrap());
        assert!(!set_level(&mut cfg, &peer, Some(LogLevel::Bytes)).unwrap());
        assert_eq!(cfg.peer("sister-phone").unwrap().log, Some(LogLevel::Bytes));
        assert!(set_level(&mut cfg, &peer, None).unwrap());
        assert_eq!(cfg.peer("sister-phone").unwrap().log, None);

        let grant = Target::Grant("family".into());
        assert!(set_level(&mut cfg, &grant, Some(LogLevel::Denied)).unwrap());
        assert_eq!(cfg.grant("family").unwrap().log, Some(LogLevel::Denied));
        assert!(set_level(&mut cfg, &Target::Global, Some(LogLevel::Connections)).unwrap());
        assert_eq!(cfg.server.logs.level, LogLevel::Connections);

        let err = set_level(&mut cfg, &Target::Global, None).unwrap_err();
        assert!(err.to_string().contains("nothing to inherit"), "{err}");
        let err = set_level(&mut cfg, &Target::Peer("nobody".into()), None).unwrap_err();
        assert!(err.to_string().contains("nobody"), "{err}");
    }

    fn flow(src: [u8; 4], mark: u32) -> Flow {
        Flow {
            id: 7,
            protocol: 6,
            src: Ipv4Addr::from(src),
            dst: Ipv4Addr::new(198, 18, 1, 5),
            answered_by: Ipv4Addr::new(192, 168, 1, 5),
            port: Some(2283),
            mark,
            bytes: Some((1200, 34_000)),
        }
    }

    #[test]
    fn flows_are_attributed_to_their_peer_with_both_destinations() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        let mark = crate::generate::firewall::FLOW_MARK | 0x1;
        // sister-phone, 10.8.2.1
        let r = attribute(&cfg, &Event::Opened(flow([10, 8, 2, 1], mark)), 1000).unwrap();
        assert_eq!(r.peer, "sister-phone");
        assert_eq!(r.grants, "family");
        assert_eq!(r.kind, RecordKind::Opened);
        assert_eq!(r.destination, Ipv4Addr::new(198, 18, 1, 5));
        assert_eq!(r.real_destination, Some(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(r.network.as_deref(), Some("home"));
        assert_eq!(
            (r.protocol.as_str(), r.port, r.flow),
            ("tcp", Some(2283), Some(7))
        );

        // Bytes only at `bytes` and up.
        let closed = Event::Closed(flow([10, 8, 2, 1], mark));
        assert_eq!(attribute(&cfg, &closed, 2000).unwrap().bytes_out, None);
        cfg.server.logs.level = LogLevel::Bytes;
        let r = attribute(&cfg, &closed, 2000).unwrap();
        assert_eq!((r.bytes_out, r.bytes_in), (Some(1200), Some(34_000)));

        // Unmarked flows, unknown sources and peers at `off` give nothing.
        assert!(attribute(&cfg, &Event::Opened(flow([10, 8, 2, 1], 0x1)), 1).is_none());
        assert!(attribute(&cfg, &Event::Opened(flow([10, 8, 9, 9], mark)), 1).is_none());
        cfg.peers[2].log = Some(LogLevel::Off);
        assert!(attribute(&cfg, &closed, 1).is_none());
    }

    #[test]
    fn blocked_packets_are_mapped_back_and_need_the_denied_level() {
        let mut cfg = canonical_config();
        let blocked = Event::Blocked(Blocked {
            protocol: 17,
            src: Ipv4Addr::new(10, 8, 2, 1),
            dst: Ipv4Addr::new(192, 168, 1, 9),
            port: Some(53),
            to_gateway: false,
        });
        cfg.server.logs.level = LogLevel::Bytes;
        assert!(attribute(&cfg, &blocked, 1).is_none());
        cfg.server.logs.level = LogLevel::Denied;
        let r = attribute(&cfg, &blocked, 1).unwrap();
        assert_eq!(r.kind, RecordKind::Denied);
        assert_eq!(r.destination, Ipv4Addr::new(198, 18, 1, 9));
        assert_eq!(r.real_destination, Some(Ipv4Addr::new(192, 168, 1, 9)));
        assert_eq!(r.protocol, "udp");
    }

    /// Levels survive TOML (import, export, `config edit`). The daemon's
    /// socket reads through the same form (its test is in the CLI).
    #[test]
    fn levels_survive_toml() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        cfg.grants[1].log = Some(LogLevel::Denied);
        cfg.peers[0].log = Some(LogLevel::Off);
        let toml = cfg.to_toml().unwrap();
        assert_eq!(Config::from_toml(&toml).unwrap(), cfg);
    }

    #[test]
    fn nobody_is_logged_by_default() {
        let cfg = canonical_config();
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(!any(&model, LogLevel::Connections));
        assert!(addresses(&model, LogLevel::Connections).is_empty());
    }
}
