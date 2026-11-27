//! Which peers' traffic the gateway logs, and how much (docs/logging.md).
//! The firewall marks the flows of logged peers and hands their blocked
//! attempts to the collector; nothing is marked or handed over for peers
//! at `off`, so logging nobody costs nothing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, RwLock};

use ipnet::Ipv4Net;

use crate::model::{LogLevel, LogsServer, Peer, TransportKind};
use crate::{Config, Error, Model, Result};

/// Whose level `parallax log level` sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `server.logs.level`.
    Global,
    Peer(String),
    Grant(String),
}

/// A setting `parallax log` changes: the global one, or a peer's or
/// grant's own.
enum Setting<'a> {
    Global(&'a mut LogsServer),
    Own {
        log: &'a mut Option<LogLevel>,
        log_dns: &'a mut Option<bool>,
    },
}

fn setting<'a>(config: &'a mut Config, target: &Target) -> Result<Setting<'a>> {
    let not_found = |kind: &'static str, name: &str| Error::NotFound {
        kind,
        name: name.to_string(),
    };
    Ok(match target {
        Target::Global => Setting::Global(&mut config.server.logs),
        Target::Peer(name) => {
            let p = config
                .peers
                .iter_mut()
                .find(|p| &p.name == name)
                .ok_or_else(|| not_found("peer", name))?;
            Setting::Own {
                log: &mut p.log,
                log_dns: &mut p.log_dns,
            }
        }
        Target::Grant(name) => {
            let g = config
                .grants
                .iter_mut()
                .find(|g| &g.name == name)
                .ok_or_else(|| not_found("grant", name))?;
            Setting::Own {
                log: &mut g.log,
                log_dns: &mut g.log_dns,
            }
        }
    })
}

/// Replace `slot` with `value`; true when that changed it.
fn put<T: PartialEq>(slot: &mut T, value: T) -> bool {
    let changed = *slot != value;
    *slot = value;
    changed
}

/// `inherit` for the global setting, which has nothing above it.
fn nothing_to_inherit(what: &'static str, global: &str, choices: &str) -> Error {
    Error::Malformed {
        what,
        detail: format!("the global {global} has nothing to inherit from; set {choices}"),
    }
}

/// Set a level, or with `None` clear a peer's or grant's own so it follows
/// the rest again. True when something changed.
pub fn set_level(config: &mut Config, target: &Target, level: Option<LogLevel>) -> Result<bool> {
    Ok(match setting(config, target)? {
        Setting::Global(logs) => {
            let level = level.ok_or_else(|| {
                nothing_to_inherit(
                    "log level",
                    "level (server.logs.level)",
                    "off, blocked, connections or detailed",
                )
            })?;
            put(&mut logs.level, level)
        }
        Setting::Own { log, .. } => put(log, level),
    })
}

/// Turn DNS query logging on or off, or with `None` clear a peer's or
/// grant's own so it follows the rest again. True when something changed.
pub fn set_dns(config: &mut Config, target: &Target, on: Option<bool>) -> Result<bool> {
    Ok(match setting(config, target)? {
        Setting::Global(logs) => {
            let on = on.ok_or_else(|| {
                nothing_to_inherit("DNS logging", "setting (server.logs.dns)", "on or off")
            })?;
            put(&mut logs.dns, on)
        }
        Setting::Own { log_dns, .. } => put(log_dns, on),
    })
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

/// Whether `peer`'s DNS queries are logged: its own `log_dns` if set,
/// otherwise on if any of its grants that set one turn it on, otherwise
/// `server.logs.dns`. The same precedence as [`level`]; no level implies it.
pub fn dns(config: &Config, peer: &Peer) -> bool {
    if let Some(own) = peer.log_dns {
        return own;
    }
    config
        .grants
        .iter()
        .filter(|g| g.everyone || peer.grants.contains(&g.name))
        .filter_map(|g| g.log_dns)
        .max()
        .unwrap_or(config.server.logs.dns)
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

/// The enabled WireGuard peers that `logged` picks, by tunnel address. From
/// the configuration alone; expired peers count, which only means listening
/// for traffic nobody sends.
fn logged_clients(config: &Config, logged: impl Fn(&Peer) -> bool) -> HashMap<Ipv4Addr, Logged> {
    config
        .peers
        .iter()
        .filter(|p| p.enabled && p.transport == TransportKind::WireGuard)
        .filter(|p| logged(p))
        .filter_map(|p| {
            let address = p.wireguard.as_ref().and_then(|w| w.address)?;
            let logged = Logged {
                peer: p.name.clone(),
                level: level(config, p),
            };
            Some((address, logged))
        })
        .collect()
}

/// The peers logged at `at_least` or more: whose requests the HTTPS proxy
/// hands over (at `blocked` and up).
pub fn level_clients(config: &Config, at_least: LogLevel) -> HashMap<Ipv4Addr, Logged> {
    logged_clients(config, |p| level(config, p) >= at_least)
}

/// The peers whose DNS queries are logged.
pub fn dns_clients(config: &Config) -> HashMap<Ipv4Addr, Logged> {
    logged_clients(config, |p| dns(config, p))
}

/// Whether some enabled WireGuard peer with an address is logged at
/// `at_least` or more: what the collector reads for.
pub fn configured(config: &Config, at_least: LogLevel) -> bool {
    !level_clients(config, at_least).is_empty()
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
    /// Where the peer sent it, from its connection-tracking entry: `dst` is
    /// after NETMAP. `None` when the kernel didn't say.
    pub addressed: Option<Ipv4Addr>,
}

/// A request the HTTPS proxy forwarded or refused, or a connection it
/// refused before reading any request. Never the URL path: that says what
/// someone did inside a service, not only which one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub client: Ipv4Addr,
    /// The peer the client was when the request came in.
    pub peer: String,
    /// The site the peer asked for (the TLS server name), if it named one.
    pub hostname: Option<String>,
    /// The site's upstream, when the hostname is a configured site.
    pub upstream: Option<SocketAddrV4>,
    /// None for a connection refused before a request was read.
    pub method: Option<String>,
    pub status: Option<u16>,
    /// Why the proxy refused it; none when it was forwarded.
    pub refused: Option<&'static str>,
    /// Bytes of the request's body and of the response's.
    pub bytes: Option<(u64, u64)>,
}

/// A DNS query the gateway's DNS server answered, as the peer asked it.
/// Never the addresses in the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub client: Ipv4Addr,
    /// The peer the client was when the query came in.
    pub peer: String,
    /// The DNS server's address.
    pub server: Ipv4Addr,
    pub protocol: u8,
    pub name: String,
    /// `A`, `AAAA`, `HTTPS` and so on.
    pub query_type: String,
    pub outcome: QueryOutcome,
}

/// How the DNS server answered a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryOutcome {
    /// With addresses or without (a name that has no `AAAA`, say).
    Answered,
    /// The peer's tier may not look the name up, or the query isn't one
    /// the server answers.
    Refused,
    /// The name doesn't exist.
    NxDomain,
    /// The upstream failed or the query was malformed.
    Failed,
}

impl QueryOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            QueryOutcome::Answered => "answered",
            QueryOutcome::Refused => "refused",
            QueryOutcome::NxDomain => "nxdomain",
            QueryOutcome::Failed => "failed",
        }
    }
}

/// What the collector hears: from the kernel, the HTTPS proxy and the DNS
/// server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Opened(Flow),
    Closed(Flow),
    Blocked(Blocked),
    Request(Request),
    Query(Query),
}

/// A peer a tap wants, as it was when its request or query came in: its
/// events are recorded for this peer or not at all, so an address that
/// passed to another peer meanwhile can't move them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logged {
    pub peer: String,
    pub level: LogLevel,
}

/// Where the HTTPS proxy and the DNS server hand over what logged peers do.
/// Only callers in its set are handed over, so with nobody logged nothing
/// is; a full queue drops (and counts) rather than slow anyone down.
#[derive(Debug, Clone)]
pub struct Tap {
    tx: SyncSender<Event>,
    clients: Arc<RwLock<HashMap<Ipv4Addr, Logged>>>,
    dropped: Arc<AtomicU64>,
}

impl Tap {
    /// A tap and the end its events come out of, holding up to `capacity`.
    pub fn new(capacity: usize) -> (Tap, Receiver<Event>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        let tap = Tap {
            tx,
            clients: Arc::default(),
            dropped: Arc::default(),
        };
        (tap, rx)
    }

    /// The peer `client` is, if what it does is wanted.
    pub fn admit(&self, client: Ipv4Addr) -> Option<Logged> {
        self.clients
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&client)
            .cloned()
    }

    /// Hand `event` over, or count it as dropped if the queue is full.
    pub fn send(&self, event: Event) {
        if let Err(TrySendError::Full(_)) = self.tx.try_send(event) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Whose events are wanted from now on.
    pub fn set_clients(&self, clients: HashMap<Ipv4Addr, Logged>) {
        *self.clients.write().unwrap_or_else(|p| p.into_inner()) = clients;
    }

    /// Events dropped since the last call.
    pub fn take_dropped(&self) -> u64 {
        self.dropped.swap(0, Ordering::Relaxed)
    }
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
    /// The site a proxied request was for, or the name a DNS query asked.
    pub hostname: Option<String>,
    /// A proxied request's method and the status it was answered with.
    pub method: Option<String>,
    pub status: Option<u16>,
    /// A DNS query's type.
    pub query_type: Option<String>,
    /// How a DNS query was answered, or why the proxy refused.
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Opened,
    Closed,
    /// Blocked on its way through the gateway.
    Blocked,
    /// Blocked on its way to the gateway host itself.
    BlockedGateway,
    /// A request the HTTPS proxy forwarded.
    Request,
    /// A connection or request the HTTPS proxy refused.
    Refused,
    /// A DNS query.
    Query,
}

impl RecordKind {
    pub const ALL: [RecordKind; 7] = [
        RecordKind::Opened,
        RecordKind::Closed,
        RecordKind::Blocked,
        RecordKind::BlockedGateway,
        RecordKind::Request,
        RecordKind::Refused,
        RecordKind::Query,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Opened => "opened",
            RecordKind::Closed => "closed",
            RecordKind::Blocked => "blocked",
            RecordKind::BlockedGateway => "blocked_gateway",
            RecordKind::Request => "request",
            RecordKind::Refused => "refused",
            RecordKind::Query => "query",
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
                detail: format!(
                    "'{s}' is not one of {}",
                    RecordKind::ALL.map(RecordKind::as_str).join(", ")
                ),
            })
    }
}

/// The peer each open flow was recorded for, so a flow's end is never put
/// down to another peer that has since taken its address (a removed peer's
/// connections can outlive it by days, and the next peer added gets its
/// address).
#[derive(Debug, Default)]
pub struct OpenFlows(std::collections::HashMap<u32, String>);

impl OpenFlows {
    /// Past this many open flows (closes lost while the collector was
    /// behind), start over rather than grow without bound.
    const MAX: usize = 1 << 18;

    /// `record` is what [`attribute`] made of `event`: kept, or dropped
    /// when it ends a flow that began as another peer's.
    pub fn settle(&mut self, event: &Event, record: Option<Record>) -> Option<Record> {
        match event {
            Event::Opened(f) => {
                if let Some(r) = &record {
                    if self.0.len() >= Self::MAX {
                        self.0.clear();
                    }
                    self.0.insert(f.id, r.peer.clone());
                }
                record
            }
            Event::Closed(f) => match (self.0.remove(&f.id), record) {
                (Some(began), Some(r)) if began != r.peer => None,
                (_, record) => record,
            },
            Event::Blocked(_) | Event::Request(_) | Event::Query(_) => record,
        }
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
/// not from a peer, or more than the peer's level covers (or, for a DNS
/// query, its queries aren't logged). The firewall already marks only
/// logged peers' flows, and the proxy and DNS server hand over only logged
/// peers'; this checks again against the configuration now, which may have
/// changed since.
pub fn attribute(config: &Config, event: &Event, time: u64) -> Option<Record> {
    let marked = |f: &Flow| f.mark & crate::generate::firewall::FLOW_MARK != 0;
    let src = match event {
        Event::Opened(f) | Event::Closed(f) if !marked(f) => return None,
        Event::Opened(f) | Event::Closed(f) => f.src,
        Event::Blocked(b) => b.src,
        Event::Request(r) => r.client,
        Event::Query(q) => q.client,
    };
    let peer = config.peers.iter().find(|p| {
        p.transport == TransportKind::WireGuard
            && p.wireguard.as_ref().and_then(|w| w.address) == Some(src)
    })?;
    // Another peer has the address since the request or query came in.
    let admitted = match event {
        Event::Request(r) => Some(&r.peer),
        Event::Query(q) => Some(&q.peer),
        _ => None,
    };
    if admitted.is_some_and(|name| *name != peer.name) {
        return None;
    }
    let level = level(config, peer);
    let wanted = match event {
        Event::Opened(_) => level >= LogLevel::Connections,
        // A flow's end says only its bytes: below `detailed` there's nothing
        // to record (and half the writes saved).
        Event::Closed(_) => level >= LogLevel::Detailed,
        Event::Blocked(_) => level >= LogLevel::Blocked,
        Event::Request(r) if r.refused.is_some() => level >= LogLevel::Blocked,
        Event::Request(_) => level >= LogLevel::Connections,
        Event::Query(_) => dns(config, peer),
    };
    if !wanted {
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
        hostname: None,
        method: None,
        status: None,
        query_type: None,
        outcome: None,
    };
    // HTTPS to a proxied service is redirected to the proxy before NETMAP,
    // so the proxy answers.
    let proxy = config
        .server
        .proxy
        .listen
        .unwrap_or_else(|| config.server.wireguard.gateway_address());
    Some(match event {
        Event::Opened(f) | Event::Closed(f) => {
            // The real host is the one the peer's mapped address stands for.
            let answered_by = if f.answered_by == proxy && f.dst != proxy {
                config
                    .networks
                    .iter()
                    .find_map(|n| n.mapping().and_then(|m| m.to_real(f.dst)))
                    .unwrap_or(f.dst)
            } else {
                f.answered_by
            };
            let real = (answered_by != f.dst).then_some(answered_by);
            let closed = matches!(event, Event::Closed(_));
            let kind = if closed {
                RecordKind::Closed
            } else {
                RecordKind::Opened
            };
            let mut r = record(kind, f.dst, real, f.protocol, f.port);
            r.flow = Some(f.id);
            if closed {
                if let Some((out, back)) = f.bytes {
                    r.bytes_out = Some(out);
                    r.bytes_in = Some(back);
                }
            }
            r
        }
        // The firewall sees a blocked packet after NETMAP. What the peer
        // addressed comes from the packet's conntrack entry; without it,
        // only what was seen.
        Event::Blocked(b) => {
            let kind = if b.to_gateway {
                RecordKind::BlockedGateway
            } else {
                RecordKind::Blocked
            };
            let addressed = b.addressed.unwrap_or(b.dst);
            let real = (addressed != b.dst).then_some(b.dst);
            record(kind, addressed, real, b.protocol, b.port)
        }
        // The proxy can't see where the peer sent the connection, only the
        // site it named: a site's upstream as the peer reaches it (mapped
        // when its network is), and for a name that's no site, the proxy.
        Event::Request(q) => {
            let (destination, real, port) = match q.upstream {
                Some(up) => {
                    let real = *up.ip();
                    let mapped = config
                        .networks
                        .iter()
                        .find_map(|n| n.mapping().and_then(|m| m.to_virtual(real)))
                        .unwrap_or(real);
                    (mapped, (mapped != real).then_some(real), up.port())
                }
                None => (proxy, None, crate::generate::proxy::HTTPS),
            };
            let kind = if q.refused.is_some() {
                RecordKind::Refused
            } else {
                RecordKind::Request
            };
            let mut r = record(kind, destination, real, 6, Some(port));
            r.hostname = q.hostname.clone();
            r.method = q.method.clone();
            r.status = q.status;
            r.outcome = q.refused.map(str::to_string);
            if let (Some((out, back)), LogLevel::Detailed) = (q.bytes, level) {
                r.bytes_out = Some(out);
                r.bytes_in = Some(back);
            }
            r
        }
        Event::Query(q) => {
            let mut r = record(RecordKind::Query, q.server, None, q.protocol, Some(53));
            r.network = None;
            r.hostname = Some(q.name.clone());
            r.query_type = Some(q.query_type.clone());
            r.outcome = Some(q.outcome.as_str().to_string());
            r
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
            log: Some(LogLevel::Blocked),
            log_dns: None,
            rules: Vec::new(),
        });
        assert_eq!(level(&cfg, &peer), LogLevel::Blocked, "grant for everyone");

        peer.log = Some(LogLevel::Detailed);
        assert_eq!(level(&cfg, &peer), LogLevel::Detailed, "its own");
    }

    #[test]
    fn a_flow_s_end_never_goes_to_the_next_owner_of_its_address() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Detailed;
        let mark = crate::generate::firewall::FLOW_MARK;
        let mut open = OpenFlows::default();
        let opened = Event::Opened(flow([10, 8, 2, 1], mark));
        let closed = Event::Closed(flow([10, 8, 2, 1], mark));
        let r = open.settle(&opened, attribute(&cfg, &opened, 1));
        assert_eq!(r.unwrap().peer, "sister-phone");
        // sister-phone is gone; another peer has its address now.
        cfg.peers[2].name = "new-tablet".into();
        assert!(open.settle(&closed, attribute(&cfg, &closed, 2)).is_none());
        // A close the collector saw no start of is kept.
        let r = open.settle(&closed, attribute(&cfg, &closed, 3));
        assert_eq!(r.unwrap().peer, "new-tablet");
    }

    #[test]
    fn levels_are_set_and_cleared_by_name() {
        let mut cfg = canonical_config();
        let peer = Target::Peer("sister-phone".into());
        assert!(set_level(&mut cfg, &peer, Some(LogLevel::Detailed)).unwrap());
        assert!(!set_level(&mut cfg, &peer, Some(LogLevel::Detailed)).unwrap());
        assert_eq!(
            cfg.peer("sister-phone").unwrap().log,
            Some(LogLevel::Detailed)
        );
        assert!(set_level(&mut cfg, &peer, None).unwrap());
        assert_eq!(cfg.peer("sister-phone").unwrap().log, None);

        let grant = Target::Grant("family".into());
        assert!(set_level(&mut cfg, &grant, Some(LogLevel::Blocked)).unwrap());
        assert_eq!(cfg.grant("family").unwrap().log, Some(LogLevel::Blocked));
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

        // A flow's end only at `detailed`.
        let closed = Event::Closed(flow([10, 8, 2, 1], mark));
        assert!(attribute(&cfg, &closed, 2000).is_none());
        cfg.server.logs.level = LogLevel::Detailed;
        let r = attribute(&cfg, &closed, 2000).unwrap();
        assert_eq!((r.bytes_out, r.bytes_in), (Some(1200), Some(34_000)));

        // A connection isn't kept below `connections`.
        let mut quiet = cfg.clone();
        quiet.server.logs.level = LogLevel::Blocked;
        assert!(attribute(&quiet, &Event::Opened(flow([10, 8, 2, 1], mark)), 1).is_none());

        // Unmarked flows, unknown sources and peers at `off` give nothing.
        assert!(attribute(&cfg, &Event::Opened(flow([10, 8, 2, 1], 0x1)), 1).is_none());
        assert!(attribute(&cfg, &Event::Opened(flow([10, 8, 9, 9], mark)), 1).is_none());
        cfg.peers[2].log = Some(LogLevel::Off);
        assert!(attribute(&cfg, &closed, 1).is_none());
    }

    #[test]
    fn a_proxied_flow_records_the_host_behind_the_proxy() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        let proxy = cfg.server.wireguard.gateway_address();
        let mut f = flow([10, 8, 2, 1], crate::generate::firewall::FLOW_MARK);
        f.port = Some(443);
        f.answered_by = proxy;
        let r = attribute(&cfg, &Event::Opened(f), 1).unwrap();
        assert_eq!(r.destination, Ipv4Addr::new(198, 18, 1, 5));
        assert_eq!(r.real_destination, Some(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(r.network.as_deref(), Some("home"));
    }

    #[test]
    fn blocked_packets_give_where_they_were_sent_and_need_the_blocked_level() {
        let mut cfg = canonical_config();
        let mut b = Blocked {
            protocol: 17,
            src: Ipv4Addr::new(10, 8, 2, 1),
            dst: Ipv4Addr::new(192, 168, 1, 9),
            port: Some(53),
            to_gateway: false,
            addressed: Some(Ipv4Addr::new(198, 18, 1, 9)),
        };
        let blocked = Event::Blocked(b.clone());
        cfg.server.logs.level = LogLevel::Off;
        assert!(attribute(&cfg, &blocked, 1).is_none());
        cfg.server.logs.level = LogLevel::Blocked;
        let r = attribute(&cfg, &blocked, 1).unwrap();
        assert_eq!(r.kind, RecordKind::Blocked);
        assert_eq!(r.destination, Ipv4Addr::new(198, 18, 1, 9));
        assert_eq!(r.real_destination, Some(Ipv4Addr::new(192, 168, 1, 9)));
        assert_eq!(r.protocol, "udp");
        // Without the conntrack entry, only what was seen: never a guess.
        b.addressed = None;
        let r = attribute(&cfg, &Event::Blocked(b), 1).unwrap();
        assert_eq!(r.destination, Ipv4Addr::new(192, 168, 1, 9));
        assert_eq!(r.real_destination, None);
    }

    /// Levels survive TOML (import, export, `config edit`). The daemon's
    /// socket reads through the same form (its test is in the CLI).
    fn request(refused: Option<&'static str>) -> Request {
        Request {
            client: Ipv4Addr::new(10, 8, 2, 1),
            peer: "sister-phone".into(),
            hostname: Some("immich.example.com".into()),
            upstream: Some("192.168.1.5:443".parse().unwrap()),
            method: Some("GET".into()),
            status: Some(if refused.is_some() { 421 } else { 200 }),
            refused,
            bytes: Some((0, 4096)),
        }
    }

    #[test]
    fn proxied_requests_need_connections_and_refusals_blocked() {
        let mut cfg = canonical_config();
        let ok = Event::Request(request(None));
        let refused = Event::Request(request(Some("this connection serves a different hostname")));
        cfg.server.logs.level = LogLevel::Blocked;
        assert!(attribute(&cfg, &ok, 1).is_none());
        let r = attribute(&cfg, &refused, 1).unwrap();
        assert_eq!(r.kind, RecordKind::Refused);
        assert_eq!(r.status, Some(421));
        assert_eq!(
            r.outcome.as_deref(),
            Some("this connection serves a different hostname")
        );

        cfg.server.logs.level = LogLevel::Connections;
        let r = attribute(&cfg, &ok, 1).unwrap();
        assert_eq!(r.kind, RecordKind::Request);
        assert_eq!(r.peer, "sister-phone");
        assert_eq!(r.hostname.as_deref(), Some("immich.example.com"));
        assert_eq!((r.method.as_deref(), r.status), (Some("GET"), Some(200)));
        // As the peer reached it: the mapped address, then the real one.
        assert_eq!(r.destination, Ipv4Addr::new(198, 18, 1, 5));
        assert_eq!(r.real_destination, Some(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!((r.protocol.as_str(), r.port), ("tcp", Some(443)));
        assert_eq!(r.network.as_deref(), Some("home"));
        assert_eq!((r.bytes_out, r.bytes_in), (None, None), "bytes at detailed");

        cfg.server.logs.level = LogLevel::Detailed;
        let r = attribute(&cfg, &ok, 1).unwrap();
        assert_eq!((r.bytes_out, r.bytes_in), (Some(0), Some(4096)));
    }

    #[test]
    fn a_name_that_is_no_site_is_recorded_at_the_proxy() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Blocked;
        let event = Event::Request(Request {
            hostname: Some("router.example.com".into()),
            upstream: None,
            method: None,
            status: None,
            bytes: None,
            ..request(Some("no site for this hostname"))
        });
        let r = attribute(&cfg, &event, 1).unwrap();
        assert_eq!(r.kind, RecordKind::Refused);
        assert_eq!(r.destination, cfg.server.wireguard.gateway_address());
        assert_eq!(r.real_destination, None);
        assert_eq!(r.port, Some(443));
    }

    fn query() -> Event {
        Event::Query(Query {
            client: Ipv4Addr::new(10, 8, 2, 1),
            peer: "sister-phone".into(),
            server: Ipv4Addr::new(10, 8, 0, 1),
            protocol: 17,
            name: "immich.example.com.".into(),
            query_type: "A".into(),
            outcome: QueryOutcome::Answered,
        })
    }

    #[test]
    fn a_request_or_query_stays_with_the_peer_it_came_in_as() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        cfg.server.logs.dns = true;
        let moved = Request {
            peer: "a-removed-peer".into(),
            ..request(None)
        };
        assert!(attribute(&cfg, &Event::Request(moved), 1).is_none());
        let Event::Query(mut q) = query() else {
            unreachable!()
        };
        q.peer = "a-removed-peer".into();
        assert!(attribute(&cfg, &Event::Query(q), 1).is_none());
    }

    #[test]
    fn dns_queries_are_their_own_opt_in() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Detailed;
        assert!(
            attribute(&cfg, &query(), 1).is_none(),
            "no level implies it"
        );
        cfg.server.logs.dns = true;
        cfg.server.logs.level = LogLevel::Off;
        let r = attribute(&cfg, &query(), 1).unwrap();
        assert_eq!(r.kind, RecordKind::Query);
        assert_eq!(r.hostname.as_deref(), Some("immich.example.com."));
        assert_eq!(r.query_type.as_deref(), Some("A"));
        assert_eq!(r.outcome.as_deref(), Some("answered"));
        assert_eq!((r.protocol.as_str(), r.port), ("udp", Some(53)));
        assert_eq!(r.destination, Ipv4Addr::new(10, 8, 0, 1));
        assert_eq!(r.network, None);
    }

    #[test]
    fn a_peer_s_own_dns_setting_wins_then_any_grant_then_the_global_one() {
        let mut cfg = canonical_config();
        let mut peer = cfg.peers[1].clone();
        peer.grants = vec!["family".into()];
        assert!(!dns(&cfg, &peer), "off by default");
        cfg.server.logs.dns = true;
        assert!(dns(&cfg, &peer), "the global setting");
        let family = cfg.grants.iter().position(|g| g.name == "family").unwrap();
        cfg.grants[family].log_dns = Some(false);
        assert!(!dns(&cfg, &peer), "its grant");
        cfg.grants.push(Grant {
            name: "watched".into(),
            everyone: true,
            log: None,
            log_dns: Some(true),
            rules: Vec::new(),
        });
        assert!(dns(&cfg, &peer), "any grant that turns it on");
        peer.log_dns = Some(false);
        assert!(!dns(&cfg, &peer), "its own");
    }

    #[test]
    fn dns_logging_is_set_and_cleared_by_name() {
        let mut cfg = canonical_config();
        let peer = Target::Peer("sister-phone".into());
        assert!(set_dns(&mut cfg, &peer, Some(true)).unwrap());
        assert!(!set_dns(&mut cfg, &peer, Some(true)).unwrap(), "unchanged");
        assert_eq!(cfg.peer("sister-phone").unwrap().log_dns, Some(true));
        assert!(set_dns(&mut cfg, &peer, None).unwrap());
        assert!(set_dns(&mut cfg, &Target::Grant("family".into()), Some(true)).unwrap());
        assert!(set_dns(&mut cfg, &Target::Global, Some(true)).unwrap());
        assert!(cfg.server.logs.dns);
        let e = set_dns(&mut cfg, &Target::Global, None).unwrap_err();
        assert!(e.to_string().contains("nothing to inherit"), "{e}");
        let e = set_dns(&mut cfg, &Target::Peer("nobody".into()), Some(true)).unwrap_err();
        assert!(e.to_string().contains("nobody"), "{e}");
        // The level is untouched.
        assert_eq!(cfg.server.logs.level, LogLevel::Off);
    }

    #[test]
    fn a_tap_hands_over_only_the_peers_it_wants_and_counts_what_it_drops() {
        let (tap, events) = Tap::new(1);
        let sister = Ipv4Addr::new(10, 8, 2, 1);
        assert_eq!(tap.admit(sister), None, "nobody to begin with");
        let mut cfg = canonical_config();
        cfg.server.logs.dns = true;
        tap.set_clients(dns_clients(&cfg));
        assert_eq!(
            tap.admit(sister),
            Some(Logged {
                peer: "sister-phone".into(),
                level: LogLevel::Off
            })
        );
        tap.send(query());
        tap.send(query());
        assert_eq!(events.try_iter().count(), 1);
        assert_eq!(tap.take_dropped(), 1);
        assert_eq!(tap.take_dropped(), 0);
        cfg.peers.iter_mut().for_each(|p| p.enabled = false);
        assert!(dns_clients(&cfg).is_empty(), "disabled peers aren't wanted");
    }

    #[test]
    fn levels_survive_toml() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        cfg.grants[1].log = Some(LogLevel::Blocked);
        cfg.peers[0].log = Some(LogLevel::Off);
        let toml = cfg.to_toml().unwrap();
        assert_eq!(Config::from_toml(&toml).unwrap(), cfg);
    }

    #[test]
    fn nobody_is_logged_by_default() {
        let cfg = canonical_config();
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(!any(&model, LogLevel::Blocked));
        assert!(addresses(&model, LogLevel::Blocked).is_empty());
    }
}
