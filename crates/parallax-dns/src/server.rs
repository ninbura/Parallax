//! The running server: hickory's server handles UDP and TCP framing, EDNS
//! and truncation; this answers each query by the caller's tier, forwarding
//! through one caching resolver per zone (and one for public names).
//!
//! The routes live behind a lock. The daemon hands new ones over a channel
//! ([`Reload`]); taking them swaps in a new state. Routes that fail to load
//! leave none, and every query is refused until good ones come, rather than
//! keep answering by grants that may have been revoked. Each query holds
//! the state it answers by until its reply is handed over, which is how a
//! reload knows the queries under older routes are done.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use hickory_server::net::runtime::{Time, TokioRuntimeProvider};
use hickory_server::net::{DnsError, NetError};
use hickory_server::proto::op::{
    Edns, Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode,
};
use hickory_server::proto::rr::{DNSClass, Name, Record, RecordType};
use hickory_server::resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_server::resolver::TokioResolver;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use hickory_server::Server;
use parallax_core::generate::dns::{DnsRoutes, DnsTier, Route};
use parallax_core::logging::{Event, Logged, Query, QueryOutcome, Tap};
use parallax_core::netmap::Mapping;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};

use crate::{answer, Error, Result};

/// Time one upstream gets to answer. Clients usually retry after 5 seconds,
/// so a SERVFAIL comes back before they give up on us.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// The most one query may take, all its upstreams and CNAMEs together: it
/// ends before a reload stops waiting for it, and before most clients retry.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(4);
/// How long a reload waits for queries under older routes to answer. Past
/// that, the reload isn't confirmed.
const DRAIN: Duration = Duration::from_secs(5);
/// Idle time before a TCP client is dropped.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);
/// Answers each resolver keeps (a small cache: the upstreams cache too).
const CACHE_SIZE: u64 = 1024;
/// Lookups one tunnel address may have in flight; more are refused, so one
/// peer can't flood the upstreams.
const MAX_PER_SOURCE: usize = 64;
/// Largest UDP answer, whatever the client offers.
const MAX_UDP_PAYLOAD: u16 = 1232;
/// Responses queued per TCP connection (hickory's default).
const TCP_QUEUE: usize = 32;

// Best effort: a log line nobody can read is dropped. `eprintln!` would panic
// the task, and the daemon stops the gateway when this server's task ends.
fn log(msg: impl std::fmt::Display) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "parallax dns: {msg}");
}

/// Everything a query needs, swapped whole on reload.
struct State {
    routes: DnsRoutes,
    mappings: Vec<Mapping>,
    /// One resolver per zone, by zone name.
    home: HashMap<String, TokioResolver>,
    public: TokioResolver,
}

/// `None`: the last reload failed, refuse everything.
type Shared = Arc<RwLock<Option<Arc<State>>>>;

fn resolver(upstreams: &[Ipv4Addr], port: u16) -> Result<TokioResolver> {
    let servers = upstreams
        .iter()
        .map(|ip| {
            let mut ns = NameServerConfig::udp_and_tcp(IpAddr::V4(*ip));
            for c in &mut ns.connections {
                c.port = port;
            }
            ns
        })
        .collect();
    // No domain or search list: every name is looked up as given.
    let config = ResolverConfig::from_parts(None, Vec::new(), servers);
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    let opts = builder.options_mut();
    opts.timeout = UPSTREAM_TIMEOUT;
    opts.attempts = 1;
    opts.cache_size = CACHE_SIZE;
    opts.use_hosts_file = ResolveHosts::Never;
    // Keep the CNAMEs between the name asked and the address.
    opts.preserve_intermediates = true;
    opts.try_tcp_on_error = true;
    builder
        .build()
        .map_err(|e| Error::dns(format!("setting up the resolver for {upstreams:?}"), e))
}

fn load_state(routes: DnsRoutes, upstream_port: u16) -> Result<State> {
    let mappings = routes.mapping_list()?;
    let mut home = HashMap::new();
    for zone in &routes.zones {
        home.insert(zone.name.clone(), resolver(&zone.upstream, upstream_port)?);
    }
    let public = resolver(&[routes.public_resolver], upstream_port)?;
    Ok(State {
        routes,
        mappings,
        home,
        public,
    })
}

/// Routes on their way to the server, and who to tell what came of them.
struct Handover {
    routes: DnsRoutes,
    loaded: oneshot::Sender<std::result::Result<(), String>>,
    checked: oneshot::Sender<bool>,
}

/// Hands a DNS server new routes ([`Dns::reloader`]).
#[derive(Debug, Clone)]
pub struct Reload(mpsc::UnboundedSender<Handover>);

impl Reload {
    /// Have the server answer by `routes`, and wait for the queries under
    /// older ones. The receiver gets whether every query under older routes
    /// had sent its reply in time, once the new routes are in force (or,
    /// routes that didn't load, once every query is refused), and an error
    /// if the server has stopped. Routes are put in force in the order sent,
    /// even once nobody waits for them.
    pub fn send(&self, routes: DnsRoutes) -> oneshot::Receiver<bool> {
        let (loaded, _) = oneshot::channel();
        let (checked, checked_rx) = oneshot::channel();
        // A stopped server drops `checked`, which the receiver reports.
        let _ = self.0.send(Handover {
            routes,
            loaded,
            checked,
        });
        checked_rx
    }

    /// [`Reload::send`] for routes nobody waits on older queries for: the
    /// server doesn't wait either. The receiver says whether they loaded.
    pub fn load(&self, routes: DnsRoutes) -> oneshot::Receiver<std::result::Result<(), String>> {
        let (loaded, loaded_rx) = oneshot::channel();
        // Closed before it's sent, so the reloader never starts a wait
        // that would hold up the next routes.
        let (checked, _) = oneshot::channel();
        let _ = self.0.send(Handover {
            routes,
            loaded,
            checked,
        });
        loaded_rx
    }
}

/// A loaded DNS server, ready to run on its sockets.
pub struct Dns {
    upstream_port: u16,
    state: Arc<State>,
    reload: Reload,
    reloads: mpsc::UnboundedReceiver<Handover>,
    tap: Option<Tap>,
}

impl Dns {
    /// Answer by `routes`. Upstreams are asked on `upstream_port` (53,
    /// except in tests).
    pub fn new(routes: DnsRoutes, upstream_port: u16) -> Result<Dns> {
        let (reload, reloads) = mpsc::unbounded_channel();
        Ok(Dns {
            upstream_port,
            state: Arc::new(load_state(routes, upstream_port)?),
            reload: Reload(reload),
            reloads,
            tap: None,
        })
    }

    /// Hand the queries of peers whose DNS is logged to `tap`
    /// (docs/logging.md): name, type and outcome, never the answer.
    pub fn tap(mut self, tap: Tap) -> Self {
        self.tap = Some(tap);
        self
    }

    /// The address the routes say to listen on.
    pub fn listen(&self) -> SocketAddrV4 {
        self.state.routes.listen
    }

    /// What hands this server new routes (the daemon does around each
    /// apply).
    pub fn reloader(&self) -> Reload {
        self.reload.clone()
    }

    /// Serve on `udp` and `tcp` until the task is dropped.
    pub async fn run(self, udp: UdpSocket, tcp: TcpListener) -> Result<()> {
        let local = udp
            .local_addr()
            .map_err(|e| Error::io("reading the listening address", e))?;
        log(format!(
            "listening on {local} (udp, tcp), {} zone(s), {} tier(s)",
            self.state.routes.zones.len(),
            self.state.routes.tiers.len()
        ));
        let listening = self.state.routes.listen;
        let shared: Shared = Arc::new(RwLock::new(Some(self.state)));
        // Part of this future, not a task of its own: once it's dropped, no
        // routes are confirmed.
        let reloading = reloader(
            listening,
            self.upstream_port,
            Arc::clone(&shared),
            self.reloads,
        );
        let mut server = Server::new(Handler {
            state: shared,
            inflight: Arc::default(),
            tap: self.tap,
            server: listening,
        });
        server.register_socket(udp);
        server.register_listener(tcp, TCP_TIMEOUT, TCP_QUEUE);
        let serving = server.block_until_done();
        tokio::pin!(serving, reloading);
        let done = tokio::select! {
            done = &mut serving => done,
            // Nobody can hand it routes anymore: serve on.
            () = &mut reloading => serving.await,
        };
        done.map_err(|e| Error::dns(format!("serving on {local}"), e))
    }
}

async fn reloader(
    listening: SocketAddrV4,
    upstream_port: u16,
    shared: Shared,
    mut reloads: mpsc::UnboundedReceiver<Handover>,
) {
    // Every state replaced that a query under way may still answer by.
    let mut replaced: Vec<Arc<State>> = Vec::new();
    while let Some(Handover {
        routes,
        loaded,
        checked,
    }) = reloads.recv().await
    {
        let (next, outcome) = match load_state(routes, upstream_port) {
            Ok(state) => {
                if state.routes.listen != listening {
                    log(format!(
                        "the routes now say to listen on {}, but the server stays on {listening}; restart Parallax to move",
                        state.routes.listen
                    ));
                }
                log(format!(
                    "routes reloaded: {} zone(s), {} tier(s)",
                    state.routes.zones.len(),
                    state.routes.tiers.len()
                ));
                (Some(Arc::new(state)), Ok(()))
            }
            Err(e) => {
                log(format!(
                    "reload failed, refusing every query until one succeeds: {e}"
                ));
                (None, Err(e.to_string()))
            }
        };
        let old = std::mem::replace(
            &mut *shared.write().unwrap_or_else(|p| p.into_inner()),
            next,
        );
        replaced.extend(old);
        let _ = loaded.send(outcome);
        // Queries that come in from now on take the new state. Those under
        // way still answer by an older one: whoever waits is told once
        // they've all sent their replies, since the address that asked may
        // belong to another peer next. Nobody waiting: the next wait covers
        // these too.
        if checked.is_closed() {
            replaced.retain(|s| Arc::strong_count(s) > 1);
        } else {
            let all = drained(&mut replaced, DRAIN).await;
            let _ = checked.send(all);
        }
    }
}

/// Wait until no query holds a state in `replaced`: each has sent its
/// reply. False if some still do after `cap`.
async fn drained(replaced: &mut Vec<Arc<State>>, cap: Duration) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        // Ours is the last reference once every query under it has replied.
        replaced.retain(|s| Arc::strong_count(s) > 1);
        if replaced.is_empty() {
            return true;
        }
        if start.elapsed() > cap {
            let held: usize = replaced.iter().map(|s| Arc::strong_count(s) - 1).sum();
            log(format!(
                "{held} queries still under older routes after {cap:?}"
            ));
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// What both `served` and `new` let each member look up, and alike: for
/// while an apply is under way, which can leave either configuration's
/// firewall and WireGuard peers live (or, failing partway, a mix). A member
/// keeps the zones both give it, the names both allow (by name or by their
/// whole zone), and public names if both do; a member only one of them has
/// gets nothing. So an address moving to another peer answers neither
/// owner's names beyond what both may see.
///
/// Answers are what both routes give alike, too: an address is rewritten
/// only by a mapping both have, and passed unchanged only where both leave
/// it unmapped. A zone only one of them has, or with other resolvers in
/// each, is nobody's: a name in it is refused, not sent to the public
/// resolver or a parent zone's resolvers. Public names need the same public
/// resolver in both.
pub fn overlap(served: &DnsRoutes, new: &DnsRoutes) -> DnsRoutes {
    fn allows(routes: &DnsRoutes, tier: &DnsTier, name: &str) -> bool {
        tier.names.iter().any(|n| n == name)
            || routes
                .zone_of(name)
                .is_some_and(|z| tier.zones.contains(&z.name))
    }
    // Both have it, with the same resolvers.
    let alike = |zone: &str| {
        let find = |r: &DnsRoutes| r.zones.iter().find(|z| z.name == zone).cloned();
        find(served).is_some_and(|z| Some(z) == find(new))
    };
    let mut out = DnsRoutes {
        listen: served.listen,
        public_resolver: served.public_resolver,
        unmapped: served
            .unmapped
            .iter()
            .filter(|n| new.unmapped.contains(n))
            .copied()
            .collect(),
        zones: served.zones.clone(),
        mappings: served
            .mappings
            .iter()
            .filter(|m| new.mappings.contains(m))
            .cloned()
            .collect(),
        tiers: Vec::new(),
    };
    // Kept, so a name in one stays out of a parent zone and public lookups.
    let added = new
        .zones
        .iter()
        .filter(|z| !served.zones.iter().any(|s| s.name == z.name));
    out.zones.extend(added.cloned());
    let same_public = served.public_resolver == new.public_resolver;
    for old in &served.tiers {
        for member in &old.members {
            let Some(next) = new.tiers.iter().find(|t| t.members.contains(member)) else {
                continue;
            };
            let zones: Vec<String> = old
                .zones
                .iter()
                .filter(|z| next.zones.contains(z) && alike(z))
                .cloned()
                .collect();
            let mut names: Vec<String> = Vec::new();
            for n in old.names.iter().chain(&next.names) {
                let Some(zone) = out.zone_of(n) else {
                    continue;
                };
                if allows(served, old, n)
                    && allows(new, next, n)
                    && alike(&zone.name)
                    && !zones.contains(&zone.name)
                    && !names.contains(n)
                {
                    names.push(n.clone());
                }
            }
            let public = old.public && next.public && same_public;
            let alike = |t: &&mut DnsTier| {
                t.tier == old.tier && t.zones == zones && t.names == names && t.public == public
            };
            match out.tiers.iter_mut().find(alike) {
                Some(tier) => tier.members.push(*member),
                None => out.tiers.push(DnsTier {
                    tier: old.tier.clone(),
                    members: vec![*member],
                    zones,
                    names,
                    public,
                }),
            }
        }
    }
    out
}

fn ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// One lookup in flight, counted against its source address.
struct Slot {
    counts: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
    client: Ipv4Addr,
}

impl Slot {
    fn take(counts: &Arc<Mutex<HashMap<Ipv4Addr, usize>>>, client: Ipv4Addr) -> Option<Slot> {
        let mut map = counts.lock().unwrap_or_else(|p| p.into_inner());
        let n = map.entry(client).or_insert(0);
        if *n >= MAX_PER_SOURCE {
            return None;
        }
        *n += 1;
        Some(Slot {
            counts: Arc::clone(counts),
            client,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut map = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = map.get_mut(&self.client) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.client);
            }
        }
    }
}

/// How an answer is filtered.
#[derive(Clone, Copy)]
enum Kind {
    Home { whole_zone: bool },
    Public,
}

struct Handler {
    state: Shared,
    inflight: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
    /// Where logged peers' queries go, if anywhere.
    tap: Option<Tap>,
    /// The address the server answers on, for the records.
    server: SocketAddrV4,
}

fn reply(code: ResponseCode) -> (ResponseCode, Vec<Record>) {
    (code, Vec::new())
}

impl Handler {
    fn current(&self) -> Option<Arc<State>> {
        self.state.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The peer that asked, if its queries are logged.
    fn admit(&self, request: &Request) -> Option<Logged> {
        let tap = self.tap.as_ref()?;
        let client = ipv4(request.request_info().ok()?.src.ip())?;
        tap.admit(client)
    }

    /// Hand the query to the tap for `logged`.
    fn record(&self, request: &Request, logged: Logged, code: ResponseCode) {
        let (Some(tap), Ok(info)) = (&self.tap, request.request_info()) else {
            return;
        };
        let Some(client) = ipv4(info.src.ip()) else {
            return;
        };
        let mut name: Name = info.query.name().clone().into();
        name.set_fqdn(true);
        let outcome = match code {
            ResponseCode::NoError => QueryOutcome::Answered,
            ResponseCode::Refused | ResponseCode::NotImp => QueryOutcome::Refused,
            ResponseCode::NXDomain => QueryOutcome::NxDomain,
            _ => QueryOutcome::Failed,
        };
        tap.send(Event::Query(Query {
            client,
            peer: logged.peer,
            server: self.server,
            protocol: if info.protocol.is_datagram() { 17 } else { 6 },
            name: name.to_ascii(),
            query_type: info.query.query_type().to_string(),
            outcome,
        }));
    }

    /// The response code and answer records for `request`, by `state`
    /// (`None`: refuse).
    async fn answer(
        &self,
        request: &Request,
        state: Option<&State>,
    ) -> (ResponseCode, Vec<Record>) {
        if request.metadata.message_type != MessageType::Query
            || request.metadata.op_code != OpCode::Query
        {
            return reply(ResponseCode::NotImp);
        }
        let Ok(info) = request.request_info() else {
            return reply(ResponseCode::FormErr);
        };
        let Some(client) = ipv4(info.src.ip()) else {
            return reply(ResponseCode::Refused);
        };
        let query = info.query;
        let qtype = query.query_type();
        // Zone transfers and ANY are never forwarded.
        if query.query_class() != DNSClass::IN
            || matches!(qtype, RecordType::AXFR | RecordType::IXFR | RecordType::ANY)
        {
            return reply(ResponseCode::Refused);
        }
        let Some(state) = state else {
            return reply(ResponseCode::Refused);
        };
        let mut name: Name = query.name().clone().into();
        name.set_fqdn(true);
        // ASCII (punycode), as the zones are written: displaying a `Name`
        // would turn `xn--` labels into Unicode and miss the zone.
        let asked = name.to_ascii();
        let (resolver, kind, upstream) = match state.routes.route(client, &asked) {
            Route::Refused => return reply(ResponseCode::Refused),
            // No IPv6 through the tunnel: say the name has no AAAA.
            Route::Home { .. } if qtype == RecordType::AAAA => return reply(ResponseCode::NoError),
            Route::Home { zone, whole_zone } => match state.home.get(&zone.name) {
                Some(r) => (
                    r,
                    Kind::Home { whole_zone },
                    format!("zone {} ({})", zone.name, zone.network),
                ),
                None => return reply(ResponseCode::ServFail),
            },
            Route::Public => (
                &state.public,
                Kind::Public,
                format!("public resolver {}", state.routes.public_resolver),
            ),
        };
        let Some(_slot) = Slot::take(&self.inflight, client) else {
            return reply(ResponseCode::Refused);
        };
        let Ok(found) =
            tokio::time::timeout(LOOKUP_TIMEOUT, resolver.lookup(name.clone(), qtype)).await
        else {
            log(format!(
                "{asked} {qtype} from {client}: {upstream} took over {} s",
                LOOKUP_TIMEOUT.as_secs()
            ));
            return reply(ResponseCode::ServFail);
        };
        match found {
            Ok(lookup) => {
                let records = match kind {
                    Kind::Home { whole_zone: true } => {
                        answer::home(lookup.answers(), &state.mappings, &state.routes.unmapped)
                    }
                    // A tier that may see only this name gets the addresses
                    // under it, not the CNAMEs that would name others.
                    Kind::Home { whole_zone: false } => answer::flatten(
                        answer::home(lookup.answers(), &state.mappings, &state.routes.unmapped),
                        &name,
                        qtype,
                    ),
                    Kind::Public => answer::public(lookup.answers()),
                };
                (ResponseCode::NoError, records)
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(none))) => reply(none.response_code),
            Err(e) => {
                log(format!(
                    "{asked} {qtype} from {client}: {upstream} failed: {e}"
                ));
                reply(ResponseCode::ServFail)
            }
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Only EDNS version 0 exists; anything newer gets BADVERS so the
        // client can fall back (RFC 6891).
        // Whether it's wanted is decided as the query comes in.
        let logged = self.admit(request);
        // Held until the reply is handed to hickory, which sends it next:
        // a reload waits for that, as the address may be another peer's
        // once it's confirmed.
        let state = self.current();
        let (code, answers) = match &request.edns {
            Some(e) if e.version() > 0 => reply(ResponseCode::BADVERS),
            _ => self.answer(request, state.as_deref()).await,
        };
        if let Some(logged) = logged {
            self.record(request, logged, code);
        }
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = code;
        let mut builder = MessageResponseBuilder::from_message_request(request);
        // Echo EDNS so UDP answers may use the client's buffer size, up to
        // 1232 bytes (DNS Flag Day 2020): bigger would fragment inside the
        // tunnel. Anything larger is truncated and the client retries over TCP.
        let edns = request.edns.as_ref().map(|req| {
            let mut e = Edns::new();
            e.set_max_payload(req.max_payload().clamp(512, MAX_UDP_PAYLOAD));
            e.set_version(0);
            e
        });
        if let Some(e) = &edns {
            builder.edns(e);
        }
        let response = builder.build(
            metadata,
            answers.iter(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );
        let sent = match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                log(format!("sending a response to {}: {e}", request.src()));
                metadata.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                })
            }
        };
        drop(state);
        sent
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests: failures should panic loudly")]

    use super::*;

    /// #108: a query that holds older routes past the cap fails the wait,
    /// rather than confirm a handover it hasn't finished.
    #[tokio::test]
    async fn a_drain_past_its_cap_is_not_confirmed() {
        let routes = DnsRoutes::from_toml(
            "listen = \"127.0.0.1:53\"\npublic_resolver = \"127.0.0.1\"\nunmapped = []\n",
        )
        .unwrap();
        let old = Arc::new(load_state(routes, 53).unwrap());
        let query = Arc::clone(&old);
        let mut replaced = vec![old];
        assert!(!drained(&mut replaced, Duration::from_millis(30)).await);
        assert_eq!(replaced.len(), 1);
        drop(query);
        assert!(drained(&mut replaced, Duration::from_millis(30)).await);
        assert!(replaced.is_empty());
    }
}
