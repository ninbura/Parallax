//! The running server: hickory's server handles UDP and TCP framing, EDNS
//! and truncation; this answers each query by the caller's tier, forwarding
//! through one caching resolver per zone (and one for public names).
//!
//! The routes live behind a lock. A reload swaps in a new state; a reload
//! that fails leaves none, and every query is refused until one succeeds,
//! rather than keep answering by grants that may have been revoked.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
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
use parallax_core::generate::dns::{DnsRoutes, Route};
use parallax_core::netmap::Mapping;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Notify;

use crate::{answer, Error, Result};

/// Time one upstream gets to answer. Clients usually retry after 5 seconds,
/// so a SERVFAIL comes back before they give up on us.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(2);
/// Idle time before a TCP client is dropped.
const TCP_TIMEOUT: Duration = Duration::from_secs(10);
/// Answers each resolver keeps (a small cache: the upstreams cache too).
const CACHE_SIZE: u64 = 1024;
/// Lookups one tunnel address may have in flight; more are refused, so one
/// peer can't flood the upstreams.
const MAX_PER_SOURCE: usize = 64;
/// Responses queued per TCP connection (hickory's default).
const TCP_QUEUE: usize = 32;

fn log(msg: impl std::fmt::Display) {
    eprintln!("parallax dns: {msg}");
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

fn load_state(routes_path: &Path, upstream_port: u16) -> Result<State> {
    let text = std::fs::read_to_string(routes_path)
        .map_err(|e| Error::io(format!("reading {}", routes_path.display()), e))?;
    let routes = DnsRoutes::from_toml(&text)?;
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

/// A loaded DNS server, ready to run on its sockets.
pub struct Dns {
    routes_path: PathBuf,
    upstream_port: u16,
    state: Arc<State>,
    reload: Arc<Notify>,
}

impl Dns {
    /// Read the routes. Upstreams are asked on `upstream_port` (53, except
    /// in tests).
    pub fn load(routes_path: &Path, upstream_port: u16) -> Result<Dns> {
        Ok(Dns {
            routes_path: routes_path.to_path_buf(),
            upstream_port,
            state: Arc::new(load_state(routes_path, upstream_port)?),
            reload: Arc::new(Notify::new()),
        })
    }

    /// The address the routes say to listen on.
    pub fn listen(&self) -> SocketAddrV4 {
        self.state.routes.listen
    }

    /// Notifying this re-reads the routes, like SIGHUP does.
    pub fn reload_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.reload)
    }

    /// Serve on `udp` and `tcp` until the process ends. SIGHUP re-reads the routes.
    pub async fn run(self, udp: UdpSocket, tcp: TcpListener) -> Result<()> {
        let local = udp
            .local_addr()
            .map_err(|e| Error::io("reading the listening address", e))?;
        log(format!(
            "listening on {local} (udp, tcp), {} zone(s), {} tier(s)",
            self.state.routes.zones.len(),
            self.state.routes.tiers.len()
        ));
        let shared: Shared = Arc::new(RwLock::new(Some(self.state)));
        // Before spawning: until a handler is installed, SIGHUP would kill the process.
        let hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(s) => Some(s),
            Err(e) => {
                log(format!("cannot watch SIGHUP, routes won't reload: {e}"));
                None
            }
        };
        tokio::spawn(reloader(
            self.routes_path,
            self.upstream_port,
            Arc::clone(&shared),
            self.reload,
            hangup,
        ));
        let mut server = Server::new(Handler {
            state: shared,
            inflight: Arc::default(),
        });
        server.register_socket(udp);
        server.register_listener(tcp, TCP_TIMEOUT, TCP_QUEUE);
        server
            .block_until_done()
            .await
            .map_err(|e| Error::dns(format!("serving on {local}"), e))
    }
}

/// Load the routes at `routes_path` and serve until the process ends.
pub fn serve(routes_path: &Path) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::io("starting the async runtime", e))?;
    runtime.block_on(async {
        let dns = Dns::load(routes_path, 53)?;
        let listen = dns.listen();
        let udp = UdpSocket::bind(listen)
            .await
            .map_err(|e| Error::io(format!("listening on udp {listen}"), e))?;
        let tcp = TcpListener::bind(listen)
            .await
            .map_err(|e| Error::io(format!("listening on tcp {listen}"), e))?;
        dns.run(udp, tcp).await
    })
}

async fn reloader(
    routes_path: PathBuf,
    upstream_port: u16,
    shared: Shared,
    reload: Arc<Notify>,
    mut hangup: Option<tokio::signal::unix::Signal>,
) {
    loop {
        tokio::select! {
            Some(()) = async {
                match hangup.as_mut() {
                    Some(h) => h.recv().await,
                    None => std::future::pending().await,
                }
            } => {}
            () = reload.notified() => {}
        }
        let next = match load_state(&routes_path, upstream_port) {
            Ok(state) => {
                log(format!(
                    "routes reloaded: {} zone(s), {} tier(s)",
                    state.routes.zones.len(),
                    state.routes.tiers.len()
                ));
                Some(Arc::new(state))
            }
            Err(e) => {
                log(format!(
                    "reload failed, refusing every query until one succeeds: {e}"
                ));
                None
            }
        };
        *shared.write().unwrap_or_else(|p| p.into_inner()) = next;
    }
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

struct Handler {
    state: Shared,
    inflight: Arc<Mutex<HashMap<Ipv4Addr, usize>>>,
}

fn reply(code: ResponseCode) -> (ResponseCode, Vec<Record>) {
    (code, Vec::new())
}

impl Handler {
    fn current(&self) -> Option<Arc<State>> {
        self.state.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The response code and answer records for `request`.
    async fn answer(&self, request: &Request) -> (ResponseCode, Vec<Record>) {
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
        let Some(state) = self.current() else {
            return reply(ResponseCode::Refused);
        };
        let asked = query.name().to_string();
        let (resolver, home, upstream) = match state.routes.route(client, &asked) {
            Route::Refused => return reply(ResponseCode::Refused),
            // No IPv6 through the tunnel: say the name has no AAAA.
            Route::Home(_) if qtype == RecordType::AAAA => return reply(ResponseCode::NoError),
            Route::Home(zone) => match state.home.get(&zone.name) {
                Some(r) => (r, true, format!("zone {} ({})", zone.name, zone.network)),
                None => return reply(ResponseCode::ServFail),
            },
            Route::Public => (
                &state.public,
                false,
                format!("public resolver {}", state.routes.public_resolver),
            ),
        };
        let Some(_slot) = Slot::take(&self.inflight, client) else {
            return reply(ResponseCode::Refused);
        };
        let mut name: Name = query.name().clone().into();
        name.set_fqdn(true);
        match resolver.lookup(name, qtype).await {
            Ok(lookup) => {
                let records = if home {
                    answer::home(lookup.answers(), &state.mappings)
                } else {
                    answer::public(lookup.answers())
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
        let (code, answers) = self.answer(request).await;
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.recursion_available = true;
        metadata.response_code = code;
        let mut builder = MessageResponseBuilder::from_message_request(request);
        // Echo EDNS so UDP answers may use the client's buffer size;
        // anything bigger is truncated and the client retries over TCP.
        let edns = request.edns.as_ref().map(|req| {
            let mut e = Edns::new();
            e.set_max_payload(req.max_payload().max(512));
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
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                log(format!("sending a response to {}: {e}", request.src()));
                metadata.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                })
            }
        }
    }
}
