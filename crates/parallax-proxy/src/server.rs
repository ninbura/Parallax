//! The running proxy: accept, pick the site from SNI before any certificate
//! is sent, check the caller's tunnel address, then serve HTTP/1.1 or HTTP/2
//! and forward each checked request to the site's upstream over TLS.
//!
//! The routes live in a `watch` channel. New routes ([`Reload`]) become a
//! new state; every request looks its site up in the current one, and open
//! connections and WebSocket relays re-check theirs on every change, so
//! revoking a grant cuts off connections that were already open.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body as _, Frame, Incoming, SizeHint};
use hyper::header::UPGRADE;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use parallax_core::generate::proxy::{ProxyRoutes, ProxySite};
use parallax_core::logging::{self, Event, Logged, Tap};
use parallax_core::model::LogLevel;
use rustls::server::Acceptor;
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;

use crate::{certs, http, Error, Result};

/// Time allowed for a TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for HTTP/1 request headers, idle time between requests included.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// HTTP/2 pings, so connections to vanished peers don't linger.
const KEEPALIVE: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// Concurrent requests on one HTTP/2 connection; each may open an upstream
/// connection, so this bounds what one connection can fan out to.
const MAX_STREAMS: u32 = 100;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the certificate folder is checked for renewals.
const CERT_REFRESH: Duration = Duration::from_secs(60);
/// How long open connections may take to check new routes before a reload
/// goes unconfirmed (the daemon then stops the apply).
const DRAIN: Duration = Duration::from_secs(5);
/// Open connections one tunnel address may hold. Browsers open about six per
/// site over HTTP/1.1 and one over HTTP/2; this bounds what one peer can
/// take from everyone else.
const MAX_PER_SOURCE: usize = 64;
/// The longest method a request's record keeps. A client can send an
/// extension method of any length (hyper reads up to its ~400 KiB buffer),
/// and one guest's records mustn't grow with it (#65).
const LOGGED_METHOD: usize = 32;

/// Boxed, so a response can end in an error of the proxy's own: one cut
/// off mid-body must not look complete to the peer.
type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;
type Upstream = Client<HttpsConnector<HttpConnector<FixedResolver>>, Body>;

// Best effort: a log line nobody can read is dropped. `eprintln!` would panic
// the task, and the daemon stops the gateway when this server's task ends.
fn log(msg: impl std::fmt::Display) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "parallax proxy: {msg}");
}

/// Resolves every name to the site's configured upstream: the proxy never
/// looks up a client-supplied name.
#[derive(Clone)]
struct FixedResolver(SocketAddr);

impl tower_service::Service<Name> for FixedResolver {
    type Response = std::iter::Once<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<std::io::Result<Self::Response>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Name) -> Self::Future {
        std::future::ready(Ok(std::iter::once(self.0)))
    }
}

struct Site {
    route: ProxySite,
    /// `None` when no usable certificate covers the hostname: refused.
    tls: Option<Arc<ServerConfig>>,
    upstream: Upstream,
}

/// Everything a connection needs, swapped whole on reload.
struct State {
    routes: ProxyRoutes,
    sites: HashMap<String, Arc<Site>>,
    certs_fingerprint: u64,
}

impl State {
    /// The site for `hostname`, if `client` may use it right now.
    fn authorized(&self, hostname: &str, client: Ipv4Addr) -> Option<&Arc<Site>> {
        self.sites
            .get(hostname)
            .filter(|site| site.route.allows(client))
    }
}

type Shared = watch::Receiver<Arc<State>>;

/// Routes on their way to the proxy, and who to tell what came of them.
struct Handover {
    routes: ProxyRoutes,
    loaded: oneshot::Sender<std::result::Result<(), String>>,
    checked: oneshot::Sender<bool>,
}

/// Hands a proxy new routes ([`Proxy::reloader`]).
#[derive(Debug, Clone)]
pub struct Reload(mpsc::UnboundedSender<Handover>);

/// What a proxy says about routes it was handed ([`Reload::send`]). Either
/// receiver gets an error if the proxy has stopped.
#[derive(Debug)]
pub struct Taking {
    /// Once they're in force: `Ok` when they loaded, or why they didn't,
    /// in which case the proxy refuses every connection until some do.
    pub loaded: oneshot::Receiver<std::result::Result<(), String>>,
    /// Once they're in force, whether every open connection has checked
    /// them in time (`false` when some still held older routes after a few
    /// seconds). Drop it when nobody waits: the proxy then doesn't wait
    /// either.
    pub checked: oneshot::Receiver<bool>,
}

impl Reload {
    /// Have the proxy serve `routes`. Routes are put in force in the order
    /// sent, each one whatever came of the one before.
    pub fn send(&self, routes: ProxyRoutes) -> Taking {
        let (loaded, loaded_rx) = oneshot::channel();
        let (checked, checked_rx) = oneshot::channel();
        // A stopped proxy drops the senders, which the receivers report.
        let _ = self.0.send(Handover {
            routes,
            loaded,
            checked,
        });
        Taking {
            loaded: loaded_rx,
            checked: checked_rx,
        }
    }

    /// [`Reload::send`] for routes nobody waits on open connections for:
    /// the proxy doesn't wait either. The receiver says whether they loaded.
    pub fn load(&self, routes: ProxyRoutes) -> oneshot::Receiver<std::result::Result<(), String>> {
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

/// A loaded proxy, ready to run on a listener.
pub struct Proxy {
    state: Arc<State>,
    refresh: Duration,
    reload: Reload,
    reloads: mpsc::UnboundedReceiver<Handover>,
    tap: Option<Tap>,
}

impl Proxy {
    /// Load `routes`: the CA bundle and the certificates they name.
    pub fn new(routes: ProxyRoutes) -> Result<Proxy> {
        let (reload, reloads) = mpsc::unbounded_channel();
        Ok(Proxy {
            state: Arc::new(load_state(routes)?),
            refresh: CERT_REFRESH,
            reload: Reload(reload),
            reloads,
            tap: None,
        })
    }

    /// Hand what logged peers do to `tap` (docs/logging.md): each request
    /// and refusal, never a URL path.
    pub fn tap(mut self, tap: Tap) -> Self {
        self.tap = Some(tap);
        self
    }

    /// The address the routes say to listen on.
    pub fn listen(&self) -> SocketAddrV4 {
        self.state.routes.listen
    }

    /// Check the certificate folder this often instead of every minute.
    pub fn refresh_every(mut self, every: Duration) -> Self {
        self.refresh = every;
        self
    }

    /// What hands this proxy new routes (the daemon does around each apply).
    pub fn reloader(&self) -> Reload {
        self.reload.clone()
    }

    /// Serve on `listener` until the task is dropped.
    pub async fn run(self, listener: TcpListener) -> Result<()> {
        let local = listener
            .local_addr()
            .map_err(|e| Error::io("reading the listening address", e))?;
        log(format!(
            "listening on {local}, {} site(s)",
            self.state.sites.len()
        ));
        let (tx, rx) = watch::channel(self.state);
        // Part of this future, not a task of its own: once it's dropped, no
        // routes are confirmed.
        let reloading = reloader(tx, self.refresh, self.reloads);
        tokio::pin!(reloading);
        let counts: Arc<Mutex<HashMap<Ipv4Addr, usize>>> = Arc::default();
        loop {
            let accepted = tokio::select! {
                () = &mut reloading => return Ok(()),
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, peer)) => {
                    let Some(client) = ipv4(peer.ip()) else {
                        continue;
                    };
                    let Some(slot) = Slot::take(&counts, client) else {
                        log(format!(
                            "{client}: refused, already {MAX_PER_SOURCE} open connections"
                        ));
                        refused_connection(
                            self.tap.as_ref(),
                            client,
                            None,
                            None,
                            "too many open connections",
                        );
                        continue;
                    };
                    let tap = self.tap.clone();
                    tokio::spawn(handle(stream, client, rx.clone(), slot, tap));
                }
                Err(e) => {
                    // Usually out of file descriptors; back off rather than spin.
                    log(format!("accept failed: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

fn ipv4(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    }
}

/// One open connection counted against its source address.
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

fn load_state(routes: ProxyRoutes) -> Result<State> {
    let (tls, certs_fingerprint) = server_configs(&routes);
    let mut sites = HashMap::new();
    // With no sites there is nothing to verify, and no CA bundle is needed.
    if !routes.sites.is_empty() {
        let client_tls = ClientConfig::builder_with_provider(certs::provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::invalid("setting up upstream TLS", e))?
            .with_root_certificates(certs::upstream_roots(&routes.upstream_ca)?)
            .with_no_client_auth();
        for route in &routes.sites {
            let site = Site {
                route: route.clone(),
                tls: tls.get(&route.hostname).cloned().flatten(),
                upstream: upstream_client(route.upstream, client_tls.clone()),
            };
            sites.insert(route.hostname.clone(), Arc::new(site));
        }
    }
    Ok(State {
        routes,
        sites,
        certs_fingerprint,
    })
}

fn upstream_client(upstream: SocketAddrV4, tls: ClientConfig) -> Upstream {
    let mut http = HttpConnector::new_with_resolver(FixedResolver(SocketAddr::V4(upstream)));
    http.enforce_http(false);
    http.set_connect_timeout(Some(CONNECT_TIMEOUT));
    // HTTP/1.1 upstream: nginx always speaks it, and WebSocket upgrades need it.
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new()).build(https)
}

/// A server TLS config per hostname (`None` where no usable certificate
/// covers it), plus the fingerprint of the folder they came from.
fn server_configs(routes: &ProxyRoutes) -> (HashMap<String, Option<Arc<ServerConfig>>>, u64) {
    let fingerprint = certs::fingerprint(&routes.certificates);
    let mut out = HashMap::new();
    if routes.sites.is_empty() {
        return (out, fingerprint);
    }
    let found = match certs::scan(&routes.certificates) {
        Ok((found, problems)) => {
            for p in problems {
                log(p);
            }
            found
        }
        Err(e) => {
            log(e);
            Vec::new()
        }
    };
    for site in &routes.sites {
        let config = match certs::select(&found, &site.hostname) {
            Ok((_, config)) => Some(config),
            Err(why) => {
                log(format!("{why}; refusing it until one does"));
                None
            }
        };
        out.insert(site.hostname.clone(), config);
    }
    (out, fingerprint)
}

/// Runs as long as the proxy does.
async fn reloader(
    tx: watch::Sender<Arc<State>>,
    refresh: Duration,
    mut reloads: mpsc::UnboundedReceiver<Handover>,
) {
    let mut tick = tokio::time::interval(refresh);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    // Every state replaced that an open connection may still answer to, by
    // reloads and certificate renewals alike.
    let mut replaced: Vec<Arc<State>> = Vec::new();
    let mut open = true;
    loop {
        tokio::select! {
            handover = reloads.recv(), if open => {
                // Nobody can send routes any more: the last ones stay, and
                // certificates are still renewed.
                let Some(Handover { routes, loaded, checked }) = handover else {
                    open = false;
                    continue;
                };
                // Put in force even when nobody waits any more: the daemon
                // counts on routes being taken in the order sent (#103).
                let (old, outcome) = reload(routes, &tx);
                replaced.push(old);
                let _ = loaded.send(outcome);
                // Not confirmed until then: the daemon changes the firewall
                // next. Nobody waiting: the next confirmation waits for
                // these too.
                if !checked.is_closed() {
                    let all = drained(&mut replaced).await;
                    let _ = checked.send(all);
                }
            }
            _ = tick.tick() => {
                let before = Arc::clone(&tx.borrow());
                refresh_certificates(&tx);
                if !Arc::ptr_eq(&before, &tx.borrow()) {
                    replaced.push(before);
                }
            }
        }
        replaced.retain(|s| Arc::strong_count(s) > 1);
    }
}

/// Wait until no open connection answers to any state in `replaced` any
/// more: each has checked the current routes, or closed. False if some
/// still do after [`DRAIN`].
async fn drained(replaced: &mut Vec<Arc<State>>) -> bool {
    let start = tokio::time::Instant::now();
    loop {
        // Ours is the last reference once every connection has moved on.
        replaced.retain(|s| Arc::strong_count(s) > 1);
        if replaced.is_empty() {
            return true;
        }
        if start.elapsed() > DRAIN {
            let held: usize = replaced.iter().map(|s| Arc::strong_count(s) - 1).sum();
            log(format!(
                "{held} connection(s) still on older routes after {} s",
                DRAIN.as_secs()
            ));
            return false;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

/// Serve `routes`. When they don't load, refuse everything until some do:
/// the old routes may grant what the new configuration takes away. Returns
/// the routes they replaced, and why they didn't load.
fn reload(
    routes: ProxyRoutes,
    tx: &watch::Sender<Arc<State>>,
) -> (Arc<State>, std::result::Result<(), String>) {
    let old = Arc::clone(&tx.borrow());
    match load_state(routes) {
        Ok(state) => {
            if state.routes.listen != old.routes.listen {
                log(format!(
                    "the listen address changed to {}; restart Parallax to use it",
                    state.routes.listen
                ));
            }
            log(format!("routes reloaded, {} site(s)", state.sites.len()));
            tx.send_replace(Arc::new(state));
            (old, Ok(()))
        }
        Err(e) => {
            log(format!(
                "reload failed, refusing every connection until one succeeds: {e}"
            ));
            tx.send_replace(Arc::new(State {
                routes: old.routes.clone(),
                sites: HashMap::new(),
                certs_fingerprint: old.certs_fingerprint,
            }));
            (old, Err(e.to_string()))
        }
    }
}

/// Pick up renewed certificates. A renewal caught halfway (certbot swaps the
/// chain and the key one after the other) or a folder that can't be read
/// keeps the working certificate, and the next tick tries again.
fn refresh_certificates(tx: &watch::Sender<Arc<State>>) {
    let old = Arc::clone(&tx.borrow());
    let dir = &old.routes.certificates;
    let fingerprint = certs::fingerprint(dir);
    if old.sites.is_empty() || fingerprint == old.certs_fingerprint {
        return;
    }
    let found = match certs::scan(dir) {
        Ok((found, _)) => found,
        Err(e) => {
            log(format!("{e}; keeping the current certificates"));
            return;
        }
    };
    let mut settled = true;
    let mut sites = HashMap::new();
    for (name, site) in &old.sites {
        let tls = match certs::select(&found, name) {
            Ok((_, config)) => Some(config),
            Err(why) if site.tls.is_some() => {
                log(format!("{why}; keeping the current one for now"));
                settled = false;
                site.tls.clone()
            }
            Err(_) => None,
        };
        let site = Site {
            route: site.route.clone(),
            tls,
            upstream: site.upstream.clone(),
        };
        sites.insert(name.clone(), Arc::new(site));
    }
    if settled {
        log("certificates changed, reloaded");
    }
    tx.send_replace(Arc::new(State {
        routes: old.routes.clone(),
        sites,
        // Unsettled: stay on the old fingerprint so the next tick retries.
        certs_fingerprint: if settled {
            fingerprint
        } else {
            old.certs_fingerprint
        },
    }));
}

/// Drive `work` until it ends (its output) or `client` loses `hostname` in
/// a reload, or, for work with `upstream`, the hostname moves elsewhere, or
/// the proxy stops (`None`). Checked against the current routes first, and
/// again on every change before `work` goes on. The routes last checked are
/// held meanwhile: a reload is confirmed only once no connection holds the
/// ones it replaced ([`drained`]).
async fn while_authorized<F: Future>(
    work: F,
    mut state: Shared,
    hostname: &str,
    client: Ipv4Addr,
    upstream: Option<SocketAddrV4>,
) -> Option<F::Output> {
    // Declared before `work` so it's dropped after it: the routes checked
    // are held until the connection or relay has closed (#115).
    let mut checked: Option<Arc<State>> = None;
    tokio::pin!(work);
    loop {
        let now = Arc::clone(&state.borrow_and_update());
        if !checked.as_ref().is_some_and(|c| Arc::ptr_eq(c, &now)) {
            let still = now
                .authorized(hostname, client)
                .is_some_and(|site| upstream.is_none_or(|u| site.route.upstream == u));
            if !still {
                log(format!(
                    "{client}: {hostname}: access revoked or moved, closing"
                ));
                return None;
            }
            checked = Some(now);
        }
        tokio::select! {
            biased;
            changed = state.changed() => {
                if changed.is_err() {
                    // The proxy has stopped, and nothing could revoke what
                    // these routes grant any more (#102).
                    log(format!("{client}: {hostname}: the proxy stopped, closing"));
                    return None;
                }
            }
            done = &mut work => return Some(done),
        }
    }
}

/// `tap` and the peer `client` is, if the tap wants what it does.
fn admitted(tap: Option<&Tap>, client: Ipv4Addr) -> Option<(Tap, Logged)> {
    let tap = tap?;
    tap.admit(client).map(|logged| (tap.clone(), logged))
}

/// Tell the tap, if it wants `client`, that a connection was refused before
/// any request.
fn refused_connection(
    tap: Option<&Tap>,
    client: Ipv4Addr,
    hostname: Option<&str>,
    upstream: Option<SocketAddrV4>,
    why: &'static str,
) {
    if let Some((tap, logged)) = admitted(tap, client) {
        tap.send(Event::Request(logging::Request {
            client,
            peer: logged.peer,
            hostname: hostname.map(str::to_string),
            upstream,
            method: None,
            status: None,
            refused: Some(why),
            bytes: None,
        }));
    }
}

async fn handle(stream: TcpStream, client: Ipv4Addr, state: Shared, _slot: Slot, tap: Option<Tap>) {
    let start = match timeout(
        HANDSHAKE_TIMEOUT,
        LazyConfigAcceptor::new(Acceptor::default(), stream),
    )
    .await
    {
        Ok(Ok(start)) => start,
        _ => return,
    };
    // Decide before sending a certificate, so a refused caller learns nothing.
    let sni = start
        .client_hello()
        .server_name()
        .map(str::to_ascii_lowercase);
    let site = {
        let current = state.borrow();
        let Some(site) = sni.as_deref().and_then(|n| current.sites.get(n)) else {
            log(format!(
                "{client}: refused, no site for {}",
                sni.as_deref().unwrap_or("a connection without SNI")
            ));
            let why = match sni {
                Some(_) => "no site for this hostname",
                None => "no hostname given (SNI)",
            };
            refused_connection(tap.as_ref(), client, sni.as_deref(), None, why);
            return;
        };
        Arc::clone(site)
    };
    let hostname = site.route.hostname.clone();
    if !site.route.allows(client) {
        log(format!(
            "{client}: refused {hostname}: not allowed from this address"
        ));
        refused_connection(
            tap.as_ref(),
            client,
            Some(&hostname),
            Some(site.route.upstream),
            "not allowed from this address",
        );
        return;
    }
    let Some(tls) = site.tls.clone() else {
        log(format!(
            "{client}: refused {hostname}: no certificate covers it"
        ));
        refused_connection(
            tap.as_ref(),
            client,
            Some(&hostname),
            Some(site.route.upstream),
            "no certificate covers this hostname",
        );
        return;
    };
    let stream = match timeout(HANDSHAKE_TIMEOUT, start.into_stream(tls)).await {
        Ok(Ok(stream)) => stream,
        _ => return,
    };
    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = TokioIo::new(stream);
    let service = {
        let (hostname, state) = (hostname.clone(), state.clone());
        service_fn(move |req| {
            let tap = admitted(tap.as_ref(), client);
            forward(req, hostname.clone(), client, state.clone(), tap)
        })
    };
    // The protocol comes from ALPN, so the HTTP/1 header timeout runs from the
    // first byte: an idle peer can't hold the socket.
    if h2 {
        let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .keep_alive_interval(KEEPALIVE)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .max_concurrent_streams(MAX_STREAMS)
            .serve_connection(io, service);
        let _ = while_authorized(conn, state, &hostname, client, None).await;
    } else {
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .serve_connection(io, service)
            .with_upgrades();
        let _ = while_authorized(conn, state, &hostname, client, None).await;
    }
}

fn reply(status: StatusCode, message: &str) -> Response<Body> {
    let mut resp = Response::new(
        Full::new(Bytes::from(format!("{message}\n")))
            .map_err(|never| match never {})
            .boxed(),
    );
    *resp.status_mut() = status;
    resp
}

/// An error and its causes on one line (hyper's top-level messages are vague).
fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cause = c.source();
    }
    s
}

/// A logged peer's request, handed to the tap once its response is done
/// with (sent, or abandoned by the peer), with the bytes of the bodies
/// each way. A peer logged only at `blocked` hands over only refusals.
struct Exchange {
    tap: Tap,
    event: Option<logging::Request>,
    /// Whether a request that was forwarded is recorded too.
    forwarded: bool,
    out: Arc<AtomicU64>,
    back: Arc<AtomicU64>,
}

/// `method` as a record keeps it: a standard one whole, any other cut to
/// [`LOGGED_METHOD`] characters.
fn logged_method(method: &Method) -> String {
    method.as_str().chars().take(LOGGED_METHOD).collect()
}

impl Exchange {
    fn new(tap: Tap, logged: Logged, client: Ipv4Addr, hostname: &str, method: &Method) -> Self {
        Exchange {
            tap,
            forwarded: logged.level >= LogLevel::Connections,
            event: Some(logging::Request {
                client,
                peer: logged.peer,
                hostname: Some(hostname.to_string()),
                upstream: None,
                method: Some(logged_method(method)),
                status: None,
                refused: None,
                bytes: None,
            }),
            out: Arc::default(),
            back: Arc::default(),
        }
    }

    fn event(&mut self) -> Option<&mut logging::Request> {
        self.event.as_mut()
    }

    /// The request's body, counted on its way upstream.
    fn count_out(&self, body: Incoming) -> Body {
        Counted {
            body: body.map_err(BoxError::from).boxed(),
            tally: Arc::clone(&self.out),
            _exchange: None,
        }
        .boxed()
    }

    /// Answer with `resp`, counting its body on the way to the peer; the
    /// record goes when the body does.
    fn answer(mut self, resp: Response<Body>) -> Response<Body> {
        if let Some(e) = self.event() {
            e.status = Some(resp.status().as_u16());
        }
        let tally = Arc::clone(&self.back);
        resp.map(|body| {
            Counted {
                body,
                tally,
                _exchange: Some(self),
            }
            .boxed()
        })
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        let Some(mut event) = self.event.take() else {
            return;
        };
        if event.refused.is_none() && !self.forwarded {
            return;
        }
        event.bytes = Some((
            self.out.load(Ordering::Relaxed),
            self.back.load(Ordering::Relaxed),
        ));
        self.tap.send(Event::Request(event));
    }
}

/// A body that adds its data's length to a tally and passes the rest
/// through (its size, its end), so counting never changes how it's framed.
struct Counted {
    body: Body,
    tally: Arc<AtomicU64>,
    /// Held for its drop: the response's record goes when the body does.
    _exchange: Option<Exchange>,
}

impl hyper::body::Body for Counted {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        let polled = Pin::new(&mut self.body).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled {
            if let Some(data) = frame.data_ref() {
                self.tally.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A stream that adds the bytes read from it to a tally.
struct Counting<T> {
    io: T,
    read: Arc<AtomicU64>,
}

impl<T> Counting<T> {
    fn new(io: T, read: Arc<AtomicU64>) -> Self {
        Counting { io, read }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Counting<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled {
            let n = buf.filled().len().saturating_sub(before);
            self.read.fetch_add(n as u64, Ordering::Relaxed);
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counting<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// `resp` for the peer, recorded if `exchange` is.
fn respond(exchange: Option<Exchange>, resp: Response<Body>) -> Response<Body> {
    match exchange {
        Some(x) => x.answer(resp),
        None => resp,
    }
}

/// Refuse with `status` and say `why`, recorded as a refusal if `exchange`
/// is.
fn refuse(mut exchange: Option<Exchange>, status: StatusCode, why: &'static str) -> Response<Body> {
    if let Some(e) = exchange.as_mut().and_then(Exchange::event) {
        e.refused = Some(why);
    }
    respond(exchange, reply(status, why))
}

/// Forward one request. `tap` is set only when the peer is logged.
async fn forward(
    mut req: Request<Incoming>,
    hostname: String,
    client: Ipv4Addr,
    state: Shared,
    tap: Option<(Tap, Logged)>,
) -> std::result::Result<Response<Body>, Infallible> {
    let mut exchange =
        tap.map(|(tap, logged)| Exchange::new(tap, logged, client, &hostname, req.method()));
    // Look the site up per request: a reload may have revoked or moved it.
    let Some(site) = state.borrow().authorized(&hostname, client).cloned() else {
        return Ok(refuse(
            exchange,
            StatusCode::FORBIDDEN,
            "access was revoked",
        ));
    };
    if let Some(e) = exchange.as_mut().and_then(Exchange::event) {
        e.upstream = Some(site.route.upstream);
    }
    if let Err(r) = http::check(&req, &hostname) {
        log(format!("{client}: {hostname}: {}", r.message()));
        return Ok(refuse(exchange, r.status(), r.message()));
    }
    let downstream_upgrade = http::upgrade(&req).map(|_| hyper::upgrade::on(&mut req));
    let req = match &exchange {
        Some(x) => req.map(|b| x.count_out(b)),
        None => req.map(|b| b.map_err(BoxError::from).boxed()),
    };
    let up = match http::upstream_request(req, &hostname, site.route.upstream.port(), client) {
        Ok(up) => up,
        Err(r) => return Ok(refuse(exchange, r.status(), r.message())),
    };
    // Guarded too: an HTTP/2 stream runs as a task of its own, and must not
    // reach the upstream once a reload has taken the hostname away.
    let sent = while_authorized(
        site.upstream.request(up),
        state.clone(),
        &hostname,
        client,
        Some(site.route.upstream),
    )
    .await;
    let Some(sent) = sent else {
        return Ok(refuse(
            exchange,
            StatusCode::FORBIDDEN,
            "access was revoked",
        ));
    };
    let mut resp = match sent {
        Ok(resp) => resp,
        Err(e) => {
            log(format!(
                "{hostname}: upstream {} failed: {}",
                site.route.upstream,
                chain(&e)
            ));
            return Ok(respond(
                exchange,
                reply(StatusCode::BAD_GATEWAY, "the upstream is unreachable"),
            ));
        }
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        http::strip_hop_by_hop(resp.headers_mut(), None);
        let upstream = site.route.upstream;
        let resp = resp.map(|body| guarded(body, state, hostname, client, upstream));
        return Ok(respond(exchange, resp));
    }
    // Only a WebSocket switch we asked for: another protocol on the raw
    // stream would carry requests the checks above never see.
    let confirmed = resp
        .headers()
        .get(UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let (Some(downstream), true) = (downstream_upgrade, confirmed) else {
        return Ok(respond(
            exchange,
            reply(StatusCode::BAD_GATEWAY, "unexpected protocol switch"),
        ));
    };
    let upgrade = resp.headers().get(UPGRADE).cloned();
    http::strip_hop_by_hop(resp.headers_mut(), upgrade);
    let relayed_to = site.route.upstream;
    let upstream = hyper::upgrade::on(&mut resp);
    // A WebSocket's record goes when it closes, with what it carried.
    if let Some(e) = exchange.as_mut().and_then(Exchange::event) {
        e.status = Some(StatusCode::SWITCHING_PROTOCOLS.as_u16());
    }
    tokio::spawn(async move {
        if let (Ok(down), Ok(up)) = tokio::join!(downstream, upstream) {
            let (mut down, mut up) = (TokioIo::new(down), TokioIo::new(up));
            let relay = async {
                let _ = match &exchange {
                    // Counted as read, so the tally survives a relay that ends
                    // in an error (a peer gone, an upstream closing without
                    // TLS's goodbye).
                    Some(x) => {
                        tokio::io::copy_bidirectional(
                            &mut Counting::new(down, Arc::clone(&x.out)),
                            &mut Counting::new(up, Arc::clone(&x.back)),
                        )
                        .await
                    }
                    None => tokio::io::copy_bidirectional(&mut down, &mut up).await,
                };
            };
            let _ = while_authorized(relay, state, &hostname, client, Some(relayed_to)).await;
        }
        drop(exchange);
    });
    Ok(resp.map(|b| b.map_err(BoxError::from).boxed()))
}

/// What a frame of a response body comes as, from [`pass_on`]: `None` once
/// the body has ended.
type Piece = Option<std::result::Result<Frame<Bytes>, hyper::Error>>;

/// `body` for the peer, passed on only while `client` keeps `hostname` at
/// `upstream`, like a WebSocket relay: the response may stream long after
/// its headers (a download), and a reload takes it away mid-way (#115).
/// Its pump holds the routes it last checked, so a reload isn't confirmed
/// while it streams under ones it replaced. Cut off, the body ends in an
/// error rather than early, so it doesn't look complete.
fn guarded(
    body: Incoming,
    state: Shared,
    hostname: String,
    client: Ipv4Addr,
    upstream: SocketAddrV4,
) -> Body {
    if body.is_end_stream() {
        return body.map_err(BoxError::from).boxed();
    }
    let size = body.size_hint();
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let pump = pass_on(body, &tx);
        // `None` drops the sender without an end: the body fails.
        let _ = while_authorized(pump, state, &hostname, client, Some(upstream)).await;
    });
    Streamed {
        pieces: rx,
        size,
        ended: false,
    }
    .boxed()
}

/// Send `body`'s frames down `tx` until it ends, fails or nobody reads.
async fn pass_on(mut body: Incoming, tx: &mpsc::Sender<Piece>) {
    loop {
        let piece = tokio::select! {
            piece = body.frame() => piece,
            // The peer has gone: stop reading the upstream.
            () = tx.closed() => return,
        };
        let last = !matches!(piece, Some(Ok(_)));
        if tx.send(piece).await.is_err() || last {
            return;
        }
    }
}

/// A response body fed by [`pass_on`].
struct Streamed {
    pieces: mpsc::Receiver<Piece>,
    /// The upstream body's: passing it on keeps a known length known.
    size: SizeHint,
    ended: bool,
}

impl hyper::body::Body for Streamed {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        Poll::Ready(match std::task::ready!(self.pieces.poll_recv(cx)) {
            Some(Some(Ok(frame))) => Some(Ok(frame)),
            Some(Some(Err(e))) => {
                self.ended = true;
                Some(Err(e.into()))
            }
            Some(None) => {
                self.ended = true;
                None
            }
            None => {
                self.ended = true;
                Some(Err("access was revoked, or the proxy stopped".into()))
            }
        })
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        self.size
    }
}
