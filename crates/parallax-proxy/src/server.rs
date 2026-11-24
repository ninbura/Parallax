//! The running proxy: accept, pick the site from SNI before any certificate
//! is sent, check the caller's tunnel address, then serve HTTP/1.1 or HTTP/2
//! and forward each checked request to the site's upstream over TLS.
//!
//! The routes live in a `watch` channel. A reload sends a new state; every
//! request looks its site up in the current one, and open connections and
//! WebSocket relays re-check theirs on every change, so revoking a grant
//! cuts off connections that were already open.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::UPGRADE;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use parallax_core::generate::proxy::{ProxyRoutes, ProxySite};
use rustls::server::Acceptor;
use rustls::{ClientConfig, ServerConfig};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Notify};
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
/// Open connections one tunnel address may hold. Browsers open about six per
/// site over HTTP/1.1 and one over HTTP/2; this bounds what one peer can
/// take from everyone else.
const MAX_PER_SOURCE: usize = 64;

type Body = BoxBody<Bytes, hyper::Error>;
type Upstream = Client<HttpsConnector<HttpConnector<FixedResolver>>, Incoming>;

fn log(msg: impl std::fmt::Display) {
    eprintln!("parallax proxy: {msg}");
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

/// A loaded proxy, ready to run on a listener.
pub struct Proxy {
    routes_path: PathBuf,
    state: Arc<State>,
    refresh: Duration,
    reload: Arc<Notify>,
}

impl Proxy {
    /// Read the routes file, the CA bundle and the certificates.
    pub fn load(routes_path: &Path) -> Result<Proxy> {
        Ok(Proxy {
            routes_path: routes_path.to_path_buf(),
            state: Arc::new(load_state(routes_path)?),
            refresh: CERT_REFRESH,
            reload: Arc::new(Notify::new()),
        })
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

    /// Notifying this re-reads the routes (the daemon does after each apply).
    pub fn reload_trigger(&self) -> Arc<Notify> {
        Arc::clone(&self.reload)
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
        tokio::spawn(reloader(self.routes_path, tx, self.refresh, self.reload));
        let counts: Arc<Mutex<HashMap<Ipv4Addr, usize>>> = Arc::default();
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let Some(client) = ipv4(peer.ip()) else {
                        continue;
                    };
                    let Some(slot) = Slot::take(&counts, client) else {
                        log(format!(
                            "{client}: refused, already {MAX_PER_SOURCE} open connections"
                        ));
                        continue;
                    };
                    tokio::spawn(handle(stream, client, rx.clone(), slot));
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

fn load_state(routes_path: &Path) -> Result<State> {
    let text = std::fs::read_to_string(routes_path)
        .map_err(|e| Error::io(format!("reading {}", routes_path.display()), e))?;
    let routes = ProxyRoutes::from_toml(&text)?;
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

async fn reloader(
    routes_path: PathBuf,
    tx: watch::Sender<Arc<State>>,
    refresh: Duration,
    trigger: Arc<Notify>,
) {
    let mut tick = tokio::time::interval(refresh);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            () = trigger.notified() => reload(&routes_path, &tx),
            _ = tick.tick() => refresh_certificates(&tx),
        }
    }
}

/// Re-read the routes. On failure, refuse everything until a reload works:
/// the old routes may grant what the new configuration takes away.
fn reload(routes_path: &Path, tx: &watch::Sender<Arc<State>>) {
    let old = Arc::clone(&tx.borrow());
    match load_state(routes_path) {
        Ok(state) => {
            if state.routes.listen != old.routes.listen {
                log(format!(
                    "the listen address changed to {}; restart Parallax to use it",
                    state.routes.listen
                ));
            }
            log(format!("routes reloaded, {} site(s)", state.sites.len()));
            tx.send_replace(Arc::new(state));
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

/// Drive `work` until it ends or `client` loses `hostname` in a reload.
async fn while_authorized<F: Future>(work: F, mut state: Shared, hostname: &str, client: Ipv4Addr) {
    tokio::pin!(work);
    loop {
        tokio::select! {
            _ = &mut work => return,
            changed = state.changed() => {
                if changed.is_err() {
                    // The reloader is gone; the last state stays in force.
                    work.await;
                    return;
                }
                if state.borrow_and_update().authorized(hostname, client).is_none() {
                    log(format!("{client}: {hostname}: access revoked, closing"));
                    return;
                }
            }
        }
    }
}

async fn handle(stream: TcpStream, client: Ipv4Addr, state: Shared, _slot: Slot) {
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
            return;
        };
        Arc::clone(site)
    };
    let hostname = site.route.hostname.clone();
    if !site.route.allows(client) {
        log(format!(
            "{client}: refused {hostname}: not allowed from this address"
        ));
        return;
    }
    let Some(tls) = site.tls.clone() else {
        log(format!(
            "{client}: refused {hostname}: no certificate covers it"
        ));
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
        service_fn(move |req| forward(req, hostname.clone(), client, state.clone()))
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
        while_authorized(conn, state, &hostname, client).await;
    } else {
        let conn = hyper::server::conn::http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .serve_connection(io, service)
            .with_upgrades();
        while_authorized(conn, state, &hostname, client).await;
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

async fn forward(
    mut req: Request<Incoming>,
    hostname: String,
    client: Ipv4Addr,
    state: Shared,
) -> std::result::Result<Response<Body>, Infallible> {
    // Look the site up per request: a reload may have revoked or moved it.
    let Some(site) = state.borrow().authorized(&hostname, client).cloned() else {
        return Ok(reply(StatusCode::FORBIDDEN, "access was revoked"));
    };
    if let Err(r) = http::check(&req, &hostname) {
        log(format!("{client}: {hostname}: {}", r.message()));
        return Ok(reply(r.status(), r.message()));
    }
    let downstream_upgrade = http::upgrade(&req).map(|_| hyper::upgrade::on(&mut req));
    let up = match http::upstream_request(req, &hostname, site.route.upstream.port(), client) {
        Ok(up) => up,
        Err(r) => return Ok(reply(r.status(), r.message())),
    };
    let mut resp = match site.upstream.request(up).await {
        Ok(resp) => resp,
        Err(e) => {
            log(format!(
                "{hostname}: upstream {} failed: {}",
                site.route.upstream,
                chain(&e)
            ));
            return Ok(reply(
                StatusCode::BAD_GATEWAY,
                "the upstream is unreachable",
            ));
        }
    };
    if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
        http::strip_hop_by_hop(resp.headers_mut(), None);
        return Ok(resp.map(BodyExt::boxed));
    }
    // Only a WebSocket switch we asked for: another protocol on the raw
    // stream would carry requests the checks above never see.
    let confirmed = resp
        .headers()
        .get(UPGRADE)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"));
    let (Some(downstream), true) = (downstream_upgrade, confirmed) else {
        return Ok(reply(StatusCode::BAD_GATEWAY, "unexpected protocol switch"));
    };
    let upgrade = resp.headers().get(UPGRADE).cloned();
    http::strip_hop_by_hop(resp.headers_mut(), upgrade);
    let upstream = hyper::upgrade::on(&mut resp);
    tokio::spawn(async move {
        if let (Ok(down), Ok(up)) = tokio::join!(downstream, upstream) {
            let relay = async move {
                let _ =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(down), &mut TokioIo::new(up))
                        .await;
            };
            while_authorized(relay, state, &hostname, client).await;
        }
    });
    Ok(resp.map(BodyExt::boxed))
}
