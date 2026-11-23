//! The running proxy: accept, pick the site from SNI before any certificate
//! is sent, check the caller's tunnel address, then serve HTTP/1.1 or HTTP/2
//! and forward each checked request to the site's upstream over TLS.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::dns::Name;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use parallax_core::generate::proxy::{ProxyRoutes, ProxySite};
use rustls::crypto::CryptoProvider;
use rustls::server::Acceptor;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::LazyConfigAcceptor;

use crate::{certs, http, Error, Result};

/// Time allowed for a TLS handshake, and for HTTP/1 request headers.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the certificate folder is checked for renewals.
const CERT_REFRESH: Duration = Duration::from_secs(60);

type Body = BoxBody<Bytes, hyper::Error>;
type Upstream = Client<HttpsConnector<HttpConnector<FixedResolver>>, Incoming>;

fn log(msg: impl std::fmt::Display) {
    eprintln!("parallax proxy: {msg}");
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
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
    /// `None` when no certificate covers the hostname: connections are refused.
    tls: Option<Arc<ServerConfig>>,
    upstream: Upstream,
}

/// Everything a connection needs, swapped whole on reload.
struct State {
    routes: ProxyRoutes,
    sites: HashMap<String, Arc<Site>>,
    certs_fingerprint: u64,
}

/// A loaded proxy, ready to run on a listener.
pub struct Proxy {
    routes_path: PathBuf,
    state: Arc<State>,
    refresh: Duration,
}

impl Proxy {
    /// Read the routes file, the CA bundle and the certificates.
    pub fn load(routes_path: &Path) -> Result<Proxy> {
        Ok(Proxy {
            routes_path: routes_path.to_path_buf(),
            state: Arc::new(load_state(routes_path)?),
            refresh: CERT_REFRESH,
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

    /// Serve on `listener` until the process ends. SIGHUP re-reads the routes.
    pub async fn run(self, listener: TcpListener) -> Result<()> {
        let local = listener
            .local_addr()
            .map_err(|e| Error::io("reading the listening address", e))?;
        log(format!(
            "listening on {local}, {} site(s)",
            self.state.sites.len()
        ));
        let shared = Arc::new(RwLock::new(self.state));
        tokio::spawn(reloader(
            self.routes_path,
            Arc::clone(&shared),
            self.refresh,
        ));
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = current(&shared);
                    tokio::spawn(handle(stream, peer, state));
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

/// Load the routes at `routes_path` and serve until the process ends.
pub fn serve(routes_path: &Path) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::io("starting the async runtime", e))?;
    runtime.block_on(async {
        let proxy = Proxy::load(routes_path)?;
        let listen = proxy.listen();
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|e| Error::io(format!("listening on {listen}"), e))?;
        proxy.run(listener).await
    })
}

fn current(shared: &RwLock<Arc<State>>) -> Arc<State> {
    match shared.read() {
        Ok(state) => Arc::clone(&state),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    }
}

fn replace(shared: &RwLock<Arc<State>>, state: State) {
    match shared.write() {
        Ok(mut slot) => *slot = Arc::new(state),
        Err(poisoned) => *poisoned.into_inner() = Arc::new(state),
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
        let client_tls = client_config(&routes.upstream_ca)?;
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

fn client_config(ca: &Path) -> Result<ClientConfig> {
    let context = || format!("reading the upstream CA bundle {}", ca.display());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca).map_err(|e| Error::invalid(context(), e))? {
        let cert = cert.map_err(|e| Error::invalid(context(), e))?;
        // Bundles carry the odd certificate webpki can't use; skip those.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(Error::invalid(context(), "no usable CA certificate in it"));
    }
    Ok(ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::invalid("setting up upstream TLS", e))?
        .with_root_certificates(roots)
        .with_no_client_auth())
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

/// A server TLS config per hostname (`None` where no certificate covers it),
/// plus the fingerprint of the folder they came from.
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
        let config = match certs::pick(&found, &site.hostname) {
            None => {
                log(format!(
                    "no certificate in {} covers {}; refusing it until one does",
                    routes.certificates.display(),
                    site.hostname
                ));
                None
            }
            Some(cert) => match server_config(cert) {
                Ok(config) => Some(config),
                Err(e) => {
                    log(format!("{}: {e}", site.hostname));
                    None
                }
            },
        };
        out.insert(site.hostname.clone(), config);
    }
    (out, fingerprint)
}

fn server_config(cert: &certs::Certificate) -> Result<Arc<ServerConfig>> {
    let context = || format!("certificate in {}", cert.dir.display());
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::invalid(context(), e))?
        .with_no_client_auth()
        .with_single_cert(cert.chain.clone(), cert.private_key()?)
        .map_err(|e| Error::invalid(context(), e))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

async fn reloader(routes_path: PathBuf, shared: Arc<RwLock<Arc<State>>>, refresh: Duration) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut hangup = match signal(SignalKind::hangup()) {
        Ok(s) => Some(s),
        Err(e) => {
            log(format!("cannot watch SIGHUP, routes won't reload: {e}"));
            None
        }
    };
    let mut tick = tokio::time::interval(refresh);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tokio::select! {
            Some(()) = recv(&mut hangup) => match load_state(&routes_path) {
                Ok(state) => {
                    let old = current(&shared);
                    if state.routes.listen != old.routes.listen {
                        log(format!(
                            "the listen address changed to {}; restart the proxy to use it",
                            state.routes.listen
                        ));
                    }
                    log(format!("routes reloaded, {} site(s)", state.sites.len()));
                    replace(&shared, state);
                }
                Err(e) => log(format!("reload failed, keeping the previous routes: {e}")),
            },
            _ = tick.tick() => {
                let old = current(&shared);
                if certs::fingerprint(&old.routes.certificates) == old.certs_fingerprint {
                    continue;
                }
                let (tls, certs_fingerprint) = server_configs(&old.routes);
                let sites = old
                    .sites
                    .iter()
                    .map(|(name, site)| {
                        let site = Site {
                            route: site.route.clone(),
                            tls: tls.get(name).cloned().flatten(),
                            upstream: site.upstream.clone(),
                        };
                        (name.clone(), Arc::new(site))
                    })
                    .collect();
                log("certificates changed, reloaded");
                replace(&shared, State { routes: old.routes.clone(), sites, certs_fingerprint });
            }
        }
    }
}

async fn recv(signal: &mut Option<tokio::signal::unix::Signal>) -> Option<()> {
    match signal {
        Some(s) => s.recv().await,
        None => std::future::pending().await,
    }
}

async fn handle(stream: TcpStream, peer: SocketAddr, state: Arc<State>) {
    let client = match peer.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4,
            None => return,
        },
    };
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
    let Some(site) = sni.as_deref().and_then(|n| state.sites.get(n)) else {
        log(format!(
            "{client}: refused, no site for {}",
            sni.as_deref().unwrap_or("a connection without SNI")
        ));
        return;
    };
    let hostname = &site.route.hostname;
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
    let site = Arc::clone(site);
    let service = service_fn(move |req| forward(req, Arc::clone(&site), client));
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT);
    let _ = builder
        .serve_connection_with_upgrades(TokioIo::new(stream), service)
        .await;
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
    site: Arc<Site>,
    client: Ipv4Addr,
) -> std::result::Result<Response<Body>, Infallible> {
    let hostname = &site.route.hostname;
    if let Err(r) = http::check(&req, hostname) {
        log(format!("{client}: {hostname}: {}", r.message()));
        return Ok(reply(r.status(), r.message()));
    }
    let downstream_upgrade = http::upgrade(&req).map(|_| hyper::upgrade::on(&mut req));
    let up = match http::upstream_request(req, hostname, site.route.upstream.port(), client) {
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
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let Some(downstream) = downstream_upgrade else {
            return Ok(reply(StatusCode::BAD_GATEWAY, "unexpected protocol switch"));
        };
        let upstream = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            if let (Ok(down), Ok(up)) = tokio::join!(downstream, upstream) {
                let _ =
                    tokio::io::copy_bidirectional(&mut TokioIo::new(down), &mut TokioIo::new(up))
                        .await;
            }
        });
    } else {
        http::strip_hop_by_hop(resp.headers_mut(), None);
    }
    Ok(resp.map(BodyExt::boxed))
}
