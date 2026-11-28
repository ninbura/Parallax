//! End to end: a throwaway CA, a fake nginx upstream, the proxy on
//! localhost, and real TLS clients speaking HTTP/1.1 and HTTP/2.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test helpers: failures should panic loudly"
)]

use std::convert::Infallible;
use std::net::{SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, UPGRADE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parallax_core::generate::proxy::{ProxyRoutes, ProxySite};
use parallax_core::logging::{Event, Tap};
use parallax_proxy::{certs, Proxy, Reload};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const IMMICH: &str = "immich.example.test";
/// Served by the proxy, but only to 10.0.0.0/8: the test client is another tier.
const OTHER: &str = "other.example.test";
/// Served by the proxy, but the upstream's certificate doesn't name it.
const BAD: &str = "bad.example.test";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

struct Ca(CertifiedIssuer<'static, KeyPair>);

impl Ca {
    fn new() -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Ca(CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap())
    }
    /// A leaf for `names`: (full chain PEM, key PEM).
    fn leaf(&self, names: &[&str]) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let cert = CertificateParams::new(names)
            .unwrap()
            .signed_by(&key, &self.0)
            .unwrap();
        (cert.pem() + &self.0.pem(), key.serialize_pem())
    }
}

fn write_cert(dir: &Path, (chain, key): &(String, String)) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(certs::CHAIN_FILE), chain).unwrap();
    std::fs::write(dir.join(certs::KEY_FILE), key).unwrap();
}

fn temp_dir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "parallax-proxy-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A stand-in for nginx: echoes what it was asked, and echoes bytes after a
/// WebSocket-style upgrade.
async fn fake_upstream((chain, key): (String, String)) -> SocketAddrV4 {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let SocketAddr::V4(addr) = listener.local_addr().unwrap() else {
        unreachable!()
    };
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(upstream_service))
                    .with_upgrades()
                    .await;
            });
        }
    });
    addr
}

/// Bytes the fake upstream has read from `/upload` bodies. Only
/// [`an_upload_stops_at_the_revocation`] uploads.
static UPLOADED: AtomicUsize = AtomicUsize::new(0);

/// A request body fed from a channel, one frame per message.
struct Chunks(tokio::sync::mpsc::Receiver<Bytes>);

impl hyper::body::Body for Chunks {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        self.0
            .poll_recv(cx)
            .map(|b| b.map(|b| Ok(hyper::body::Frame::data(b))))
    }
}

async fn upstream_service(mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.uri().path() == "/upload" {
        let mut body = req.into_body();
        while let Some(Ok(frame)) = body.frame().await {
            if let Some(data) = frame.data_ref() {
                UPLOADED.fetch_add(data.len(), Ordering::SeqCst);
            }
        }
        return Ok(Response::new(Full::default()));
    }
    if req.headers().contains_key(UPGRADE) {
        let on = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let mut io = TokioIo::new(on.await.unwrap());
            let mut buf = [0u8; 4];
            io.read_exact(&mut buf).await.unwrap();
            io.write_all(&buf).await.unwrap();
        });
        let resp = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(CONNECTION, "upgrade")
            .header(UPGRADE, "websocket")
            .body(Full::default())
            .unwrap();
        return Ok(resp);
    }
    let header = |name: &str| {
        req.headers()
            .get(name)
            .map(|v| v.to_str().unwrap().to_string())
            .unwrap_or_default()
    };
    let body = format!(
        "host={} target={} xff={}",
        header("host"),
        req.uri(),
        header("x-forwarded-for")
    );
    Ok(Response::new(Full::new(Bytes::from(body))))
}

struct Env {
    dir: PathBuf,
    ca: Ca,
    proxy: SocketAddr,
    roots: RootCertStore,
    routes: ProxyRoutes,
    reload: Reload,
    task: tokio::task::JoinHandle<parallax_proxy::Result<()>>,
}

impl Drop for Env {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Env {
    async fn start() -> Env {
        Env::start_tapped(None).await
    }

    /// With the proxy handing what it does over to `tap`.
    async fn start_tapped(tap: Option<Tap>) -> Env {
        let dir = temp_dir();
        let ca = Ca::new();
        std::fs::write(dir.join("ca.pem"), ca.0.pem()).unwrap();
        write_cert(
            &dir.join("certs/live/sites"),
            &ca.leaf(&[IMMICH, OTHER, BAD]),
        );
        let upstream = fake_upstream(ca.leaf(&[IMMICH, OTHER])).await;
        let site = |hostname: &str, allowed: &str| ProxySite {
            hostname: hostname.into(),
            service: "test".into(),
            upstream,
            allowed: vec![allowed.parse().unwrap()],
        };
        let routes = ProxyRoutes {
            listen: "127.0.0.1:1".parse().unwrap(),
            certificates: dir.join("certs"),
            upstream_ca: dir.join("ca.pem"),
            sites: vec![
                site(IMMICH, "127.0.0.0/8"),
                site(OTHER, "10.0.0.0/8"),
                site(BAD, "127.0.0.0/8"),
            ],
        };
        let mut proxy = Proxy::new(routes.clone())
            .unwrap()
            .refresh_every(Duration::from_millis(100));
        if let Some(tap) = tap {
            proxy = proxy.tap(tap);
        }
        let reload = proxy.reloader();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(proxy.run(listener));
        let mut roots = RootCertStore::empty();
        roots.add(ca.0.der().clone()).unwrap();
        Env {
            dir,
            ca,
            proxy: addr,
            roots,
            routes,
            reload,
            task,
        }
    }

    /// Hand the proxy `routes` and wait until every connection has checked
    /// them. Returns whether they loaded.
    async fn reload_with(&self, routes: ProxyRoutes) -> Result<(), String> {
        let taking = self.reload.send(routes);
        assert!(taking.checked.await.unwrap(), "connections didn't move on");
        taking.loaded.await.unwrap()
    }

    /// Reload with IMMICH granted to another tier only.
    async fn revoke_immich(&self) {
        let mut routes = self.routes.clone();
        routes.sites[0].allowed = vec!["10.0.0.0/8".parse().unwrap()];
        self.reload_with(routes).await.unwrap();
    }

    async fn connect(&self, sni: &str, alpn: &[u8]) -> std::io::Result<TlsStream<TcpStream>> {
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(self.roots.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let tcp = TcpStream::connect(self.proxy).await?;
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(sni.to_string()).unwrap(), tcp)
            .await
    }

    /// One HTTP/1.1 request on a connection with SNI `sni`.
    async fn h1(&self, sni: &str, req: Request<Empty<Bytes>>) -> (StatusCode, String) {
        let tls = self.connect(sni, b"http/1.1").await.unwrap();
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        tokio::spawn(conn);
        let resp = send.send_request(req).await.unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }
}

fn get(target: &str, host: &str) -> Request<Empty<Bytes>> {
    Request::builder()
        .uri(target)
        .header(HOST, host)
        .header("x-forwarded-for", "6.6.6.6")
        .body(Empty::new())
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn allowed_hostname_reaches_the_upstream() {
    let env = Env::start().await;
    let (status, body) = env.h1(IMMICH, get("/api/ping?x=1", IMMICH)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        "host=immich.example.test target=/api/ping?x=1 xff=127.0.0.1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn host_other_than_sni_is_misdirected() {
    let env = Env::start().await;
    let (status, _) = env.h1(IMMICH, get("/", OTHER)).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    let (status, _) = env.h1(IMMICH, get("/", "198.18.1.5")).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn http2_reuse_for_another_authority_is_misdirected() {
    let env = Env::start().await;
    let tls = env.connect(IMMICH, b"h2").await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut send, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    for (authority, expected) in [
        (IMMICH, StatusCode::OK),
        (OTHER, StatusCode::MISDIRECTED_REQUEST),
        (IMMICH, StatusCode::OK),
    ] {
        let req = Request::builder()
            .uri(format!("https://{authority}/"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = send.send_request(req).await.unwrap();
        assert_eq!(resp.status(), expected, "{authority}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_or_disallowed_hostnames_get_no_handshake() {
    let env = Env::start().await;
    // Not a site at all.
    assert!(env.connect("nope.example.test", b"http/1.1").await.is_err());
    // A site, but for another tier.
    assert!(env.connect(OTHER, b"http/1.1").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_and_absolute_targets_are_refused() {
    let env = Env::start().await;
    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri("192.168.1.1:22")
        .header(HOST, IMMICH)
        .body(Empty::new())
        .unwrap();
    assert_eq!(
        env.h1(IMMICH, connect).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    let absolute = get("https://immich.example.test/", IMMICH);
    assert_eq!(env.h1(IMMICH, absolute).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_certificate_must_name_the_hostname() {
    let env = Env::start().await;
    let (status, _) = env.h1(BAD, get("/", BAD)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

#[tokio::test(flavor = "multi_thread")]
async fn websocket_upgrades_pass_through() {
    let env = Env::start().await;
    let mut io = websocket(&env).await;
    io.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    io.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
}

#[tokio::test(flavor = "multi_thread")]
async fn renewed_certificates_are_picked_up_without_a_restart() {
    let env = Env::start().await;
    let served =
        |tls: &TlsStream<TcpStream>| tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let before = served(&env.connect(IMMICH, b"http/1.1").await.unwrap());
    write_cert(
        &env.dir.join("certs/live/sites"),
        &env.ca.leaf(&[IMMICH, OTHER, BAD]),
    );
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = served(&env.connect(IMMICH, b"http/1.1").await.unwrap());
        if now != before {
            return;
        }
    }
    panic!("the renewed certificate was never served");
}

#[test]
fn exact_names_win_over_wildcards_and_gaps_are_reported() {
    let dir = temp_dir();
    let ca = Ca::new();
    write_cert(&dir.join("a-wildcard"), &ca.leaf(&["*.example.test"]));
    write_cert(&dir.join("b-immich"), &ca.leaf(&[IMMICH]));
    std::fs::write(dir.join("README"), "certbot leaves files like this around").unwrap();
    let (found, problems) = certs::scan(&dir).unwrap();
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(found.len(), 2);
    let chosen = |name: &str| certs::select(&found, name).map(|(c, _)| c.dir.clone());
    assert_eq!(chosen(IMMICH), Ok(dir.join("b-immich")));
    assert_eq!(chosen("photos.example.test"), Ok(dir.join("a-wildcard")));
    assert!(chosen("immich.other.test")
        .unwrap_err()
        .contains("no certificate covers immich.other.test"));
    assert!(certs::scan(&dir.join("missing")).is_err());

    // A key that doesn't match its certificate is skipped, not served.
    let (chain, _) = ca.leaf(&[IMMICH]);
    let (_, other_key) = ca.leaf(&[IMMICH]);
    write_cert(&dir.join("b-immich"), &(chain, other_key));
    let (found, _) = certs::scan(&dir).unwrap();
    assert_eq!(chosen_in(&found, IMMICH), Some(dir.join("a-wildcard")));
    std::fs::remove_dir_all(dir.join("a-wildcard")).unwrap();
    let (found, _) = certs::scan(&dir).unwrap();
    let why = certs::select(&found, IMMICH).unwrap_err();
    assert!(why.contains("no usable certificate covers"), "{why}");
    std::fs::remove_dir_all(&dir).unwrap();
}

fn chosen_in(found: &[certs::Certificate], name: &str) -> Option<PathBuf> {
    certs::select(found, name).ok().map(|(c, _)| c.dir.clone())
}

#[tokio::test(flavor = "multi_thread")]
async fn revoking_a_grant_closes_open_connections() {
    let env = Env::start().await;
    // An HTTP/2 connection and a WebSocket, both open before the change.
    let tls = env.connect(IMMICH, b"h2").await.unwrap();
    let (mut h2, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let req = || {
        Request::builder()
            .uri(format!("https://{IMMICH}/"))
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    assert_eq!(
        h2.send_request(req()).await.unwrap().status(),
        StatusCode::OK
    );
    let mut ws = websocket(&env).await;

    env.revoke_immich().await;
    assert!(
        h2.send_request(req()).await.is_err(),
        "the HTTP/2 connection must be closed"
    );
    let mut buf = [0u8; 4];
    let _ = ws.write_all(b"ping").await;
    assert!(
        !matches!(ws.read(&mut buf).await, Ok(n) if n > 0),
        "the WebSocket must be closed"
    );
    assert!(env.connect(IMMICH, b"http/1.1").await.is_err());
}

/// An upload in progress when the grant is revoked reaches the upstream no
/// further once the proxy has confirmed the revocation (lane C, #104).
#[tokio::test(flavor = "multi_thread")]
async fn an_upload_stops_at_the_revocation() {
    let env = Env::start().await;
    let tls = env.connect(IMMICH, b"h2").await.unwrap();
    let (mut h2, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("https://{IMMICH}/upload"))
        .body(Chunks(rx))
        .unwrap();
    let resp = tokio::spawn(async move { h2.send_request(req).await.map(|r| r.status()) });
    tx.send(Bytes::from(vec![b'a'; 1000])).await.unwrap();
    for _ in 0..50 {
        if UPLOADED.load(Ordering::SeqCst) >= 1000 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        UPLOADED.load(Ordering::SeqCst),
        1000,
        "the first chunk never arrived"
    );

    env.revoke_immich().await;
    let _ = tx.send(Bytes::from(vec![b'b'; 1000])).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        UPLOADED.load(Ordering::SeqCst),
        1000,
        "bytes sent after the revocation reached the upstream"
    );
    drop(tx);
    let _ = resp.await;
}

/// A hostname moved to another upstream closes the WebSocket relayed to the
/// old one.
#[tokio::test(flavor = "multi_thread")]
async fn moving_a_hostname_closes_relays_to_the_old_upstream() {
    let env = Env::start().await;
    let mut ws = websocket(&env).await;
    let mut moved = env.routes.clone();
    // Nothing listens there; only the move matters.
    moved.sites[0].upstream = "127.0.0.1:9".parse().unwrap();
    env.reload_with(moved).await.unwrap();
    let mut buf = [0u8; 4];
    let _ = ws.write_all(b"ping").await;
    assert!(
        !matches!(ws.read(&mut buf).await, Ok(n) if n > 0),
        "the WebSocket must be closed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_reload_refuses_everything() {
    let env = Env::start().await;
    assert!(env.connect(IMMICH, b"http/1.1").await.is_ok());
    // The CA bundle is gone.
    let mut broken = env.routes.clone();
    broken.upstream_ca = env.dir.join("missing.pem");
    // The daemon is told, so it can count the apply as failed (#103).
    let why = env.reload_with(broken).await.unwrap_err();
    assert!(why.contains("missing.pem"), "{why}");
    assert!(env.connect(IMMICH, b"http/1.1").await.is_err());
    env.reload_with(env.routes.clone()).await.unwrap();
    assert!(env.connect(IMMICH, b"http/1.1").await.is_ok());
}

/// #103: routes nobody waits for any more still go in, so the daemon knows
/// what the proxy serves next.
#[tokio::test(flavor = "multi_thread")]
async fn routes_go_in_even_when_nobody_waits() {
    let env = Env::start().await;
    let mut revoked = env.routes.clone();
    revoked.sites[0].allowed = vec!["10.0.0.0/8".parse().unwrap()];
    drop(env.reload.send(revoked));
    let mut refused = false;
    for _ in 0..100 {
        if env.connect(IMMICH, b"http/1.1").await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(refused, "the routes nobody waited for never went in");
}

/// #102: once the proxy has stopped, nothing could revoke what its last
/// routes grant, so open connections close too.
#[tokio::test(flavor = "multi_thread")]
async fn open_connections_close_when_the_proxy_stops() {
    let mut env = Env::start().await;
    let tls = env.connect(IMMICH, b"h2").await.unwrap();
    let (mut h2, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    tokio::spawn(conn);
    let req = || {
        Request::builder()
            .uri(format!("https://{IMMICH}/"))
            .body(Empty::<Bytes>::new())
            .unwrap()
    };
    assert_eq!(
        h2.send_request(req()).await.unwrap().status(),
        StatusCode::OK
    );
    let mut ws = websocket(&env).await;

    env.task.abort();
    let _ = (&mut env.task).await;
    let mut buf = [0u8; 4];
    let _ = ws.write_all(b"ping").await;
    // Closed, not just quiet: an end or an error before the timeout.
    assert!(
        matches!(
            tokio::time::timeout(Duration::from_secs(5), ws.read(&mut buf)).await,
            Ok(Ok(0) | Err(_))
        ),
        "the WebSocket must be closed"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), h2.send_request(req()))
            .await
            .is_ok_and(|r| r.is_err()),
        "the HTTP/2 connection must be closed"
    );
    // A later reload is answered as stopped.
    assert!(env.reload.send(env.routes.clone()).loaded.await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn only_websocket_upgrades_are_forwarded() {
    let env = Env::start().await;
    let req = Request::builder()
        .uri("/")
        .header(HOST, IMMICH)
        .header(CONNECTION, "Upgrade, HTTP2-Settings")
        .header(UPGRADE, "h2c")
        .header("http2-settings", "AAMAAABkAAQAAP__")
        .body(Empty::new())
        .unwrap();
    // The fake upstream switches whenever it sees `Upgrade`; it must not see one.
    let (status, body) = env.h1(IMMICH, req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_address_cannot_take_every_connection() {
    let env = Env::start().await;
    let mut held = Vec::new();
    for _ in 0..64 {
        held.push(env.connect(IMMICH, b"http/1.1").await.unwrap());
    }
    assert!(env.connect(IMMICH, b"http/1.1").await.is_err());
    held.pop();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(env.connect(IMMICH, b"http/1.1").await.is_ok());
}

/// An open WebSocket through the proxy, already switched.
async fn websocket(env: &Env) -> TokioIo<hyper::upgrade::Upgraded> {
    let tls = env.connect(IMMICH, b"http/1.1").await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn.with_upgrades());
    let req = Request::builder()
        .uri("/api/socket.io/")
        .header(HOST, IMMICH)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = send.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
    TokioIo::new(hyper::upgrade::on(resp).await.unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_renewal_caught_halfway_keeps_the_working_certificate() {
    let env = Env::start().await;
    let served =
        |tls: &TlsStream<TcpStream>| tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let before = served(&env.connect(IMMICH, b"http/1.1").await.unwrap());
    // certbot has swapped the chain but not yet the key.
    let dir = env.dir.join("certs/live/sites");
    let (chain, key) = env.ca.leaf(&[IMMICH, OTHER, BAD]);
    std::fs::write(dir.join(certs::CHAIN_FILE), &chain).unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let during = served(&env.connect(IMMICH, b"http/1.1").await.unwrap());
    assert_eq!(
        during, before,
        "the working certificate must stay in service"
    );
    // The key lands: the new certificate is served.
    std::fs::write(dir.join(certs::KEY_FILE), &key).unwrap();
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if served(&env.connect(IMMICH, b"http/1.1").await.unwrap()) != before {
            return;
        }
    }
    panic!("the completed renewal was never served");
}

/// The requests the tap got within a second or two, in no set order.
fn requests(events: &std::sync::mpsc::Receiver<Event>) -> Vec<parallax_core::logging::Request> {
    let mut out = Vec::new();
    while let Ok(event) = events.recv_timeout(Duration::from_millis(1500)) {
        match event {
            Event::Request(r) => out.push(r),
            other => panic!("not a request: {other:?}"),
        }
    }
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn a_logged_peer_s_requests_and_refusals_are_handed_over_without_paths() {
    let (tap, events) = tap_for(parallax_core::model::LogLevel::Detailed);
    let env = Env::start_tapped(Some(tap)).await;
    let (status, body) = env
        .h1(IMMICH, get("/api/assets/3f2a9c/thumbnail", IMMICH))
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = env.h1(IMMICH, get("/", OTHER)).await;
    assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
    assert!(env.connect("nope.example.test", b"http/1.1").await.is_err());
    assert!(env.connect(OTHER, b"http/1.1").await.is_err());
    {
        let mut io = websocket(&env).await;
        io.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        io.read_exact(&mut buf).await.unwrap();
    }

    let got = requests(&events);
    assert!(
        !format!("{got:?}").contains("3f2a9c"),
        "never a path: {got:?}"
    );
    let find = |f: &dyn Fn(&parallax_core::logging::Request) -> bool| {
        got.iter()
            .find(|r| f(r))
            .unwrap_or_else(|| panic!("not in {got:?}"))
    };
    let ok = find(&|r| r.status == Some(200));
    assert_eq!(ok.hostname.as_deref(), Some(IMMICH));
    assert_eq!(ok.method.as_deref(), Some("GET"));
    assert_eq!(ok.refused, None);
    assert_eq!(ok.upstream, Some(env.routes.sites[0].upstream));
    assert_eq!(ok.bytes, Some((0, body.len() as u64)));

    let misdirected = find(&|r| r.status == Some(421));
    assert_eq!(
        misdirected.refused,
        Some("this connection serves a different hostname")
    );
    let unknown = find(&|r| r.hostname.as_deref() == Some("nope.example.test"));
    assert_eq!(unknown.refused, Some("no site for this hostname"));
    assert_eq!((unknown.method.as_ref(), unknown.upstream), (None, None));
    let other = find(&|r| r.hostname.as_deref() == Some(OTHER) && r.method.is_none());
    assert_eq!(other.refused, Some("not allowed from this address"));
    // A WebSocket's record comes when it closes, with what it carried.
    let socket = find(&|r| r.status == Some(101));
    assert_eq!(socket.bytes, Some((4, 4)));
    assert_eq!(got.len(), 5, "{got:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn peers_nobody_logs_hand_nothing_over() {
    let (tap, events) = Tap::new(64);
    let env = Env::start_tapped(Some(tap)).await;
    let (status, _) = env.h1(IMMICH, get("/", IMMICH)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(env.connect("nope.example.test", b"http/1.1").await.is_err());
    assert!(requests(&events).is_empty());
}

fn tap_for(level: parallax_core::model::LogLevel) -> (Tap, std::sync::mpsc::Receiver<Event>) {
    let (tap, events) = Tap::new(64);
    tap.set_clients(
        [(
            std::net::Ipv4Addr::LOCALHOST,
            parallax_core::logging::Logged {
                peer: "guest".into(),
                level,
            },
        )]
        .into(),
    );
    (tap, events)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_logged_at_blocked_hands_over_only_refusals() {
    let (tap, events) = tap_for(parallax_core::model::LogLevel::Blocked);
    let env = Env::start_tapped(Some(tap)).await;
    assert_eq!(env.h1(IMMICH, get("/", IMMICH)).await.0, StatusCode::OK);
    assert_eq!(
        env.h1(IMMICH, get("/", OTHER)).await.0,
        StatusCode::MISDIRECTED_REQUEST
    );
    let got = requests(&events);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].status, Some(421));
    assert_eq!(got[0].peer, "guest");
}

#[tokio::test(flavor = "multi_thread")]
async fn logging_keeps_a_reply_s_length() {
    let (tap, _events) = tap_for(parallax_core::model::LogLevel::Detailed);
    let env = Env::start_tapped(Some(tap)).await;
    let tls = env.connect(IMMICH, b"http/1.1").await.unwrap();
    let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    tokio::spawn(conn);
    // The proxy's own reply, and the upstream's.
    for host in [OTHER, IMMICH] {
        // The connection takes the next request once it has finished the
        // last; sending sooner fails now and then ("connection was not ready").
        send.ready().await.unwrap();
        let resp = send.send_request(get("/", host)).await.unwrap();
        assert!(
            resp.headers().contains_key(hyper::header::CONTENT_LENGTH),
            "{host}: {:?}",
            resp.headers()
        );
        resp.into_body().collect().await.unwrap();
    }
}

/// A client's method is the one field of a record it chooses freely: a long
/// extension method is kept cut short, so one guest can't write records of
/// hundreds of KiB (#65). Refusals count, at `blocked`.
#[tokio::test(flavor = "multi_thread")]
async fn a_long_method_is_recorded_cut_short() {
    let (tap, events) = tap_for(parallax_core::model::LogLevel::Blocked);
    let env = Env::start_tapped(Some(tap)).await;
    // The first 32 characters are kept, and only those.
    let kept = "PROPFIND-0123456789abcdefghijklm";
    assert_eq!(kept.len(), 32);
    let long = format!("{kept}{}", "z".repeat(300_000));
    let method = hyper::Method::from_bytes(long.as_bytes()).unwrap();
    let req = Request::builder()
        .method(method)
        .uri("/")
        .header(HOST, OTHER)
        .body(Empty::<Bytes>::new())
        .unwrap();
    assert_eq!(env.h1(IMMICH, req).await.0, StatusCode::MISDIRECTED_REQUEST);
    let got = requests(&events);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].method.as_deref(), Some(kept));
}
