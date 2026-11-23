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
use parallax_proxy::{certs, Proxy};
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

async fn upstream_service(mut req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
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
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Env {
    async fn start() -> Env {
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
        let routes_path = dir.join("routes.toml");
        std::fs::write(&routes_path, toml::to_string(&routes).unwrap()).unwrap();
        let proxy = Proxy::load(&routes_path)
            .unwrap()
            .refresh_every(Duration::from_millis(100));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(proxy.run(listener));
        let mut roots = RootCertStore::empty();
        roots.add(ca.0.der().clone()).unwrap();
        Env {
            dir,
            ca,
            proxy: addr,
            roots,
        }
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
    let mut io = TokioIo::new(hyper::upgrade::on(resp).await.unwrap());
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
    assert_eq!(
        certs::pick(&found, IMMICH).unwrap().dir,
        dir.join("b-immich")
    );
    assert_eq!(
        certs::pick(&found, "photos.example.test").unwrap().dir,
        dir.join("a-wildcard")
    );
    assert_eq!(
        certs::uncovered(
            &found,
            &[IMMICH, "photos.example.test", "immich.other.test"]
        ),
        vec!["immich.other.test"]
    );
    assert!(certs::scan(&dir.join("missing")).is_err());
    std::fs::remove_dir_all(&dir).unwrap();
}
