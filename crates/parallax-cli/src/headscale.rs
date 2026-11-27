//! The real [`HeadscaleApi`]: HTTP or HTTPS to `server.headscale.server_url`,
//! with the API key from `server.headscale.api_key_file`. HTTPS
//! certificates are checked against `server.proxy.upstream_ca`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::{header, Request, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use parallax_core::io::{HeadscaleApi, HttpReply};
use parallax_core::model::ServerConfig;
use parallax_core::secret::Secret;
use parallax_core::{Error, Result};

/// How long one request may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest reply read. A node list of thousands of nodes fits.
const MAX_REPLY: usize = 16 << 20;

/// Headscale's API as the configuration names it.
#[derive(Debug, Clone)]
pub struct Api {
    url: String,
    key_file: PathBuf,
    ca: PathBuf,
    /// How the key is read: as root, as the user the configuration is from.
    files: crate::owner::ConfigFiles,
}

impl Api {
    pub fn new(server: &ServerConfig, files: crate::owner::ConfigFiles) -> Self {
        Api {
            files,
            url: server
                .headscale
                .server_url
                .trim_end_matches('/')
                .to_string(),
            key_file: server.headscale.api_key_file.clone(),
            ca: server.proxy.upstream_ca.clone(),
        }
    }

    /// Read on every request, so a new key takes effect without a restart.
    /// Only the API gets it: `/version` is public, and a reverse proxy may
    /// log it differently.
    fn key(&self, path: &str) -> Result<Option<Secret>> {
        if !path.starts_with("/api/") {
            return Ok(None);
        }
        let key = match self.files.read_secret(&self.key_file) {
            Ok(Some(key)) => key.trim().to_string(),
            Ok(None) => {
                return Err(Error::Headscale(format!(
                    "no API key for Headscale at {}: {} doesn't exist. Create a key with `headscale apikeys create` and write it there (mode 0600)",
                    self.url,
                    self.key_file.display()
                )));
            }
            Err(e) => {
                return Err(Error::Headscale(format!(
                    "can't read the Headscale API key {}: {e}",
                    self.key_file.display()
                )));
            }
        };
        if key.is_empty() {
            return Err(Error::Headscale(format!(
                "the Headscale API key file {} is empty",
                self.key_file.display()
            )));
        }
        Ok(Some(Secret::new(key)))
    }

    async fn ask(&self, path: &str) -> std::result::Result<HttpReply, String> {
        let uri: Uri = format!("{}{path}", self.url).parse().map_err(|e| {
            format!(
                "server.headscale.server_url '{}' isn't a URL: {e}",
                self.url
            )
        })?;
        let https = match uri.scheme_str() {
            Some("https") => true,
            Some("http") => false,
            _ => {
                return Err(format!(
                    "server.headscale.server_url '{}' must start with http:// or https://",
                    self.url
                ))
            }
        };
        // `path` is appended: a query or fragment would swallow it.
        if uri.authority().is_none() || self.url.contains(['?', '#']) {
            return Err(format!(
                "server.headscale.server_url '{}' must be Headscale's own URL, like https://headscale.example.com",
                self.url
            ));
        }
        let key = self.key(path).map_err(|e| e.to_string())?;
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(TIMEOUT));
        let mut request = Request::get(uri).header(header::ACCEPT, "application/json");
        if let Some(key) = &key {
            let mut value = header::HeaderValue::try_from(format!("Bearer {}", key.expose()))
                .map_err(|_| {
                    format!(
                        "the API key in {} isn't a valid header value",
                        self.key_file.display()
                    )
                })?;
            // Kept out of hyper's debug output.
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        let request = request
            .body(Empty::<Bytes>::new())
            .map_err(|e| e.to_string())?;
        let exchange = async {
            // TLS only for https: plain HTTP mustn't need the CA bundle.
            let response = if https {
                let connector = HttpsConnectorBuilder::new()
                    .with_tls_config(self.tls()?)
                    .https_only()
                    .enable_http1()
                    .wrap_connector(http);
                Client::builder(TokioExecutor::new())
                    .build(connector)
                    .request(request)
                    .await
            } else {
                Client::builder(TokioExecutor::new())
                    .build(http)
                    .request(request)
                    .await
            }
            .map_err(|e| chain(&e))?;
            let status = response.status().as_u16();
            let body = Limited::new(response.into_body(), MAX_REPLY)
                .collect()
                .await
                .map_err(|e| format!("reading the reply: {e}"))?
                .to_bytes();
            Ok(HttpReply {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            })
        };
        tokio::time::timeout(TIMEOUT, exchange)
            .await
            .map_err(|_| format!("no answer within {} seconds", TIMEOUT.as_secs()))?
    }

    fn tls(&self) -> std::result::Result<rustls::ClientConfig, String> {
        let roots = parallax_proxy::certs::upstream_roots(&self.ca).map_err(|e| e.to_string())?;
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map(|b| b.with_root_certificates(roots).with_no_client_auth())
        .map_err(|e| e.to_string())
    }
}

impl HeadscaleApi for Api {
    /// Blocks. Runs on a thread and runtime of its own, so it works from
    /// anywhere, inside an async runtime too (where it blocks that thread).
    fn get(&self, path: &str) -> Result<HttpReply> {
        let run = || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("starting a runtime: {e}"))?
                .block_on(self.ask(path))
        };
        std::thread::scope(|scope| {
            scope
                .spawn(run)
                .join()
                .unwrap_or_else(|_| Err("the request thread panicked".into()))
        })
        .map_err(|e| Error::Headscale(format!("Headscale at {}: GET {path}: {e}", self.url)))
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// One HTTP exchange on a local port: returns the request it got.
    fn serve_once(reply: &'static str) -> (String, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            stream.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        (url, handle)
    }

    fn api(url: &str, key_file: PathBuf) -> Api {
        Api {
            files: crate::owner::ConfigFiles::default(),
            url: url.into(),
            key_file,
            ca: PathBuf::from("/etc/ssl/certs/ca-certificates.crt"),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("parallax-hs-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn sends_the_key_and_returns_any_status() {
        let dir = scratch("key");
        let key_file = dir.join("headscale-api.key");
        std::fs::write(&key_file, "hskey-api-test\n").unwrap();
        let (url, request) = serve_once(
            "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/problem+json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}",
        );
        let reply = api(&url, key_file).get("/api/v1/node").unwrap();
        let request = request.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            reply,
            HttpReply {
                status: 401,
                body: "{}".into()
            }
        );
        assert!(
            request.starts_with("GET /api/v1/node HTTP/1.1"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer hskey-api-test\r\n"),
            "{request}"
        );
    }

    #[test]
    fn version_gets_no_key() {
        let dir = scratch("version");
        let key_file = dir.join("headscale-api.key");
        std::fs::write(&key_file, "hskey-api-test\n").unwrap();
        let (url, request) =
            serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}");
        api(&url, key_file).get("/version").unwrap();
        let request = request.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            !request.to_ascii_lowercase().contains("authorization"),
            "{request}"
        );
    }

    #[test]
    fn a_missing_key_file_is_named() {
        let dir = scratch("missing");
        let e = api("http://127.0.0.1:9", dir.join("nope.key"))
            .get("/api/v1/node")
            .unwrap_err()
            .to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(e.contains("nope.key doesn't exist"), "{e}");
        assert!(e.contains("headscale apikeys create"), "{e}");
    }

    #[test]
    fn unreachable_says_where() {
        let dir = scratch("unreachable");
        let key_file = dir.join("k");
        std::fs::write(&key_file, "hskey-api-test").unwrap();
        // Port 9 (discard) is closed on test machines.
        let e = api("http://127.0.0.1:9", key_file)
            .get("/api/v1/node")
            .unwrap_err()
            .to_string();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            e.starts_with("Headscale at http://127.0.0.1:9: GET /api/v1/node: "),
            "{e}"
        );
        assert!(!e.contains("hskey-api-test"), "{e}");
    }

    #[test]
    fn plain_http_needs_no_ca_bundle() {
        let (url, request) =
            serve_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}");
        let mut api = api(&url, PathBuf::from("/nonexistent/key"));
        api.ca = PathBuf::from("/nonexistent/ca.pem");
        assert_eq!(api.get("/version").unwrap().status, 200);
        request.join().unwrap();
    }

    #[test]
    fn a_url_with_a_query_is_refused() {
        let e = api(
            "https://headscale.example.com/?x=1",
            PathBuf::from("/nonexistent"),
        )
        .get("/version")
        .unwrap_err()
        .to_string();
        assert!(e.contains("must be Headscale's own URL"), "{e}");
    }

    #[test]
    fn only_http_and_https() {
        let e = api("ftp://headscale", PathBuf::from("/nonexistent"))
            .get("/version")
            .unwrap_err()
            .to_string();
        assert!(e.contains("must start with http:// or https://"), "{e}");
    }
}
