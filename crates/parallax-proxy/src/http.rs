//! What the proxy checks on every request, and how it rewrites one for the
//! upstream. Plain functions over `http` types, so they're tested without
//! sockets.
//!
//! The TLS handshake already pinned the connection to one hostname (SNI).
//! Every request on it must name that same hostname in `Host` and, on
//! HTTP/2, `:authority`. Otherwise a client could open a connection for an
//! allowed site and then ask nginx, which picks the site by `Host`, for
//! another one.

use std::net::Ipv4Addr;

use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, StatusCode, Uri, Version};

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// `CONNECT` would turn the proxy into a tunnel to anywhere.
    Connect,
    /// HTTP/1 absolute-form (`GET https://host/ HTTP/1.1`) is for forward proxies.
    AbsoluteForm,
    /// No `Host` and no `:authority`.
    NoHost,
    /// More than one `Host` header.
    ManyHosts,
    /// `Host` or `:authority` names another site than the connection's SNI.
    WrongHost,
    /// The request target can't be rebuilt for the upstream.
    BadTarget,
}

impl Rejection {
    pub fn status(self) -> StatusCode {
        match self {
            Rejection::Connect => StatusCode::METHOD_NOT_ALLOWED,
            Rejection::WrongHost => StatusCode::MISDIRECTED_REQUEST,
            Rejection::AbsoluteForm
            | Rejection::NoHost
            | Rejection::ManyHosts
            | Rejection::BadTarget => StatusCode::BAD_REQUEST,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Rejection::Connect => "CONNECT is not allowed",
            Rejection::AbsoluteForm => "absolute request targets are not allowed",
            Rejection::NoHost => "the request names no host",
            Rejection::ManyHosts => "the request has more than one Host header",
            Rejection::WrongHost => "this connection serves a different hostname",
            Rejection::BadTarget => "the request target is malformed",
        }
    }
}

/// Check a request on a connection whose SNI was `hostname`.
pub fn check<B>(req: &Request<B>, hostname: &str) -> Result<(), Rejection> {
    if req.method() == Method::CONNECT {
        return Err(Rejection::Connect);
    }
    let http2 = req.version() == Version::HTTP_2;
    let uri = req.uri();
    if !http2 && (uri.scheme().is_some() || uri.authority().is_some()) {
        return Err(Rejection::AbsoluteForm);
    }
    let hosts: Vec<&HeaderValue> = req.headers().get_all(header::HOST).iter().collect();
    if hosts.len() > 1 {
        return Err(Rejection::ManyHosts);
    }
    let authority = if http2 { uri.authority() } else { None };
    if hosts.is_empty() && authority.is_none() {
        return Err(Rejection::NoHost);
    }
    let host_ok = hosts
        .iter()
        .all(|v| v.to_str().is_ok_and(|v| names(v, hostname)));
    let authority_ok = authority.is_none_or(|a| names(a.as_str(), hostname));
    if host_ok && authority_ok {
        Ok(())
    } else {
        Err(Rejection::WrongHost)
    }
}

/// Does a `Host` or `:authority` value name `hostname`? Port 443 or none,
/// no user info, one trailing dot allowed.
fn names(value: &str, hostname: &str) -> bool {
    if value.contains('@') {
        return false;
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (value, None),
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    port.is_none_or(|p| p == "443") && host.eq_ignore_ascii_case(hostname)
}

/// An HTTP/1.1 WebSocket upgrade: `Connection: upgrade` plus `Upgrade:
/// websocket`. Returns the `Upgrade` value to pass on. Other upgrades (h2c,
/// say) are dropped: after a switch the proxy only relays bytes, so a
/// protocol that carries requests would get past the checks.
pub fn upgrade<B>(req: &Request<B>) -> Option<HeaderValue> {
    if req.version() != Version::HTTP_11 || req.method() != Method::GET {
        return None;
    }
    let wants = connection_tokens(req.headers()).any(|t| t.eq_ignore_ascii_case("upgrade"));
    req.headers()
        .get(header::UPGRADE)
        .filter(|v| wants && v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        .cloned()
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

/// Remove hop-by-hop headers (RFC 9110 §7.6.1). With `upgrade`, put back the
/// pair that asks for (or confirms) the protocol switch.
pub fn strip_hop_by_hop(headers: &mut HeaderMap, upgrade: Option<HeaderValue>) {
    let named: Vec<HeaderName> = connection_tokens(headers)
        .filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
    ] {
        headers.remove(name);
    }
    if let Some(value) = upgrade {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.insert(header::UPGRADE, value);
    }
}

/// Rewrite a checked request for the upstream: HTTP/1.1 to
/// `https://<hostname>[:port]/<path>`, `Host` set to the hostname, and
/// forwarding headers replaced (never appended: the client could forge them).
pub fn upstream_request<B>(
    req: Request<B>,
    hostname: &str,
    port: u16,
    client: Ipv4Addr,
) -> Result<Request<B>, Rejection> {
    let upgrade = upgrade(&req);
    let (mut parts, body) = req.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |p| p.as_str())
        .to_string();
    let authority = if port == 443 {
        hostname.to_string()
    } else {
        format!("{hostname}:{port}")
    };
    parts.uri = Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|_| Rejection::BadTarget)?;
    parts.version = Version::HTTP_11;
    let headers = &mut parts.headers;
    strip_hop_by_hop(headers, upgrade);
    // HTTP/2 may split cookies across headers; HTTP/1.1 wants one (RFC 9113 §8.2.3).
    let cookies: Vec<&[u8]> = headers
        .get_all(header::COOKIE)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect();
    if cookies.len() > 1 {
        let joined =
            HeaderValue::from_bytes(&cookies.join(&b"; "[..])).map_err(|_| Rejection::BadTarget)?;
        headers.insert(header::COOKIE, joined);
    }
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-real-ip",
    ] {
        headers.remove(name);
    }
    headers.insert(
        header::HOST,
        HeaderValue::from_str(hostname).map_err(|_| Rejection::BadTarget)?,
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client.to_string()).map_err(|_| Rejection::BadTarget)?,
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    Ok(Request::from_parts(parts, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SITE: &str = "immich.mydomain.com";

    fn h1(uri: &str, host: Option<&str>) -> Request<()> {
        let mut b = Request::builder().uri(uri).version(Version::HTTP_11);
        if let Some(h) = host {
            b = b.header(header::HOST, h);
        }
        b.body(()).unwrap()
    }

    fn h2(authority: &str) -> Request<()> {
        Request::builder()
            .uri(format!("https://{authority}/"))
            .version(Version::HTTP_2)
            .body(())
            .unwrap()
    }

    #[test]
    fn matching_host_passes() {
        assert_eq!(check(&h1("/", Some(SITE)), SITE), Ok(()));
        assert_eq!(
            check(&h1("/a?b", Some("Immich.MyDomain.com:443")), SITE),
            Ok(())
        );
        assert_eq!(check(&h1("/", Some("immich.mydomain.com.")), SITE), Ok(()));
        assert_eq!(check(&h2(SITE), SITE), Ok(()));
    }

    #[test]
    fn another_host_is_misdirected() {
        for host in [
            "photos.mydomain.com",
            "immich.mydomain.com:8443",
            "x@immich.mydomain.com",
            "immich.mydomain.com.evil",
            "198.18.1.5",
        ] {
            assert_eq!(
                check(&h1("/", Some(host)), SITE),
                Err(Rejection::WrongHost),
                "{host}"
            );
        }
        assert_eq!(
            check(&h2("photos.mydomain.com"), SITE),
            Err(Rejection::WrongHost)
        );
        // HTTP/2 with a matching :authority but a stray Host for another site.
        let mut req = h2(SITE);
        req.headers_mut().insert(
            header::HOST,
            HeaderValue::from_static("photos.mydomain.com"),
        );
        assert_eq!(check(&req, SITE), Err(Rejection::WrongHost));
    }

    #[test]
    fn malformed_requests_are_refused() {
        assert_eq!(check(&h1("/", None), SITE), Err(Rejection::NoHost));
        let abs = h1("https://immich.mydomain.com/", Some(SITE));
        assert_eq!(check(&abs, SITE), Err(Rejection::AbsoluteForm));
        let mut two = h1("/", Some(SITE));
        two.headers_mut()
            .append(header::HOST, HeaderValue::from_static(SITE));
        assert_eq!(check(&two, SITE), Err(Rejection::ManyHosts));
        let connect = Request::builder()
            .method(Method::CONNECT)
            .uri("immich.mydomain.com:443")
            .body(())
            .unwrap();
        assert_eq!(check(&connect, SITE), Err(Rejection::Connect));
        assert_eq!(
            Rejection::WrongHost.status(),
            StatusCode::MISDIRECTED_REQUEST
        );
    }

    #[test]
    fn upstream_request_replaces_forwarding_headers() {
        let req = Request::builder()
            .uri("/api/ping?x=1")
            .version(Version::HTTP_11)
            .header(header::HOST, SITE)
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-real-ip", "6.6.6.6")
            .header(header::CONNECTION, "keep-alive, x-secret")
            .header("x-secret", "drop me")
            .body(())
            .unwrap();
        let up = upstream_request(req, SITE, 443, "10.8.2.1".parse().unwrap()).unwrap();
        assert_eq!(up.uri(), "https://immich.mydomain.com/api/ping?x=1");
        assert_eq!(up.headers()["host"], SITE);
        assert_eq!(up.headers()["x-forwarded-for"], "10.8.2.1");
        assert_eq!(up.headers()["x-forwarded-proto"], "https");
        assert!(up.headers().get("x-real-ip").is_none());
        assert!(up.headers().get("x-secret").is_none());
        assert!(up.headers().get(header::CONNECTION).is_none());
    }

    #[test]
    fn upgrades_and_cookies_survive_the_rewrite() {
        let req = Request::builder()
            .uri("/api/socket.io/")
            .version(Version::HTTP_11)
            .header(header::HOST, SITE)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::COOKIE, "a=1")
            .header(header::COOKIE, "b=2")
            .body(())
            .unwrap();
        assert!(upgrade(&req).is_some());
        let up = upstream_request(req, SITE, 8443, "10.8.2.1".parse().unwrap()).unwrap();
        assert_eq!(up.uri(), "https://immich.mydomain.com:8443/api/socket.io/");
        assert_eq!(up.headers()[header::CONNECTION], "upgrade");
        assert_eq!(up.headers()[header::UPGRADE], "websocket");
        assert_eq!(up.headers()[header::COOKIE], "a=1; b=2");
    }

    #[test]
    fn only_websocket_upgrades_pass() {
        let req = Request::builder()
            .uri("/")
            .version(Version::HTTP_11)
            .header(header::HOST, SITE)
            .header(header::CONNECTION, "Upgrade, HTTP2-Settings")
            .header(header::UPGRADE, "h2c")
            .header("http2-settings", "AAMAAABkAAQAAP__")
            .body(())
            .unwrap();
        assert!(upgrade(&req).is_none());
        let up = upstream_request(req, SITE, 443, "10.8.2.1".parse().unwrap()).unwrap();
        assert!(up.headers().get(header::UPGRADE).is_none());
        assert!(up.headers().get("http2-settings").is_none());
    }
}
