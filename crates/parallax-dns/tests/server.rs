//! The DNS server end to end on loopback: a fake upstream answers both the
//! home zone and public names, and clients ask from different 127.0.0.x
//! addresses, which the routes put in different tiers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests: failures should panic loudly"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_server::proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::{A, AAAA, CNAME};
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use parallax_dns::Dns;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;

const UPSTREAM: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 10);
const PERSONAL: &str = "127.0.0.2";
const FAMILY: &str = "127.0.0.3";
const STRANGER: &str = "127.0.0.9";
/// Addresses in the big answer: more than fit a 512-byte UDP message.
const BIG: u8 = 60;

/// What the fake upstream knows. Names are lower case with a trailing dot.
fn upstream_answer(name: &str, qtype: RecordType) -> Result<Vec<RData>, ResponseCode> {
    let a = |s: &str| RData::A(A(s.parse().unwrap()));
    match (name, qtype) {
        ("immich.mydomain.com.", RecordType::A) => Ok(vec![a("192.168.1.5")]),
        ("other.mydomain.com.", RecordType::A) => Ok(vec![a("192.168.1.5")]),
        // A host on a subnet Parallax doesn't know, next to a mapped one.
        ("vlan.mydomain.com.", RecordType::A) => Ok(vec![a("10.99.0.5"), a("192.168.1.6")]),
        ("big.mydomain.com.", RecordType::A) => Ok((1..=BIG)
            .map(|i| RData::A(A(Ipv4Addr::new(192, 168, 1, i))))
            .collect()),
        ("missing.mydomain.com.", _) => Err(ResponseCode::NXDomain),
        ("broken.mydomain.com.", _) => Err(ResponseCode::ServFail),
        ("www.xn--bcher-kva.ch.", RecordType::A) => Ok(vec![a("192.168.1.7")]),
        ("example.org.", RecordType::A) => Ok(vec![a("9.9.9.9")]),
        ("rebind.example.org.", RecordType::A) => Ok(vec![a("192.168.1.5"), a("10.8.0.1")]),
        ("v6.example.org.", RecordType::AAAA) => {
            Ok(vec![RData::AAAA(AAAA("2606:4700::1111".parse().unwrap()))])
        }
        (_, _) => Ok(Vec::new()),
    }
}

/// A fake home and public resolver on UPSTREAM, recording what it's asked.
/// Over UDP it truncates anything with more than 20 answers, so the server
/// has to fall back to TCP. It never answers `slow.mydomain.com`.
struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Upstream {
    fn asked(&self, what: &str) -> bool {
        self.seen.lock().unwrap().iter().any(|s| s == what)
    }
}

fn respond(request: &Message, over_udp: bool) -> Option<Message> {
    let query = request.queries.first()?;
    let name = query.name().to_ascii().to_ascii_lowercase();
    if name == "slow.mydomain.com." {
        return None;
    }
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_query(query.clone());
    // An alias: a granted hostname that is a CNAME for a sibling's name.
    if name == "photos.mydomain.com." && query.query_type() == RecordType::A {
        let other = Name::from_ascii("other.mydomain.com.").unwrap();
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            300,
            RData::CNAME(CNAME(other.clone())),
        ));
        response.add_answer(Record::from_rdata(
            other,
            300,
            RData::A(A("192.168.1.5".parse().unwrap())),
        ));
        return Some(response);
    }
    match upstream_answer(&name, query.query_type()) {
        Ok(data) if over_udp && data.len() > 20 => response.metadata.truncation = true,
        Ok(data) => {
            for d in data {
                response.add_answer(Record::from_rdata(query.name().clone(), 300, d));
            }
        }
        Err(code) => response.metadata.response_code = code,
    }
    Some(response)
}

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

async fn upstream() -> Upstream {
    // UDP and TCP on the same port; walk a private range until both bind.
    let (udp, tcp, port) = loop {
        let base = 20000 + (std::process::id() % 20000) as u16;
        let port = base.wrapping_add(NEXT_PORT.fetch_add(1, Ordering::SeqCst));
        let Ok(udp) = UdpSocket::bind((UPSTREAM, port)).await else {
            continue;
        };
        let Ok(tcp) = TcpListener::bind((UPSTREAM, port)).await else {
            continue;
        };
        break (udp, tcp, port);
    };
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let record = |seen: &Arc<Mutex<Vec<String>>>, m: &Message| {
        if let Some(q) = m.queries.first() {
            seen.lock().unwrap().push(format!(
                "{} {}",
                q.name().to_ascii().to_ascii_lowercase(),
                q.query_type()
            ));
        }
    };
    let udp_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let Ok(request) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            record(&udp_seen, &request);
            if let Some(response) = respond(&request, true) {
                udp.send_to(&response.to_vec().unwrap(), from)
                    .await
                    .unwrap();
            }
        }
    });
    let tcp_seen = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let seen = Arc::clone(&tcp_seen);
            tokio::spawn(async move {
                loop {
                    let Ok(len) = stream.read_u16().await else {
                        return;
                    };
                    let mut buf = vec![0u8; len as usize];
                    if stream.read_exact(&mut buf).await.is_err() {
                        return;
                    }
                    let Ok(request) = Message::from_vec(&buf) else {
                        return;
                    };
                    record(&seen, &request);
                    let Some(response) = respond(&request, false) else {
                        continue;
                    };
                    let bytes = response.to_vec().unwrap();
                    stream.write_u16(bytes.len() as u16).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
        }
    });
    Upstream { port, seen }
}

fn routes(family_public: bool) -> String {
    format!(
        r#"listen = "127.0.0.1:53"
public_resolver = "{UPSTREAM}"

[[zone]]
name = "mydomain.com"
network = "home"
upstream = ["{UPSTREAM}"]

[[zone]]
name = "xn--bcher-kva.ch"
network = "home"
upstream = ["{UPSTREAM}"]

[[mapping]]
real = "192.168.1.0/24"
virtual = "198.18.1.0/24"

[[tier]]
template = "personal"
members = ["{PERSONAL}/32"]
zones = ["mydomain.com", "xn--bcher-kva.ch"]
public = true

[[tier]]
template = "family"
members = ["{FAMILY}/32"]
names = ["immich.mydomain.com", "photos.mydomain.com"]
public = {family_public}
"#
    )
}

struct Running {
    addr: SocketAddr,
    upstream: Upstream,
    routes_path: PathBuf,
    reload: Arc<Notify>,
}

static NEXT_DIR: AtomicU16 = AtomicU16::new(0);

async fn start() -> Running {
    let upstream = upstream().await;
    let dir = std::env::temp_dir().join(format!(
        "parallax-dns-test-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let routes_path = dir.join("routes.toml");
    std::fs::write(&routes_path, routes(false)).unwrap();
    let dns = Dns::load(&routes_path, upstream.port).unwrap();
    let reload = dns.reload_trigger();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(dns.run(udp, tcp));
    Running {
        addr,
        upstream,
        routes_path,
        reload,
    }
}

fn query(name: &str, qtype: RecordType, edns: bool) -> Vec<u8> {
    query_with_edns(name, qtype, edns.then_some(0))
}

fn query_with_edns(name: &str, qtype: RecordType, edns_version: Option<u8>) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.id = 4242;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    if let Some(version) = edns_version {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_version(version);
        m.set_edns(e);
    }
    m.to_vec().unwrap()
}

async fn ask(from: &str, server: SocketAddr, name: &str, qtype: RecordType) -> Message {
    ask_udp(from, server, name, qtype, true).await
}

async fn ask_udp(
    from: &str,
    server: SocketAddr,
    name: &str,
    qtype: RecordType,
    edns: bool,
) -> Message {
    let socket = UdpSocket::bind((from, 0)).await.unwrap();
    socket
        .send_to(&query(name, qtype, edns), server)
        .await
        .unwrap();
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(8), socket.recv_from(&mut buf))
        .await
        .expect("no answer within 8s")
        .unwrap();
    let m = Message::from_vec(&buf[..n]).unwrap();
    assert_eq!(m.metadata.id, 4242);
    m
}

async fn ask_tcp(from: &str, server: SocketAddr, name: &str, qtype: RecordType) -> Message {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket
        .bind((from.parse::<Ipv4Addr>().unwrap(), 0).into())
        .unwrap();
    let mut stream: TcpStream = socket.connect(server).await.unwrap();
    let q = query(name, qtype, false);
    stream.write_u16(q.len() as u16).await.unwrap();
    stream.write_all(&q).await.unwrap();
    let len = stream.read_u16().await.unwrap();
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.unwrap();
    Message::from_vec(&buf).unwrap()
}

fn addresses(m: &Message) -> Vec<String> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(A(a)) => Some(a.to_string()),
            RData::AAAA(AAAA(a)) => Some(a.to_string()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn home_names_come_back_in_mapped_space() {
    let s = start().await;
    let m = ask(PERSONAL, s.addr, "immich.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert!(m.metadata.recursion_available);
    assert_eq!(addresses(&m), ["198.18.1.5"]);
    // Any case, as clients send it.
    let m = ask(PERSONAL, s.addr, "Immich.MyDomain.com.", RecordType::A).await;
    assert_eq!(addresses(&m), ["198.18.1.5"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tier_gets_only_its_names() {
    let s = start().await;
    let m = ask(FAMILY, s.addr, "immich.mydomain.com.", RecordType::A).await;
    assert_eq!(addresses(&m), ["198.18.1.5"]);
    for name in ["other.mydomain.com.", "example.org."] {
        let m = ask(FAMILY, s.addr, name, RecordType::A).await;
        assert_eq!(m.metadata.response_code, ResponseCode::Refused, "{name}");
        assert!(m.answers.is_empty());
    }
    // Refused names never reach an upstream.
    assert!(!s.upstream.asked("other.mydomain.com. A"));
    assert!(!s.upstream.asked("example.org. A"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_name_grant_does_not_reveal_its_alias() {
    let s = start().await;
    // The whole zone: the CNAME chain as the home resolver gave it.
    let m = ask(PERSONAL, s.addr, "photos.mydomain.com.", RecordType::A).await;
    assert_eq!(m.answers.len(), 2);
    assert_eq!(addresses(&m), ["198.18.1.5"]);
    // Just the name: its address, under its own name, and nothing that
    // names the sibling it points at.
    let m = ask(FAMILY, s.addr, "photos.mydomain.com.", RecordType::A).await;
    assert_eq!(addresses(&m), ["198.18.1.5"]);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.answers[0].name.to_ascii(), "photos.mydomain.com.");
    assert!(!m.answers.iter().any(|r| matches!(r.data, RData::CNAME(_))));
}

#[tokio::test(flavor = "multi_thread")]
async fn punycode_zones_stay_home() {
    let s = start().await;
    // Answered by the home zone (rewritten), not sent to the public resolver
    // (which would drop the private address).
    let m = ask(PERSONAL, s.addr, "www.xn--bcher-kva.ch.", RecordType::A).await;
    assert_eq!(addresses(&m), ["198.18.1.7"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn newer_edns_versions_get_badvers() {
    let s = start().await;
    let socket = UdpSocket::bind((PERSONAL, 0)).await.unwrap();
    socket
        .send_to(
            &query_with_edns("immich.mydomain.com.", RecordType::A, Some(1)),
            s.addr,
        )
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(8), socket.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let m = Message::from_vec(&buf[..n]).unwrap();
    // 16 on the wire; hickory decodes it as BADSIG, which shares the number.
    assert_eq!(u16::from(m.metadata.response_code), 16);
    assert!(m.answers.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn addresses_outside_every_tier_are_refused() {
    let s = start().await;
    let m = ask(STRANGER, s.addr, "immich.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    let m = ask_tcp(STRANGER, s.addr, "example.org.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
}

#[tokio::test(flavor = "multi_thread")]
async fn zone_transfers_and_any_are_refused() {
    let s = start().await;
    for qtype in [RecordType::ANY, RecordType::AXFR] {
        let m = ask_tcp(PERSONAL, s.addr, "mydomain.com.", qtype).await;
        assert_eq!(m.metadata.response_code, ResponseCode::Refused, "{qtype}");
    }
    assert!(!s.upstream.asked("mydomain.com. AXFR"));
}

#[tokio::test(flavor = "multi_thread")]
async fn home_names_lose_addresses_on_unknown_subnets() {
    let s = start().await;
    // 10.99.0.5 is on no configured network: off-site the client would
    // reach whatever uses that address on the visited network.
    let m = ask(PERSONAL, s.addr, "vlan.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&m), ["198.18.1.6"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn home_names_have_no_ipv6() {
    let s = start().await;
    let m = ask(PERSONAL, s.addr, "immich.mydomain.com.", RecordType::AAAA).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert!(m.answers.is_empty());
    assert!(!s.upstream.asked("immich.mydomain.com. AAAA"));
}

#[tokio::test(flavor = "multi_thread")]
async fn public_names_without_inward_addresses() {
    let s = start().await;
    let m = ask(PERSONAL, s.addr, "example.org.", RecordType::A).await;
    assert_eq!(addresses(&m), ["9.9.9.9"]);
    let m = ask(PERSONAL, s.addr, "v6.example.org.", RecordType::AAAA).await;
    assert_eq!(addresses(&m), ["2606:4700::1111"]);
    // A public name pointing at the home network or the gateway: dropped.
    let m = ask(PERSONAL, s.addr, "rebind.example.org.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert!(m.answers.is_empty(), "{:?}", addresses(&m));
}

#[tokio::test(flavor = "multi_thread")]
async fn negative_answers_pass_through() {
    let s = start().await;
    let m = ask(PERSONAL, s.addr, "missing.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test(flavor = "multi_thread")]
async fn large_answers_truncate_over_udp_and_arrive_over_tcp() {
    let s = start().await;
    // The upstream truncates over UDP, so this also needs the server's TCP fallback.
    let m = ask_tcp(PERSONAL, s.addr, "big.mydomain.com.", RecordType::A).await;
    let got = addresses(&m);
    assert_eq!(got.len(), BIG as usize);
    assert!(got.iter().all(|a| a.starts_with("198.18.1.")), "{got:?}");
    // Without EDNS a client gets 512 bytes over UDP: truncated, so it retries over TCP.
    let m = ask_udp(PERSONAL, s.addr, "big.mydomain.com.", RecordType::A, false).await;
    assert!(m.metadata.truncation);
    assert!(m.answers.len() < BIG as usize);
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_failures_are_servfail() {
    let s = start().await;
    let m = ask(PERSONAL, s.addr, "broken.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    let started = Instant::now();
    let m = ask(PERSONAL, s.addr, "slow.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert!(
        started.elapsed() < Duration::from_secs(7),
        "{:?}",
        started.elapsed()
    );
}

/// Ask until the answer has `code`, for up to two seconds (a reload is async).
async fn eventually(from: &str, server: SocketAddr, name: &str, code: ResponseCode) -> Message {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let m = ask(from, server, name, RecordType::A).await;
        if m.metadata.response_code == code || Instant::now() > deadline {
            return m;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn reloads_take_effect_and_a_broken_one_refuses_everything() {
    let s = start().await;
    std::fs::write(&s.routes_path, routes(true)).unwrap();
    s.reload.notify_one();
    let m = eventually(FAMILY, s.addr, "example.org.", ResponseCode::NoError).await;
    assert_eq!(addresses(&m), ["9.9.9.9"]);

    std::fs::write(&s.routes_path, "listen = ").unwrap();
    s.reload.notify_one();
    let m = eventually(
        PERSONAL,
        s.addr,
        "immich.mydomain.com.",
        ResponseCode::Refused,
    )
    .await;
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);

    std::fs::write(&s.routes_path, routes(false)).unwrap();
    s.reload.notify_one();
    let m = eventually(
        PERSONAL,
        s.addr,
        "immich.mydomain.com.",
        ResponseCode::NoError,
    )
    .await;
    assert_eq!(addresses(&m), ["198.18.1.5"]);
}
