//! The DNS server end to end on loopback: a fake upstream answers both the
//! home zone and public names, and clients ask from different 127.0.0.x
//! addresses, which the routes put in different tiers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests: failures should panic loudly"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_server::proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::rdata::{A, AAAA, CNAME};
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use parallax_core::generate::dns::DnsRoutes;
use parallax_core::logging::{Event, QueryOutcome, Tap};
use parallax_dns::{Dns, Reload};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
unmapped = []

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
tier = "personal"
members = ["{PERSONAL}/32"]
zones = ["mydomain.com", "xn--bcher-kva.ch"]
public = true

[[tier]]
tier = "family"
members = ["{FAMILY}/32"]
names = ["immich.mydomain.com", "photos.mydomain.com"]
public = {family_public}
"#
    )
}

struct Running {
    addr: SocketAddr,
    upstream: Upstream,
    reload: Reload,
}

impl Running {
    /// Hand the server `routes` and wait until it answers by them.
    async fn reload(&self, routes: DnsRoutes) {
        self.reload.send(routes).await.unwrap();
    }
}

async fn start() -> Running {
    start_tapped(None).await
}

/// With the server handing queries over to `tap`.
async fn start_tapped(tap: Option<Tap>) -> Running {
    let upstream = upstream().await;
    let mut dns = Dns::new(parsed(false), upstream.port).unwrap();
    if let Some(tap) = tap {
        dns = dns.tap(tap);
    }
    let reload = dns.reloader();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).await.unwrap();
    tokio::spawn(dns.run(udp, tcp));
    Running {
        addr,
        upstream,
        reload,
    }
}

fn parsed(public: bool) -> DnsRoutes {
    DnsRoutes::from_toml(&routes(public)).unwrap()
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

#[tokio::test(flavor = "multi_thread")]
async fn reloads_take_effect_and_a_broken_one_refuses_everything() {
    let s = start().await;
    // Confirmed: the next query already gets the new routes.
    s.reload(parsed(true)).await;
    let m = ask(FAMILY, s.addr, "example.org.", RecordType::A).await;
    assert_eq!(addresses(&m), ["9.9.9.9"]);

    // Routes that don't load (a mapping between prefixes of two lengths).
    let mut broken = parsed(false);
    broken.mappings[0].virt = "198.18.1.0/26".parse().unwrap();
    s.reload(broken).await;
    let m = ask(PERSONAL, s.addr, "immich.mydomain.com.", RecordType::A).await;
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);

    s.reload(parsed(false)).await;
    let m = ask(PERSONAL, s.addr, "immich.mydomain.com.", RecordType::A).await;
    assert_eq!(addresses(&m), ["198.18.1.5"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_logged_peer_s_queries_are_handed_over_without_answers() {
    let (tap, events) = Tap::new(64);
    tap.set_clients(
        [(
            FAMILY.parse().unwrap(),
            parallax_core::logging::Logged {
                peer: "guest".into(),
                level: parallax_core::model::LogLevel::Detailed,
            },
        )]
        .into(),
    );
    let s = start_tapped(Some(tap)).await;
    ask(FAMILY, s.addr, "Immich.MyDomain.com.", RecordType::A).await;
    ask(FAMILY, s.addr, "other.mydomain.com.", RecordType::A).await;
    ask_tcp(FAMILY, s.addr, "immich.mydomain.com.", RecordType::AAAA).await;
    // Not logged: nothing handed over.
    ask(PERSONAL, s.addr, "missing.mydomain.com.", RecordType::A).await;
    let mut got = Vec::new();
    while let Ok(event) = events.recv_timeout(Duration::from_millis(500)) {
        match event {
            Event::Query(q) => got.push(q),
            other => panic!("not a query: {other:?}"),
        }
    }
    let seen: Vec<_> = got
        .iter()
        .map(|q| {
            (
                q.name.as_str(),
                q.query_type.as_str(),
                q.protocol,
                q.outcome,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("immich.mydomain.com.", "A", 17, QueryOutcome::Answered),
            ("other.mydomain.com.", "A", 17, QueryOutcome::Refused),
            ("immich.mydomain.com.", "AAAA", 6, QueryOutcome::Answered),
        ]
    );
    assert!(got.iter().all(|q| q.client.to_string() == FAMILY));
    assert!(
        !format!("{got:?}").contains("198.18"),
        "never the answer: {got:?}"
    );
}

/// A query under way when new routes come answers before they're
/// confirmed: by then its address may be another peer's.
#[tokio::test(flavor = "multi_thread")]
async fn a_reload_is_confirmed_once_queries_under_the_old_routes_answered() {
    let s = start().await;
    let addr = s.addr;
    // The upstream never answers this one: it ends at the upstream timeout.
    let slow =
        tokio::spawn(async move { ask(PERSONAL, addr, "slow.mydomain.com.", RecordType::A).await });
    tokio::time::sleep(Duration::from_millis(200)).await;
    s.reload(parsed(true)).await;
    assert!(
        slow.is_finished(),
        "confirmed while a query under the old routes was still out"
    );
}

/// Where `client` may look `name` up: `Home`, `Public` or `Refused`.
fn route_of(routes: &DnsRoutes, client: &str, name: &str) -> &'static str {
    match routes.route(client.parse().unwrap(), name) {
        parallax_core::generate::dns::Route::Home { .. } => "home",
        parallax_core::generate::dns::Route::Public => "public",
        parallax_core::generate::dns::Route::Refused => "refused",
    }
}

#[test]
fn while_an_apply_runs_a_member_gets_what_both_routes_give_it() {
    let before = parsed(false);
    // Nothing changes: the routes stay as they are.
    assert_eq!(parallax_dns::overlap(&before, &before), before);
    // PERSONAL's address moves to someone with only `family`'s names.
    let mut after = parsed(true);
    after.tiers[0].members.clear();
    after.tiers[1]
        .members
        .push(format!("{PERSONAL}/32").parse().unwrap());
    let both = parallax_dns::overlap(&before, &after);
    assert_eq!(route_of(&both, PERSONAL, "immich.mydomain.com"), "home");
    // Its old owner's whole zone: not the new owner's. Public names: both.
    assert_eq!(route_of(&both, PERSONAL, "nas.mydomain.com"), "refused");
    assert_eq!(route_of(&both, PERSONAL, "example.org"), "public");
    // FAMILY gains public names in `after`: not before the apply has worked.
    assert_eq!(route_of(&both, FAMILY, "example.org"), "refused");
    assert_eq!(route_of(&both, FAMILY, "photos.mydomain.com"), "home");
    // A zone only `after` has: nobody's yet, and not a public name either.
    let mut zoned = parsed(true);
    zoned.zones.push(parallax_core::generate::dns::DnsZone {
        name: "internal.example".into(),
        network: "lab".into(),
        upstream: vec![UPSTREAM],
    });
    let both = parallax_dns::overlap(&parsed(true), &zoned);
    assert_eq!(
        route_of(&both, PERSONAL, "host.internal.example"),
        "refused"
    );
    assert_eq!(route_of(&both, PERSONAL, "example.org"), "public");
    // A child zone carved out of a zone a tier has whole: refused meanwhile.
    let mut child = parsed(false);
    child.zones.push(parallax_core::generate::dns::DnsZone {
        name: "lab.mydomain.com".into(),
        network: "lab".into(),
        upstream: vec![UPSTREAM],
    });
    let both = parallax_dns::overlap(&before, &child);
    assert_eq!(route_of(&both, PERSONAL, "x.lab.mydomain.com"), "refused");
    assert_eq!(route_of(&both, PERSONAL, "nas.mydomain.com"), "home");
    // A member only one side has gets nothing.
    let mut gone = parsed(false);
    gone.tiers.remove(1);
    let both = parallax_dns::overlap(&before, &gone);
    assert_eq!(route_of(&both, FAMILY, "immich.mydomain.com"), "refused");
}
