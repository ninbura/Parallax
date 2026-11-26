//! The home's public IPv4 address, for the guest hairpin drop.
//!
//! A guest tier with `internet` reaches public addresses only. The home's
//! own public address is public too, but the router hairpins traffic sent
//! to it back into the home's port forwards, so the guest would reach
//! exactly what its grants leave out. Such tiers drop it, and for that the
//! gateway has to know it ([`hairpin`]). Hosts named by DNS name need it
//! too: a name that resolves to it is a port forward ([`crate::names`]).
//!
//! [`find`] asks, in order, and takes the first that works:
//! 1. `server.public_ip.address`, when set: no lookup.
//! 2. The WireGuard endpoint's host, when it's a public IPv4 address.
//! 3. The endpoint's hostname through `server.dns.public_resolver` (plain
//!    DNS). Often the home router, which may answer the home's own name
//!    with the LAN address; an answer that isn't one public address is
//!    refused.
//! 4. Each `server.public_ip.encrypted_dns` provider, in order (off unless
//!    the operator lists one). Never raced: a provider only sees the
//!    question when everything before it failed.
//!
//! Nothing asks a "what's my IP" service.

use std::net::Ipv4Addr;

use crate::generate::firewall::NOT_PUBLIC;
use crate::io::{Nameserver, Resolver};
use crate::model::{Config, Rule, ServerConfig};

/// Whether some tier needs the address for the hairpin drop: one with
/// `internet` that reaches public addresses only (no `all_networks`).
pub fn hairpin(config: &Config) -> bool {
    crate::tier::tiers(config)
        .iter()
        .any(|t| t.has(&Rule::Internet) && !t.has(&Rule::AllNetworks))
}

/// Whether to look the address up: for the hairpin drop, or to tell a
/// host named by DNS name that resolves to it (a port forward) from one
/// that resolves somewhere Parallax doesn't know ([`crate::names`]).
pub fn needed(config: &Config) -> bool {
    hairpin(config) || !crate::names::used(config).is_empty()
}

/// Not private, reserved, shared (CGNAT) or otherwise outside the internet.
pub fn is_public(ip: Ipv4Addr) -> bool {
    !NOT_PUBLIC.iter().any(|n| n.contains(&ip))
}

/// The address and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub address: Ipv4Addr,
    /// For the log: "server.public_ip.address", "the endpoint", or the
    /// name and the nameserver that answered.
    pub source: String,
}

/// The endpoint's host: an IPv4 address, a hostname, or a bracketed IPv6 address.
fn endpoint_host(server: &ServerConfig) -> &str {
    let endpoint = &server.wireguard.endpoint;
    endpoint
        .rsplit_once(':')
        .map_or(endpoint.as_str(), |(host, _)| host)
}

/// The address the configuration itself gives, with no lookup: a fixed
/// `server.public_ip.address`, or a public IPv4 endpoint. A private one (a
/// lab, double NAT) isn't the home's public IP.
pub fn configured(server: &ServerConfig) -> Option<Found> {
    if let Some(address) = server.public_ip.address {
        return Some(Found {
            address,
            source: "server.public_ip.address".into(),
        });
    }
    endpoint_host(server)
        .parse::<Ipv4Addr>()
        .ok()
        .filter(|a| is_public(*a))
        .map(|address| Found {
            address,
            source: format!("the endpoint {}", server.wireguard.endpoint),
        })
}

/// What generation uses: the configured address when there is one (it's
/// right the moment it's saved), otherwise the last one a lookup found.
pub fn effective(server: &ServerConfig, last_found: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    configured(server).map(|f| f.address).or(last_found)
}

/// Find the address. `Err` lists why each way tried failed.
pub fn find(server: &ServerConfig, resolver: &dyn Resolver) -> Result<Found, Vec<String>> {
    if let Some(found) = configured(server) {
        return Ok(found);
    }
    let endpoint = &server.wireguard.endpoint;
    let host = endpoint_host(server);
    if host.starts_with('[') {
        return Err(vec![format!(
            "the endpoint {endpoint} is an IPv6 address; set server.public_ip.address to the home's public IPv4 address"
        )]);
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Err(vec![format!(
            "the endpoint {endpoint} is not a public address (a lab, or double NAT?); set server.public_ip.address to the home's public IPv4 address"
        )]);
    }
    let mut problems = Vec::new();
    let via = std::iter::once(Nameserver::Plain(server.dns.public_resolver)).chain(
        server
            .public_ip
            .encrypted_dns
            .iter()
            .map(|p| Nameserver::Encrypted(*p)),
    );
    for nameserver in via {
        let answer = resolver
            .lookup_ipv4(host, nameserver)
            .map_err(|e| e.to_string())
            .and_then(|addresses| one_public(&addresses));
        match answer {
            Ok(address) => {
                return Ok(Found {
                    address,
                    source: format!("{host} through {nameserver}"),
                })
            }
            Err(problem) => problems.push(format!("{host} through {nameserver}: {problem}")),
        }
    }
    if server.public_ip.encrypted_dns.is_empty() {
        problems.push(
            "no encrypted DNS fallback is set (server.public_ip.encrypted_dns), and no fixed address (server.public_ip.address)"
                .into(),
        );
    }
    Err(problems)
}

/// The one public address in an answer. A resolver that rewrites the
/// home's own name answers a private address; several addresses aren't one
/// home connection.
fn one_public(addresses: &[Ipv4Addr]) -> Result<Ipv4Addr, String> {
    match addresses {
        [] => Err("no IPv4 address".into()),
        [one] if is_public(*one) => Ok(*one),
        [one] => Err(format!(
            "answered {one}, which isn't a public address (a resolver that rewrites your own hostname?)"
        )),
        many => Err(format!(
            "answered {} addresses ({}); a home connection has one",
            many.len(),
            many.iter()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::memory::FakeResolver;
    use crate::model::EncryptedDns;
    use crate::testing::canonical_config;

    // Public, unlike the documentation ranges (those are private as far as
    // `internet` is concerned).
    const HOME: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
    const NAME: &str = "vpn.mydomain.com";

    fn server() -> ServerConfig {
        canonical_config().server
    }

    fn plain() -> Nameserver {
        Nameserver::Plain(Ipv4Addr::new(1, 1, 1, 1))
    }

    #[test]
    fn only_guests_with_public_only_internet_need_it() {
        let mut cfg = canonical_config();
        assert!(!needed(&cfg));
        cfg.grants[0].rules.push(Rule::Internet);
        assert!(!needed(&cfg), "all_networks reaches the router anyway");
        cfg.grants[1].rules.push(Rule::Internet);
        assert!(needed(&cfg));
        assert!(hairpin(&cfg));
        // A host named by DNS name may point at it, without any hairpin.
        let mut cfg = canonical_config();
        cfg.services[0].host = crate::model::Host::Name("immich.mydomain.com".into());
        assert!(needed(&cfg));
        assert!(!hairpin(&cfg));
    }

    #[test]
    fn a_fixed_address_asks_nobody() {
        let mut s = server();
        s.public_ip.address = Some(HOME);
        let r = FakeResolver::new();
        assert_eq!(find(&s, &r).unwrap().address, HOME);
        assert!(r.asked.borrow().is_empty());
    }

    #[test]
    fn a_public_ip_endpoint_is_used_as_is() {
        let mut s = server();
        s.wireguard.endpoint = "1.2.3.9:51820".into();
        let r = FakeResolver::new();
        assert_eq!(find(&s, &r).unwrap().address, Ipv4Addr::new(1, 2, 3, 9));
        assert!(r.asked.borrow().is_empty());
    }

    #[test]
    fn a_private_ip_endpoint_is_not_the_public_ip() {
        let mut s = server();
        s.wireguard.endpoint = "192.168.1.5:51820".into();
        let r = FakeResolver::new();
        let problems = find(&s, &r).unwrap_err();
        assert!(problems[0].contains("not a public address"), "{problems:?}");
        assert!(r.asked.borrow().is_empty());
        assert_eq!(effective(&s, None), None);
    }

    #[test]
    fn the_configured_address_wins_over_the_last_found() {
        let last = Some(Ipv4Addr::new(1, 2, 3, 5));
        assert_eq!(effective(&server(), last), last, "a hostname endpoint");
        let mut s = server();
        s.public_ip.address = Some(HOME);
        assert_eq!(effective(&s, last), Some(HOME));
        let mut s = server();
        s.wireguard.endpoint = "1.2.3.6:51820".into();
        assert_eq!(effective(&s, last), Some(Ipv4Addr::new(1, 2, 3, 6)));
    }

    #[test]
    fn an_ipv6_endpoint_needs_a_fixed_address() {
        let mut s = server();
        s.wireguard.endpoint = "[2001:db8::1]:51820".into();
        let problems = find(&s, &FakeResolver::new()).unwrap_err();
        assert!(
            problems[0].contains("server.public_ip.address"),
            "{problems:?}"
        );
    }

    #[test]
    fn the_public_resolver_comes_first() {
        let r = FakeResolver::new().answer(NAME, plain(), &[HOME]);
        let found = find(&server(), &r).unwrap();
        assert_eq!(found.address, HOME);
        assert_eq!(found.source, "vpn.mydomain.com through 1.1.1.1");
    }

    #[test]
    fn a_private_answer_falls_through_to_encrypted_dns_in_order() {
        let mut s = server();
        s.public_ip.encrypted_dns = vec![EncryptedDns::Quad9, EncryptedDns::Cloudflare];
        let quad9 = Nameserver::Encrypted(EncryptedDns::Quad9);
        let cloudflare = Nameserver::Encrypted(EncryptedDns::Cloudflare);
        // Quad9 times out (no answer in the table); Cloudflare answers.
        let r = FakeResolver::new()
            .answer(NAME, plain(), &[Ipv4Addr::new(192, 168, 1, 10)])
            .answer(NAME, cloudflare, &[HOME]);
        let found = find(&s, &r).unwrap();
        assert_eq!(found.address, HOME);
        assert_eq!(
            r.asked
                .borrow()
                .iter()
                .map(|(_, via)| *via)
                .collect::<Vec<_>>(),
            [plain(), quad9, cloudflare]
        );
    }

    #[test]
    fn encrypted_dns_is_never_asked_once_one_answers() {
        let mut s = server();
        s.public_ip.encrypted_dns = vec![EncryptedDns::Quad9, EncryptedDns::Cloudflare];
        let r = FakeResolver::new().answer(NAME, plain(), &[]).answer(
            NAME,
            Nameserver::Encrypted(EncryptedDns::Quad9),
            &[HOME],
        );
        assert_eq!(find(&s, &r).unwrap().address, HOME);
        assert_eq!(r.asked.borrow().len(), 2);
    }

    #[test]
    fn every_failure_is_named() {
        let r = FakeResolver::new().answer(NAME, plain(), &[Ipv4Addr::new(100, 64, 0, 1)]);
        let problems = find(&server(), &r).unwrap_err();
        assert!(
            problems[0].contains("isn't a public address"),
            "{problems:?}"
        );
        assert!(problems[1].contains("encrypted_dns"), "{problems:?}");
    }

    #[test]
    fn answers_must_be_exactly_one_public_address() {
        assert_eq!(one_public(&[HOME]), Ok(HOME));
        for bad in [
            &[][..],
            &[Ipv4Addr::new(10, 0, 0, 1)],
            &[Ipv4Addr::new(198, 18, 1, 5)],
            &[HOME, Ipv4Addr::new(1, 2, 3, 5)],
        ] {
            assert!(one_public(bad).is_err(), "{bad:?}");
        }
    }
}
