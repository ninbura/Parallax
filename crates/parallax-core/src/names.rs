//! Hosts named by DNS name: `host = "nas.mydomain.com"` in a service or a
//! `host` grant.
//!
//! A name is looked up through the home resolvers of the network whose zone
//! holds it (validation makes sure one does), and grants the addresses it
//! has. Those are an input to generation, like the date and the home's
//! public IP: [`crate::Model::with_names`] takes them, so the ruleset stays
//! deterministic and tests need no DNS.
//!
//! - **Only allowed answers.** Every address must be inside a configured
//!   network's real subnet, or be the home's public IP (a service behind a
//!   port forward); otherwise the whole answer is refused, so a changed or
//!   spoofed answer can't open a host Parallax doesn't know.
//! - **The home's public IP, one port at a time.** There every port is a
//!   port forward, maybe each to another machine, and a raw web port
//!   reaches every site behind it without the proxy's name check. So a
//!   template that doesn't reach it anyway (`all_networks` + `internet`) gets
//!   no `host` grant there, and web ports only as an HTTPS service with
//!   `hostnames` ([`public_ip_refusal`]).
//! - **Only the latest answer counts.** A lookup that fails, comes back
//!   empty or is refused leaves the name granting nothing until it resolves
//!   again, with a warning saying why. An old answer is never kept: a name
//!   that's gone may have been dropped on purpose, and its address may now
//!   belong to something else.
//! - **A save can't add a problem** ([`check_save`]): a new name must
//!   resolve, and a change mustn't leave a known address outside every
//!   network. Problems that were already there don't block unrelated
//!   changes, so a resolver being down never stops removing a peer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::io::{Nameserver, Resolver};
use crate::model::{ranges, Config, Grant, Host, Network, PortRange, Proto, Template};

/// The addresses each name was last found to have, sorted. Names that were
/// never found are absent.
pub type Resolved = BTreeMap<String, Vec<Ipv4Addr>>;

/// Every name the configuration uses as a host.
pub fn used(config: &Config) -> BTreeSet<&str> {
    let services = config.services.iter().map(|s| &s.host);
    let grants = config
        .templates
        .iter()
        .flat_map(|t| &t.grants)
        .filter_map(|g| match g {
            Grant::Host { host, .. } => Some(host),
            _ => None,
        });
    services.chain(grants).filter_map(Host::name).collect()
}

/// `name` is `zone` itself or a name under it. Zones may be written in
/// any case; names are lower case.
pub(crate) fn in_zone(name: &str, zone: &str) -> bool {
    let zone = zone.to_ascii_lowercase();
    name == zone
        || name
            .strip_suffix(&zone)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// The network whose zone holds `name`: the most specific zone wins, as in
/// the DNS server.
pub fn network_of<'a>(config: &'a Config, name: &str) -> Option<&'a Network> {
    config
        .networks
        .iter()
        .flat_map(|n| n.domains.iter().map(move |d| (d, n)))
        .filter(|(d, _)| in_zone(name, d))
        .max_by_key(|(d, _)| d.len())
        .map(|(_, n)| n)
}

/// Why `addresses` can't be granted for `name`, if they can't. Each must be
/// inside a configured network or be `public_ip`, the home's public IP.
pub fn refused(
    config: &Config,
    public_ip: Option<Ipv4Addr>,
    name: &str,
    addresses: &[Ipv4Addr],
) -> Option<String> {
    if addresses.is_empty() {
        return Some(format!("{name} has no IPv4 address"));
    }
    let outside: Vec<String> = addresses
        .iter()
        .filter(|a| {
            Some(**a) != public_ip && !config.networks.iter().any(|n| n.subnet.contains(*a))
        })
        .map(Ipv4Addr::to_string)
        .collect();
    (!outside.is_empty()).then(|| {
        let home = match public_ip {
            Some(ip) => format!("the home's public IP {ip}"),
            None => "the home's public IP (not known yet)".to_string(),
        };
        format!(
            "{name} resolved to {}, outside every configured network and not {home}",
            outside.join(", ")
        )
    })
}

/// Plain HTTP on tcp/80, and HTTPS or HTTP/3 on 443: ports a web server
/// answers for every site it hosts. Does `range` take one in?
pub(crate) fn covers_web(range: PortRange) -> bool {
    range.contains(range.proto, 443) || range.contains(Proto::Tcp, 80)
}

/// Why `template` may not reach `ports` (`None`: every port) on the home's
/// public IP, if it may not. `proxied`: through the HTTPS proxy, which
/// checks the name. A template with `all_networks` and `internet` reaches
/// the home's public IP anyway and isn't limited.
pub fn public_ip_refusal(
    template: &Template,
    ports: Option<&[PortRange]>,
    proxied: bool,
) -> Option<&'static str> {
    if template.grants.contains(&Grant::AllNetworks) && template.grants.contains(&Grant::Internet) {
        return None;
    }
    match ports {
        None => Some(
            "every port there is a port forward, so a grant without ports would open them all; list its ports",
        ),
        Some(ports) if !proxied && ports.iter().copied().any(covers_web) => Some(
            "web ports there serve every site behind the forward; grant it as a service with hostnames, so the HTTPS proxy checks the name",
        ),
        Some(_) => None,
    }
}

/// Look `name` up through its network's resolvers, in order: the first
/// that answers decides. The addresses come back sorted, and only when
/// [`refused`] has nothing against them.
pub fn lookup(
    config: &Config,
    public_ip: Option<Ipv4Addr>,
    resolver: &dyn Resolver,
    name: &str,
) -> Result<Vec<Ipv4Addr>, String> {
    let network = network_of(config, name)
        .ok_or_else(|| format!("{name} is not under any network's domains"))?;
    let mut failures = Vec::new();
    for upstream in &network.upstream_dns {
        match resolver.lookup_ipv4(name, Nameserver::Plain(*upstream)) {
            Ok(mut addresses) => {
                addresses.sort();
                addresses.dedup();
                return match refused(config, public_ip, name, &addresses) {
                    Some(why) => Err(format!("{why} (asked {upstream})")),
                    None => Ok(addresses),
                };
            }
            Err(e) => failures.push(format!("{upstream}: {e}")),
        }
    }
    Err(format!(
        "can't look up {name} (network '{}': {})",
        network.name,
        if failures.is_empty() {
            "no upstream_dns".to_string()
        } else {
            failures.join("; ")
        }
    ))
}

/// The outcome of looking every name up.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Refreshed {
    /// The names that resolved to allowed addresses.
    pub resolved: Resolved,
    /// Why each other name didn't.
    pub problems: Vec<String>,
}

/// Look up every name the configuration uses.
pub fn refresh(config: &Config, public_ip: Option<Ipv4Addr>, resolver: &dyn Resolver) -> Refreshed {
    let mut out = Refreshed::default();
    for name in used(config) {
        match lookup(config, public_ip, resolver, name) {
            Ok(addresses) => {
                out.resolved.insert(name.to_string(), addresses);
            }
            Err(why) => out.problems.push(format!(
                "{why}; grants on it give nothing until it resolves"
            )),
        }
    }
    out
}

/// What's wrong with the names of `config` given what they resolved to:
/// names that didn't resolve, answers no longer allowed (a network or the
/// public IP changed since), and grants the home's public IP doesn't take
/// ([`public_ip_refusal`]). Each problem names what stays in effect.
pub fn problems(config: &Config, public_ip: Option<Ipv4Addr>, resolved: &Resolved) -> Vec<String> {
    let mut out: Vec<String> = used(config)
        .into_iter()
        .filter_map(|name| match resolved.get(name) {
            None => Some(format!(
                "{name} didn't resolve; grants on it give nothing until it does"
            )),
            Some(addresses) => refused(config, public_ip, name, addresses)
                .map(|why| format!("{why}; grants on it give nothing")),
        })
        .collect();
    let Some(home) = public_ip else {
        return out;
    };
    for t in &config.templates {
        for g in &t.grants {
            let (what, host, ports, proxied) = match g {
                Grant::Host { host, ports } if ports.is_empty() => {
                    (format!("host {host}"), host, None, false)
                }
                Grant::Host { host, ports } => (
                    format!(
                        "host {host} {}",
                        ports
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    host,
                    Some(ranges(ports)),
                    false,
                ),
                Grant::Service { name } => match config.service(name) {
                    Some(s) => (
                        format!("service '{name}'"),
                        &s.host,
                        Some(ranges(&s.ports)),
                        s.is_proxied(),
                    ),
                    None => continue,
                },
                _ => continue,
            };
            let Some(name) = host.name() else { continue };
            let at_home = resolved.get(name).is_some_and(|a| a.contains(&home));
            if let Some(why) = public_ip_refusal(t, ports.as_deref(), proxied).filter(|_| at_home) {
                out.push(format!(
                    "template '{}': grant {what}: {name} is the home's public IP {home}, and {why}; it gives nothing there",
                    t.name
                ));
            }
        }
    }
    out
}

/// Before saving `new` over `old`: look up the names `new` adds, and refuse
/// the change if a new name doesn't resolve or the change adds a problem.
/// Returns the names to use from now on.
pub fn check_save(
    old: Option<&Config>,
    new: &Config,
    public_ip: Option<Ipv4Addr>,
    resolver: &dyn Resolver,
    known: &Resolved,
) -> Result<Resolved, Vec<String>> {
    let mut resolved = known.clone();
    let mut failed = Vec::new();
    // Names `old` already had keep what they have; one never found is an
    // old problem, and the regular lookups keep trying it. Every other name
    // is asked now, even if an answer for it is lying around (from a
    // configuration a restore replaced).
    // A known answer `new` no longer allows (its network was renumbered in
    // this change) is asked again too.
    let had = old.map(used).unwrap_or_default();
    for name in used(new) {
        let still_fine = match known.get(name) {
            Some(addresses) => refused(new, public_ip, name, addresses).is_none(),
            None => true,
        };
        if had.contains(name) && still_fine {
            continue;
        }
        match lookup(new, public_ip, resolver, name) {
            Ok(addresses) => {
                resolved.insert(name.to_string(), addresses);
            }
            // A name `old` had: whether this change made it worse is for
            // the comparison of problems below, not the lookup.
            Err(_) if had.contains(name) => {}
            Err(why) => failed.push(why),
        }
    }
    if !failed.is_empty() {
        return Err(failed);
    }
    let before: BTreeSet<String> = old
        .map(|old| problems(old, public_ip, known).into_iter().collect())
        .unwrap_or_default();
    let added: Vec<String> = problems(new, public_ip, &resolved)
        .into_iter()
        .filter(|p| !before.contains(p))
        .collect();
    if !added.is_empty() {
        return Err(added);
    }
    let still_used = used(new);
    resolved.retain(|name, _| still_used.contains(name.as_str()));
    Ok(resolved)
}

/// `a, b` for messages.
pub fn list(addresses: &[Ipv4Addr]) -> String {
    addresses
        .iter()
        .map(Ipv4Addr::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::memory::FakeResolver;
    use crate::model::{PortSpec, Proto};
    use crate::testing::canonical_config;

    const NAS: &str = "nas.mydomain.com";

    fn home_dns() -> Nameserver {
        Nameserver::Plain(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn nas_addr() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 9)
    }

    /// The canonical scenario with `family` granted the NAS's SMB port by name.
    fn named() -> Config {
        let mut cfg = canonical_config();
        cfg.templates[1].grants.push(Grant::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 445)],
        });
        cfg
    }

    #[test]
    fn names_come_from_services_and_host_grants() {
        let mut cfg = named();
        cfg.services[0].host = Host::Name("immich.mydomain.com".into());
        cfg.templates[0].grants.push(Grant::Host {
            host: Host::Name(NAS.into()),
            ports: Vec::new(),
        });
        assert_eq!(
            used(&cfg).into_iter().collect::<Vec<_>>(),
            ["immich.mydomain.com", NAS]
        );
        assert!(used(&canonical_config()).is_empty());
    }

    #[test]
    fn the_zone_picks_the_resolvers() {
        let cfg = named();
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        assert_eq!(lookup(&cfg, None, &r, NAS), Ok(vec![nas_addr()]));
        assert_eq!(*r.asked.borrow(), [(NAS.to_string(), home_dns())]);
    }

    #[test]
    fn the_next_resolver_is_asked_only_when_one_fails() {
        let mut cfg = named();
        let second = Ipv4Addr::new(192, 168, 1, 2);
        cfg.networks[0].upstream_dns.push(second);
        let r = FakeResolver::new().answer(NAS, Nameserver::Plain(second), &[nas_addr()]);
        assert_eq!(lookup(&cfg, None, &r, NAS), Ok(vec![nas_addr()]));
        assert_eq!(r.asked.borrow().len(), 2);
        // An empty answer is an answer: nobody else is asked.
        let r = FakeResolver::new().answer(NAS, home_dns(), &[]);
        let why = lookup(&cfg, None, &r, NAS).unwrap_err();
        assert!(why.contains("has no IPv4 address"), "{why}");
        assert_eq!(r.asked.borrow().len(), 1);
    }

    #[test]
    fn answers_outside_every_network_are_refused() {
        let cfg = named();
        let r =
            FakeResolver::new().answer(NAS, home_dns(), &[nas_addr(), Ipv4Addr::new(8, 8, 8, 8)]);
        let why = lookup(&cfg, None, &r, NAS).unwrap_err();
        assert_eq!(
            why,
            "nas.mydomain.com resolved to 8.8.8.8, outside every configured network and not the home's public IP (not known yet) (asked 192.168.1.1)"
        );
    }

    #[test]
    fn a_name_that_doesnt_resolve_gives_nothing() {
        let cfg = named();
        let ok = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        assert_eq!(refresh(&cfg, None, &ok).resolved[NAS], [nas_addr()]);
        // Refused, gone (an empty answer), or no answer at all: no address
        // from an earlier lookup stands in.
        for r in [
            FakeResolver::new().answer(NAS, home_dns(), &[Ipv4Addr::new(1, 2, 3, 4)]),
            FakeResolver::new().answer(NAS, home_dns(), &[]),
            FakeResolver::new(),
        ] {
            let out = refresh(&cfg, None, &r);
            assert!(out.resolved.is_empty(), "{out:?}");
            assert!(out.problems[0].ends_with("grants on it give nothing until it resolves"));
        }
        assert!(refresh(&canonical_config(), None, &ok).problems.is_empty());
    }

    #[test]
    fn a_save_must_resolve_new_names() {
        let old = canonical_config();
        let new = named();
        let err = check_save(
            Some(&old),
            &new,
            None,
            &FakeResolver::new(),
            &Resolved::new(),
        )
        .unwrap_err();
        assert!(
            err[0].starts_with("can't look up nas.mydomain.com"),
            "{err:?}"
        );
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        let resolved = check_save(Some(&old), &new, None, &r, &Resolved::new()).unwrap();
        assert_eq!(resolved[NAS], [nas_addr()]);
        // Known names aren't asked again.
        let r = FakeResolver::new();
        check_save(Some(&new), &new, None, &r, &resolved).unwrap();
        assert!(r.asked.borrow().is_empty());
    }

    #[test]
    fn a_save_cant_strand_a_known_address() {
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let mut new = old.clone();
        new.networks[0].subnet = "192.168.2.0/24".parse().unwrap();
        new.networks[0].upstream_dns = vec![Ipv4Addr::new(192, 168, 2, 1)];
        new.services[0].host = Host::Ip(Ipv4Addr::new(192, 168, 2, 5));
        // Asked again, DNS still has the old address.
        let r = FakeResolver::new().answer(
            NAS,
            Nameserver::Plain(Ipv4Addr::new(192, 168, 2, 1)),
            &[nas_addr()],
        );
        let err = check_save(Some(&old), &new, None, &r, &known).unwrap_err();
        assert!(
            err[0].contains("resolved to 192.168.1.9, outside every configured network"),
            "{err:?}"
        );
    }

    #[test]
    fn a_name_new_to_the_configuration_is_always_asked() {
        // Left over from a configuration a restore replaced.
        let stale: Resolved = [(NAS.to_string(), vec![Ipv4Addr::new(192, 168, 1, 99)])].into();
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        let resolved = check_save(Some(&canonical_config()), &named(), None, &r, &stale).unwrap();
        assert_eq!(resolved[NAS], [nas_addr()]);
        assert_eq!(r.asked.borrow().len(), 1);
    }

    const HOME: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);

    #[test]
    fn the_home_public_ip_is_an_allowed_answer() {
        let cfg = named();
        let r = FakeResolver::new().answer(NAS, home_dns(), &[HOME]);
        assert_eq!(lookup(&cfg, Some(HOME), &r, NAS), Ok(vec![HOME]));
        let why = lookup(&cfg, None, &r, NAS).unwrap_err();
        assert!(
            why.contains("not the home's public IP (not known yet)"),
            "{why}"
        );
        let why = lookup(&cfg, Some(Ipv4Addr::new(1, 2, 3, 5)), &r, NAS).unwrap_err();
        assert!(why.contains("not the home's public IP 1.2.3.5"), "{why}");
    }

    #[test]
    fn the_home_public_ip_takes_single_ports_and_no_raw_web() {
        let mut cfg = named();
        let at_home: Resolved = [(NAS.to_string(), vec![HOME])].into();
        // tcp/445 by name: fine.
        assert!(problems(&cfg, Some(HOME), &at_home).is_empty());
        cfg.templates[1].grants.push(Grant::Host {
            host: Host::Name(NAS.into()),
            ports: Vec::new(),
        });
        cfg.templates[1].grants.push(Grant::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Udp, 443)],
        });
        let found = problems(&cfg, Some(HOME), &at_home);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].starts_with("template 'family': grant host nas.mydomain.com: nas.mydomain.com is the home's public IP 1.2.3.4, and every port there is a port forward"),
            "{found:?}"
        );
        assert!(
            found[1].starts_with("template 'family': grant host nas.mydomain.com 443/udp:"),
            "{found:?}"
        );
        assert!(found[1].contains("service with hostnames"), "{found:?}");
        // On the LAN the same grants are fine.
        let at_lan: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        assert!(problems(&cfg, Some(HOME), &at_lan).is_empty());
        // `all_networks` alone doesn't reach the public IP: still limited.
        cfg.templates[1].grants.push(Grant::AllNetworks);
        assert_eq!(problems(&cfg, Some(HOME), &at_home).len(), 2);
        // With `internet` too it reaches everything, and isn't.
        cfg.templates[1].grants.push(Grant::Internet);
        assert!(problems(&cfg, Some(HOME), &at_home).is_empty());
    }

    #[test]
    fn a_save_cant_add_a_raw_web_grant_on_the_public_ip() {
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        let mut new = old.clone();
        new.templates[1].grants.push(Grant::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 80)],
        });
        let err =
            check_save(Some(&old), &new, Some(HOME), &FakeResolver::new(), &known).unwrap_err();
        assert!(
            err[0].contains("grant host nas.mydomain.com 80/tcp"),
            "{err:?}"
        );
        // A proxied HTTPS service there is how web traffic gets in.
        let mut new = old.clone();
        new.services[0].host = Host::Name(NAS.into());
        new.services[0].hostnames = vec![NAS.into()];
        assert!(check_save(Some(&old), &new, Some(HOME), &FakeResolver::new(), &known).is_ok());
    }

    #[test]
    fn renumbering_a_network_looks_its_names_up_again() {
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let mut new = old.clone();
        new.networks[0].subnet = "192.168.2.0/24".parse().unwrap();
        new.services[0].host = Host::Ip(Ipv4Addr::new(192, 168, 2, 5));
        let moved = Ipv4Addr::new(192, 168, 2, 9);
        let r = FakeResolver::new().answer(NAS, home_dns(), &[moved]);
        assert_eq!(
            check_save(Some(&old), &new, None, &r, &known).unwrap()[NAS],
            [moved]
        );
    }

    #[test]
    fn a_moved_public_ip_doesnt_block_other_changes() {
        // The name pointed at the old public IP; DNS hasn't caught up.
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        let moved = Some(Ipv4Addr::new(1, 2, 3, 5));
        let r = FakeResolver::new().answer(NAS, home_dns(), &[HOME]);
        let out = refresh(&old, moved, &r);
        assert!(out.resolved.is_empty(), "the old answer gives nothing now");
        assert!(
            out.problems[0].ends_with("until it resolves"),
            "{:?}",
            out.problems
        );
        let mut new = old.clone();
        new.peers.pop();
        assert!(check_save(Some(&old), &new, moved, &r, &known).is_ok());
    }

    #[test]
    fn old_problems_dont_block_other_changes() {
        // The name was never found (its resolver was down at startup).
        let old = named();
        let mut new = old.clone();
        new.peers.pop();
        let r = FakeResolver::new();
        assert_eq!(
            check_save(Some(&old), &new, None, &r, &Resolved::new()),
            Ok(Resolved::new())
        );
        assert!(r.asked.borrow().is_empty());
    }
}
