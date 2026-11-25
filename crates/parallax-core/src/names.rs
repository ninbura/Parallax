//! Hosts named by DNS name: `host = "nas.mydomain.com"` in a service or a
//! `host`/`host_port` grant.
//!
//! A name is looked up through the home resolvers of the network whose zone
//! holds it (validation makes sure one does), and grants the addresses it
//! has. Those are an input to generation, like the date and the home's
//! public IP: [`crate::Model::with_names`] takes them, so the ruleset stays
//! deterministic and tests need no DNS.
//!
//! - **Only allowed answers.** Every address must be inside a configured
//!   network's real subnet; otherwise the whole answer is refused, so a
//!   changed or spoofed answer can't open a host Parallax doesn't know.
//! - **The last good answer stays.** A lookup that fails or is refused
//!   keeps the addresses found before, and says why. Never fall open, never
//!   drop a rule silently.
//! - **Never found** means the grant gives nothing yet, with a warning.
//! - **A save can't add a problem** ([`check_save`]): a new name must
//!   resolve, and a change mustn't leave a known address outside every
//!   network. Problems that were already there don't block unrelated
//!   changes, so a resolver being down never stops removing a peer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::io::{Nameserver, Resolver};
use crate::model::{Config, Grant, Host, Network};

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
            Grant::Host { host } | Grant::HostPort { host, .. } => Some(host),
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

/// Why `addresses` can't be granted for `name`, if they can't.
pub fn refused(config: &Config, name: &str, addresses: &[Ipv4Addr]) -> Option<String> {
    if addresses.is_empty() {
        return Some(format!("{name} has no IPv4 address"));
    }
    let outside: Vec<String> = addresses
        .iter()
        .filter(|a| !config.networks.iter().any(|n| n.subnet.contains(*a)))
        .map(Ipv4Addr::to_string)
        .collect();
    (!outside.is_empty()).then(|| {
        format!(
            "{name} resolved to {}, outside every configured network",
            outside.join(", ")
        )
    })
}

/// Look `name` up through its network's resolvers, in order: the first
/// that answers decides. The addresses come back sorted, and only when
/// [`refused`] has nothing against them.
pub fn lookup(
    config: &Config,
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
                return match refused(config, name, &addresses) {
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
    /// What to use: new answers, or the last good ones where a lookup failed.
    pub resolved: Resolved,
    /// Why each failed lookup failed, and what stays in effect.
    pub problems: Vec<String>,
}

/// Look up every name the configuration uses. `known` is what was found
/// before; names the configuration no longer uses are forgotten.
pub fn refresh(config: &Config, resolver: &dyn Resolver, known: &Resolved) -> Refreshed {
    let mut out = Refreshed::default();
    for name in used(config) {
        match lookup(config, resolver, name) {
            Ok(addresses) => {
                out.resolved.insert(name.to_string(), addresses);
            }
            Err(why) => match known.get(name) {
                Some(addresses) => {
                    out.problems
                        .push(format!("{why}; keeping the last known {}", list(addresses)));
                    out.resolved.insert(name.to_string(), addresses.clone());
                }
                None => out.problems.push(format!(
                    "{why}; grants on it give nothing until it resolves"
                )),
            },
        }
    }
    out
}

/// What's wrong with the names of `config` given what they resolved to:
/// names never found, and known addresses no longer inside a network (a
/// network changed since). Each problem names what stays in effect.
pub fn problems(config: &Config, resolved: &Resolved) -> Vec<String> {
    used(config)
        .into_iter()
        .filter_map(|name| match resolved.get(name) {
            None => Some(format!(
                "{name} hasn't been found yet; grants on it give nothing until it resolves"
            )),
            Some(addresses) => refused(config, name, addresses)
                .map(|why| format!("{why}; grants on it give nothing")),
        })
        .collect()
}

/// Before saving `new` over `old`: look up the names `new` adds, and refuse
/// the change if a new name doesn't resolve or the change adds a problem.
/// Returns the names to use from now on.
pub fn check_save(
    old: Option<&Config>,
    new: &Config,
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
            Some(addresses) => refused(new, name, addresses).is_none(),
            None => true,
        };
        if had.contains(name) && still_fine {
            continue;
        }
        match lookup(new, resolver, name) {
            Ok(addresses) => {
                resolved.insert(name.to_string(), addresses);
            }
            Err(why) => failed.push(why),
        }
    }
    if !failed.is_empty() {
        return Err(failed);
    }
    let before: BTreeSet<String> = old
        .map(|old| problems(old, known).into_iter().collect())
        .unwrap_or_default();
    let added: Vec<String> = problems(new, &resolved)
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
    use crate::model::Proto;
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
        cfg.templates[1].grants.push(Grant::HostPort {
            host: Host::Name(NAS.into()),
            proto: Proto::Tcp,
            port: 445,
        });
        cfg
    }

    #[test]
    fn names_come_from_services_and_host_grants() {
        let mut cfg = named();
        cfg.services[0].host = Host::Name("immich.mydomain.com".into());
        cfg.templates[0].grants.push(Grant::Host {
            host: Host::Name(NAS.into()),
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
        assert_eq!(lookup(&cfg, &r, NAS), Ok(vec![nas_addr()]));
        assert_eq!(*r.asked.borrow(), [(NAS.to_string(), home_dns())]);
    }

    #[test]
    fn the_next_resolver_is_asked_only_when_one_fails() {
        let mut cfg = named();
        let second = Ipv4Addr::new(192, 168, 1, 2);
        cfg.networks[0].upstream_dns.push(second);
        let r = FakeResolver::new().answer(NAS, Nameserver::Plain(second), &[nas_addr()]);
        assert_eq!(lookup(&cfg, &r, NAS), Ok(vec![nas_addr()]));
        assert_eq!(r.asked.borrow().len(), 2);
        // An empty answer is an answer: nobody else is asked.
        let r = FakeResolver::new().answer(NAS, home_dns(), &[]);
        let why = lookup(&cfg, &r, NAS).unwrap_err();
        assert!(why.contains("has no IPv4 address"), "{why}");
        assert_eq!(r.asked.borrow().len(), 1);
    }

    #[test]
    fn answers_outside_every_network_are_refused() {
        let cfg = named();
        let r =
            FakeResolver::new().answer(NAS, home_dns(), &[nas_addr(), Ipv4Addr::new(8, 8, 8, 8)]);
        let why = lookup(&cfg, &r, NAS).unwrap_err();
        assert_eq!(
            why,
            "nas.mydomain.com resolved to 8.8.8.8, outside every configured network (asked 192.168.1.1)"
        );
    }

    #[test]
    fn a_failed_lookup_keeps_the_last_good_answer() {
        let cfg = named();
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let r = FakeResolver::new().answer(NAS, home_dns(), &[Ipv4Addr::new(1, 2, 3, 4)]);
        let out = refresh(&cfg, &r, &known);
        assert_eq!(out.resolved, known);
        assert!(
            out.problems[0].ends_with("keeping the last known 192.168.1.9"),
            "{:?}",
            out.problems
        );
        // Never found: nothing to keep.
        let out = refresh(&cfg, &FakeResolver::new(), &Resolved::new());
        assert!(out.resolved.is_empty());
        assert!(
            out.problems[0].contains("give nothing"),
            "{:?}",
            out.problems
        );
    }

    #[test]
    fn names_no_longer_used_are_forgotten() {
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let out = refresh(&canonical_config(), &FakeResolver::new(), &known);
        assert!(out.resolved.is_empty());
        assert!(out.problems.is_empty());
    }

    #[test]
    fn a_save_must_resolve_new_names() {
        let old = canonical_config();
        let new = named();
        let err = check_save(Some(&old), &new, &FakeResolver::new(), &Resolved::new()).unwrap_err();
        assert!(
            err[0].starts_with("can't look up nas.mydomain.com"),
            "{err:?}"
        );
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        let resolved = check_save(Some(&old), &new, &r, &Resolved::new()).unwrap();
        assert_eq!(resolved[NAS], [nas_addr()]);
        // Known names aren't asked again.
        let r = FakeResolver::new();
        check_save(Some(&new), &new, &r, &resolved).unwrap();
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
        let err = check_save(Some(&old), &new, &r, &known).unwrap_err();
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
        let resolved = check_save(Some(&canonical_config()), &named(), &r, &stale).unwrap();
        assert_eq!(resolved[NAS], [nas_addr()]);
        assert_eq!(r.asked.borrow().len(), 1);
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
            check_save(Some(&old), &new, &r, &known).unwrap()[NAS],
            [moved]
        );
    }

    #[test]
    fn old_problems_dont_block_other_changes() {
        // The name was never found (its resolver was down at startup).
        let old = named();
        let mut new = old.clone();
        new.peers.pop();
        let r = FakeResolver::new();
        assert_eq!(
            check_save(Some(&old), &new, &r, &Resolved::new()),
            Ok(Resolved::new())
        );
        assert!(r.asked.borrow().is_empty());
    }
}
