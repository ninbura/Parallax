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
//! - **The home's public IP takes listed ports.** There every port is a
//!   port forward, maybe each to another machine, and a raw web port
//!   reaches every site behind it without the proxy's name check. So a
//!   tier that doesn't reach it anyway (`all_networks` + `internet`) gets
//!   no `host` rule there without ports, and web ports only as an HTTPS
//!   service with `hostnames` ([`public_ip_refusal`]).
//! - **Only the latest answer counts.** A lookup that fails, comes back
//!   empty or is refused leaves the name granting nothing until it resolves
//!   again, with a warning saying why. An old answer is never kept: a name
//!   that's gone may have been dropped on purpose, and its address may now
//!   belong to something else.
//! - **A save can't add a problem** ([`check_save`]): a new name, or one
//!   whose resolvers changed, must resolve, and a change mustn't leave a
//!   known address outside every network or off the home's public IP.
//!   Problems that were already there don't block unrelated changes, so a
//!   resolver being down never stops removing a peer or a grant. They're
//!   told apart by what they're about (a name, or what a rule opens), not
//!   their message, and a rule is refused only if its grant didn't have it
//!   or the change moved its name's answer.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use crate::io::{Nameserver, Resolver};
use crate::model::{ranges, Config, Host, Network, PortRange, Proto, Rule};
use crate::tier::{self, Tier};

/// The addresses each name was last found to have, sorted. Names that were
/// never found are absent.
pub type Resolved = BTreeMap<String, Vec<Ipv4Addr>>;

/// Every name the configuration uses as a host.
pub fn used(config: &Config) -> BTreeSet<&str> {
    let services = config.services.iter().map(|s| &s.host);
    let rules = config
        .grants
        .iter()
        .flat_map(|g| &g.rules)
        .filter_map(|r| match r {
            Rule::Host { host, .. } => Some(host),
            _ => None,
        });
    services.chain(rules).filter_map(Host::name).collect()
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

/// Why `tier` may not reach `ports` (`None`: every port) on the home's
/// public IP, if it may not. `proxied`: through the HTTPS proxy, which
/// checks the name. A tier with `all_networks` and `internet` reaches
/// the home's public IP anyway and isn't limited.
pub fn public_ip_refusal(
    tier: &Tier<'_>,
    ports: Option<&[PortRange]>,
    proxied: bool,
) -> Option<&'static str> {
    if tier.reaches_everything() {
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
    problems_about(config, public_ip, resolved)
        .into_iter()
        .map(|(_, problem)| problem)
        .collect()
}

/// What a problem is about, so [`check_save`] tells an old one from a new
/// one by what it is, not by its message: renaming a grant or a service,
/// writing ports in another order, or a new public IP changes the message.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum About<'a> {
    /// The name didn't resolve, or its answer isn't allowed.
    Name(&'a str),
    /// A grant's rule that gives nothing on the home's public IP, by what
    /// it opens.
    Opening(&'a str, Opening<'a>),
}

/// What a rule opens at a named host: the ports (`None`: every port) as
/// sorted, merged ranges per protocol, and whether the HTTPS proxy checks
/// the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Opening<'a> {
    name: &'a str,
    ports: Option<Vec<(&'static str, u16, u16)>>,
    proxied: bool,
}

/// A rule on a named host: how messages name it, the host, its ports
/// (`None`: every port) and whether the proxy checks the name.
struct Opens<'a> {
    what: String,
    name: &'a str,
    ports: Option<Vec<PortRange>>,
    proxied: bool,
}

impl<'a> Opens<'a> {
    fn of(config: &'a Config, rule: &'a Rule) -> Option<Opens<'a>> {
        let (what, host, ports, proxied) = match rule {
            Rule::Host { host, ports } if ports.is_empty() => {
                (format!("host {host}"), host, None, false)
            }
            Rule::Host { host, ports } => (
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
            Rule::Service { name } => {
                let s = config.service(name)?;
                (
                    format!("service '{name}'"),
                    &s.host,
                    Some(ranges(&s.ports)),
                    s.is_proxied(),
                )
            }
            _ => return None,
        };
        Some(Opens {
            what,
            name: host.name()?,
            ports,
            proxied,
        })
    }

    fn key(&self) -> Opening<'a> {
        Opening {
            name: self.name,
            ports: self.ports.as_ref().map(|ports| {
                let mut sorted: Vec<_> = ports
                    .iter()
                    .map(|r| (r.proto.as_str(), r.first, r.last))
                    .collect();
                sorted.sort_unstable();
                // `442-443/tcp` and `442/tcp, 443/tcp` open the same.
                let mut key: Vec<(&'static str, u16, u16)> = Vec::new();
                for (proto, first, last) in sorted {
                    match key.last_mut() {
                        Some(prev)
                            if prev.0 == proto && u32::from(first) <= u32::from(prev.2) + 1 =>
                        {
                            prev.2 = prev.2.max(last);
                        }
                        _ => key.push((proto, first, last)),
                    }
                }
                key
            }),
            proxied: self.proxied,
        }
    }
}

/// What each grant's rules open at named hosts, by grant name.
type Openings<'a> = BTreeMap<&'a str, BTreeSet<Opening<'a>>>;

/// Only grants someone holds: a rule in a grant nobody had yet (created,
/// then attached) is new to whoever gets it.
fn openings(config: &Config) -> Openings<'_> {
    let held: BTreeSet<&str> = tier::tiers(config)
        .iter()
        .flat_map(|t| t.grants.iter().map(|g| g.name.as_str()))
        .collect();
    config
        .grants
        .iter()
        .filter(|g| held.contains(g.name.as_str()))
        .map(|g| {
            let opens = g
                .rules
                .iter()
                .filter_map(|rule| Opens::of(config, rule))
                .map(|o| o.key())
                .collect();
            (g.name.as_str(), opens)
        })
        .collect()
}

/// Whether `map` has `opening` for `grant` of the new configuration: under
/// its own name in `opened` (the old configuration), or for a grant new
/// by name, under any old grant that's gone from `kept` (a rename).
fn held<'a>(
    map: &Openings<'a>,
    opened: &Openings<'a>,
    kept: &BTreeSet<&'a str>,
    grant: &'a str,
    opening: &Opening<'a>,
) -> bool {
    let has = |g: &str| map.get(g).is_some_and(|set| set.contains(opening));
    if opened.contains_key(grant) {
        return has(grant);
    }
    opened.keys().filter(|g| !kept.contains(*g)).any(|g| has(g))
}

/// [`problems`], each with what it's about.
fn problems_about<'a>(
    config: &'a Config,
    public_ip: Option<Ipv4Addr>,
    resolved: &Resolved,
) -> Vec<(About<'a>, String)> {
    let mut out: Vec<(About<'a>, String)> = used(config)
        .into_iter()
        .filter_map(|name| {
            match resolved.get(name) {
                None => Some(format!(
                    "{name} didn't resolve; grants on it give nothing until it does"
                )),
                Some(addresses) => refused(config, public_ip, name, addresses)
                    .map(|why| format!("{why}; grants on it give nothing")),
            }
            .map(|problem| (About::Name(name), problem))
        })
        .collect();
    let Some(home) = public_ip else {
        return out;
    };
    for t in tier::tiers(config) {
        for (grant, rule) in t
            .grants
            .iter()
            .flat_map(|g| g.rules.iter().map(move |r| (g, r)))
        {
            let Some(opens) = Opens::of(config, rule) else {
                continue;
            };
            let name = opens.name;
            let at_home = resolved.get(name).is_some_and(|a| a.contains(&home));
            let Some(why) =
                public_ip_refusal(&t, opens.ports.as_deref(), opens.proxied).filter(|_| at_home)
            else {
                continue;
            };
            let problem = format!(
                "grant '{}': rule {}: {name} is the home's public IP {home}, and {why}; it gives nothing there",
                grant.name, opens.what
            );
            // Every tier holding the grant would say it again.
            if !out.iter().any(|(_, p)| *p == problem) {
                out.push((About::Opening(grant.name.as_str(), opens.key()), problem));
            }
        }
    }
    out
}

/// The names a save of `new` over `old` looks up whatever is known of them:
/// new to the configuration, or asked through other resolvers than in `old`
/// (its `upstream_dns` changed, or its zone moved to another network).
pub fn asked_on_save<'a>(old: Option<&Config>, new: &'a Config) -> BTreeSet<&'a str> {
    fn resolvers<'c>(config: &'c Config, name: &str) -> Option<&'c [Ipv4Addr]> {
        network_of(config, name).map(|n| n.upstream_dns.as_slice())
    }
    let Some(old) = old else {
        return used(new);
    };
    let had = used(old);
    used(new)
        .into_iter()
        .filter(|name| !had.contains(name) || resolvers(old, name) != resolvers(new, name))
        .collect()
}

/// Before saving `new` over `old`: look up the names [`asked_on_save`], and
/// refuse the change if one doesn't resolve or the change adds a problem.
/// `old_public_ip` and `public_ip` are the home's public IP in effect under
/// each. Returns the names to use from now on.
pub fn check_save(
    old: Option<&Config>,
    old_public_ip: Option<Ipv4Addr>,
    new: &Config,
    public_ip: Option<Ipv4Addr>,
    resolver: &dyn Resolver,
    known: &Resolved,
) -> Result<Resolved, Vec<String>> {
    let mut resolved = known.clone();
    let mut failed = Vec::new();
    // Names `old` already had, through the same resolvers, keep what they
    // have; one never found is an old problem, and the regular lookups keep
    // trying it. The others ([`asked_on_save`]) are asked now and must
    // resolve, even if an answer for one is lying around (from a
    // configuration a restore replaced, or from the resolvers this change
    // replaces). A known answer `new` no longer allows (its network was
    // renumbered in this change) is asked again too.
    let fresh = asked_on_save(old, new);
    let had = old.map(used).unwrap_or_default();
    for name in used(new) {
        let still_fine = match known.get(name) {
            Some(addresses) => refused(new, public_ip, name, addresses).is_none(),
            None => true,
        };
        if !fresh.contains(name) && still_fine {
            continue;
        }
        match lookup(new, public_ip, resolver, name) {
            Ok(addresses) => {
                resolved.insert(name.to_string(), addresses);
            }
            // A name kept from `old`: whether this change made it worse is
            // for the comparison of problems below, not the lookup.
            Err(_) if !fresh.contains(name) => {}
            // New resolvers that can't answer for a name nothing knows an
            // answer for. If `old`'s resolvers can't either, it's an old
            // problem (a resolver change mustn't need every broken name
            // fixed first); if they can, this change breaks it. Nothing
            // known may also mean nothing has asked yet (just started, a
            // restore), so `old`'s are asked rather than assumed broken.
            Err(why) if had.contains(name) && !known.contains_key(name) => {
                let answers_before =
                    old.is_some_and(|old| lookup(old, old_public_ip, resolver, name).is_ok());
                if answers_before {
                    failed.push(why);
                }
            }
            Err(why) => failed.push(why),
        }
    }
    if !failed.is_empty() {
        return Err(failed);
    }
    // A name that was broken stays an old problem. A grant's rule that gives
    // nothing on the home's public IP is old if the grant had the rule
    // before (or, for a grant new by name, one that's gone did: a rename)
    // and either it gave nothing before too, or this change didn't move the
    // name's answer. So taking access away (a grant from a peer that reached
    // everything), a rename or a new public IP is never refused for what it
    // reveals, while a rule added to a grant, or a resolver change that
    // moves a working rule's name onto the public IP, is.
    let before = old
        .map(|old| problems_about(old, old_public_ip, known))
        .unwrap_or_default();
    let mut broken: BTreeSet<&str> = BTreeSet::new();
    let mut gave_nothing: Openings<'_> = BTreeMap::new();
    for (about, _) in before {
        match about {
            About::Name(name) => {
                broken.insert(name);
            }
            About::Opening(grant, opening) => {
                gave_nothing.entry(grant).or_default().insert(opening);
            }
        }
    }
    let opened = old.map(openings).unwrap_or_default();
    let kept_grants: BTreeSet<&str> = new.grants.iter().map(|g| g.name.as_str()).collect();
    let added: Vec<String> = problems_about(new, public_ip, &resolved)
        .into_iter()
        .filter(|(about, _)| match about {
            About::Name(name) => !broken.contains(name),
            About::Opening(grant, opening) => {
                let same_answer = resolved.get(opening.name) == known.get(opening.name);
                let held = |map: &Openings<'_>| held(map, &opened, &kept_grants, grant, opening);
                !(held(&opened) && (same_answer || held(&gave_nothing)))
            }
        })
        .map(|(_, problem)| problem)
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
        cfg.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 445)],
        });
        cfg
    }

    #[test]
    fn names_come_from_services_and_host_grants() {
        let mut cfg = named();
        cfg.services[0].host = Host::Name("immich.mydomain.com".into());
        cfg.grants[0].rules.push(Rule::Host {
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
            None,
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
        let resolved = check_save(Some(&old), None, &new, None, &r, &Resolved::new()).unwrap();
        assert_eq!(resolved[NAS], [nas_addr()]);
        // Known names aren't asked again.
        let r = FakeResolver::new();
        check_save(Some(&new), None, &new, None, &r, &resolved).unwrap();
        assert!(r.asked.borrow().is_empty());
    }

    #[test]
    fn a_save_cant_strand_a_known_address() {
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let mut new = old.clone();
        new.networks[0].subnet = "192.168.2.0/24".parse().unwrap();
        new.services[0].host = Host::Ip(Ipv4Addr::new(192, 168, 2, 5));
        // Asked again through the same resolver, which still has the old address.
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        let err = check_save(Some(&old), None, &new, None, &r, &known).unwrap_err();
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
        let resolved =
            check_save(Some(&canonical_config()), None, &named(), None, &r, &stale).unwrap();
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
        cfg.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: Vec::new(),
        });
        cfg.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Udp, 443)],
        });
        let found = problems(&cfg, Some(HOME), &at_home);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(
            found[0].starts_with("grant 'family': rule host nas.mydomain.com: nas.mydomain.com is the home's public IP 1.2.3.4, and every port there is a port forward"),
            "{found:?}"
        );
        assert!(
            found[1].starts_with("grant 'family': rule host nas.mydomain.com 443/udp:"),
            "{found:?}"
        );
        assert!(found[1].contains("service with hostnames"), "{found:?}");
        // On the LAN the same grants are fine.
        let at_lan: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        assert!(problems(&cfg, Some(HOME), &at_lan).is_empty());
        // `all_networks` alone doesn't reach the public IP: still limited.
        cfg.grants[1].rules.push(Rule::AllNetworks);
        assert_eq!(problems(&cfg, Some(HOME), &at_home).len(), 2);
        // With `internet` too it reaches everything, and isn't.
        cfg.grants[1].rules.push(Rule::Internet);
        assert!(problems(&cfg, Some(HOME), &at_home).is_empty());
    }

    #[test]
    fn a_range_that_takes_in_a_web_port_is_raw_web() {
        let mut cfg = named();
        let at_home: Resolved = [(NAS.to_string(), vec![HOME])].into();
        cfg.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec!["70-90/tcp".parse().unwrap()],
        });
        let found = problems(&cfg, Some(HOME), &at_home);
        assert!(has_web(&found), "{found:?}");
        // 70-90/udp takes in no web port.
        cfg.grants[1].rules.pop();
        cfg.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec!["70-90/udp".parse().unwrap()],
        });
        assert!(problems(&cfg, Some(HOME), &at_home).is_empty());
    }

    fn has_web(found: &[String]) -> bool {
        found.iter().any(|p| p.contains("service with hostnames"))
    }

    #[test]
    fn a_save_cant_add_a_raw_web_grant_on_the_public_ip() {
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        let mut new = old.clone();
        new.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 80)],
        });
        let err = check_save(
            Some(&old),
            Some(HOME),
            &new,
            Some(HOME),
            &FakeResolver::new(),
            &known,
        )
        .unwrap_err();
        assert!(
            err[0].contains("rule host nas.mydomain.com 80/tcp"),
            "{err:?}"
        );
        // A proxied HTTPS service there is how web traffic gets in.
        let mut new = old.clone();
        new.services[0].host = Host::Name(NAS.into());
        new.services[0].hostnames = vec![NAS.into()];
        assert!(check_save(
            Some(&old),
            Some(HOME),
            &new,
            Some(HOME),
            &FakeResolver::new(),
            &known
        )
        .is_ok());
    }

    #[test]
    fn an_old_problem_doesnt_block_removing_a_peer() {
        // Every port of the public IP: a problem already, for a tier of two.
        let mut old = named();
        old.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: Vec::new(),
        });
        old.peers[1].grants = vec!["family".into()];
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert_eq!(problems(&old, Some(HOME), &known).len(), 1);
        let mut new = old.clone();
        new.peers.remove(1);
        assert!(check_save(
            Some(&old),
            Some(HOME),
            &new,
            Some(HOME),
            &FakeResolver::new(),
            &known
        )
        .is_ok());
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
            check_save(Some(&old), None, &new, None, &r, &known).unwrap()[NAS],
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
        assert!(check_save(Some(&old), moved, &new, moved, &r, &known).is_ok());
    }

    #[test]
    fn old_problems_dont_block_other_changes() {
        // The name was never found (its resolver was down at startup).
        let old = named();
        let mut new = old.clone();
        new.peers.pop();
        let r = FakeResolver::new();
        assert_eq!(
            check_save(Some(&old), None, &new, None, &r, &Resolved::new()),
            Ok(Resolved::new())
        );
        assert!(r.asked.borrow().is_empty());
    }

    #[test]
    fn changing_a_names_resolvers_asks_it_again() {
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let mut new = old.clone();
        let other = Ipv4Addr::new(192, 168, 1, 53);
        new.networks[0].upstream_dns = vec![other];
        assert_eq!(asked_on_save(Some(&old), &new), BTreeSet::from([NAS]));
        assert!(asked_on_save(Some(&old), &old).is_empty());
        let moved = Ipv4Addr::new(192, 168, 1, 10);
        let r = FakeResolver::new().answer(NAS, Nameserver::Plain(other), &[moved]);
        let resolved = check_save(Some(&old), None, &new, None, &r, &known).unwrap();
        assert_eq!(resolved[NAS], [moved]);
        assert_eq!(
            *r.asked.borrow(),
            [(NAS.to_string(), Nameserver::Plain(other))]
        );
        // The new resolver doesn't have it: the old resolver's answer
        // doesn't stand in, and the change is refused.
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        let err = check_save(Some(&old), None, &new, None, &r, &known).unwrap_err();
        assert!(
            err[0].starts_with("can't look up nas.mydomain.com"),
            "{err:?}"
        );
    }

    #[test]
    fn an_old_public_ip_problem_doesnt_block_a_peers_other_grants() {
        // `family` already has a problem there: a host rule without ports.
        let mut old = named();
        old.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: Vec::new(),
        });
        let mut photos = old.grants[1].clone();
        photos.name = "photos".into();
        photos.rules = vec![Rule::PublicDns];
        old.grants.push(photos);
        old.peers[2].grants = vec!["family".into(), "photos".into()];
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert_eq!(problems(&old, Some(HOME), &known).len(), 1);
        let save = |new: &Config| {
            check_save(
                Some(&old),
                Some(HOME),
                new,
                Some(HOME),
                &FakeResolver::new(),
                &known,
            )
        };
        // Revoking the other grant, and giving it to everyone.
        let mut new = old.clone();
        new.peers[2].grants = vec!["family".into()];
        assert!(save(&new).is_ok(), "{:?}", save(&new));
        let mut new = old.clone();
        new.grants[2].everyone = true;
        assert!(save(&new).is_ok(), "{:?}", save(&new));
        // Two tiers holding `family` report its problem once.
        let mut two = old.clone();
        two.peers[1].grants = vec!["family".into()];
        assert_eq!(tier::tiers(&two).len(), 3);
        assert_eq!(problems(&two, Some(HOME), &known).len(), 1);
    }

    #[test]
    fn a_public_ip_change_that_strands_a_known_name_is_refused() {
        // `server.public_ip.address` edited to another address: NAS's
        // answer, the old address, isn't allowed anymore.
        let old = named();
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        let typo = Some(Ipv4Addr::new(1, 2, 3, 40));
        let r = FakeResolver::new().answer(NAS, home_dns(), &[HOME]);
        let err = check_save(Some(&old), Some(HOME), &old, typo, &r, &known).unwrap_err();
        assert!(
            err[0].contains("not the home's public IP 1.2.3.40"),
            "{err:?}"
        );
    }

    #[test]
    fn a_name_never_found_doesnt_block_a_resolver_change() {
        // OLDBOX was already missing; NAS resolves through the new resolver.
        const OLDBOX: &str = "oldbox.mydomain.com";
        let mut old = named();
        old.grants[1].rules.push(Rule::Host {
            host: Host::Name(OLDBOX.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 22)],
        });
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let mut new = old.clone();
        let other = Ipv4Addr::new(192, 168, 1, 53);
        new.networks[0].upstream_dns = vec![other];
        let r = FakeResolver::new().answer(NAS, Nameserver::Plain(other), &[nas_addr()]);
        let resolved = check_save(Some(&old), None, &new, None, &r, &known).unwrap();
        assert_eq!(resolved, known);
    }

    #[test]
    fn a_zone_moved_to_another_network_is_asked_again() {
        // A more specific zone on a second network takes NAS's name over.
        let old = named();
        let mut new = old.clone();
        let mut lab = new.networks[0].clone();
        lab.name = "lab".into();
        lab.domains = vec![NAS.into()];
        lab.upstream_dns = vec![Ipv4Addr::new(192, 168, 1, 53)];
        new.networks.push(lab);
        assert_eq!(asked_on_save(Some(&old), &new), BTreeSet::from([NAS]));
    }

    /// `named()` with `family` granted every port of NAS, which is on the
    /// home's public IP: a problem already.
    fn every_port_at_home() -> (Config, Resolved) {
        let mut old = named();
        old.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: Vec::new(),
        });
        (old, [(NAS.to_string(), vec![HOME])].into())
    }

    #[test]
    fn renaming_a_grant_keeps_its_old_problem_old() {
        let (old, known) = every_port_at_home();
        let mut new = old.clone();
        new.grants[1].name = "relatives".into();
        for g in new.peers.iter_mut().flat_map(|p| &mut p.grants) {
            if g == "family" {
                *g = "relatives".into();
            }
        }
        let r = FakeResolver::new();
        assert!(check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).is_ok());
    }

    #[test]
    fn a_new_public_ip_keeps_an_old_problem_old() {
        let (old, _) = every_port_at_home();
        let at = Ipv4Addr::new(5, 6, 7, 8);
        let known: Resolved = [(NAS.to_string(), vec![at])].into();
        let r = FakeResolver::new();
        assert!(check_save(Some(&old), Some(HOME), &old, Some(at), &r, &known).is_ok());
    }

    #[test]
    fn reordering_ports_keeps_an_old_problem_old() {
        let mut old = named();
        let web = |order: [u16; 2]| Rule::Host {
            host: Host::Name(NAS.into()),
            ports: order.map(|p| PortSpec::one(Proto::Tcp, p)).to_vec(),
        };
        old.grants[1].rules.push(web([80, 443]));
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert_eq!(problems(&old, Some(HOME), &known).len(), 1);
        let mut new = old.clone();
        *new.grants[1].rules.last_mut().unwrap() = web([443, 80]);
        let r = FakeResolver::new();
        assert!(check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).is_ok());
        // Another port is another rule: refused.
        *new.grants[1].rules.last_mut().unwrap() = web([443, 8443]);
        assert!(check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).is_err());
    }

    #[test]
    fn taking_access_away_is_never_refused_for_what_it_reveals() {
        // Everyone reaches everything, so `web`'s raw web port on the home's
        // public IP is no problem for anyone yet.
        let mut old = named();
        old.grants[0].rules = vec![Rule::AllNetworks, Rule::Internet];
        for p in &mut old.peers {
            p.grants = vec!["personal".into()];
        }
        let mut web = old.grants[1].clone();
        web.name = "web".into();
        web.everyone = true;
        web.rules = vec![Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 443)],
        }];
        old.grants.push(web);
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert!(problems(&old, Some(HOME), &known).is_empty());
        let r = FakeResolver::new();
        let save = |new: &Config| check_save(Some(&old), Some(HOME), new, Some(HOME), &r, &known);
        // Revoking `personal` from a peer, or `internet` from `personal`.
        let mut new = old.clone();
        new.peers[0].grants.clear();
        assert!(save(&new).is_ok(), "{:?}", save(&new));
        let mut new = old.clone();
        new.grants[0].rules.pop();
        assert!(save(&new).is_ok(), "{:?}", save(&new));
        // A rule nobody had before is still refused.
        let mut new = old.clone();
        new.peers[0].grants.clear();
        new.grants[2].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 80)],
        });
        assert!(save(&new).is_err());
    }

    #[test]
    fn with_nothing_known_yet_a_resolver_change_must_still_answer() {
        // Just started or restored: nothing asked yet, but the old resolver
        // answers and the new one doesn't.
        let old = named();
        let mut new = old.clone();
        new.networks[0].upstream_dns = vec![Ipv4Addr::new(192, 168, 1, 53)];
        let r = FakeResolver::new().answer(NAS, home_dns(), &[nas_addr()]);
        let err = check_save(Some(&old), None, &new, None, &r, &Resolved::new()).unwrap_err();
        assert!(
            err[0].starts_with("can't look up nas.mydomain.com"),
            "{err:?}"
        );
    }

    #[test]
    fn moving_a_rule_into_a_grant_it_fails_in_is_refused() {
        // `personal` reaches everything, so its raw web rule there works.
        let mut old = named();
        old.grants[0].rules = vec![
            Rule::AllNetworks,
            Rule::Internet,
            Rule::Host {
                host: Host::Name(NAS.into()),
                ports: vec![PortSpec::one(Proto::Tcp, 443)],
            },
        ];
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert!(problems(&old, Some(HOME), &known).is_empty());
        let mut new = old.clone();
        let rule = new.grants[0].rules.pop().unwrap();
        new.grants[1].rules.push(rule);
        let r = FakeResolver::new();
        let err = check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).unwrap_err();
        assert!(
            err[0].starts_with("grant 'family': rule host nas.mydomain.com 443/tcp"),
            "{err:?}"
        );
    }

    #[test]
    fn a_resolver_change_that_moves_a_working_rule_onto_the_public_ip_is_refused() {
        // Raw web on the LAN is fine; on the home's public IP it isn't.
        let mut old = named();
        old.grants[1].rules.push(Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 443)],
        });
        let known: Resolved = [(NAS.to_string(), vec![nas_addr()])].into();
        let mut new = old.clone();
        let other = Ipv4Addr::new(192, 168, 1, 53);
        new.networks[0].upstream_dns = vec![other];
        let r = FakeResolver::new().answer(NAS, Nameserver::Plain(other), &[HOME]);
        let err = check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).unwrap_err();
        assert!(
            err[0].contains("rule host nas.mydomain.com 443/tcp"),
            "{err:?}"
        );
    }

    #[test]
    fn a_range_and_its_ports_open_the_same() {
        let mut old = named();
        let rule = |ports: &[&str]| Rule::Host {
            host: Host::Name(NAS.into()),
            ports: ports.iter().map(|p| p.parse().unwrap()).collect(),
        };
        old.grants[1].rules.push(rule(&["442-443/tcp"]));
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert_eq!(problems(&old, Some(HOME), &known).len(), 1);
        let mut new = old.clone();
        *new.grants[1].rules.last_mut().unwrap() = rule(&["442/tcp", "443/tcp"]);
        let r = FakeResolver::new();
        assert!(check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).is_ok());
    }

    #[test]
    fn attaching_a_grant_nobody_held_is_judged_like_a_new_rule() {
        // `web` was created with a raw web rule on the public IP, then attached.
        let mut old = named();
        let mut web = old.grants[1].clone();
        web.name = "web".into();
        web.rules = vec![Rule::Host {
            host: Host::Name(NAS.into()),
            ports: vec![PortSpec::one(Proto::Tcp, 443)],
        }];
        old.grants.push(web);
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        assert!(problems(&old, Some(HOME), &known).is_empty());
        let mut new = old.clone();
        new.peers[2].grants.push("web".into());
        let r = FakeResolver::new();
        assert!(check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).is_err());
        // A guest added while `web` is for everyone isn't (#85).
        old.grants[2].everyone = true;
        old.grants[0].rules = vec![Rule::AllNetworks, Rule::Internet];
        for p in &mut old.peers {
            p.grants = vec!["personal".into()];
        }
        let mut new = old.clone();
        let mut guest = new.peers[2].clone();
        guest.name = "guest".into();
        guest.grants.clear();
        new.peers.push(guest);
        assert!(check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known).is_ok());
    }

    #[test]
    fn renaming_a_service_or_spelling_its_protocols_out_keeps_its_problem_old() {
        // immich is a service on NAS's port 443, unproxied, at the home's public IP.
        let mut old = named();
        old.services[0].host = Host::Name(NAS.into());
        old.services[0].hostnames.clear();
        old.services[0].ports = vec!["443".parse().unwrap()];
        let known: Resolved = [(NAS.to_string(), vec![HOME])].into();
        let found = problems(&old, Some(HOME), &known);
        assert!(
            found.iter().any(|p| p.contains("service 'immich'")),
            "{found:?}"
        );
        let r = FakeResolver::new();
        let mut new = old.clone();
        new.services[0].name = "photos".into();
        new.grants[1].rules = vec![Rule::Service {
            name: "photos".into(),
        }];
        new.services[0].ports = vec!["443/tcp".parse().unwrap(), "443/udp".parse().unwrap()];
        let saved = check_save(Some(&old), Some(HOME), &new, Some(HOME), &r, &known);
        assert!(saved.is_ok(), "{saved:?}");
    }
}
