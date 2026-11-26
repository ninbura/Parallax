//! Changing grants and who has them: the operations behind `parallax grant`
//! and `parallax peer grants` (and later the GUI). Each edits a [`Config`];
//! the caller validates and saves the result in one write, so a refused
//! change leaves nothing half done.
//!
//! Adding what's already there changes nothing and says so. Removing what
//! isn't there is refused: it's usually a typo, and going ahead would leave
//! the access in place while the operator thinks it's gone.

use crate::model::{Config, Grant, Peer, Rule};
use crate::{Error, Result};

/// What an addition did: the items it added, and those already there.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Added {
    pub added: Vec<String>,
    pub already: Vec<String>,
}

/// A new grant, after every existing one.
pub fn create(config: &mut Config, name: &str, everyone: bool, rules: Vec<Rule>) -> Result<()> {
    if config.grant(name).is_some() {
        return Err(Error::Refused(format!("grant '{name}' already exists")));
    }
    let mut grant = Grant {
        name: name.to_string(),
        everyone,
        rules: Vec::new(),
    };
    for rule in rules {
        if !grant.rules.contains(&rule) {
            grant.rules.push(rule);
        }
    }
    config.grants.push(grant);
    Ok(())
}

/// Remove a grant and detach it from every peer. Returns who had it
/// ([`holders`], before the removal).
pub fn remove(config: &mut Config, name: &str) -> Result<Vec<String>> {
    let had = names(&holders(config, name)?);
    config.grants.retain(|g| g.name != name);
    for peer in &mut config.peers {
        peer.grants.retain(|g| g != name);
    }
    Ok(had)
}

/// Rename a grant, and every peer's reference to it. Returns the peers
/// whose list changed.
pub fn rename(config: &mut Config, from: &str, to: &str) -> Result<Vec<String>> {
    if config.grant(to).is_some() {
        return Err(Error::Refused(format!(
            "can't rename grant '{from}' to '{to}': grant '{to}' already exists"
        )));
    }
    grant_mut(config, from)?.name = to.to_string();
    let mut changed = Vec::new();
    for peer in &mut config.peers {
        for g in &mut peer.grants {
            if g == from {
                *g = to.to_string();
                changed.push(peer.name.clone());
            }
        }
    }
    Ok(changed)
}

/// Add rules to a grant, after its own.
pub fn add_rules(config: &mut Config, grant: &str, rules: &[Rule]) -> Result<Added> {
    let grant = grant_mut(config, grant)?;
    let mut out = Added::default();
    for rule in rules {
        if grant.rules.contains(rule) {
            out.already.push(rule.to_string());
        } else {
            grant.rules.push(rule.clone());
            out.added.push(rule.to_string());
        }
    }
    Ok(out)
}

/// Remove rules from a grant. Every one must be there, written as the
/// grant holds it (a host rule with the same ports in the same order).
pub fn remove_rules(config: &mut Config, grant: &str, rules: &[Rule]) -> Result<()> {
    let g = grant_mut(config, grant)?;
    let missing: Vec<String> = rules
        .iter()
        .filter(|r| !g.rules.contains(r))
        .map(ToString::to_string)
        .collect();
    if !missing.is_empty() {
        let has = if g.rules.is_empty() {
            "it has none".to_string()
        } else {
            format!(
                "its rules: {}",
                list(g.rules.iter().map(ToString::to_string))
            )
        };
        return Err(Error::Refused(format!(
            "grant '{grant}' has no rule {}; nothing removed ({has})",
            list(missing.into_iter())
        )));
    }
    g.rules.retain(|r| !rules.contains(r));
    Ok(())
}

/// Switch whether a grant applies to every peer, current and future.
/// Returns whether that changed anything.
pub fn set_everyone(config: &mut Config, grant: &str, on: bool) -> Result<bool> {
    let g = grant_mut(config, grant)?;
    let changed = g.everyone != on;
    g.everyone = on;
    Ok(changed)
}

/// Attach a grant to peers.
pub fn attach(config: &mut Config, grant: &str, peers: &[String]) -> Result<Added> {
    known_grant(config, grant)?;
    known_peers(config, peers)?;
    let mut out = Added::default();
    for name in peers {
        let peer = peer_mut(config, name)?;
        if peer.grants.iter().any(|g| g == grant) {
            out.already.push(name.clone());
        } else {
            peer.grants.push(grant.to_string());
            out.added.push(name.clone());
        }
    }
    Ok(out)
}

/// Detach a grant from peers. Each must have it attached.
pub fn detach(config: &mut Config, grant: &str, peers: &[String]) -> Result<()> {
    let everyone = known_grant(config, grant)?.everyone;
    known_peers(config, peers)?;
    for name in peers {
        let peer = peer_mut(config, name)?;
        if !peer.grants.iter().any(|g| g == grant) {
            return Err(not_attached(peer, grant, everyone));
        }
        peer.grants.retain(|g| g != grant);
    }
    Ok(())
}

/// Give a peer exactly these grants (besides grants for everyone).
pub fn set_peer(config: &mut Config, peer: &str, grants: &[String]) -> Result<()> {
    for g in grants {
        known_grant(config, g)?;
    }
    let mut list: Vec<String> = Vec::new();
    for g in grants {
        if !list.contains(g) {
            list.push(g.clone());
        }
    }
    peer_mut(config, peer)?.grants = list;
    Ok(())
}

/// Attach grants to one peer.
pub fn peer_add(config: &mut Config, peer: &str, grants: &[String]) -> Result<Added> {
    let mut out = Added::default();
    for g in grants {
        let one = attach(config, g, std::slice::from_ref(&peer.to_string()))?;
        if one.added.is_empty() {
            out.already.push(g.clone());
        } else {
            out.added.push(g.clone());
        }
    }
    Ok(out)
}

/// Detach grants from one peer. It must have each attached.
pub fn peer_remove(config: &mut Config, peer: &str, grants: &[String]) -> Result<()> {
    for g in grants {
        detach(config, g, std::slice::from_ref(&peer.to_string()))?;
    }
    Ok(())
}

/// Who has a grant: every peer when it applies to everyone, otherwise the
/// peers it's attached to, in configuration order.
pub fn holders<'a>(config: &'a Config, grant: &str) -> Result<Vec<&'a Peer>> {
    let everyone = known_grant(config, grant)?.everyone;
    Ok(config
        .peers
        .iter()
        .filter(|p| everyone || p.grants.iter().any(|g| g == grant))
        .collect())
}

fn names(peers: &[&Peer]) -> Vec<String> {
    peers.iter().map(|p| p.name.clone()).collect()
}

fn not_attached(peer: &Peer, grant: &str, everyone: bool) -> Error {
    if everyone {
        return Error::Refused(format!(
            "peer '{}' has grant '{grant}' because it applies to everyone, not attached; switch that off to take it away",
            peer.name
        ));
    }
    let has = if peer.grants.is_empty() {
        "it has none attached".to_string()
    } else {
        format!(
            "its grants: {}",
            list(peer.grants.iter().map(|g| format!("'{g}'")))
        )
    };
    Error::Refused(format!(
        "peer '{}' doesn't have grant '{grant}'; nothing detached ({has})",
        peer.name
    ))
}

fn list(items: impl Iterator<Item = String>) -> String {
    items.collect::<Vec<_>>().join(", ")
}

fn known_grant<'a>(config: &'a Config, name: &str) -> Result<&'a Grant> {
    config.grant(name).ok_or_else(|| Error::NotFound {
        kind: "grant",
        name: name.to_string(),
    })
}

/// Every peer named must exist, so a typo among several changes none.
fn known_peers(config: &Config, peers: &[String]) -> Result<()> {
    match peers.iter().find(|p| config.peer(p).is_none()) {
        Some(p) => Err(Error::NotFound {
            kind: "peer",
            name: p.clone(),
        }),
        None => Ok(()),
    }
}

fn grant_mut<'a>(config: &'a mut Config, name: &str) -> Result<&'a mut Grant> {
    config
        .grants
        .iter_mut()
        .find(|g| g.name == name)
        .ok_or_else(|| Error::NotFound {
            kind: "grant",
            name: name.to_string(),
        })
}

fn peer_mut<'a>(config: &'a mut Config, name: &str) -> Result<&'a mut Peer> {
    config.peer_mut(name).ok_or_else(|| Error::NotFound {
        kind: "peer",
        name: name.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::canonical_config;

    fn rule(s: &str) -> Rule {
        s.parse().unwrap()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    fn grants_of(config: &Config, peer: &str) -> Vec<String> {
        config.peer(peer).unwrap().grants.clone()
    }

    #[test]
    fn create_refuses_a_taken_name_and_drops_repeated_rules() {
        let mut cfg = canonical_config();
        create(
            &mut cfg,
            "photos",
            false,
            vec![rule("service:immich"), rule("service:immich")],
        )
        .unwrap();
        assert_eq!(cfg.grant("photos").unwrap().rules, [rule("service:immich")]);
        assert_eq!(cfg.grants.last().unwrap().name, "photos");
        let e = create(&mut cfg, "family", false, Vec::new()).unwrap_err();
        assert_eq!(e.to_string(), "grant 'family' already exists");
    }

    #[test]
    fn remove_detaches_and_says_who_had_it() {
        let mut cfg = canonical_config();
        assert_eq!(
            remove(&mut cfg, "personal").unwrap(),
            strings(&["router", "laptop"])
        );
        assert!(cfg.grant("personal").is_none());
        assert!(grants_of(&cfg, "router").is_empty());
        let e = remove(&mut cfg, "personal").unwrap_err();
        assert_eq!(e.to_string(), "grant 'personal' not found");
    }

    #[test]
    fn rename_follows_into_every_peer() {
        let mut cfg = canonical_config();
        assert_eq!(
            rename(&mut cfg, "personal", "own").unwrap(),
            strings(&["router", "laptop"])
        );
        assert_eq!(grants_of(&cfg, "laptop"), ["own"]);
        assert!(cfg.grant("own").is_some());
        let e = rename(&mut cfg, "own", "family").unwrap_err();
        assert_eq!(
            e.to_string(),
            "can't rename grant 'own' to 'family': grant 'family' already exists"
        );
        let e = rename(&mut cfg, "ghost", "spirit").unwrap_err();
        assert_eq!(e.to_string(), "grant 'ghost' not found");
    }

    #[test]
    fn rules_add_once_and_remove_only_what_is_there() {
        let mut cfg = canonical_config();
        let added = add_rules(
            &mut cfg,
            "family",
            &[rule("service:immich"), rule("host:192.168.1.9:445/tcp")],
        )
        .unwrap();
        assert_eq!(added.added, ["host:192.168.1.9:445/tcp"]);
        assert_eq!(added.already, ["service:immich"]);

        // A typo in the ports must not look like success: the rule stays.
        let before = cfg.clone();
        let e = remove_rules(
            &mut cfg,
            "family",
            &[rule("service:immich"), rule("host:192.168.1.9:445/udp")],
        )
        .unwrap_err();
        assert_eq!(
            e.to_string(),
            "grant 'family' has no rule host:192.168.1.9:445/udp; nothing removed (its rules: service:immich, host:192.168.1.9:445/tcp)"
        );
        assert_eq!(cfg, before);
        remove_rules(&mut cfg, "family", &[rule("host:192.168.1.9:445/tcp")]).unwrap();
        assert_eq!(cfg.grant("family").unwrap().rules, [rule("service:immich")]);
    }

    #[test]
    fn attach_and_detach_from_the_grant_side() {
        let mut cfg = canonical_config();
        let added = attach(&mut cfg, "family", &strings(&["laptop", "sister-phone"])).unwrap();
        assert_eq!(added.added, ["laptop"]);
        assert_eq!(added.already, ["sister-phone"]);
        assert_eq!(grants_of(&cfg, "laptop"), ["personal", "family"]);

        // One unknown peer among several changes none.
        let before = cfg.clone();
        let e = attach(&mut cfg, "personal", &strings(&["sister-phone", "mom"])).unwrap_err();
        assert_eq!(e.to_string(), "peer 'mom' not found");
        assert_eq!(cfg, before);

        detach(&mut cfg, "family", &strings(&["laptop", "sister-phone"])).unwrap();
        assert_eq!(grants_of(&cfg, "laptop"), ["personal"]);
        assert!(grants_of(&cfg, "sister-phone").is_empty());
        let e = detach(&mut cfg, "family", &strings(&["router"])).unwrap_err();
        assert_eq!(
            e.to_string(),
            "peer 'router' doesn't have grant 'family'; nothing detached (its grants: 'personal')"
        );
    }

    #[test]
    fn grants_for_everyone_have_every_peer_and_cannot_be_detached() {
        let mut cfg = canonical_config();
        create(&mut cfg, "public", false, vec![Rule::PublicDns]).unwrap();
        assert!(holders(&cfg, "public").unwrap().is_empty());
        assert!(set_everyone(&mut cfg, "public", true).unwrap());
        assert!(!set_everyone(&mut cfg, "public", true).unwrap());
        assert_eq!(
            names(&holders(&cfg, "public").unwrap()),
            ["router", "laptop", "sister-phone"]
        );
        let e = detach(&mut cfg, "public", &strings(&["laptop"])).unwrap_err();
        assert!(
            e.to_string().contains("because it applies to everyone"),
            "{e}"
        );
        assert_eq!(names(&holders(&cfg, "family").unwrap()), ["sister-phone"]);
    }

    #[test]
    fn from_the_peer_side() {
        let mut cfg = canonical_config();
        let added = peer_add(&mut cfg, "laptop", &strings(&["family", "personal"])).unwrap();
        assert_eq!(added.added, ["family"]);
        assert_eq!(added.already, ["personal"]);
        peer_remove(&mut cfg, "laptop", &strings(&["personal"])).unwrap();
        assert_eq!(grants_of(&cfg, "laptop"), ["family"]);
        set_peer(
            &mut cfg,
            "laptop",
            &strings(&["personal", "family", "personal"]),
        )
        .unwrap();
        assert_eq!(grants_of(&cfg, "laptop"), ["personal", "family"]);
        set_peer(&mut cfg, "laptop", &[]).unwrap();
        assert!(grants_of(&cfg, "laptop").is_empty());
        let e = set_peer(&mut cfg, "laptop", &strings(&["familly"])).unwrap_err();
        assert_eq!(e.to_string(), "grant 'familly' not found");
        let e = peer_remove(&mut cfg, "laptop", &strings(&["family"])).unwrap_err();
        assert!(e.to_string().contains("it has none attached"), "{e}");
    }

    #[test]
    fn grants_never_touch_an_address() {
        let mut cfg = canonical_config();
        let address = |c: &Config| c.peer("laptop").unwrap().wireguard.clone();
        let before = address(&cfg);
        set_peer(&mut cfg, "laptop", &strings(&["family"])).unwrap();
        rename(&mut cfg, "family", "photos").unwrap();
        remove(&mut cfg, "photos").unwrap();
        assert_eq!(address(&cfg), before);
    }
}
