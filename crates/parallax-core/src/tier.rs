//! Tiers: peers with the same effective grants (their own plus every
//! `everyone` grant) form one tier, and every generator works per tier, not
//! per peer. A tier gets one firewall chain, one DNS and one proxy entry,
//! built from the union of its grants' rules, so a hundred peers on the same
//! grants cost what one does.
//!
//! Tiers come from the configuration alone (every peer, enabled or not), so
//! they and their numbering don't change when a peer expires. Which
//! addresses are members is the generators' business: active peers only.

use std::collections::BTreeMap;

use crate::model::{Config, Grant, Peer, Rule};

/// One combination of grants in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tier<'a> {
    /// Position among the tiers: names its firewall chain and sets.
    pub index: usize,
    /// Its grants, in configuration order.
    pub grants: Vec<&'a Grant>,
    /// The union of their rules, in grant order, each once.
    pub rules: Vec<&'a Rule>,
    /// Its peers, in configuration order, enabled or not.
    pub peers: Vec<&'a Peer>,
}

impl Tier<'_> {
    /// The grant names joined by `+` (`family+photos`): for comments and
    /// logs. Grant names have no `+`, so it's unambiguous.
    pub fn label(&self) -> String {
        self.grants
            .iter()
            .map(|g| g.name.as_str())
            .collect::<Vec<_>>()
            .join("+")
    }

    /// 16 hex digits naming the tier by its grants, not its position, so
    /// the firewall can tell its sets apart while it builds the rules. It
    /// then renames each set after the tier's whole access (issue #35).
    pub fn key(&self) -> String {
        fnv64(&self.label())
    }

    pub fn has(&self, rule: &Rule) -> bool {
        self.rules.contains(&rule)
    }

    /// Reaches every configured network and the internet: the owner's own
    /// devices. The home's public IP is no different from any public
    /// address for these, so its limits ([`crate::names::public_ip_refusal`])
    /// and the hairpin drop don't apply.
    pub fn reaches_everything(&self) -> bool {
        self.has(&Rule::AllNetworks) && self.has(&Rule::Internet)
    }

    /// Who a message is about: `peer 'sister-phone' (grant 'family')`,
    /// `peers 'laptop', 'router' (grants 'lan', 'photos')`.
    pub fn context(&self) -> String {
        let peers = quoted(self.peers.iter().map(|p| p.name.as_str()));
        format!(
            "{} {peers} ({})",
            if self.peers.len() == 1 {
                "peer"
            } else {
                "peers"
            },
            self.grant_context()
        )
    }

    /// The grants alone: `grant 'family'`, `grants 'lan', 'photos'`. For
    /// messages that are compared before and after a change, which adding
    /// or removing a peer mustn't alter.
    pub fn grant_context(&self) -> String {
        format!(
            "{} {}",
            if self.grants.len() == 1 {
                "grant"
            } else {
                "grants"
            },
            quoted(self.grants.iter().map(|g| g.name.as_str()))
        )
    }
}

/// 16 hex digits of FNV-1a: fixed across builds, no dependency.
pub(crate) fn fnv64(text: &str) -> String {
    let hash = text.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    format!("{hash:016x}")
}

fn quoted<'a>(names: impl Iterator<Item = &'a str>) -> String {
    names
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Names of the grants `peer` has, its own and every `everyone` grant, in
/// configuration order.
pub fn grant_names<'a>(config: &'a Config, peer: &Peer) -> Vec<&'a str> {
    effective(config, peer)
        .into_iter()
        .map(|i| config.grants[i].name.as_str())
        .collect()
}

/// Positions in `config.grants` of what `peer` has: its own grants and
/// every `everyone` grant, sorted, each once. Unknown names are left out
/// (validation reports them).
fn effective(config: &Config, peer: &Peer) -> Vec<usize> {
    let mut out: Vec<usize> = config
        .grants
        .iter()
        .enumerate()
        .filter(|(_, g)| g.everyone || peer.grants.contains(&g.name))
        .map(|(i, _)| i)
        .collect();
    // Two grants of one name: the first counts, as in `Config::grant`.
    out.retain(|&i| {
        config
            .grants
            .iter()
            .position(|g| g.name == config.grants[i].name)
            == Some(i)
    });
    out
}

/// Every tier in use, ordered by their grants' positions in the
/// configuration, so the same configuration always numbers them alike.
/// Peers with no grants at all are in none: they reach nothing.
pub fn tiers(config: &Config) -> Vec<Tier<'_>> {
    let mut by_grants: BTreeMap<Vec<usize>, Vec<&Peer>> = BTreeMap::new();
    for peer in &config.peers {
        let grants = effective(config, peer);
        if !grants.is_empty() {
            by_grants.entry(grants).or_default().push(peer);
        }
    }
    by_grants
        .into_iter()
        .enumerate()
        .map(|(index, (positions, peers))| {
            let grants: Vec<&Grant> = positions
                .into_iter()
                .filter_map(|i| config.grants.get(i))
                .collect();
            let mut rules: Vec<&Rule> = Vec::new();
            for rule in grants.iter().flat_map(|g| &g.rules) {
                if !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
            Tier {
                index,
                grants,
                rules,
                peers,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::canonical_config;

    fn labels(config: &Config) -> Vec<(String, Vec<String>)> {
        tiers(config)
            .iter()
            .map(|t| (t.label(), t.peers.iter().map(|p| p.name.clone()).collect()))
            .collect()
    }

    #[test]
    fn peers_with_the_same_grants_share_a_tier() {
        let cfg = canonical_config();
        assert_eq!(
            labels(&cfg),
            [
                ("personal".into(), vec!["router".into(), "laptop".into()]),
                ("family".into(), vec!["sister-phone".into()]),
            ]
        );
    }

    #[test]
    fn grants_combine_in_configuration_order_and_everyone_joins_all() {
        let mut cfg = canonical_config();
        // Order and duplicates in the peer's list don't make another tier.
        cfg.peers[0].grants = vec!["family".into(), "personal".into(), "family".into()];
        cfg.peers[1].grants = vec!["personal".into(), "family".into()];
        cfg.grants.push(Grant {
            name: "public".into(),
            everyone: true,
            log: None,
            rules: vec![Rule::PublicDns],
        });
        cfg.peers[2].grants.clear();
        let all = tiers(&cfg);
        assert_eq!(
            labels(&cfg),
            [
                (
                    "personal+family+public".into(),
                    vec!["router".into(), "laptop".into()]
                ),
                ("public".into(), vec!["sister-phone".into()]),
            ]
        );
        // The union, each rule once.
        assert_eq!(
            all[0].rules,
            [
                &Rule::AllNetworks,
                &Rule::PublicDns,
                &Rule::Service {
                    name: "immich".into()
                },
            ]
        );
        assert_eq!(
            all[0].context(),
            "peers 'router', 'laptop' (grants 'personal', 'family', 'public')"
        );
        assert_eq!(all[1].context(), "peer 'sister-phone' (grant 'public')");
    }

    #[test]
    fn a_peer_without_grants_is_in_no_tier() {
        let mut cfg = canonical_config();
        cfg.peers[2].grants.clear();
        assert_eq!(tiers(&cfg).len(), 1);
    }
}
