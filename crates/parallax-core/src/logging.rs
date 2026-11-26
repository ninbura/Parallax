//! Which peers' traffic the gateway logs, and how much (docs/logging.md).
//! The firewall marks the flows of logged peers and hands their blocked
//! attempts to the collector; nothing is marked or handed over for peers
//! at `off`, so logging nobody costs nothing.

use ipnet::Ipv4Net;

use crate::model::{LogLevel, Peer, TransportKind};
use crate::{Config, Error, Model, Result};

/// Whose level `parallax log level` sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `server.logs.level`.
    Global,
    Peer(String),
    Grant(String),
}

/// Set a level, or with `None` clear a peer's or grant's own so it follows
/// the rest again. True when something changed.
pub fn set_level(config: &mut Config, target: &Target, level: Option<LogLevel>) -> Result<bool> {
    let not_found = |kind: &'static str, name: &str| Error::NotFound {
        kind,
        name: name.to_string(),
    };
    let slot = match target {
        Target::Global => {
            let Some(level) = level else {
                return Err(Error::Malformed {
                    what: "log level",
                    detail: "the global level (server.logs.level) has nothing to inherit from; \
                             set off, connections, bytes or denied"
                        .into(),
                });
            };
            let changed = config.server.logs.level != level;
            config.server.logs.level = level;
            return Ok(changed);
        }
        Target::Peer(name) => {
            &mut config
                .peers
                .iter_mut()
                .find(|p| &p.name == name)
                .ok_or_else(|| not_found("peer", name))?
                .log
        }
        Target::Grant(name) => {
            &mut config
                .grants
                .iter_mut()
                .find(|g| &g.name == name)
                .ok_or_else(|| not_found("grant", name))?
                .log
        }
    };
    let changed = *slot != level;
    *slot = level;
    Ok(changed)
}

/// The level that applies to `peer`: its own `log` if set, otherwise the
/// most detailed `log` among its grants (grants for everyone included),
/// otherwise `server.logs.level`.
pub fn level(config: &Config, peer: &Peer) -> LogLevel {
    if let Some(own) = peer.log {
        return own;
    }
    config
        .grants
        .iter()
        .filter(|g| g.everyone || peer.grants.contains(&g.name))
        .filter_map(|g| g.log)
        .max()
        .unwrap_or(config.server.logs.level)
}

/// Tunnel addresses of the active WireGuard peers logged at `at_least` or
/// more, sorted. Tailscale nodes join in M2, when their addresses come from
/// Headscale.
pub fn addresses(model: &Model<'_>, at_least: LogLevel) -> Vec<Ipv4Net> {
    let mut out: Vec<Ipv4Net> = model
        .peers_on(TransportKind::WireGuard)
        .filter(|p| level(model.config(), p) >= at_least)
        .filter_map(|p| p.wireguard.as_ref().and_then(|w| w.address))
        .map(Ipv4Net::from)
        .collect();
    out.sort();
    out
}

/// Whether some peer the firewall can mark is logged at `at_least` or
/// more (the same peers as [`addresses`]).
pub fn any(model: &Model<'_>, at_least: LogLevel) -> bool {
    !addresses(model, at_least).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Grant;
    use crate::testing::{canonical_config, today};

    #[test]
    fn a_peer_s_own_level_wins_then_its_grants_then_the_global_one() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        let peer = cfg.peers[1].clone();
        assert_eq!(level(&cfg, &peer), LogLevel::Connections, "global");

        // The most detailed of its grants', even below the global level.
        let family = cfg
            .grants
            .iter_mut()
            .position(|g| g.name == "family")
            .unwrap();
        cfg.grants[family].log = Some(LogLevel::Off);
        let mut peer = cfg.peers[1].clone();
        peer.grants = vec!["family".into()];
        assert_eq!(level(&cfg, &peer), LogLevel::Off, "its grant");
        cfg.grants.push(Grant {
            name: "watched".into(),
            everyone: true,
            log: Some(LogLevel::Denied),
            rules: Vec::new(),
        });
        assert_eq!(level(&cfg, &peer), LogLevel::Denied, "grant for everyone");

        peer.log = Some(LogLevel::Bytes);
        assert_eq!(level(&cfg, &peer), LogLevel::Bytes, "its own");
    }

    #[test]
    fn levels_are_set_and_cleared_by_name() {
        let mut cfg = canonical_config();
        let peer = Target::Peer("sister-phone".into());
        assert!(set_level(&mut cfg, &peer, Some(LogLevel::Bytes)).unwrap());
        assert!(!set_level(&mut cfg, &peer, Some(LogLevel::Bytes)).unwrap());
        assert_eq!(cfg.peer("sister-phone").unwrap().log, Some(LogLevel::Bytes));
        assert!(set_level(&mut cfg, &peer, None).unwrap());
        assert_eq!(cfg.peer("sister-phone").unwrap().log, None);

        let grant = Target::Grant("family".into());
        assert!(set_level(&mut cfg, &grant, Some(LogLevel::Denied)).unwrap());
        assert_eq!(cfg.grant("family").unwrap().log, Some(LogLevel::Denied));
        assert!(set_level(&mut cfg, &Target::Global, Some(LogLevel::Connections)).unwrap());
        assert_eq!(cfg.server.logs.level, LogLevel::Connections);

        let err = set_level(&mut cfg, &Target::Global, None).unwrap_err();
        assert!(err.to_string().contains("nothing to inherit"), "{err}");
        let err = set_level(&mut cfg, &Target::Peer("nobody".into()), None).unwrap_err();
        assert!(err.to_string().contains("nobody"), "{err}");
    }

    /// Levels survive TOML (import, export, `config edit`). The daemon's
    /// socket reads through the same form (its test is in the CLI).
    #[test]
    fn levels_survive_toml() {
        let mut cfg = canonical_config();
        cfg.server.logs.level = LogLevel::Connections;
        cfg.grants[1].log = Some(LogLevel::Denied);
        cfg.peers[0].log = Some(LogLevel::Off);
        let toml = cfg.to_toml().unwrap();
        assert_eq!(Config::from_toml(&toml).unwrap(), cfg);
    }

    #[test]
    fn nobody_is_logged_by_default() {
        let cfg = canonical_config();
        let model = Model::resolve(&cfg, today()).unwrap();
        assert!(!any(&model, LogLevel::Connections));
        assert!(addresses(&model, LogLevel::Connections).is_empty());
    }
}
