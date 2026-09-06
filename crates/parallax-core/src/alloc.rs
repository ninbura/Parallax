//! WireGuard address allocation: lowest free host of the template pool,
//! skipping the gateway address and every address already held by a peer.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use crate::model::{Config, TransportKind};
use crate::{Error, Result};

/// Addresses that must never be handed out.
fn reserved(config: &Config) -> BTreeSet<Ipv4Addr> {
    let mut set: BTreeSet<Ipv4Addr> = config
        .peers
        .iter()
        .filter_map(|p| p.wireguard.as_ref().and_then(|w| w.address))
        .collect();
    set.insert(config.server.wireguard.gateway_address());
    if let Some(listen) = config.server.dns.listen {
        set.insert(listen);
    }
    set
}

/// Pick the lowest free host in `pool`.
pub fn pick(pool: Ipv4Net, taken: &BTreeSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    pool.hosts().find(|a| !taken.contains(a))
}

/// Allocate an address for a new WireGuard peer of `template`.
pub fn allocate(config: &Config, template: &str) -> Result<Ipv4Addr> {
    let t = config.template(template).ok_or_else(|| Error::NotFound {
        kind: "template",
        name: template.to_string(),
    })?;
    pick(t.wireguard.pool, &reserved(config)).ok_or_else(|| Error::PoolExhausted {
        template: template.to_string(),
        pool: t.wireguard.pool,
    })
}

/// Give every WireGuard peer without an address one. Returns `(peer, address)` pairs.
pub fn allocate_missing(config: &mut Config) -> Result<Vec<(String, Ipv4Addr)>> {
    let mut done = Vec::new();
    let names: Vec<String> = config
        .peers
        .iter()
        .filter(|p| {
            p.transport == TransportKind::WireGuard
                && p.wireguard.as_ref().is_some_and(|w| w.address.is_none())
        })
        .map(|p| p.name.clone())
        .collect();
    for name in names {
        let template = config
            .peer(&name)
            .map(|p| p.template.clone())
            .unwrap_or_default();
        let addr = allocate(config, &template)?;
        if let Some(w) = config.peer_mut(&name).and_then(|p| p.wireguard.as_mut()) {
            w.address = Some(addr);
        }
        done.push((name, addr));
    }
    Ok(done)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_lowest_free_and_skips_reserved() {
        let pool: Ipv4Net = "10.8.1.0/30".parse().unwrap();
        let mut taken = BTreeSet::new();
        assert_eq!(pick(pool, &taken), Some("10.8.1.1".parse().unwrap()));
        taken.insert("10.8.1.1".parse().unwrap());
        assert_eq!(pick(pool, &taken), Some("10.8.1.2".parse().unwrap()));
        taken.insert("10.8.1.2".parse().unwrap());
        assert_eq!(pick(pool, &taken), None);
    }
}
