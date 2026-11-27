//! Tailscale transport through Headscale. M1 ships the parts the shared
//! generators need (interface, ranges, tier identity) so the nftables ruleset
//! has its final shape; provisioning, artifacts, export and apply arrive in M2
//! with the Headscale API client.

use ipnet::Ipv4Net;

use super::{ProvisionOptions, Transport};
use crate::generate::{Artifact, Export};
use crate::io::{FileSystem, KeyGenerator, System};
use crate::model::{Peer, Platform, ServerConfig, TransportKind};
use crate::tier::Tier;
use crate::validate::Model;
use crate::{Error, Result, TAILSCALE_CGNAT};

#[derive(Debug, Clone, Copy, Default)]
pub struct TailscaleTransport;

impl TailscaleTransport {
    /// A Tailscale peer's address: its node's, wherever Headscale says, and
    /// none until it has said (a configured address could be another
    /// node's by now). A peer that names no node has its configured one.
    pub fn address(model: &Model<'_>, peer: &Peer) -> Option<std::net::Ipv4Addr> {
        let ts = peer.tailscale.as_ref()?;
        match ts.node_id {
            Some(id) => model.tailnet()?.get(&id).copied(),
            None => ts.address,
        }
    }
}

impl Transport for TailscaleTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tailscale
    }

    fn ingress_interface(&self, server: &ServerConfig) -> String {
        server.headscale.interface.clone()
    }

    fn source_range(&self, _server: &ServerConfig) -> Ipv4Net {
        TAILSCALE_CGNAT
    }

    fn set_prefix(&self) -> &'static str {
        "ts"
    }

    fn members_known(&self) -> bool {
        false
    }

    fn tier_members(&self, model: &Model<'_>, tier: &Tier<'_>) -> Vec<Ipv4Net> {
        let mut members: Vec<Ipv4Net> = model
            .members_on(tier, TransportKind::Tailscale)
            .filter_map(|p| Self::address(model, p))
            .map(Ipv4Net::from)
            .collect();
        // An address twice would be a conflicting interval to nft.
        members.sort();
        members.dedup();
        members
    }

    fn provision(
        &self,
        _model: &Model<'_>,
        _grants: &[String],
        _name: &str,
        _keys: &dyn KeyGenerator,
        _opts: &ProvisionOptions,
    ) -> Result<Peer> {
        Err(Error::NotImplemented(
            "Tailscale peers are provisioned through Headscale in M2",
        ))
    }

    fn generate(&self, _model: &Model<'_>, _fs: &dyn FileSystem) -> Result<Vec<Artifact>> {
        // M2: Headscale ACL policy (HuJSON), DNS config, advertised routes.
        Ok(Vec::new())
    }

    fn export(&self, _model: &Model<'_>, _peer: &Peer, _platform: Platform) -> Result<Export> {
        Err(Error::NotImplemented(
            "Tailscale export (preauth key + login instructions) arrives in M2",
        ))
    }

    fn apply(
        &self,
        _model: &Model<'_>,
        _artifacts: &[Artifact],
        _sys: System<'_>,
    ) -> Result<Vec<String>> {
        Ok(vec![
            "tailscale: nothing to apply in M1 (Headscale is driven in M2)".into(),
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::headscale::Tailnet;
    use crate::model::TailscalePeer;
    use crate::testing::{canonical_config, today};

    const STORED: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 9);
    const FROM_HEADSCALE: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 1);

    /// The canonical scenario plus a Tailscale twin of its first peer.
    fn with_tailscale_peer() -> crate::Config {
        let mut config = canonical_config();
        let mut peer = config.peers[0].clone();
        peer.name = "twin-tablet".into();
        peer.transport = TransportKind::Tailscale;
        peer.wireguard = None;
        peer.tailscale = Some(TailscalePeer {
            node_id: Some(1),
            address: Some(STORED),
        });
        config.peers.push(peer);
        config
    }

    fn members(model: &Model<'_>) -> Vec<Ipv4Net> {
        let config = model.config();
        let peer = config.peers.last().unwrap();
        let tier = model.tier_of(peer).unwrap();
        TailscaleTransport.tier_members(model, tier)
    }

    #[test]
    fn a_peer_is_where_headscale_says_its_node_is() {
        let config = with_tailscale_peer();
        // Headscale hasn't answered: the configured address could be
        // another node's by now, so none.
        let model = Model::resolve(&config, today()).unwrap();
        assert!(members(&model).is_empty());

        let known = Tailnet::from([(1, FROM_HEADSCALE)]);
        let model = Model::resolve(&config, today())
            .unwrap()
            .with_tailnet(Some(known));
        assert_eq!(members(&model), vec![Ipv4Net::from(FROM_HEADSCALE)]);

        // Headscale doesn't know the node (deleted): no address, no access.
        let model = Model::resolve(&config, today())
            .unwrap()
            .with_tailnet(Some(Tailnet::new()));
        assert!(members(&model).is_empty());
    }

    #[test]
    fn a_peer_without_a_node_keeps_its_configured_address() {
        let mut config = with_tailscale_peer();
        let mut plain = config.peers.last().unwrap().clone();
        plain.name = "plain-tablet".into();
        plain.tailscale = Some(TailscalePeer {
            node_id: None,
            address: Some(Ipv4Addr::new(100, 64, 0, 20)),
        });
        config.peers.push(plain);
        let model = Model::resolve(&config, today())
            .unwrap()
            .with_tailnet(Some(Tailnet::from([(1, FROM_HEADSCALE)])));
        // Same grants, so the same tier: both, each from its own source.
        let mut got = members(&model);
        got.sort();
        assert_eq!(
            got,
            vec![
                Ipv4Net::from(FROM_HEADSCALE),
                Ipv4Net::from(Ipv4Addr::new(100, 64, 0, 20))
            ]
        );
    }

    #[test]
    fn the_firewall_set_follows_headscale() {
        let config = with_tailscale_peer();
        let model = Model::resolve(&config, today())
            .unwrap()
            .with_tailnet(Some(Tailnet::from([(1, FROM_HEADSCALE)])));
        let rs = crate::generate::firewall::build(&model).unwrap();
        let ts: Vec<_> = rs
            .sets
            .iter()
            .filter(|s| s.name.starts_with("ts_"))
            .collect();
        assert!(
            ts.iter()
                .any(|s| s.elements == vec![Ipv4Net::from(FROM_HEADSCALE)]),
            "{ts:?}"
        );
        assert!(!ts
            .iter()
            .any(|s| s.elements.contains(&Ipv4Net::from(STORED))));
    }
}
