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
        model
            .members_on(tier, TransportKind::Tailscale)
            .filter_map(|p| p.tailscale.as_ref().and_then(|t| t.address))
            .map(Ipv4Net::from)
            .collect()
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
