//! Tailscale transport through Headscale. M1 ships the parts the shared
//! generators need (interface, ranges, tier identity) so the nftables ruleset
//! has its final shape; provisioning, artifacts, export and apply arrive in M2
//! with the Headscale API client.

use ipnet::Ipv4Net;

use super::{ProvisionOptions, TierSource, Transport};
use crate::generate::{Artifact, Export};
use crate::io::{FileSystem, KeyGenerator, System};
use crate::model::{Peer, Platform, ServerConfig, Template, TransportKind};
use crate::validate::Model;
use crate::{Error, Result, TAILSCALE_CGNAT};

#[derive(Debug, Clone, Copy, Default)]
pub struct TailscaleTransport;

impl TailscaleTransport {
    /// nftables set holding the Tailscale addresses of a template's nodes.
    pub fn set_name(template: &Template) -> String {
        format!("ts_{}", template.name.replace('-', "_"))
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

    fn tier_source(&self, _server: &ServerConfig, template: &Template) -> TierSource {
        TierSource::Set(Self::set_name(template))
    }

    fn tier_members(&self, model: &Model<'_>, template: &Template) -> Vec<Ipv4Net> {
        model
            .peers_on(TransportKind::Tailscale, Some(&template.name))
            .filter_map(|p| p.tailscale.as_ref().and_then(|t| t.address))
            .map(|a| Ipv4Net::new(a, 32).expect("/32"))
            .collect()
    }

    fn provision(
        &self,
        _model: &Model<'_>,
        _template: &Template,
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
