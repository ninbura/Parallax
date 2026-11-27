//! The [`Transport`] abstraction. Parallax always runs both transports; the
//! shared layers (NETMAP, firewall, DNS shim, nginx snippets) are written once
//! against this trait and never per transport.

mod tailscale;
mod wireguard;

pub use tailscale::TailscaleTransport;
pub use wireguard::WireGuardTransport;

use ipnet::Ipv4Net;

use crate::generate::{Artifact, Export};
use crate::io::{KeyGenerator, System};
use crate::model::{Peer, Platform, ServerConfig, TransportKind};
use crate::tier::Tier;
use crate::validate::Model;
use crate::Result;

/// Options for [`Transport::provision`].
#[derive(Debug, Clone, Default)]
pub struct ProvisionOptions {
    /// Keep the private key in the model so configs can be regenerated later.
    pub retain_private_key: bool,
    /// Also issue a preshared key (WireGuard only).
    pub preshared_key: bool,
    pub expires: Option<crate::date::Date>,
}

/// Per-transport responsibilities. Everything not listed here is shared.
pub trait Transport {
    fn kind(&self) -> TransportKind;

    /// Interface on the gateway this transport's traffic arrives on.
    fn ingress_interface(&self, server: &ServerConfig) -> String;

    /// Range every source address on this transport falls in. Used for the
    /// trailing default-deny and for return routes on the LAN router.
    fn source_range(&self, server: &ServerConfig) -> Ipv4Net;

    /// The named address set holding `tier`'s members on this transport,
    /// which the firewall matches them by. Named by the tier's grants
    /// ([`Tier::key`]) while the ruleset is built; the firewall then renames
    /// it after its members and the rules that use it (issue #35). At most 19 characters
    /// either way (ipset's limit is 31).
    fn set_name(&self, tier: &Tier<'_>) -> String {
        format!("{}_{}", self.set_prefix(), tier.key())
    }

    /// `wg`, `ts`: starts this transport's set names.
    fn set_prefix(&self) -> &'static str;

    /// Whether the members are known when the ruleset is generated. Then
    /// FORWARD picks a tier's chain by looking the source address up in
    /// one verdict map; otherwise by the tier's set, which the control
    /// plane keeps in sync without a new ruleset (Tailscale, M2).
    fn members_known(&self) -> bool;

    /// The tier's active members, one /32 each (Tailscale: the nodes known
    /// so far), for the firewall's sets and the L7 allow-lists.
    fn tier_members(&self, model: &Model<'_>, tier: &Tier<'_>) -> Vec<Ipv4Net>;

    /// Create identity, credentials and address for a new device with
    /// `grants`. Returns the peer to insert into the configuration; nothing
    /// is persisted here.
    fn provision(
        &self,
        model: &Model<'_>,
        grants: &[String],
        name: &str,
        keys: &dyn KeyGenerator,
        opts: &ProvisionOptions,
    ) -> Result<Peer>;

    /// Transport-native artifacts (server config for WireGuard; ACL/DNS/route
    /// policy for Headscale).
    fn generate(&self, model: &Model<'_>, fs: &dyn crate::io::FileSystem) -> Result<Vec<Artifact>>;

    /// Credentials a device needs, rendered for a platform.
    fn export(&self, model: &Model<'_>, peer: &Peer, platform: Platform) -> Result<Export>;

    /// Reconcile the live system with `artifacts` (the whole bundle, contents
    /// included). Returns a log of what was done.
    fn apply(
        &self,
        model: &Model<'_>,
        artifacts: &[Artifact],
        sys: System<'_>,
    ) -> Result<Vec<String>>;
}

/// Both transports, in stable order. There is no way to run fewer.
pub fn all() -> Vec<Box<dyn Transport>> {
    vec![Box::new(WireGuardTransport), Box::new(TailscaleTransport)]
}

/// Look up a transport by kind.
pub fn by_kind(kind: TransportKind) -> Box<dyn Transport> {
    match kind {
        TransportKind::WireGuard => Box::new(WireGuardTransport),
        TransportKind::Tailscale => Box::new(TailscaleTransport),
    }
}
