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
use crate::model::{Peer, Platform, ServerConfig, Template, TransportKind};
use crate::validate::Model;
use crate::Result;

/// How the firewall identifies members of a template on a transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TierSource {
    /// A static prefix: the template's WireGuard pool. The address *is* the tier.
    Cidr(Ipv4Net),
    /// A named nftables set of node addresses, kept in sync from the control plane.
    Set(String),
}

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

    /// How the firewall matches members of `template`.
    fn tier_source(&self, server: &ServerConfig, template: &Template) -> TierSource;

    /// Concrete prefixes of the template's members for L7 allow-lists
    /// (WireGuard: the pool; Tailscale: one /32 per known node).
    fn tier_members(&self, model: &Model<'_>, template: &Template) -> Vec<Ipv4Net>;

    /// Create identity, credentials and address for a new device. Returns the
    /// peer to insert into the configuration; nothing is persisted here.
    fn provision(
        &self,
        model: &Model<'_>,
        template: &Template,
        name: &str,
        keys: &dyn KeyGenerator,
        opts: &ProvisionOptions,
    ) -> Result<Peer>;

    /// Transport-native artifacts (server config for WireGuard; ACL/DNS/route
    /// policy for Headscale).
    fn generate(&self, model: &Model<'_>, fs: &dyn crate::io::FileSystem) -> Result<Vec<Artifact>>;

    /// Credentials a device needs, rendered for a platform.
    fn export(&self, model: &Model<'_>, peer: &Peer, platform: Platform) -> Result<Export>;

    /// Reconcile the live system with `artifacts`. Returns a log of what was done.
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
