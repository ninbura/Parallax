//! Generators. Every output is derived from the [`Model`]; nothing is ever
//! hand-edited. Output is deterministic so plan/diff and golden tests are exact.

pub mod client;
pub mod dnsmasq;
pub mod firewall;
pub mod nginx;
pub mod wg_server;

use std::path::{Path, PathBuf};

use crate::io::FileSystem;
use crate::model::Platform;
use crate::validate::Model;
use crate::Result;

/// What an artifact is, for apply ordering and reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ArtifactKind {
    WireGuardServer,
    Firewall,
    FirewallDockerUser,
    Dnsmasq,
    NginxSnippet,
    ClientConfig,
}

/// One generated file, addressed relative to the output directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub kind: ArtifactKind,
    pub path: PathBuf,
    pub contents: String,
    /// Must be written with mode 0600.
    pub secret: bool,
}

impl Artifact {
    pub fn public(kind: ArtifactKind, path: impl Into<PathBuf>, contents: String) -> Self {
        Artifact {
            kind,
            path: path.into(),
            contents,
            secret: false,
        }
    }
    pub fn secret(kind: ArtifactKind, path: impl Into<PathBuf>, contents: String) -> Self {
        Artifact {
            kind,
            path: path.into(),
            contents,
            secret: true,
        }
    }
}

/// A client credential bundle rendered for one platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub peer: String,
    pub platform: Platform,
    /// The config text (QR-ready for WireGuard).
    pub contents: String,
    /// The text contains a private key.
    pub contains_secret: bool,
    /// Honest caveats for the operator (e.g. no split DNS on this platform).
    pub warnings: Vec<String>,
}

/// Everything `generate` produces.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Bundle {
    pub artifacts: Vec<Artifact>,
    pub warnings: Vec<String>,
}

impl Bundle {
    pub fn find(&self, path: impl AsRef<Path>) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.path == path.as_ref())
    }
    pub fn of_kind(&self, kind: ArtifactKind) -> impl Iterator<Item = &Artifact> {
        self.artifacts.iter().filter(move |a| a.kind == kind)
    }
}

/// Run every generator: transport-native artifacts first, then the shared
/// layers. Artifacts are sorted by path.
pub fn generate_all(model: &Model<'_>, fs: &dyn FileSystem) -> Result<Bundle> {
    let mut bundle = Bundle {
        artifacts: Vec::new(),
        warnings: model.warnings().to_vec(),
    };
    for transport in crate::transport::all() {
        bundle.artifacts.extend(transport.generate(model, fs)?);
    }
    bundle.artifacts.extend(firewall::render(model)?);
    bundle.artifacts.push(dnsmasq::render(model)?);
    bundle.artifacts.extend(nginx::render(model)?);
    bundle.artifacts.sort_by(|a, b| a.path.cmp(&b.path));
    if !model.needs_catch_all_resolver() {
        for t in &model.config().templates {
            if t.dns.wireguard == crate::model::DnsMode::Split {
                bundle.warnings.push(format!(
                    "template '{}': mobile WireGuard exports fall back to tunnel-wide DNS, but no template enables the shim's catch-all resolver; set dns.wireguard = \"tunnel_wide\" on a template or use the Tailscale transport for phones",
                    t.name
                ));
                break;
            }
        }
    }
    Ok(bundle)
}
