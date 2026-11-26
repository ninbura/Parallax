//! Plain WireGuard transport.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use super::{ProvisionOptions, Transport};
use crate::generate::{client, wg_server, Artifact, ArtifactKind, Export};
use crate::io::{FileSystem, KeyGenerator, System};
use crate::model::{Peer, Platform, ServerConfig, TransportKind, WireGuardPeer};
use crate::tier::Tier;
use crate::validate::Model;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, Default)]
pub struct WireGuardTransport;

impl Transport for WireGuardTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::WireGuard
    }

    fn ingress_interface(&self, server: &ServerConfig) -> String {
        server.wireguard.interface.clone()
    }

    fn source_range(&self, server: &ServerConfig) -> Ipv4Net {
        server.wireguard.supernet.trunc()
    }

    fn set_prefix(&self) -> &'static str {
        "wg"
    }

    fn members_known(&self) -> bool {
        true
    }

    fn tier_members(&self, model: &Model<'_>, tier: &Tier<'_>) -> Vec<Ipv4Net> {
        model
            .members_on(tier, TransportKind::WireGuard)
            .filter_map(|p| p.wireguard.as_ref().and_then(|w| w.address))
            .map(Ipv4Net::from)
            .collect()
    }

    fn provision(
        &self,
        model: &Model<'_>,
        grants: &[String],
        name: &str,
        keys: &dyn KeyGenerator,
        opts: &ProvisionOptions,
    ) -> Result<Peer> {
        if model.config().peer(name).is_some() {
            return Err(Error::Malformed {
                what: "peer",
                detail: format!("a peer named '{name}' already exists"),
            });
        }
        for g in grants {
            model.grant(g)?;
        }
        let address = crate::alloc::allocate(model.config())?;
        let kp = keys.keypair();
        let mut wireguard = WireGuardPeer::new(kp.public, &model.server().wireguard.peer_defaults);
        wireguard.address = Some(address);
        // Always present here so the caller can do the one-time export;
        // the caller strips it before persisting unless
        // `opts.retain_private_key` is set.
        wireguard.private_key = Some(kp.private);
        wireguard.preshared_key = opts.preshared_key.then(|| keys.preshared_key());
        Ok(Peer {
            name: name.to_string(),
            grants: grants.to_vec(),
            transport: TransportKind::WireGuard,
            enabled: true,
            expires: opts.expires,
            wireguard: Some(wireguard),
            tailscale: None,
        })
    }

    fn generate(&self, model: &Model<'_>, fs: &dyn FileSystem) -> Result<Vec<Artifact>> {
        let mut out = vec![wg_server::render(model, fs)?];
        for peer in model.peers_on(TransportKind::WireGuard) {
            if peer
                .wireguard
                .as_ref()
                .is_some_and(|w| w.private_key.is_some())
            {
                for platform in Platform::ALL {
                    let export = client::render(model, peer, platform)?;
                    out.push(Artifact::secret(
                        ArtifactKind::ClientConfig,
                        format!("clients/{}/{}.conf", peer.name, platform),
                        export.contents,
                    ));
                }
            }
        }
        Ok(out)
    }

    fn export(&self, model: &Model<'_>, peer: &Peer, platform: Platform) -> Result<Export> {
        client::render(model, peer, platform)
    }

    fn apply(
        &self,
        model: &Model<'_>,
        artifacts: &[Artifact],
        sys: System<'_>,
    ) -> Result<Vec<String>> {
        let wg = &model.server().wireguard;
        let iface = wg.interface.as_str();
        let conf = artifacts
            .iter()
            .find(|a| a.kind == ArtifactKind::WireGuardServer)
            .ok_or_else(|| Error::Malformed {
                what: "apply",
                detail: "no WireGuard server artifact in the bundle".into(),
            })?;
        let mut log = Vec::new();
        let exists = sys
            .runner
            .run("ip", &["link", "show", "dev", iface], None)?
            .ok();
        if !exists {
            let out = sys
                .runner
                .run("ip", &["link", "add", iface, "type", "wireguard"], None)?;
            if !out.ok() {
                return Err(Error::Malformed {
                    what: "wireguard",
                    detail: format!(
                        "cannot create {iface}: {}. Is the WireGuard kernel module loaded on the host (`modprobe wireguard`)?",
                        out.stderr.trim()
                    ),
                });
            }
            log.push(format!("wireguard: created interface {iface}"));
        }
        let cidr = format!("{}/{}", gateway(wg.supernet), wg.supernet.prefix_len());
        sys.runner
            .run_checked("ip", &["address", "replace", &cidr, "dev", iface], None)?;
        // Piped, not a path: Ubuntu's AppArmor profile for `wg` lets it open
        // files only under /etc/wireguard. wg-quick feeds `wg` the same way.
        sys.runner.run_checked(
            "wg",
            &["syncconf", iface, "/dev/stdin"],
            Some(&conf.contents),
        )?;
        sys.runner
            .run_checked("ip", &["link", "set", "up", "dev", iface], None)?;
        log.push(format!(
            "wireguard: {iface} at {cidr} synced ({} peers)",
            model.peers_on(TransportKind::WireGuard).count()
        ));
        Ok(log)
    }
}

fn gateway(supernet: Ipv4Net) -> Ipv4Addr {
    supernet.hosts().next().unwrap_or_else(|| supernet.addr())
}
