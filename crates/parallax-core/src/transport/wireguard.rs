//! Plain WireGuard transport.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

use super::{ProvisionOptions, TierSource, Transport};
use crate::generate::{client, wg_server, Artifact, ArtifactKind, Export};
use crate::io::{FileSystem, KeyGenerator, System};
use crate::model::{Peer, Platform, ServerConfig, Template, TransportKind, WireGuardPeer};
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

    fn tier_source(&self, _server: &ServerConfig, template: &Template) -> TierSource {
        TierSource::Cidr(template.wireguard.pool.trunc())
    }

    fn tier_members(&self, _model: &Model<'_>, template: &Template) -> Vec<Ipv4Net> {
        vec![template.wireguard.pool.trunc()]
    }

    fn provision(
        &self,
        model: &Model<'_>,
        template: &Template,
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
        let address = crate::alloc::allocate(model.config(), &template.name)?;
        let kp = keys.keypair();
        Ok(Peer {
            name: name.to_string(),
            template: template.name.clone(),
            transport: TransportKind::WireGuard,
            enabled: true,
            expires: opts.expires,
            wireguard: Some(WireGuardPeer {
                public_key: kp.public,
                address: Some(address),
                // Always present here so the caller can do the one-time export;
                // the caller strips it before persisting unless
                // `opts.retain_private_key` is set.
                private_key: Some(kp.private),
                preshared_key: opts.preshared_key.then(|| keys.preshared_key()),
            }),
            tailscale: None,
        })
    }

    fn generate(&self, model: &Model<'_>, fs: &dyn FileSystem) -> Result<Vec<Artifact>> {
        let mut out = vec![wg_server::render(model, fs)?];
        for peer in model.peers_on(TransportKind::WireGuard, None) {
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
        let conf_path = conf.path.to_string_lossy().into_owned();
        sys.runner
            .run_checked("wg", &["syncconf", iface, &conf_path], None)?;
        sys.runner
            .run_checked("ip", &["link", "set", "up", "dev", iface], None)?;
        log.push(format!(
            "wireguard: {iface} at {cidr} synced ({} peers)",
            model.peers_on(TransportKind::WireGuard, None).count()
        ));
        Ok(log)
    }
}

fn gateway(supernet: Ipv4Net) -> Ipv4Addr {
    supernet.hosts().next().unwrap_or_else(|| supernet.addr())
}
