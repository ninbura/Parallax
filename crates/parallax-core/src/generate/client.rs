//! Per-peer, per-platform WireGuard client configs.
//!
//! `AllowedIPs` is a courtesy that shapes the client's routing table; the
//! gateway's FORWARD chain is the only enforcement point. The DNS section is
//! where platforms differ, and the generator encodes that honestly.

use std::fmt::Write as _;

use ipnet::Ipv4Net;

use super::Export;
use crate::model::{AllowedIpsStrategy, DnsMode, Peer, Platform, Template, TransportKind};
use crate::validate::{Model, ReachKind};
use crate::{Error, Result};

/// The DNS mode a platform actually gets, given the template's wish.
pub fn effective_dns_mode(template: &Template, platform: Platform) -> DnsMode {
    match (template.dns.wireguard, platform) {
        (DnsMode::Split, Platform::Mobile) => DnsMode::TunnelWide,
        (mode, _) => mode,
    }
}

/// The courtesy `AllowedIPs` for a template on WireGuard.
pub fn allowed_ips(model: &Model<'_>, template: &Template, platform: Platform) -> Vec<Ipv4Net> {
    let mut out: Vec<Ipv4Net> = Vec::new();
    let mut push = |n: Ipv4Net| {
        if !out.iter().any(|o| o.contains(&n)) {
            out.retain(|o| !n.contains(o));
            out.push(n);
        }
    };
    match template.client.allowed_ips {
        AllowedIpsStrategy::FullTunnel => {
            push("0.0.0.0/0".parse().expect("cidr"));
            return out;
        }
        AllowedIpsStrategy::MappedSubnets => {
            for n in model.visible_networks(template) {
                push(n.client_subnet().trunc());
            }
        }
        AllowedIpsStrategy::GrantsOnly => {
            for r in model.reaches(template) {
                match r.kind {
                    ReachKind::Internet => push("0.0.0.0/0".parse().expect("cidr")),
                    ReachKind::Lan { .. } => {
                        if let Some(n) = r.client_net() {
                            push(n);
                        }
                    }
                }
            }
        }
    }
    if effective_dns_mode(template, platform) != DnsMode::None {
        push(Ipv4Net::new(model.shim_address(), 32).expect("/32"));
    }
    out
}

pub fn render(model: &Model<'_>, peer: &Peer, platform: Platform) -> Result<Export> {
    if peer.transport != TransportKind::WireGuard {
        return Err(Error::Malformed {
            what: "peer",
            detail: format!(
                "'{}' is a {} peer, not WireGuard",
                peer.name, peer.transport
            ),
        });
    }
    let wg = peer.wireguard.as_ref().ok_or_else(|| Error::Malformed {
        what: "peer",
        detail: format!("'{}' has no WireGuard identity", peer.name),
    })?;
    let address = wg.address.ok_or_else(|| Error::Malformed {
        what: "peer",
        detail: format!(
            "'{}' has no address; run `parallax peer allocate`",
            peer.name
        ),
    })?;
    let template = model.template(&peer.template)?;
    let server = model.server();
    let shim = model.shim_address();
    let mode = effective_dns_mode(template, platform);
    let domains = model.routing_domains(template);
    let mut warnings = Vec::new();
    let mut s = String::new();

    let _ = writeln!(
        s,
        "# Parallax peer \"{}\" (template \"{}\", {} flavour)",
        peer.name, template.name, platform
    );
    s.push_str("# AllowedIPs are a courtesy for split tunnelling; the gateway enforces access server-side.\n");
    s.push_str("[Interface]\n");
    match &wg.private_key {
        Some(k) => {
            let _ = writeln!(s, "PrivateKey = {}", k.expose_base64());
        }
        None => {
            s.push_str("PrivateKey = <paste the private key shown when this peer was created>\n");
            warnings.push(format!(
                "peer '{}' does not retain its private key; only the one-time export at creation contained it",
                peer.name
            ));
        }
    }
    let _ = writeln!(s, "Address = {address}/32");
    if let Some(mtu) = template.client.mtu {
        let _ = writeln!(s, "MTU = {mtu}");
    }

    match mode {
        DnsMode::None => {
            s.push_str(
                "# DNS: none (template policy). Mapped raw IPs work without any resolver.\n",
            );
        }
        DnsMode::TunnelWide => {
            let _ = writeln!(s, "DNS = {shim}");
            if platform == Platform::Mobile {
                s.push_str("# DNS is tunnel-wide: the official iOS/Android WireGuard apps cannot route DNS per domain.\n");
                s.push_str("# Names on the network you are visiting will not resolve while connected (mDNS/Bonjour,\n");
                s.push_str("# e.g. casting and AirPlay, is multicast and unaffected; raw IPs always work; Android can\n");
                s.push_str("# exempt apps). For real split DNS on a phone use the Tailscale transport instead.\n");
                if template.dns.wireguard == DnsMode::Split {
                    warnings.push(format!(
                        "template '{}' asks for split DNS but the mobile WireGuard apps cannot do it; this export sends all DNS to the shim",
                        template.name
                    ));
                }
            } else {
                s.push_str("# DNS is tunnel-wide by template policy; the shim forwards non-home zones to a public resolver.\n");
            }
        }
        DnsMode::Split => {
            let zones = domains.join(", ");
            match platform {
                Platform::Linux => {
                    s.push_str("# Split DNS via systemd-resolved: only the home zones use the shim through the tunnel.\n");
                    let _ = writeln!(
                        s,
                        "PostUp = resolvectl dns %i {shim}; resolvectl domain %i {}",
                        domains
                            .iter()
                            .map(|d| format!("~{d}"))
                            .collect::<Vec<_>>()
                            .join(" ")
                    );
                    s.push_str("PostDown = resolvectl revert %i\n");
                }
                Platform::Macos => {
                    let _ = writeln!(
                        s,
                        "# Split DNS on macOS: the WireGuard app cannot route DNS per domain, so tell the system\n# resolver to use the shim only for the home zones ({zones}). Once, as admin:"
                    );
                    s.push_str("#   sudo mkdir -p /etc/resolver\n");
                    for d in &domains {
                        let _ = writeln!(
                            s,
                            "#   printf 'nameserver {shim}\\n' | sudo tee /etc/resolver/{d}"
                        );
                    }
                    s.push_str("# Leave the DNS line unset so all other names keep using the local network's resolver.\n");
                }
                Platform::Windows => {
                    let _ = writeln!(
                        s,
                        "# Split DNS on Windows: add a Name Resolution Policy Table rule for the home zones ({zones}).\n# Once, in an elevated PowerShell:"
                    );
                    for d in &domains {
                        let _ = writeln!(
                            s,
                            "#   Add-DnsClientNrptRule -Namespace \".{d}\" -NameServers \"{shim}\""
                        );
                    }
                    s.push_str("# Leave the DNS line unset so all other names keep using the local network's resolver.\n");
                }
                Platform::Mobile => unreachable!("mobile split falls back to tunnel-wide"),
            }
            if domains.is_empty() {
                warnings.push(format!(
                    "template '{}' uses split DNS but no visible network declares domains; nothing is routed to the shim",
                    template.name
                ));
            }
        }
    }

    s.push_str("\n[Peer]\n");
    let _ = writeln!(s, "PublicKey = {}", server.wireguard.public_key);
    if let Some(psk) = &wg.preshared_key {
        let _ = writeln!(s, "PresharedKey = {}", psk.expose_base64());
    }
    let _ = writeln!(s, "Endpoint = {}", server.wireguard.endpoint);
    let ips = allowed_ips(model, template, platform)
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(s, "AllowedIPs = {ips}");
    if let Some(k) = template.client.persistent_keepalive {
        let _ = writeln!(s, "PersistentKeepalive = {k}");
    }

    Ok(Export {
        peer: peer.name.clone(),
        platform,
        contents: s,
        contains_secret: wg.private_key.is_some(),
        warnings,
    })
}
