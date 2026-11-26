//! `apply`: write the bundle, then reconcile the live system in a fixed
//! order — WireGuard peers whose address changed hands off the interface,
//! then the firewall (so a half-configured interface never forwards
//! unfiltered), then each transport. Every step is idempotent, so
//! re-applying an unchanged bundle changes nothing. The DNS server and the
//! HTTPS proxy read the routes written here; the daemon has them re-read
//! after each apply.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;

use ipnet::Ipv4Net;

use crate::generate::{ArtifactKind, Bundle};
use crate::io::System;
use crate::model::FirewallBackend;
use crate::validate::Model;
use crate::{Error, Result};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub log: Vec<String>,
}

/// Check the host has the tools apply runs. Returns one message per missing tool.
pub fn preflight(backend: FirewallBackend, sys: System<'_>) -> Vec<String> {
    let mut missing = Vec::new();
    let fw_bin = match backend {
        FirewallBackend::Nftables => "nft",
        FirewallBackend::IptablesNft => "iptables",
    };
    if sys
        .runner
        .run(fw_bin, &["--version"], None)
        .map(|o| !o.ok())
        .unwrap_or(true)
    {
        missing.push(format!(
            "`{fw_bin}` is not available: install {}",
            match backend {
                FirewallBackend::Nftables => "nftables",
                FirewallBackend::IptablesNft => "iptables (nft variant)",
            }
        ));
    }
    if backend == FirewallBackend::IptablesNft {
        for (tool, package) in [("iptables-restore", "iptables"), ("ipset", "ipset")] {
            if sys
                .runner
                .run(tool, &["--version"], None)
                .map(|o| !o.ok())
                .unwrap_or(true)
            {
                missing.push(format!("`{tool}` is not available: install {package}"));
            }
        }
    }
    if sys
        .runner
        .run("wg", &["--version"], None)
        .map(|o| !o.ok())
        .unwrap_or(true)
    {
        missing.push("`wg` is not available: install wireguard-tools".into());
    }
    if sys
        .runner
        .run("ip", &["-V"], None)
        .map(|o| !o.ok())
        .unwrap_or(true)
    {
        missing.push("`ip` is not available: install iproute2".into());
    }
    missing
}

fn apply_firewall(
    model: &Model<'_>,
    bundle: &Bundle,
    out_dir: &Path,
    sys: System<'_>,
    log: &mut Vec<String>,
) -> Result<()> {
    let main = bundle
        .of_kind(ArtifactKind::Firewall)
        .next()
        .ok_or_else(|| Error::Malformed {
            what: "apply",
            detail: "no firewall artifact in the bundle".into(),
        })?;
    let main_path = out_dir.join(&main.path);
    let main_str = main_path.to_string_lossy().into_owned();
    match model.server().firewall.backend {
        FirewallBackend::Nftables => {
            // Check mode validates against the running kernel: catches missing NETMAP/NAT support.
            let check = sys.runner.run("nft", &["-c", "-f", &main_str], None)?;
            if !check.ok() {
                return Err(Error::Malformed {
                    what: "firewall",
                    detail: format!(
                        "the kernel rejected the ruleset: {}. NETMAP needs nf_nat with prefix mapping (nftables >= 0.9.4, kernel >= 5.x)",
                        check.stderr.trim()
                    ),
                });
            }
            sys.runner.run_checked("nft", &["-f", &main_str], None)?;
            log.push(format!(
                "firewall: table inet {} replaced",
                crate::generate::firewall::TABLE
            ));
            if let Some(docker) = bundle.of_kind(ArtifactKind::FirewallDockerUser).next() {
                let listing = sys.runner.run(
                    "nft",
                    &["-a", "list", "chain", "ip", "filter", "DOCKER-USER"],
                    None,
                )?;
                if !listing.ok() {
                    log.push("firewall: DOCKER-USER chain not present, skipping Docker coexistence rules".into());
                } else {
                    let mut handles: Vec<String> = listing
                        .stdout
                        .lines()
                        .filter(|l| l.contains("comment \"parallax\""))
                        .filter_map(|l| l.rsplit("# handle ").next().map(|h| h.trim().to_string()))
                        .collect();
                    handles.reverse();
                    for h in &handles {
                        sys.runner.run_checked(
                            "nft",
                            &["delete", "rule", "ip", "filter", "DOCKER-USER", "handle", h],
                            None,
                        )?;
                    }
                    let p = out_dir.join(&docker.path);
                    sys.runner
                        .run_checked("nft", &["-f", &p.to_string_lossy()], None)?;
                    log.push(format!(
                        "firewall: DOCKER-USER rules refreshed ({} removed)",
                        handles.len()
                    ));
                }
            }
        }
        FirewallBackend::IptablesNft => {
            use crate::generate::firewall::iptables::CHAINS;
            let rs = crate::generate::firewall::build(model)?;
            // Fill a fresh set and swap it in: flushing the live one would
            // briefly leave `! --match-set not_public` matching everything.
            // One short scratch name: ipset names stop at 31 characters.
            let next = "parallax-swap";
            for set in &rs.sets {
                for name in [set.name.as_str(), next] {
                    sys.runner.run_checked(
                        "ipset",
                        &["create", "-exist", name, "hash:net"],
                        None,
                    )?;
                }
                sys.runner.run_checked("ipset", &["flush", next], None)?;
                for e in &set.elements {
                    sys.runner.run_checked(
                        "ipset",
                        &["add", "-exist", next, &e.to_string()],
                        None,
                    )?;
                }
                sys.runner
                    .run_checked("ipset", &["swap", next, &set.name], None)?;
                sys.runner.run_checked("ipset", &["destroy", next], None)?;
            }
            // The restore file declares every PARALLAX_* chain, which creates
            // it or flushes it in the same transaction as the refill: no
            // window with empty chains, and a failed restore changes nothing.
            sys.runner
                .run_checked("iptables-restore", &["--noflush", &main_str], None)?;
            // Chains of tiers that no longer exist: nothing jumps to them
            // since the restore, so they can go.
            let listing = sys
                .runner
                .run_checked("iptables", &["-t", "filter", "-S"], None)?;
            for chain in listing
                .stdout
                .lines()
                .filter_map(|l| l.strip_prefix("-N "))
                .filter(|c| {
                    c.strip_prefix("PARALLAX_T")
                        .and_then(|n| n.parse::<usize>().ok())
                        .is_some_and(|n| n >= rs.tiers.len())
                })
            {
                sys.runner
                    .run_checked("iptables", &["-t", "filter", "-F", chain], None)?;
                sys.runner
                    .run_checked("iptables", &["-t", "filter", "-X", chain], None)?;
            }
            // Sets of tiers that no longer exist: no rule uses them since the
            // restore. Prefixed as the transports name them (and as builds
            // before grants did: `ts_<template>`).
            let live = sys.runner.run("ipset", &["list", "-n"], None)?;
            for name in live.stdout.lines().map(str::trim).filter(|n| {
                (n.starts_with("wg_") || n.starts_with("ts_"))
                    && !rs.sets.iter().any(|s| s.name == *n)
            }) {
                sys.runner.run("ipset", &["destroy", name], None)?;
            }
            for (table, builtin, own) in CHAINS {
                let present = sys
                    .runner
                    .run("iptables", &["-t", table, "-C", builtin, "-j", own], None)?
                    .ok();
                if !present {
                    sys.runner.run_checked(
                        "iptables",
                        &["-t", table, "-I", builtin, "-j", own],
                        None,
                    )?;
                }
            }
            log.push("firewall: PARALLAX_* chains restored".into());
            if let Some(docker) = bundle.of_kind(ArtifactKind::FirewallDockerUser).next() {
                let exists = sys
                    .runner
                    .run(
                        "iptables",
                        &["-t", "filter", "-L", "DOCKER-USER", "-n"],
                        None,
                    )?
                    .ok();
                if exists {
                    // Remove previous parallax rules, then insert the generated ones.
                    let listing =
                        sys.runner
                            .run("iptables", &["-t", "filter", "-S", "DOCKER-USER"], None)?;
                    for line in listing.stdout.lines().filter(|l| {
                        l.contains("--comment parallax") || l.contains("--comment \"parallax\"")
                    }) {
                        let args: Vec<&str> = line.trim_start_matches("-A ").split(' ').collect();
                        let mut del = vec!["-t", "filter", "-D"];
                        del.extend(args);
                        sys.runner.run("iptables", &del, None)?;
                    }
                    for line in docker.contents.lines().filter(|l| l.starts_with("-I")) {
                        let args: Vec<&str> = line.split(' ').collect();
                        sys.runner.run_checked("iptables", &args, None)?;
                    }
                    log.push("firewall: DOCKER-USER rules refreshed".into());
                } else {
                    log.push("firewall: DOCKER-USER chain not present, skipping Docker coexistence rules".into());
                }
            }
        }
    }
    Ok(())
}

/// Before the firewall changes: take a live WireGuard peer off the
/// interface when it holds an address the new configuration gives another
/// key. An address says nothing about access, so the new firewall may give
/// it someone else's grants; the old key must not hold it meanwhile, nor if
/// a later step fails. Every other difference is left to `wg syncconf`, so
/// unchanged peers keep their sessions. No interface yet: nothing to do.
fn drop_moved_peers(model: &Model<'_>, sys: System<'_>, log: &mut Vec<String>) -> Result<()> {
    let iface = model.server().wireguard.interface.as_str();
    let live = sys
        .runner
        .run("wg", &["show", iface, "allowed-ips"], None)?;
    if !live.ok() {
        return Ok(());
    }
    let owners: BTreeMap<Ipv4Addr, String> = model
        .peers_on(crate::model::TransportKind::WireGuard)
        .filter_map(|p| p.wireguard.as_ref())
        .filter_map(|w| Some((w.address?, w.public_key.to_base64())))
        .collect();
    let mut dropped = 0;
    for line in live.stdout.lines() {
        let mut fields = line.split_whitespace();
        let Some(key) = fields.next() else { continue };
        // IPv6 entries and `(none)` don't parse, and can't hold an owner's address.
        let held: Vec<Ipv4Net> = fields.filter_map(|f| f.parse().ok()).collect();
        let takes_anothers = owners
            .iter()
            .any(|(addr, owner)| owner != key && held.iter().any(|n| n.contains(addr)));
        if !takes_anothers {
            continue;
        }
        sys.runner
            .run_checked("wg", &["set", iface, "peer", key, "remove"], None)?;
        dropped += 1;
    }
    if dropped > 0 {
        log.push(format!(
            "wireguard: {dropped} peers whose address changed hands taken off {iface} first"
        ));
    }
    Ok(())
}

/// Write the bundle and reconcile the system.
pub fn apply(
    model: &Model<'_>,
    bundle: &Bundle,
    out_dir: &Path,
    sys: System<'_>,
) -> Result<ApplyReport> {
    let missing = preflight(model.server().firewall.backend, sys);
    if !missing.is_empty() {
        return Err(Error::Invalid(missing));
    }
    crate::plan::write_bundle(bundle, out_dir, sys.fs)?;
    let mut log = vec![format!(
        "wrote {} artifacts under {}",
        bundle.artifacts.len(),
        out_dir.display()
    )];
    drop_moved_peers(model, sys, &mut log)?;
    apply_firewall(model, bundle, out_dir, sys, &mut log)?;
    for transport in crate::transport::all() {
        let owned: Vec<_> = bundle
            .artifacts
            .iter()
            .map(|a| crate::generate::Artifact {
                kind: a.kind,
                path: out_dir.join(&a.path),
                contents: String::new(),
                secret: a.secret,
            })
            .collect();
        log.extend(transport.apply(model, &owned, sys)?);
    }
    Ok(ApplyReport { log })
}
