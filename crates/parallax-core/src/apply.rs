//! `apply`: write the bundle, then reconcile the live system in a fixed
//! order — firewall first (so a half-configured interface never forwards
//! unfiltered), then each transport, then the DNS shim. Every step is
//! idempotent, so re-applying an unchanged bundle changes nothing.

use std::path::Path;

use crate::generate::{ArtifactKind, Bundle};
use crate::io::System;
use crate::model::FirewallBackend;
use crate::validate::Model;
use crate::{Error, Result};

/// Where the shim's pid file lives, relative to the output directory.
pub const DNSMASQ_PIDFILE: &str = "dnsmasq/dnsmasq.pid";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub log: Vec<String>,
}

/// Check the host has what apply needs. Returns one message per missing piece.
pub fn preflight(model: &Model<'_>, sys: System<'_>) -> Vec<String> {
    let mut missing = Vec::new();
    let backend = model.server().firewall.backend;
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
            "`{fw_bin}` is not available: install {} in the gateway container",
            match backend {
                FirewallBackend::Nftables => "nftables",
                FirewallBackend::IptablesNft => "iptables (nft variant)",
            }
        ));
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
    if sys
        .runner
        .run("dnsmasq", &["--version"], None)
        .map(|o| !o.ok())
        .unwrap_or(true)
    {
        missing.push("`dnsmasq` is not available: install dnsmasq".into());
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
            for set in &rs.sets {
                sys.runner.run_checked(
                    "ipset",
                    &["create", "-exist", &set.name, "hash:net"],
                    None,
                )?;
                sys.runner
                    .run_checked("ipset", &["flush", &set.name], None)?;
                for e in &set.elements {
                    sys.runner.run_checked(
                        "ipset",
                        &["add", "-exist", &set.name, &e.to_string()],
                        None,
                    )?;
                }
            }
            for (table, _, own) in CHAINS {
                sys.runner
                    .run("iptables", &["-t", table, "-N", own], None)?;
                sys.runner
                    .run_checked("iptables", &["-t", table, "-F", own], None)?;
            }
            sys.runner
                .run_checked("iptables-restore", &["--noflush", &main_str], None)?;
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

fn apply_dnsmasq(
    bundle: &Bundle,
    out_dir: &Path,
    sys: System<'_>,
    log: &mut Vec<String>,
) -> Result<()> {
    let conf = bundle
        .of_kind(ArtifactKind::Dnsmasq)
        .next()
        .ok_or_else(|| Error::Malformed {
            what: "apply",
            detail: "no dnsmasq artifact in the bundle".into(),
        })?;
    let conf_path = out_dir.join(&conf.path);
    let conf_str = conf_path.to_string_lossy().into_owned();
    let pid_path = out_dir.join(DNSMASQ_PIDFILE);
    let pid_str = pid_path.to_string_lossy().into_owned();
    sys.runner
        .run_checked("dnsmasq", &["--test", "--conf-file", &conf_str], None)?;
    // dnsmasq only re-reads hosts files on SIGHUP, not server=/alias= lines: restart.
    if let Some(pid) = sys.fs.read(&pid_path)? {
        let pid = pid.trim().to_string();
        if !pid.is_empty() {
            let _ = sys.runner.run("kill", &[&pid], None)?;
            log.push(format!("dnsmasq: stopped previous instance (pid {pid})"));
        }
    }
    sys.runner.run_checked(
        "dnsmasq",
        &[
            "--conf-file",
            &conf_str,
            "--pid-file",
            &pid_str,
            "--user",
            "root",
        ],
        None,
    )?;
    log.push("dnsmasq: started with the generated shim config".into());
    Ok(())
}

/// Write the bundle and reconcile the system.
pub fn apply(
    model: &Model<'_>,
    bundle: &Bundle,
    out_dir: &Path,
    sys: System<'_>,
) -> Result<ApplyReport> {
    let missing = preflight(model, sys);
    if !missing.is_empty() {
        return Err(Error::Invalid(missing));
    }
    crate::plan::write_bundle(bundle, out_dir, sys.fs)?;
    let mut log = vec![format!(
        "wrote {} artifacts under {}",
        bundle.artifacts.len(),
        out_dir.display()
    )];
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
    apply_dnsmasq(bundle, out_dir, sys, &mut log)?;
    Ok(ApplyReport { log })
}
