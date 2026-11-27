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
            let next = SWAP_SET;
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
            // it or flushes it in the same transaction as its refill, so no
            // chain is ever empty. But each table commits at its own COMMIT
            // (issue #56): for a moment, or for good if `nat` fails, the new
            // filter runs with the old NAT, and a connection opened then
            // keeps that NAT for its life. A stale masquerade, say, shows a
            // newly granted peer to the LAN as the gateway. So first a dry
            // run, which stops syntax errors and missing sets before either
            // table changes; then tunnel peers open no new connections until
            // both tables are in. Open ones carry on under the NAT they
            // started with. If the restore fails, the hold stays until an
            // apply succeeds (the daemon retries).
            sys.runner.run_checked(
                "iptables-restore",
                &["--test", "--noflush", &main_str],
                None,
            )?;
            for rule in hold_rules(model.server()) {
                // A failed apply may have left it: keep that one rather than
                // lift it for a moment.
                if !sys
                    .runner
                    .run("iptables", &hold_args("-C", &rule), None)?
                    .ok()
                {
                    sys.runner
                        .run_checked("iptables", &hold_args("-I", &rule), None)?;
                }
            }
            sys.runner
                .run_checked("iptables-restore", &["--noflush", &main_str], None)
                .map_err(|e| match e {
                    Error::Command {
                        command,
                        status,
                        stderr,
                    } => Error::Command {
                        command,
                        status,
                        stderr: format!(
                            "{}; tunnel peers can't open new connections until an apply succeeds (issue #56)",
                            stderr.trim_end()
                        ),
                    },
                    e => e,
                })?;
            let listing = sys
                .runner
                .run_checked("iptables", &["-t", "filter", "-S"], None)?;
            // Docker's chain before the hooks, so a FORWARD that Docker's jump
            // heads already counts as Parallax deciding first (issue #74);
            // and before the hold comes off, so nothing new starts while
            // Parallax's rules there are out.
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
                    for rule in docker_user_rules(&listing.stdout) {
                        let mut del = vec!["-t", "filter", "-D"];
                        del.extend(rule.iter().map(String::as_str));
                        sys.runner.run("iptables", &del, None)?;
                    }
                    for line in docker.contents.lines().filter(|l| l.starts_with("-I")) {
                        let words = iptables_words(line);
                        let args: Vec<&str> = words.iter().map(String::as_str).collect();
                        sys.runner.run_checked("iptables", &args, None)?;
                    }
                    log.push("firewall: DOCKER-USER rules refreshed".into());
                } else {
                    log.push("firewall: DOCKER-USER chain not present, skipping Docker coexistence rules".into());
                }
            }
            // Hooks next, then the hold comes off: until both tables are
            // attached nothing new starts. `nat` first: a filter jump goes in
            // above the hold, so once it's there both tables must be. A jump
            // that's present but below someone else's rules (Docker's, after
            // it restarts: issue #74) moves to the top. Every hold goes, also
            // one for an interface since renamed.
            for (table, builtin, own) in CHAINS.iter().rev() {
                let live = sys
                    .runner
                    .run_checked("iptables", &["-t", table, "-S"], None)?;
                // Present too, not only reached through DOCKER-USER: Docker
                // may drop its jump, and then nothing would lead to Parallax.
                let jump = format!("-A {builtin} -j {own}");
                let present = live.stdout.lines().filter(|l| *l == jump).count();
                if present > 0 && decides_first(&live.stdout, builtin, own) {
                    continue;
                }
                for _ in 0..present {
                    sys.runner.run_checked(
                        "iptables",
                        &["-t", table, "-D", builtin, "-j", own],
                        None,
                    )?;
                }
                sys.runner.run_checked(
                    "iptables",
                    &["-t", table, "-I", builtin, "1", "-j", own],
                    None,
                )?;
                if present > 0 {
                    log.push(format!(
                        "firewall: other rules came before {own} in {builtin}; its jump is first again"
                    ));
                }
            }
            for args in held(&listing.stdout) {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                sys.runner.run_checked("iptables", &args, None)?;
            }
            // Chains of tiers that no longer exist: nothing jumps to them
            // since the restore, so they can go.
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
            // Sets of tiers that no longer exist, and the logging sets once
            // nobody is logged: no rule uses them since the restore. The rules are in by now, so a failure here is only a
            // leftover set: say so and carry on to the hooks.
            let live = sys.runner.run("ipset", &["list", "-n"], None)?;
            if !live.ok() {
                log.push(format!(
                    "firewall: couldn't list ipsets, stale sets stay: {}",
                    live.stderr.trim()
                ));
            }
            for name in stale_sets(&live.stdout, &rs.sets) {
                let destroy = sys.runner.run("ipset", &["destroy", name], None)?;
                if !destroy.ok() {
                    log.push(format!(
                        "firewall: stale set {name} stays: {}",
                        destroy.stderr.trim()
                    ));
                }
            }
            log.push("firewall: PARALLAX_* chains restored".into());
        }
    }
    Ok(())
}

/// The words of an iptables rule as `iptables -S` lists it, or as the
/// generator writes it: split on spaces, a double-quoted word kept whole and
/// unquoted, `\"` and `\\` inside it unescaped. The generator's rules are
/// run as arguments, not through a shell, so their quotes must go.
pub(crate) fn iptables_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let (mut quoted, mut escaped, mut started) = (false, false, false);
    for c in line.chars() {
        match c {
            _ if escaped => {
                word.push(c);
                escaped = false;
            }
            '\\' if quoted => escaped = true,
            '"' => {
                quoted = !quoted;
                started = true;
            }
            ' ' if !quoted => {
                if started || !word.is_empty() {
                    words.push(std::mem::take(&mut word));
                }
                started = false;
            }
            _ => word.push(c),
        }
    }
    if started || !word.is_empty() {
        words.push(word);
    }
    words
}

/// Parallax's rules in an `iptables -S DOCKER-USER` listing, each as the
/// words after `-A`: those commented exactly `parallax`, and `"parallax"`
/// with the quotes, as builds before this one inserted them.
pub(crate) fn docker_user_rules(listing: &str) -> Vec<Vec<String>> {
    listing
        .lines()
        .map(iptables_words)
        .filter(|w| w.first().is_some_and(|a| a == "-A"))
        .filter(|w| {
            w.windows(2)
                .any(|p| p[0] == "--comment" && (p[1] == "parallax" || p[1] == "\"parallax\""))
        })
        .map(|w| w[1..].to_vec())
        .collect()
}

/// The scratch set each set is filled in before it's swapped in. A failed
/// apply can leave it.
const SWAP_SET: &str = "parallax-swap";

/// Every set in an `ipset list -n` listing that Parallax made, for
/// teardown: what [`stale_sets`] finds against an empty ruleset, and the
/// scratch set.
pub(crate) fn own_sets(listing: &str) -> Vec<&str> {
    let mut sets = stale_sets(listing, &[]);
    sets.extend(listing.lines().map(str::trim).filter(|n| *n == SWAP_SET));
    sets
}

/// Sets in an `ipset list -n` listing that Parallax made and the new ruleset
/// no longer has: a transport's prefix or a shared set's base name
/// (`not_public`) and a 16-digit hash, as `generate::firewall` names them,
/// and the logging sets' plain names. Anything else listed is someone
/// else's. That includes the `ts_<template>` sets of builds before grants
/// (always empty: no Tailscale peers before M2), and the plain `lan_real`
/// and `not_public` of builds before hashed names: a name built from a grant,
/// or a word like those, could be an operator's own set.
fn stale_sets<'a>(
    listing: &'a str,
    keep: &[crate::generate::firewall::AddressSet],
) -> Vec<&'a str> {
    use crate::generate::firewall::{LAN_SET, LOG_DENIED_SET, LOG_FLOWS_SET, NOT_PUBLIC_SET};
    let shared = [LAN_SET, NOT_PUBLIC_SET, LOG_FLOWS_SET, LOG_DENIED_SET];
    // Logging came in shortly before hashed names, under these names.
    let plain = [LOG_FLOWS_SET, LOG_DENIED_SET];
    let transports = crate::transport::all();
    let bases: Vec<&str> = transports
        .iter()
        .map(|t| t.set_prefix())
        .chain(shared)
        .collect();
    let hash =
        |key: &str| key.len() == 16 && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let ours = |name: &str| {
        plain.contains(&name)
            || bases.iter().any(|p| {
                name.strip_prefix(p)
                    .and_then(|rest| rest.strip_prefix('_'))
                    .is_some_and(hash)
            })
    };
    listing
        .lines()
        .map(str::trim)
        .filter(|n| ours(n) && !keep.iter().any(|s| s.name == *n))
        .collect()
}

/// Before the firewall changes: take a live WireGuard peer off the
/// interface when it holds an address the new configuration gives another
/// key. An address says nothing about access, so the new firewall may give
/// it someone else's grants; the old key must not hold it meanwhile, nor if
/// a later step fails. Every other difference is left to `wg syncconf`, so
/// unchanged peers keep their sessions. No interface yet: nothing to do.
/// An interface whose peers can't be read stops the apply here, before the
/// firewall changes: carrying on would skip the hand-over.
fn drop_moved_peers(model: &Model<'_>, sys: System<'_>, log: &mut Vec<String>) -> Result<()> {
    let iface = model.server().wireguard.interface.as_str();
    let live = sys
        .runner
        .run("wg", &["show", iface, "allowed-ips"], None)?;
    if !live.ok() {
        let link = sys
            .runner
            .run("ip", &["link", "show", "dev", iface], None)?;
        // Only `ip` saying so means there's no interface. Any other failure
        // (no netlink permission, say) can't tell, so it stops too.
        if !link.ok() && link.stderr.contains("does not exist") {
            return Ok(());
        }
        let probe = match link.ok() {
            true => String::new(),
            false => format!("; `ip link show dev {iface}`: {}", link.stderr.trim()),
        };
        return Err(Error::Refused(format!(
            "can't read which addresses the peers on {iface} hold, so the firewall stays as it is: `wg show {iface} allowed-ips`: {}{probe}",
            live.stderr.trim()
        )));
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
        log.extend(transport.apply(model, &bundle.artifacts, sys)?);
    }
    Ok(ApplyReport { log })
}

/// Comment on the hold rules, one word so `iptables -S` prints it plain.
pub const HOLD_COMMENT: &str = "parallax-hold";

/// What keeps tunnel peers from opening connections while `iptables-restore`
/// swaps the rules (issue #56): rules at the top of INPUT and FORWARD that
/// drop new flows from each tunnel interface, and in FORWARD those toward
/// it (LAN-initiated, which NETMAP's source map would mislabel). Each is the
/// rule as `iptables -t filter <-C|-I>` takes it.
pub fn hold_rules(server: &crate::model::ServerConfig) -> Vec<Vec<String>> {
    let mut rules = Vec::new();
    for t in crate::transport::all() {
        let iface = t.ingress_interface(server);
        for (chain, dir) in [("INPUT", "-i"), ("FORWARD", "-i"), ("FORWARD", "-o")] {
            rules.push(
                [
                    chain,
                    dir,
                    &iface,
                    "-m",
                    "conntrack",
                    "--ctstate",
                    "NEW",
                    "-m",
                    "comment",
                    "--comment",
                    HOLD_COMMENT,
                    "-j",
                    "DROP",
                ]
                .map(String::from)
                .to_vec(),
            );
        }
    }
    rules
}

/// `iptables` arguments that delete every hold in `listing` (`iptables -t
/// filter -S`), whatever interface it names.
pub fn held(listing: &str) -> Vec<Vec<String>> {
    let marker = format!("--comment {HOLD_COMMENT} ");
    listing
        .lines()
        .filter(|l| l.contains(&marker))
        .filter_map(|l| l.strip_prefix("-A "))
        .map(|rule| {
            ["-t", "filter", "-D"]
                .into_iter()
                .map(String::from)
                .chain(iptables_words(rule))
                .collect()
        })
        .collect()
}

/// Whether Parallax's chain `own` sees every packet of the built-in chain
/// `builtin` before anything else does, in `listing` (`iptables -t <table>
/// -S`, or that table's part of `iptables-save`). Holds don't count. The
/// first rule must jump to `own`, or, in `FORWARD`, jump to Docker's
/// `DOCKER-USER` whose first rule jumps to `own`: Docker puts that jump
/// back on top whenever it starts (issue #74), and this way neither order
/// needs undoing.
pub fn decides_first(listing: &str, builtin: &str, own: &str) -> bool {
    use crate::generate::firewall::iptables::DOCKER_USER;
    let hold = format!("--comment {HOLD_COMMENT} ");
    let first = |chain: &str| {
        let prefix = format!("-A {chain} ");
        listing
            .lines()
            .filter(|l| l.starts_with(&prefix) && !l.contains(&hold))
            .map(iptables_words)
            .next()
    };
    let Some(rule) = first(builtin) else {
        return false;
    };
    if rule == ["-A", builtin, "-j", own] {
        return true;
    }
    builtin == "FORWARD"
        && rule == ["-A", builtin, "-j", DOCKER_USER]
        && first(DOCKER_USER).is_some_and(|r| {
            r == [
                "-A",
                DOCKER_USER,
                "-m",
                "comment",
                "--comment",
                "parallax",
                "-j",
                own,
            ]
        })
}

/// `iptables` arguments to check for (`-C`) or insert (`-I`, at the top)
/// one of [`hold_rules`].
pub fn hold_args<'a>(op: &'a str, rule: &'a [String]) -> Vec<&'a str> {
    ["-t", "filter", op]
        .into_iter()
        .chain(rule.iter().map(String::as_str))
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]

    use super::*;
    use crate::generate::firewall::AddressSet;
    use crate::io::memory::{MemoryFs, RecordingRunner};
    use crate::io::Output;

    fn failed(stderr: &str) -> Output {
        Output {
            status: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    /// Apply the canonical scenario with `wg show` failing and `ip link
    /// show` answering `link`.
    fn apply_with_unreadable_wg0(link: Option<Output>) -> (Result<ApplyReport>, Vec<String>) {
        let cfg = crate::testing::canonical_config();
        let model = Model::resolve(&cfg, crate::testing::today()).unwrap();
        let fs = MemoryFs::new().with_file(
            "/etc/parallax/wg-server.key",
            crate::testing::keypair(200).private.expose_base64(),
        );
        let bundle = crate::generate::generate_all(&model, &fs).unwrap();
        let runner = RecordingRunner::new();
        runner.respond_to(
            "wg",
            &["show", "wg0", "allowed-ips"],
            failed("Unable to access interface: Operation not permitted"),
        );
        // The hand-over asks first, then the WireGuard transport.
        if let Some(link) = link {
            runner.respond_to("ip", &["link", "show", "dev", "wg0"], link.clone());
            runner.respond_to("ip", &["link", "show", "dev", "wg0"], link);
        }
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        let result = apply(&model, &bundle, Path::new("/var/lib/parallax"), sys);
        (result, runner.command_lines())
    }

    /// Who holds which address can't be read, but the interface is there,
    /// or `ip` can't tell: stop before the firewall changes instead of
    /// skipping the hand-over.
    #[test]
    fn an_unreadable_interface_stops_before_the_firewall() {
        let no_netlink = failed("Cannot open netlink socket: Operation not permitted");
        for link in [None, Some(no_netlink)] {
            let (result, lines) = apply_with_unreadable_wg0(link);
            let err = result.unwrap_err().to_string();
            assert!(
                err.contains("peers on wg0") && err.contains("Operation not permitted"),
                "{err}"
            );
            assert!(
                !lines
                    .iter()
                    .any(|l| l.starts_with("nft -f") || l.starts_with("wg set")),
                "{lines:#?}"
            );
        }
    }

    /// No interface yet (first apply): nothing to hand over, and the apply
    /// goes on to create it.
    #[test]
    fn a_missing_interface_is_created() {
        let (result, lines) =
            apply_with_unreadable_wg0(Some(failed("Device \"wg0\" does not exist.")));
        result.unwrap();
        let pos = |needle: &str| lines.iter().position(|l| l.starts_with(needle));
        assert!(
            pos("nft -f").unwrap() < pos("ip link add wg0").unwrap(),
            "{lines:#?}"
        );
        assert!(!lines.iter().any(|l| l.ends_with(" remove")), "{lines:#?}");
    }

    /// Only sets named as Parallax names them go: a transport's prefix or a
    /// shared set's base and 16 lowercase hex digits, or a logging set's
    /// plain name. An operator's `wg_external_allow`, `ts_family` even with
    /// a grant `family`, and a plain `not_public` or `lan_real`, stay.
    /// The generator's quotes go, as a shell would take them; a listing's
    /// escaped quotes stay part of the word.
    #[test]
    fn iptables_words_are_split_as_iptables_lists_them() {
        assert_eq!(
            iptables_words(r#"-I DOCKER-USER -i wg0 -m comment --comment "parallax" -j ACCEPT"#),
            [
                "-I",
                "DOCKER-USER",
                "-i",
                "wg0",
                "-m",
                "comment",
                "--comment",
                "parallax",
                "-j",
                "ACCEPT"
            ]
        );
        assert_eq!(
            iptables_words(r#"-A X -m comment --comment "\"parallax\"" -j ACCEPT"#)[5],
            "\"parallax\""
        );
        assert_eq!(
            iptables_words(r#"--comment "two words""#),
            ["--comment", "two words"]
        );
        assert_eq!(iptables_words(r#"--comment """#), ["--comment", ""]);
    }

    /// Issue #74: Parallax's chain must see a packet before Docker's (or
    /// anyone's) rules do. Present is not enough.
    #[test]
    fn decides_first_needs_the_first_rule() {
        let first = |forward: &str, docker_user: &str| {
            let listing = format!("-P FORWARD DROP\n-N DOCKER-USER\n{forward}{docker_user}");
            decides_first(&listing, "FORWARD", "PARALLAX_FORWARD")
        };
        let ours = "-A DOCKER-USER -m comment --comment parallax -j PARALLAX_FORWARD\n";
        let hold = "-A FORWARD -i wg0 -m conntrack --ctstate NEW -m comment --comment parallax-hold -j DROP\n";
        assert!(first(
            "-A FORWARD -j PARALLAX_FORWARD\n-A FORWARD -j DOCKER-USER\n",
            ours
        ));
        // Holds sit above while an apply runs.
        assert!(first(
            &format!("{hold}-A FORWARD -j PARALLAX_FORWARD\n"),
            ""
        ));
        // Docker restarted: its jumps went in above.
        assert!(!first(
            "-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j PARALLAX_FORWARD\n",
            ours
        ));
        // DOCKER-USER first is fine once it starts with Parallax's chain,
        // not with an older build's accepts or an operator's rule.
        assert!(first(
            "-A FORWARD -j DOCKER-USER\n-A FORWARD -j PARALLAX_FORWARD\n",
            ours
        ));
        let accept = "-A DOCKER-USER -i wg0 -m comment --comment parallax -j ACCEPT\n";
        assert!(!first(
            "-A FORWARD -j DOCKER-USER\n-A FORWARD -j PARALLAX_FORWARD\n",
            accept
        ));
        assert!(!first(
            "-A FORWARD -j DOCKER-USER\n",
            &format!("-A DOCKER-USER -s 10.0.0.0/8 -j DROP\n{ours}")
        ));
        assert!(!first("", ours));
        // Only FORWARD goes through DOCKER-USER.
        let listing = format!("-A INPUT -j DOCKER-USER\n{ours}");
        assert!(!decides_first(&listing, "INPUT", "PARALLAX_INPUT"));
    }

    /// Issue #74, through a whole apply: a jump that's there but below
    /// Docker's moves to the top; Docker's chain gets Parallax's rules before
    /// the hold comes off.
    #[test]
    fn an_iptables_apply_puts_its_jump_back_on_top() {
        let mut cfg = crate::testing::canonical_config();
        cfg.server.firewall.backend = crate::FirewallBackend::IptablesNft;
        let model = Model::resolve(&cfg, crate::testing::today()).unwrap();
        let fs = MemoryFs::new().with_file(
            "/etc/parallax/wg-server.key",
            crate::testing::keypair(200).private.expose_base64(),
        );
        let bundle = crate::generate::generate_all(&model, &fs).unwrap();
        let runner = RecordingRunner::new();
        let listing = |forward: &str| {
            Output {
            status: 0,
            stdout: format!(
                "-P FORWARD DROP\n-N DOCKER-USER\n\
                 -A INPUT -j PARALLAX_INPUT\n\
                 -A FORWARD -i wg0 -m conntrack --ctstate NEW -m comment --comment parallax-hold -j DROP\n\
                 {forward}"
            ),
            stderr: String::new(),
        }
        };
        let docker_first = "-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j PARALLAX_FORWARD\n-A FORWARD -j PARALLAX_FORWARD\n";
        // After the restore (holds), then the FORWARD hook, then INPUT.
        for _ in 0..3 {
            runner.respond_to("iptables", &["-t", "filter", "-S"], listing(docker_first));
        }
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        let report = apply(&model, &bundle, Path::new("/var/lib/parallax"), sys).unwrap();
        let lines = runner.command_lines();
        let pos = |line: &str| lines.iter().position(|l| l == line);
        let removed = lines
            .iter()
            .filter(|l| *l == "iptables -t filter -D FORWARD -j PARALLAX_FORWARD")
            .count();
        assert_eq!(removed, 2, "{lines:#?}");
        let top = pos("iptables -t filter -I FORWARD 1 -j PARALLAX_FORWARD").unwrap();
        assert!(
            pos("iptables -t filter -D FORWARD -j PARALLAX_FORWARD").unwrap() < top,
            "{lines:#?}"
        );
        // INPUT's jump is first: left alone.
        assert!(!lines
            .iter()
            .any(|l| l.contains("INPUT -j PARALLAX_INPUT") && !l.contains(" -S")));
        let docker =
            pos("iptables -I DOCKER-USER 1 -m comment --comment parallax -j PARALLAX_FORWARD")
                .unwrap();
        let lifted = lines
            .iter()
            .position(|l| l.contains(" -D FORWARD -i wg0 ") && l.contains(HOLD_COMMENT))
            .unwrap();
        assert!(docker < top && top < lifted, "{lines:#?}");
        assert!(
            report
                .log
                .iter()
                .any(|l| l.contains("PARALLAX_FORWARD in FORWARD")),
            "{:#?}",
            report.log
        );

        // DOCKER-USER first and starting with Parallax's jump, but no jump
        // of Parallax's own in FORWARD (a first apply beside Docker): it goes
        // in at the top, or nothing leads to Parallax once Docker drops its
        // jump.
        let runner = RecordingRunner::new();
        let through_docker = "-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n\
             -A DOCKER-USER -m comment --comment parallax -j PARALLAX_FORWARD\n";
        for _ in 0..3 {
            runner.respond_to("iptables", &["-t", "filter", "-S"], listing(through_docker));
        }
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        apply(&model, &bundle, Path::new("/var/lib/parallax"), sys).unwrap();
        let lines = runner.command_lines();
        assert!(
            lines.contains(&"iptables -t filter -I FORWARD 1 -j PARALLAX_FORWARD".into()),
            "{lines:#?}"
        );
        assert!(!lines
            .iter()
            .any(|l| l.contains("-D FORWARD -j PARALLAX_FORWARD")));
    }

    /// Exactly `parallax`, or `"parallax"` from builds that kept the
    /// quotes; not an operator's `parallax-backup`, nor a rule without one.
    #[test]
    fn docker_user_rules_are_parallaxs_own_only() {
        let listing = r#"-N DOCKER-USER
-A DOCKER-USER -i wg0 -m comment --comment parallax -j ACCEPT
-A DOCKER-USER -o wg0 -m comment --comment "\"parallax\"" -j ACCEPT
-A DOCKER-USER -s 10.0.0.0/8 -m comment --comment parallax-backup -j DROP
-A DOCKER-USER -j RETURN"#;
        let rules = docker_user_rules(listing);
        assert_eq!(rules.len(), 2, "{rules:?}");
        assert_eq!(rules[0][..3], ["DOCKER-USER", "-i", "wg0"]);
        assert_eq!(rules[1][..3], ["DOCKER-USER", "-o", "wg0"]);
    }

    #[test]
    fn cleanup_destroys_only_parallaxs_own_sets() {
        let set = |name: &str| AddressSet {
            name: name.into(),
            elements: Vec::new(),
            comment: String::new(),
        };
        let keep = [set("wg_0123456789abcdef"), set("ts_0123456789abcdef")];
        let listing = "wg_0123456789abcdef\nts_0123456789abcdef\n\
                       wg_fedcba9876543210\nts_00000000000000ff\n  wg_00000000000000aa  \n\
                       wg_external_allow\nts_family\nts_home_lab\nts_other\n\
                       wg_0123456789ABCDEF\nwg_0123456789abcde\nwg_0123456789abcdef0\n\
                       wg_0123456789abcdeg\nwg0123456789abcdef\nxx_0123456789abcdef\n\
                       not_public\nlan_real\nparallax-swap\nlog_flows\nlog_denied_x\n\
                       not_public_00000000000000bb\nlan_real_00000000000000cc\n\
                       log_denied_00000000000000dd\nnot_public_x\nlan_real_0123\n\n";
        assert_eq!(
            stale_sets(listing, &keep),
            [
                "wg_fedcba9876543210",
                "ts_00000000000000ff",
                "wg_00000000000000aa",
                "log_flows",
                "not_public_00000000000000bb",
                "lan_real_00000000000000cc",
                "log_denied_00000000000000dd"
            ]
        );
    }

    /// Issue #35: a failed restore leaves the old rules in place, so the
    /// sets they use must be exactly as they were: no set only the old
    /// ruleset uses is filled, swapped or destroyed, only new ones made
    /// beside them. Issue #56: a failed dry run stops before the real restore, which can
    /// commit `filter` without `nat`.
    #[test]
    fn a_failed_iptables_restore_leaves_the_old_sets_alone() {
        let mut cfg = crate::testing::canonical_config();
        cfg.server.firewall.backend = crate::FirewallBackend::IptablesNft;
        let old_model = Model::resolve(&cfg, crate::testing::today()).unwrap();
        let old: Vec<String> = crate::generate::firewall::build(&old_model)
            .unwrap()
            .sets
            .into_iter()
            .map(|s| s.name)
            .collect();
        // The issue's save: sister-phone moves from family to personal.
        cfg.peers[2].grants = vec!["personal".into()];
        let model = Model::resolve(&cfg, crate::testing::today()).unwrap();
        let fs = MemoryFs::new().with_file(
            "/etc/parallax/wg-server.key",
            crate::testing::keypair(200).private.expose_base64(),
        );
        let bundle = crate::generate::generate_all(&model, &fs).unwrap();
        // A set both rulesets name means the same in both (its name is a
        // hash of its members), so refilling it changes nothing. The ones
        // only the old rules use must stay as they are.
        let new = crate::generate::firewall::build(&model).unwrap().sets;
        let retired: Vec<&String> = old
            .iter()
            .filter(|o| !new.iter().any(|n| n.name == **o))
            .collect();
        assert!(!retired.is_empty());
        let rules = "/var/lib/parallax/iptables/parallax.rules";
        let dry_run = ["--test", "--noflush", rules];
        let restore = ["--noflush", rules];
        for failing in [&dry_run[..], &restore[..]] {
            let runner = RecordingRunner::new();
            runner.respond_to(
                "ipset",
                &["list", "-n"],
                Output {
                    status: 0,
                    stdout: old.join("\n"),
                    stderr: String::new(),
                },
            );
            runner.respond_to(
                "iptables-restore",
                failing,
                failed("iptables-restore: line 12 failed"),
            );
            // A failed apply left one hold; the others aren't there.
            let holds = hold_rules(model.server());
            for rule in &holds[1..] {
                runner.respond_to("iptables", &hold_args("-C", rule), failed("Bad rule"));
            }
            let sys = System {
                fs: &fs,
                runner: &runner,
            };
            let err = apply(&model, &bundle, Path::new("/var/lib/parallax"), sys)
                .unwrap_err()
                .to_string();
            let lines = runner.command_lines();
            let ran = |args: &[&str]| {
                let line = format!("iptables-restore {}", args.join(" "));
                lines.contains(&line)
            };
            assert!(ran(failing), "{lines:#?}");
            assert_eq!(ran(&restore), failing == restore, "{lines:#?}");
            // The hold: never placed when the dry run fails. When the
            // restore fails, placed for both transports (the one already
            // there kept, never lifted for a moment) and left in, which the
            // error says.
            let touched: Vec<&String> = lines.iter().filter(|l| l.contains(HOLD_COMMENT)).collect();
            if failing == dry_run {
                assert!(touched.is_empty(), "{lines:#?}");
            } else {
                assert_eq!(holds.len(), 6);
                let placed = touched.iter().filter(|l| l.contains(" -I ")).count();
                assert_eq!(placed, 5, "{lines:#?}");
                assert!(!touched.iter().any(|l| l.contains(" -D ")), "{lines:#?}");
                assert!(
                    err.contains("tunnel peers can't open new connections until an apply succeeds"),
                    "{err}"
                );
            }
            for name in &retired {
                assert!(
                    !lines
                        .iter()
                        .any(|l| l.split(" ").any(|w| w == name.as_str())),
                    "{name} was touched: {lines:#?}"
                );
            }
        }
    }

    /// Through a whole iptables-nft apply: once the rules are restored, a
    /// stale set of Parallax's goes, the new ruleset's sets and the
    /// operator's own stay, and a set that won't go is reported, not fatal.
    #[test]
    fn an_iptables_apply_keeps_the_operators_sets() {
        let mut cfg = crate::testing::canonical_config();
        cfg.server.firewall.backend = crate::FirewallBackend::IptablesNft;
        let model = Model::resolve(&cfg, crate::testing::today()).unwrap();
        let fs = MemoryFs::new().with_file(
            "/etc/parallax/wg-server.key",
            crate::testing::keypair(200).private.expose_base64(),
        );
        let bundle = crate::generate::generate_all(&model, &fs).unwrap();
        let current: Vec<String> = crate::generate::firewall::build(&model)
            .unwrap()
            .sets
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert!(!current.is_empty());
        let runner = RecordingRunner::new();
        let listing = format!(
            "{}\nnot_public\nwg_fedcba9876543210\nts_00000000000000ff\nwg_external_allow\nts_family\n",
            current.join("\n")
        );
        runner.respond_to(
            "ipset",
            &["list", "-n"],
            Output {
                status: 0,
                stdout: listing,
                stderr: String::new(),
            },
        );
        runner.respond_to(
            "ipset",
            &["destroy", "ts_00000000000000ff"],
            failed("ipset v7.22: Set cannot be destroyed: it is in use by a kernel component"),
        );
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        let report = apply(&model, &bundle, Path::new("/var/lib/parallax"), sys).unwrap();
        let lines = runner.command_lines();
        let destroyed: Vec<&str> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("ipset destroy "))
            .filter(|n| *n != "parallax-swap")
            .collect();
        assert_eq!(
            destroyed,
            ["wg_fedcba9876543210", "ts_00000000000000ff"],
            "{lines:#?}"
        );
        let pos = |needle: &str| lines.iter().position(|l| l.starts_with(needle)).unwrap();
        assert!(
            pos("iptables-restore") < pos("ipset destroy wg_fedcba9876543210"),
            "{lines:#?}"
        );
        assert!(
            report
                .log
                .iter()
                .any(|l| l.contains("ts_00000000000000ff stays") && l.contains("in use")),
            "{:#?}",
            report.log
        );
    }
}
