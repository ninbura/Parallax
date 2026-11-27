//! What the daemon's reconcile loop decides, kept apart from its timers so
//! it can be tested with any date and any live state.
//!
//! After each apply the daemon records the date and a listing of the live
//! state (the nftables table, the WireGuard interface). On each tick it
//! re-applies when the last apply failed, when the UTC date changed (peer
//! expiry is in UTC days), or when the live state no longer matches the
//! listing: someone deleted the table or the interface, or changed a rule.

use std::collections::BTreeSet;
use std::fmt;

use crate::date::Date;
use crate::io::System;
use crate::model::{FirewallBackend, ServerConfig};

/// A listing of what `apply` set up, compared as a whole. It holds no
/// secrets: nothing here prints a private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveState(String);

/// Why the loop applies again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The last apply failed (or none has worked yet).
    Retry,
    /// The UTC date changed since the last apply, so peers may have expired.
    NewDay,
    /// The live state differs from what the last apply left.
    Drift,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::Retry => "the last apply failed; trying again",
            Reason::NewDay => "a new day (UTC); peer expiry may have changed",
            Reason::Drift => "the live firewall or WireGuard interface changed",
        })
    }
}

/// The outcome of the last apply.
#[derive(Debug, Default)]
pub struct Reconciler {
    last: Option<(Date, LiveState)>,
}

impl Reconciler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful apply on `today`, leaving `live`.
    pub fn applied(&mut self, today: Date, live: LiveState) {
        self.last = Some((today, live));
    }

    /// Record a failed apply: the next tick tries again.
    pub fn failed(&mut self) {
        self.last = None;
    }

    /// Whether a tick on `today` should apply, and why. `live` lists the
    /// live state; it is only asked for when nothing else already decides.
    pub fn on_tick(&self, today: Date, live: impl FnOnce() -> LiveState) -> Option<Reason> {
        match &self.last {
            None => Some(Reason::Retry),
            Some((date, _)) if *date != today => Some(Reason::NewDay),
            Some((_, recorded)) => (live() != *recorded).then_some(Reason::Drift),
        }
    }
}

/// List the live state `apply` set up for `server`. A listing that fails
/// (the table is gone) is part of the state, so it differs from one that
/// worked.
pub fn live_state(server: &ServerConfig, sys: System<'_>) -> LiveState {
    let iface = server.wireguard.interface.as_str();
    let mut commands: Vec<(&str, Vec<&str>)> = Vec::new();
    match server.firewall.backend {
        // -s: without counters, which change with every packet.
        FirewallBackend::Nftables => commands.push((
            "nft",
            vec![
                "-s",
                "list",
                "table",
                "inet",
                crate::generate::firewall::TABLE,
            ],
        )),
        FirewallBackend::IptablesNft => commands.push(("iptables-save", vec![])),
    }
    // Apply's accepts in Docker's chain: a Docker restart or a firewall
    // reload can drop them while the table stays.
    let docker =
        server.firewall.docker_coexistence && server.firewall.backend == FirewallBackend::Nftables;
    if docker {
        commands.push((
            "nft",
            vec!["-s", "list", "chain", "ip", "filter", "DOCKER-USER"],
        ));
    }
    commands.extend([
        ("ip", vec!["-o", "link", "show", "dev", iface]),
        ("ip", vec!["-4", "-o", "addr", "show", "dev", iface]),
        ("wg", vec!["show", iface, "listen-port"]),
        ("wg", vec!["show", iface, "allowed-ips"]),
    ]);
    let mut listing = String::new();
    for (program, args) in commands {
        listing.push_str(&format!("$ {program} {}\n", args.join(" ")));
        match sys.runner.run(program, &args, None) {
            Ok(out) => {
                listing.push_str(&format!("status {}\n", out.status));
                if program == "iptables-save" || args.contains(&"DOCKER-USER") {
                    // Only Parallax's rules: the rest belong to others (Docker).
                    for line in out.stdout.lines().filter(|l| {
                        l.contains("PARALLAX")
                            || l.contains("comment \"parallax\"")
                            || l.contains("--comment parallax")
                    }) {
                        listing.push_str(line);
                        listing.push('\n');
                    }
                    // Lines only Parallax's own: someone else's rule going
                    // in above its jump changes none of them (issue #74).
                    if program == "iptables-save" {
                        for (table, builtin, own) in crate::generate::firewall::iptables::CHAINS {
                            let first = crate::apply::decides_first(
                                &save_table(&out.stdout, table),
                                builtin,
                                own,
                            );
                            listing.push_str(&format!("{own} first in {builtin}: {first}\n"));
                        }
                    }
                } else {
                    listing.push_str(&out.stdout);
                }
            }
            Err(e) => listing.push_str(&format!("error {e}\n")),
        }
    }
    LiveState(listing)
}

/// The lines of `table` in an `iptables-save` listing: mangle and raw have
/// chains named like nat's and filter's.
fn save_table(save: &str, table: &str) -> String {
    let header = format!("*{table}");
    save.lines()
        .skip_while(|l| *l != header)
        .skip(1)
        .take_while(|l| *l != "COMMIT")
        .map(|l| format!("{l}\n"))
        .collect()
}

/// The parts of the host `apply` sets up, in the order [`teardown`]
/// removes them: what lets traffic in first (the accepts in Docker's chain,
/// then the interface), while Parallax's firewall still filters it; then the
/// firewall, before the sets its rules use.
const PARTS: usize = 4;

/// What of each part [`teardown`] removes is on the host, as the commands
/// that would remove it (empty: it's gone), or `None`: couldn't tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts([Option<BTreeSet<Command>>; PARTS]);

/// What of the parts `apply` sets up for `server` is on the host now.
pub fn parts_present(server: &ServerConfig, sys: System<'_>) -> Parts {
    Parts(found(server, sys).map(|(_, f)| f.ok().map(|c| c.into_iter().collect())))
}

/// Take down everything `apply` set up for `server`: Parallax's firewall
/// (the nftables table, or iptables-nft's `PARALLAX_*` chains and the jumps
/// to them), its ipsets, its accepts in Docker's `DOCKER-USER` chain, and
/// the WireGuard interface. Returns a log line per part it found; a step
/// that fails is logged and the next one still runs.
pub fn teardown(server: &ServerConfig, sys: System<'_>) -> Vec<String> {
    remove(found(server, sys), [true; PARTS], sys)
}

/// After a failed apply: take down what it added, what's on the host now
/// that `before` (taken just before it) didn't have: a chain, a set or a
/// rule at a time. What was there already stays, whoever set it up, and so
/// does all of a part either check couldn't tell about. Log lines as for
/// [`teardown`].
pub fn teardown_added(server: &ServerConfig, before: Parts, sys: System<'_>) -> Vec<String> {
    let mut now = found(server, sys);
    for ((_, commands), before) in now.iter_mut().zip(&before.0) {
        if let (Ok(commands), Some(before)) = (commands, before) {
            commands.retain(|c| !before.contains(c));
        }
    }
    remove(now, before.0.map(|b| b.is_some()), sys)
}

/// A command: the program and its arguments.
type Command = (&'static str, Vec<String>);

/// Per part: what it is, for the log, and the commands that remove what
/// of it is on the host now (none: it's gone), or why that can't be told.
type Found = (String, Result<Vec<Command>, String>);

fn found(server: &ServerConfig, sys: System<'_>) -> [Found; PARTS] {
    let iface = server.wireguard.interface.as_str();
    let nftables = server.firewall.backend == FirewallBackend::Nftables;
    let table = crate::generate::firewall::TABLE;
    [
        (
            "Parallax's DOCKER-USER rules".into(),
            if nftables {
                nft_docker_user(sys)
            } else {
                iptables_docker_user(sys)
            },
        ),
        (format!("interface {iface}"), interface(iface, sys)),
        if nftables {
            (format!("table inet {table}"), nft_table(sys))
        } else {
            ("the PARALLAX_* chains".into(), iptables_chains(sys))
        },
        (
            "Parallax's ipsets".into(),
            if nftables {
                Ok(Vec::new())
            } else {
                ipsets(sys)
            },
        ),
    ]
}

/// Run `program args`: its stdout, `None` when its stderr says what was
/// asked for isn't there (one of `gone`), or why it failed.
fn list(
    sys: System<'_>,
    program: &str,
    args: &[&str],
    gone: &[&str],
) -> Result<Option<String>, String> {
    match sys.runner.run(program, args, None) {
        Ok(out) if out.ok() => Ok(Some(out.stdout)),
        Ok(out) if gone.iter().any(|g| out.stderr.contains(g)) => Ok(None),
        Ok(out) => Err(format!(
            "`{program} {}`: {}",
            args.join(" "),
            out.stderr.trim()
        )),
        Err(e) => Err(e.to_string()),
    }
}

fn command(program: &'static str, args: &[&str]) -> Command {
    (program, args.iter().map(|a| a.to_string()).collect())
}

const NFT_GONE: &[&str] = &["No such file or directory"];
const IPTABLES_GONE: &[&str] = &["No chain/target/match by that name"];

fn nft_table(sys: System<'_>) -> Result<Vec<Command>, String> {
    let table = crate::generate::firewall::TABLE;
    let there = list(
        sys,
        "nft",
        &["-t", "list", "table", "inet", table],
        NFT_GONE,
    )?;
    Ok(there
        .map(|_| vec![command("nft", &["delete", "table", "inet", table])])
        .unwrap_or_default())
}

/// The jumps from the built-in chains first, then Parallax's chains
/// flushed, then deleted: a chain something still jumps to can't go. Then
/// any hold a failed apply left. Only
/// the names the generator gives: an operator's `PARALLAX_MINE` stays.
fn iptables_chains(sys: System<'_>) -> Result<Vec<Command>, String> {
    use crate::generate::firewall::iptables::CHAINS;
    let (mut jumps, mut flushes, mut deletes) = (Vec::new(), Vec::new(), Vec::new());
    let mut holds = Vec::new();
    for table in ["filter", "nat"] {
        let Some(listing) = list(sys, "iptables", &["-t", table, "-S"], IPTABLES_GONE)? else {
            continue;
        };
        if table == "filter" {
            holds.extend(
                crate::apply::held(&listing)
                    .into_iter()
                    .map(|args| ("iptables", args)),
            );
        }
        for line in listing.lines() {
            for (t, builtin, own) in CHAINS {
                if t == table && line == format!("-A {builtin} -j {own}") {
                    jumps.push(command(
                        "iptables",
                        &["-t", table, "-D", builtin, "-j", own],
                    ));
                }
            }
            let ours = |chain: &str| {
                CHAINS
                    .iter()
                    .any(|(t, _, own)| *t == table && *own == chain)
                    || (table == "filter"
                        && chain.strip_prefix("PARALLAX_T").is_some_and(|n| {
                            !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                        }))
            };
            if let Some(chain) = line.strip_prefix("-N ").filter(|c| ours(c)) {
                flushes.push(command("iptables", &["-t", table, "-F", chain]));
                deletes.push(command("iptables", &["-t", table, "-X", chain]));
            }
        }
    }
    // A failed apply's hold on new connections (issue #56) goes last: until
    // the rules are gone, nothing starts under what's left of them.
    Ok([jumps, flushes, deletes, holds].concat())
}

fn ipsets(sys: System<'_>) -> Result<Vec<Command>, String> {
    let listing = list(sys, "ipset", &["list", "-n"], &[])?.unwrap_or_default();
    Ok(crate::apply::own_sets(&listing)
        .into_iter()
        .map(|name| command("ipset", &["destroy", name]))
        .collect())
}

/// Apply's accepts carry the comment `parallax`, as apply finds them.
fn nft_docker_user(sys: System<'_>) -> Result<Vec<Command>, String> {
    let chain = ["ip", "filter", "DOCKER-USER"];
    let listing = list(
        sys,
        "nft",
        &["-a", "list", "chain", "ip", "filter", "DOCKER-USER"],
        NFT_GONE,
    )?
    .unwrap_or_default();
    Ok(listing
        .lines()
        .filter_map(|l| l.rsplit_once(" # handle "))
        // Exactly apply's comment, last on the rule as nft lists it.
        .filter(|(rule, _)| rule.ends_with(" comment \"parallax\""))
        .map(|(_, handle)| handle.trim())
        .map(|handle| {
            let mut args = vec!["delete", "rule"];
            args.extend(chain);
            args.extend(["handle", handle]);
            command("nft", &args)
        })
        .collect())
}

fn iptables_docker_user(sys: System<'_>) -> Result<Vec<Command>, String> {
    let listing = list(
        sys,
        "iptables",
        &["-t", "filter", "-S", "DOCKER-USER"],
        IPTABLES_GONE,
    )?
    .unwrap_or_default();
    Ok(crate::apply::docker_user_rules(&listing)
        .into_iter()
        .map(|rule| {
            let mut args = vec!["-t", "filter", "-D"];
            args.extend(rule.iter().map(String::as_str));
            command("iptables", &args)
        })
        .collect())
}

fn interface(iface: &str, sys: System<'_>) -> Result<Vec<Command>, String> {
    let there = list(
        sys,
        "ip",
        &["link", "show", "dev", iface],
        &["does not exist"],
    )?;
    Ok(there
        .map(|_| vec![command("ip", &["link", "del", "dev", iface])])
        .unwrap_or_default())
}

/// Run the removals of the parts `chosen` picks. A part that's gone logs
/// nothing; one that couldn't be checked, or whose removal failed, says so.
fn remove(found: [Found; PARTS], chosen: [bool; PARTS], sys: System<'_>) -> Vec<String> {
    let mut log = Vec::new();
    for ((what, commands), chosen) in found.into_iter().zip(chosen) {
        if !chosen {
            continue;
        }
        let commands = match commands {
            Ok(c) if c.is_empty() => continue,
            Ok(c) => c,
            Err(e) => {
                log.push(format!("could not check {what}, left as it is: {e}"));
                continue;
            }
        };
        let failed: Vec<String> = commands
            .iter()
            .filter_map(|(program, args)| {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                sys.runner
                    .run_checked(program, &args, None)
                    .err()
                    .map(|e| e.to_string())
            })
            .collect();
        log.push(match failed.first() {
            None => format!("removed {what}"),
            Some(e) => format!("could not remove {what}: {e}"),
        });
    }
    log
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;
    use crate::io::memory::{MemoryFs, RecordingRunner};
    use crate::io::Output;
    use crate::testing::canonical_config;

    fn day(d: u8) -> Date {
        Date::new(2026, 11, d).unwrap()
    }

    fn state(s: &str) -> LiveState {
        LiveState(s.into())
    }

    #[test]
    fn retries_until_an_apply_works() {
        let mut r = Reconciler::new();
        assert_eq!(r.on_tick(day(24), || state("a")), Some(Reason::Retry));
        r.applied(day(24), state("a"));
        assert_eq!(r.on_tick(day(24), || state("a")), None);
        r.failed();
        assert_eq!(r.on_tick(day(24), || state("a")), Some(Reason::Retry));
    }

    #[test]
    fn applies_once_the_date_changes() {
        let mut r = Reconciler::new();
        r.applied(day(24), state("a"));
        let asked = std::cell::Cell::new(false);
        let live = || {
            asked.set(true);
            state("a")
        };
        assert_eq!(r.on_tick(day(25), live), Some(Reason::NewDay));
        assert!(!asked.get(), "a new day needs no listing");
        r.applied(day(25), state("a"));
        assert_eq!(r.on_tick(day(25), || state("a")), None);
    }

    #[test]
    fn applies_only_when_the_live_state_differs() {
        let mut r = Reconciler::new();
        r.applied(day(24), state("table\nwg0"));
        assert_eq!(r.on_tick(day(24), || state("table\nwg0")), None);
        assert_eq!(r.on_tick(day(24), || state("wg0")), Some(Reason::Drift));
    }

    #[test]
    fn a_failed_listing_differs_from_a_working_one() {
        let config = canonical_config();
        let fs = MemoryFs::new();
        let ok = RecordingRunner::new();
        let sys = System {
            fs: &fs,
            runner: &ok,
        };
        let before = live_state(&config.server, sys);
        let gone = RecordingRunner::new();
        gone.respond(
            "nft",
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "No such file or directory".into(),
            },
        );
        let sys = System {
            fs: &fs,
            runner: &gone,
        };
        assert_ne!(live_state(&config.server, sys), before);
        assert_eq!(
            ok.command_lines(),
            [
                "nft -s list table inet parallax",
                "nft -s list chain ip filter DOCKER-USER",
                "ip -o link show dev wg0",
                "ip -4 -o addr show dev wg0",
                "wg show wg0 listen-port",
                "wg show wg0 allowed-ips",
            ]
        );
    }

    #[test]
    fn lost_docker_user_accepts_count_as_drift() {
        let config = canonical_config();
        let fs = MemoryFs::new();
        let listing = |chain: &str| {
            let runner = RecordingRunner::new();
            runner.respond_to(
                "nft",
                &["-s", "list", "chain", "ip", "filter", "DOCKER-USER"],
                Output {
                    status: 0,
                    stdout: chain.into(),
                    stderr: String::new(),
                },
            );
            live_state(
                &config.server,
                System {
                    fs: &fs,
                    runner: &runner,
                },
            )
        };
        let ours = "iifname \"wg0\" accept comment \"parallax\"\n";
        // Docker's own rules come and go; only ours matter.
        assert_eq!(
            listing(ours),
            listing(&format!("{ours}counter jump DOCKER\n"))
        );
        assert_ne!(listing(ours), listing("counter jump DOCKER\n"));
    }

    #[test]
    fn iptables_listing_keeps_only_parallax_rules() {
        let mut config = canonical_config();
        config.server.firewall.backend = FirewallBackend::IptablesNft;
        let fs = MemoryFs::new();
        let listing = |docker: &str| {
            let runner = RecordingRunner::new();
            runner.respond(
                "iptables-save",
                Output {
                    status: 0,
                    stdout: format!("# Generated at {docker}\n-A FORWARD -j PARALLAX_FORWARD\n-A DOCKER {docker}\n"),
                    stderr: String::new(),
                },
            );
            live_state(
                &config.server,
                System {
                    fs: &fs,
                    runner: &runner,
                },
            )
        };
        assert_eq!(listing("one"), listing("two"));
    }

    /// Issue #74: a Docker restart puts its jumps above Parallax's. Only
    /// Parallax's lines are listed, so the order has to be part of the state.
    #[test]
    fn a_rule_above_parallaxs_jump_counts_as_drift() {
        let mut config = canonical_config();
        config.server.firewall.backend = FirewallBackend::IptablesNft;
        let fs = MemoryFs::new();
        let listing = |forward: &str| {
            let runner = RecordingRunner::new();
            runner.respond(
                "iptables-save",
                Output {
                    status: 0,
                    stdout: format!(
                        "*nat\n-A PREROUTING -j PARALLAX_PREROUTING\n-A POSTROUTING -j PARALLAX_POSTROUTING\nCOMMIT\n\
                         *filter\n-A INPUT -j PARALLAX_INPUT\n{forward}\
                         -A DOCKER-USER -m comment --comment parallax -j PARALLAX_FORWARD\n\
                         -A DOCKER-USER -o wg0 -m comment --comment parallax -j ACCEPT\nCOMMIT\n"
                    ),
                    stderr: String::new(),
                },
            );
            live_state(
                &config.server,
                System {
                    fs: &fs,
                    runner: &runner,
                },
            )
        };
        let ours = "-A FORWARD -j PARALLAX_FORWARD\n-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n";
        let applied = listing(ours);
        assert_ne!(
            applied,
            listing("-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j PARALLAX_FORWARD\n")
        );
        // DOCKER-USER first sends everything through Parallax's chain too,
        // so Docker putting it back on top is no reason to apply again.
        assert_eq!(
            applied,
            listing("-A FORWARD -j DOCKER-USER\n-A FORWARD -j DOCKER-FORWARD\n-A FORWARD -j PARALLAX_FORWARD\n")
        );
    }

    /// How a listing answers.
    #[derive(Clone, Copy)]
    enum Check {
        /// It works and prints this.
        There(&'static str),
        Gone,
        /// Fails for another reason than "not there".
        Unclear,
    }
    use Check::{Gone, There, Unclear};

    const NFT_GONE: &str = "Error: No such file or directory";
    const IP_GONE: &str = "Device \"wg0\" does not exist.";
    const IPTABLES_GONE: &str = "iptables: No chain/target/match by that name.";

    fn reply(runner: &RecordingRunner, program: &str, args: &[&str], check: Check, gone: &str) {
        let (status, stdout, stderr) = match check {
            There(out) => (0, out, ""),
            Gone => (1, "", gone),
            Unclear => (1, "", "Operation not permitted"),
        };
        runner.respond_to(
            program,
            args,
            Output {
                status,
                stdout: stdout.into(),
                stderr: stderr.into(),
            },
        );
    }

    /// An nftables host, as one look at it answers.
    fn nft_host(runner: &RecordingRunner, table: Check, docker_user: Check, wg0: Check) {
        let table_args = ["-t", "list", "table", "inet", "parallax"];
        reply(runner, "nft", &table_args, table, NFT_GONE);
        let docker_args = ["-a", "list", "chain", "ip", "filter", "DOCKER-USER"];
        reply(runner, "nft", &docker_args, docker_user, NFT_GONE);
        reply(runner, "ip", &["link", "show", "dev", "wg0"], wg0, IP_GONE);
    }

    const TABLE: Check = There("table inet parallax {}");
    const WG0: Check = There("4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP>");
    /// Docker's chain with apply's two accepts for wg0 among Docker's own.
    const DOCKER_USER: Check = There(
        "table ip filter {
	chain DOCKER-USER { # handle 1
		iifname \"wg0\" accept comment \"parallax\" # handle 7
		oifname \"wg0\" accept comment \"parallax\" # handle 8
		counter packets 0 bytes 0 return # handle 3
	}
}",
    );

    fn removals(runner: &RecordingRunner) -> Vec<String> {
        runner
            .command_lines()
            .into_iter()
            .filter(|l| {
                [" del", " -D ", " -F ", " -X ", "destroy"]
                    .iter()
                    .any(|v| l.contains(v))
            })
            .collect()
    }

    /// Teardown touches no files: an empty `MemoryFs` stands in.
    fn on<'a>(fs: &'a MemoryFs, runner: &'a RecordingRunner) -> System<'a> {
        System { fs, runner }
    }

    #[test]
    fn teardown_removes_everything_apply_set_up() {
        let config = canonical_config();
        let runner = RecordingRunner::new();
        nft_host(&runner, TABLE, DOCKER_USER, WG0);
        let log = teardown(&config.server, on(&MemoryFs::new(), &runner));
        assert_eq!(
            removals(&runner),
            [
                "nft delete rule ip filter DOCKER-USER handle 7",
                "nft delete rule ip filter DOCKER-USER handle 8",
                "ip link del dev wg0",
                "nft delete table inet parallax",
            ]
        );
        assert_eq!(
            log,
            [
                "removed Parallax's DOCKER-USER rules",
                "removed interface wg0",
                "removed table inet parallax",
            ]
        );
    }

    #[test]
    fn teardown_logs_a_failure_and_keeps_going() {
        let config = canonical_config();
        let runner = RecordingRunner::new();
        nft_host(&runner, TABLE, Gone, WG0);
        reply(
            &runner,
            "nft",
            &["delete", "table", "inet", "parallax"],
            Unclear,
            "",
        );
        let log = teardown(&config.server, on(&MemoryFs::new(), &runner));
        assert_eq!(log[0], "removed interface wg0");
        assert!(
            log[1].starts_with("could not remove table inet parallax"),
            "{log:?}"
        );
    }

    /// Nothing there: nothing to remove, nothing to say. A listing that
    /// fails otherwise is said, and nothing of that part is touched.
    #[test]
    fn teardown_says_only_what_it_found() {
        let config = canonical_config();
        let runner = RecordingRunner::new();
        nft_host(&runner, Gone, Gone, Gone);
        assert!(teardown(&config.server, on(&MemoryFs::new(), &runner)).is_empty());
        assert!(removals(&runner).is_empty());

        let runner = RecordingRunner::new();
        nft_host(&runner, Unclear, Gone, WG0);
        let log = teardown(&config.server, on(&MemoryFs::new(), &runner));
        assert_eq!(removals(&runner), ["ip link del dev wg0"]);
        assert!(
            log[1].starts_with("could not check table inet parallax, left as it is: "),
            "{log:?}"
        );
    }

    /// iptables-nft: the DOCKER-USER accepts and the interface, then the
    /// jumps, Parallax's chains (flushed, then deleted) and its sets. An operator's chains
    /// (`PARALLAX_MINE` too), jump, sets and DOCKER-USER rules stay.
    #[test]
    fn iptables_teardown_removes_only_parallaxs_own() {
        let mut config = canonical_config();
        config.server.firewall.backend = FirewallBackend::IptablesNft;
        let runner = RecordingRunner::new();
        let filter = "-P INPUT ACCEPT
-N MINE
-N PARALLAX_MINE
-N PARALLAX_INPUT
-N PARALLAX_FORWARD
-N PARALLAX_T0
-A INPUT -i wg0 -m conntrack --ctstate NEW -m comment --comment parallax-hold -j DROP
-A INPUT -j MINE
-A INPUT -j PARALLAX_INPUT
-A FORWARD -j PARALLAX_FORWARD
-A FORWARD -m comment --comment parallax-holdout -j ACCEPT
-A PARALLAX_FORWARD -j PARALLAX_T0";
        let nat = "-N PARALLAX_POSTROUTING
-A POSTROUTING -j PARALLAX_POSTROUTING";
        let sets = "wg_0123456789abcdef
not_public_fedcba9876543210
parallax-swap
wg_external_allow
not_public";
        let docker = "-N DOCKER-USER
-A DOCKER-USER -i wg0 -m comment --comment parallax -j ACCEPT
-A DOCKER-USER -o wg0 -m comment --comment \"\\\"parallax\\\"\" -j ACCEPT
-A DOCKER-USER -s 10.0.0.0/8 -m comment --comment parallax-backup -j DROP
-A DOCKER-USER -j RETURN";
        let ipt = "iptables";
        reply(
            &runner,
            ipt,
            &["-t", "filter", "-S"],
            There(filter),
            IPTABLES_GONE,
        );
        reply(
            &runner,
            ipt,
            &["-t", "nat", "-S"],
            There(nat),
            IPTABLES_GONE,
        );
        reply(&runner, "ipset", &["list", "-n"], There(sets), "");
        let docker_args = ["-t", "filter", "-S", "DOCKER-USER"];
        reply(&runner, ipt, &docker_args, There(docker), IPTABLES_GONE);
        reply(&runner, "ip", &["link", "show", "dev", "wg0"], WG0, IP_GONE);
        let log = teardown(&config.server, on(&MemoryFs::new(), &runner));
        assert_eq!(
            removals(&runner),
            [
                "iptables -t filter -D DOCKER-USER -i wg0 -m comment --comment parallax -j ACCEPT",
                // One a build before this one inserted, the quotes kept.
                "iptables -t filter -D DOCKER-USER -o wg0 -m comment --comment \"parallax\" -j ACCEPT",
                "ip link del dev wg0",
                "iptables -t filter -D INPUT -j PARALLAX_INPUT",
                "iptables -t filter -D FORWARD -j PARALLAX_FORWARD",
                "iptables -t nat -D POSTROUTING -j PARALLAX_POSTROUTING",
                "iptables -t filter -F PARALLAX_INPUT",
                "iptables -t filter -F PARALLAX_FORWARD",
                "iptables -t filter -F PARALLAX_T0",
                "iptables -t nat -F PARALLAX_POSTROUTING",
                "iptables -t filter -X PARALLAX_INPUT",
                "iptables -t filter -X PARALLAX_FORWARD",
                "iptables -t filter -X PARALLAX_T0",
                "iptables -t nat -X PARALLAX_POSTROUTING",
                // A failed apply's hold (#56), last; not a rule that only
                // looks like one.
                "iptables -t filter -D INPUT -i wg0 -m conntrack --ctstate NEW -m comment --comment parallax-hold -j DROP",
                "ipset destroy wg_0123456789abcdef",
                "ipset destroy not_public_fedcba9876543210",
                "ipset destroy parallax-swap",
            ]
        );
        assert_eq!(
            log,
            [
                "removed Parallax's DOCKER-USER rules",
                "removed interface wg0",
                "removed the PARALLAX_* chains",
                "removed Parallax's ipsets",
            ]
        );
    }

    /// What a failed apply takes down, given what nftables hosts answer
    /// before and after it: (table, DOCKER-USER, wg0) each.
    fn after_failed_apply(
        before: (Check, Check, Check),
        now: (Check, Check, Check),
    ) -> Vec<String> {
        let config = canonical_config();
        let runner = RecordingRunner::new();
        nft_host(&runner, before.0, before.1, before.2);
        let before = parts_present(&config.server, on(&MemoryFs::new(), &runner));
        nft_host(&runner, now.0, now.1, now.2);
        teardown_added(&config.server, before, on(&MemoryFs::new(), &runner));
        removals(&runner)
    }

    #[test]
    fn a_failed_apply_takes_down_what_it_added() {
        assert_eq!(
            after_failed_apply((Gone, Gone, Gone), (TABLE, DOCKER_USER, WG0)),
            [
                "nft delete rule ip filter DOCKER-USER handle 7",
                "nft delete rule ip filter DOCKER-USER handle 8",
                "ip link del dev wg0",
                "nft delete table inet parallax",
            ]
        );
        // Docker's chain without Parallax's rules counts as none there.
        let empty_docker_user =
            There("table ip filter {\n\tchain DOCKER-USER { # handle 1\n\t}\n}");
        assert_eq!(
            after_failed_apply((Gone, empty_docker_user, Gone), (TABLE, DOCKER_USER, Gone)),
            [
                "nft delete rule ip filter DOCKER-USER handle 7",
                "nft delete rule ip filter DOCKER-USER handle 8",
                "nft delete table inet parallax",
            ]
        );
    }

    #[test]
    fn a_failed_apply_leaves_what_was_there_before_it() {
        // An interface from before (a crashed daemon's, or someone else's).
        assert_eq!(
            after_failed_apply((Gone, Gone, WG0), (TABLE, Gone, WG0)),
            ["nft delete table inet parallax"]
        );
        // A table and its DOCKER-USER rules from before.
        assert_eq!(
            after_failed_apply((TABLE, DOCKER_USER, Gone), (TABLE, DOCKER_USER, WG0)),
            ["ip link del dev wg0"]
        );
        // It failed before changing anything.
        assert!(after_failed_apply((Gone, Gone, Gone), (Gone, Gone, Gone)).is_empty());
    }

    /// A check that fails for another reason than "not there" removes
    /// nothing: before, the part may have been there; after, it may be gone.
    #[test]
    fn an_unclear_check_removes_nothing() {
        let unclear = (Unclear, Unclear, Unclear);
        assert!(after_failed_apply(unclear, (TABLE, DOCKER_USER, WG0)).is_empty());
        assert!(after_failed_apply((Gone, Gone, Gone), unclear).is_empty());
        // And says why, after the apply.
        let config = canonical_config();
        let runner = RecordingRunner::new();
        nft_host(&runner, Gone, Gone, Gone);
        let before = parts_present(&config.server, on(&MemoryFs::new(), &runner));
        nft_host(&runner, Unclear, Gone, Gone);
        let log = teardown_added(&config.server, before, on(&MemoryFs::new(), &runner));
        assert_eq!(log.len(), 1, "{log:?}");
        assert!(
            log[0].starts_with("could not check table inet parallax, left as it is: "),
            "{log:?}"
        );
    }

    #[test]
    fn a_check_that_cannot_run_is_unclear() {
        struct NoPrograms;
        impl crate::io::ProcessRunner for NoPrograms {
            fn run(&self, program: &str, _: &[&str], _: Option<&str>) -> crate::Result<Output> {
                Err(crate::Error::Invalid(vec![format!("no {program}")]))
            }
        }
        let config = canonical_config();
        let fs = MemoryFs::new();
        let sys = System {
            fs: &fs,
            runner: &NoPrograms,
        };
        // nftables has no ipsets to look for; nothing else can be told.
        assert_eq!(
            parts_present(&config.server, sys),
            Parts([None, None, None, Some(BTreeSet::new())])
        );
        let log = teardown(&config.server, sys);
        assert_eq!(log.len(), 3, "{log:?}");
        assert!(
            log.iter().all(|l| l.starts_with("could not check ")),
            "{log:?}"
        );
    }

    /// A failed apply on iptables-nft next to a stale set from before: the
    /// sets it made go, the stale one stays.
    #[test]
    fn a_failed_apply_removes_its_own_sets_and_keeps_older_ones() {
        let mut config = canonical_config();
        config.server.firewall.backend = FirewallBackend::IptablesNft;
        let runner = RecordingRunner::new();
        let host = |sets: &'static str| {
            reply(
                &runner,
                "iptables",
                &["-t", "filter", "-S"],
                There(""),
                IPTABLES_GONE,
            );
            reply(
                &runner,
                "iptables",
                &["-t", "nat", "-S"],
                There(""),
                IPTABLES_GONE,
            );
            reply(&runner, "ipset", &["list", "-n"], There(sets), "");
            let docker_args = ["-t", "filter", "-S", "DOCKER-USER"];
            reply(&runner, "iptables", &docker_args, Gone, IPTABLES_GONE);
            reply(
                &runner,
                "ip",
                &["link", "show", "dev", "wg0"],
                Gone,
                IP_GONE,
            );
        };
        host("wg_0123456789abcdef");
        let before = parts_present(&config.server, on(&MemoryFs::new(), &runner));
        // The restore failed after the sets were filled.
        host("wg_0123456789abcdef\nwg_fedcba9876543210\nparallax-swap");
        let log = teardown_added(&config.server, before, on(&MemoryFs::new(), &runner));
        assert_eq!(
            removals(&runner),
            [
                "ipset destroy wg_fedcba9876543210",
                "ipset destroy parallax-swap"
            ]
        );
        assert_eq!(log, ["removed Parallax's ipsets"]);
    }
}
