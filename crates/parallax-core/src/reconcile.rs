//! What the daemon's reconcile loop decides, kept apart from its timers so
//! it can be tested with any date and any live state.
//!
//! After each apply the daemon records the date and a listing of the live
//! state (the nftables table, the WireGuard interface). On each tick it
//! re-applies when the last apply failed, when the UTC date changed (peer
//! expiry is in UTC days), or when the live state no longer matches the
//! listing: someone deleted the table or the interface, or changed a rule.

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
                } else {
                    listing.push_str(&out.stdout);
                }
            }
            Err(e) => listing.push_str(&format!("error {e}\n")),
        }
    }
    LiveState(listing)
}

/// Which of the parts [`teardown`] removes are on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parts {
    /// The nftables table (the nftables backend only).
    pub table: bool,
    /// The WireGuard interface.
    pub interface: bool,
}

/// Which of the parts `apply` sets up for `server` are on the host now.
/// One that can't be checked counts as there.
pub fn parts_present(server: &ServerConfig, sys: System<'_>) -> Parts {
    let there = |program: &str, args: &[&str]| {
        sys.runner
            .run(program, args, None)
            .map_or(true, |out| out.ok())
    };
    let table = crate::generate::firewall::TABLE;
    Parts {
        table: server.firewall.backend == FirewallBackend::Nftables
            && there("nft", &["-t", "list", "table", "inet", table]),
        interface: there(
            "ip",
            &["link", "show", "dev", server.wireguard.interface.as_str()],
        ),
    }
}

/// Take down what `apply` set up for `server`: the nftables table and the
/// WireGuard interface, as the container's shutdown always did. Returns a
/// log line per step; a step that fails is logged and the next one still runs.
pub fn teardown(server: &ServerConfig, sys: System<'_>) -> Vec<String> {
    let all = Parts {
        table: true,
        interface: true,
    };
    remove(server, all, sys)
}

/// After a failed apply: take down what it added, the parts on the host
/// now that weren't in `before` (taken just before it). What was there
/// already stays, whoever set it up. Log lines as for [`teardown`].
pub fn teardown_added(server: &ServerConfig, before: Parts, sys: System<'_>) -> Vec<String> {
    let now = parts_present(server, sys);
    let added = Parts {
        table: now.table && !before.table,
        interface: now.interface && !before.interface,
    };
    remove(server, added, sys)
}

fn remove(server: &ServerConfig, parts: Parts, sys: System<'_>) -> Vec<String> {
    let iface = server.wireguard.interface.as_str();
    let table = crate::generate::firewall::TABLE;
    let mut steps: Vec<(String, &str, Vec<&str>)> = Vec::new();
    if parts.table && server.firewall.backend == FirewallBackend::Nftables {
        steps.push((
            format!("table inet {table}"),
            "nft",
            vec!["delete", "table", "inet", table],
        ));
    }
    if parts.interface {
        steps.push((
            format!("interface {iface}"),
            "ip",
            vec!["link", "del", "dev", iface],
        ));
    }
    steps
        .into_iter()
        .map(
            |(what, program, args)| match sys.runner.run_checked(program, &args, None) {
                Ok(_) => format!("removed {what}"),
                Err(e) => format!("could not remove {what}: {e}"),
            },
        )
        .collect()
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

    #[test]
    fn teardown_removes_the_table_and_the_interface_and_keeps_going() {
        let config = canonical_config();
        let fs = MemoryFs::new();
        let runner = RecordingRunner::new();
        runner.respond(
            "nft",
            Output {
                status: 1,
                stdout: String::new(),
                stderr: "No such file or directory".into(),
            },
        );
        let log = teardown(
            &config.server,
            System {
                fs: &fs,
                runner: &runner,
            },
        );
        assert_eq!(
            runner.command_lines(),
            ["nft delete table inet parallax", "ip link del dev wg0"]
        );
        assert!(
            log[0].starts_with("could not remove table inet parallax"),
            "{log:?}"
        );
        assert_eq!(log[1], "removed interface wg0");
    }

    fn missing() -> Output {
        Output {
            status: 1,
            stdout: String::new(),
            stderr: "does not exist".into(),
        }
    }

    /// The table and the interface as `parts_present` asks for them.
    fn respond_present(runner: &RecordingRunner, table: bool, interface: bool) {
        let found = |there| {
            if there {
                Output {
                    status: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                }
            } else {
                missing()
            }
        };
        runner.respond_to(
            "nft",
            &["-t", "list", "table", "inet", "parallax"],
            found(table),
        );
        runner.respond_to("ip", &["link", "show", "dev", "wg0"], found(interface));
    }

    fn removals(runner: &RecordingRunner) -> Vec<String> {
        runner
            .command_lines()
            .into_iter()
            .filter(|l| l.contains(" del"))
            .collect()
    }

    #[test]
    fn a_failed_apply_takes_down_what_it_added() {
        let config = canonical_config();
        let fs = MemoryFs::new();
        let runner = RecordingRunner::new();
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        respond_present(&runner, false, false);
        let before = parts_present(&config.server, sys);
        assert_eq!(
            before,
            Parts {
                table: false,
                interface: false
            }
        );
        // The apply got as far as both before it failed.
        respond_present(&runner, true, true);
        let log = teardown_added(&config.server, before, sys);
        assert_eq!(
            removals(&runner),
            ["nft delete table inet parallax", "ip link del dev wg0"]
        );
        assert_eq!(
            log,
            ["removed table inet parallax", "removed interface wg0"]
        );
    }

    #[test]
    fn a_failed_apply_leaves_what_was_there_before_it() {
        let config = canonical_config();
        let fs = MemoryFs::new();
        let runner = RecordingRunner::new();
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        // An interface from before (a crashed daemon's, or someone else's);
        // the apply added only the table.
        respond_present(&runner, false, true);
        let before = parts_present(&config.server, sys);
        respond_present(&runner, true, true);
        let log = teardown_added(&config.server, before, sys);
        assert_eq!(removals(&runner), ["nft delete table inet parallax"]);
        assert_eq!(log, ["removed table inet parallax"]);

        // It failed before changing anything: nothing to take down.
        let runner = RecordingRunner::new();
        let sys = System {
            fs: &fs,
            runner: &runner,
        };
        respond_present(&runner, false, false);
        let before = parts_present(&config.server, sys);
        respond_present(&runner, false, false);
        assert!(teardown_added(&config.server, before, sys).is_empty());
        assert!(removals(&runner).is_empty());
    }
}
