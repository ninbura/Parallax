//! `doctor`: check that this host can run the gateway, before `apply` touches
//! anything. Docker's entrypoint and native installs run the same checks.
//!
//! Every check runs, so one pass reports every problem. Each failure says
//! what is wrong and how to fix it.

use std::path::Path;

use crate::io::System;
use crate::model::{Config, FirewallBackend};

/// The kernel's identity mapping: the initial user namespace maps every uid to itself.
const INIT_USERNS_UID_MAP: (u64, u64, u64) = (0, 0, 4_294_967_295);
/// Bit of `CAP_NET_ADMIN` in `/proc/self/status` capability masks.
const CAP_NET_ADMIN_BIT: u32 = 12;
/// Short enough for the 15-byte interface name limit, unlikely to clash.
const PROBE_INTERFACE: &str = "parallax-probe";
/// A ruleset using prefix NAT (NETMAP), checked with `nft -c` and never loaded.
const NETMAP_PROBE: &str = "table inet parallax_probe {
    chain pre {
        type nat hook prerouting priority dstnat;
        ip daddr 192.0.2.0/24 dnat ip prefix to ip daddr map { 192.0.2.0/24 : 198.51.100.0/24 }
    }
}
";
const SETUP_DOC: &str = "docs/setup.md";

/// The outcome of one check: `Ok` with what was found, or `Err` with the problem and the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub result: Result<String, String>,
}

impl Check {
    fn new(name: impl Into<String>, result: Result<String, String>) -> Self {
        Check {
            name: name.into(),
            result,
        }
    }
}

/// Run every check against the configuration at `config_path` and the host.
pub fn diagnose(config_path: &Path, sys: System<'_>) -> Vec<Check> {
    let (config_check, config) = check_config(config_path, sys);
    let mut checks = vec![
        config_check,
        Check::new("user namespace", check_user_namespace(sys)),
        Check::new("CAP_NET_ADMIN", check_net_admin(sys)),
        Check::new("ip_forward", check_ip_forward(sys)),
    ];

    let backend = config
        .as_ref()
        .map_or(FirewallBackend::Nftables, |c| c.server.firewall.backend);
    let missing = crate::apply::preflight(backend, sys);
    checks.push(Check::new(
        "tools",
        if missing.is_empty() {
            Ok("all present".into())
        } else {
            Err(missing.join("; "))
        },
    ));

    if let Some(config) = &config {
        for name in interfaces(config) {
            checks.push(Check::new(
                format!("interface {name}"),
                check_interface(name, sys),
            ));
        }
    }
    checks.push(Check::new("wireguard", check_wireguard(sys)));
    if backend == FirewallBackend::Nftables {
        checks.push(Check::new("NETMAP", check_netmap(sys)));
    }
    checks
}

/// Parse and validate. The parsed config is returned even when validation
/// fails, so the interface checks still run.
fn check_config(path: &Path, sys: System<'_>) -> (Check, Option<Config>) {
    let name = "configuration";
    let text = match sys.fs.read(path) {
        Ok(Some(text)) => text,
        Ok(None) => {
            return (
                Check::new(name, Err(format!("no configuration at {}", path.display()))),
                None,
            )
        }
        Err(e) => return (Check::new(name, Err(e.to_string())), None),
    };
    let config = match Config::from_toml(&text) {
        Ok(c) => c,
        Err(e) => {
            return (
                Check::new(name, Err(format!("{}: {e}", path.display()))),
                None,
            )
        }
    };
    let (errors, warnings) = crate::validate::check(&config);
    let result = if errors.is_empty() {
        Ok(match warnings.len() {
            0 => format!("{} is valid", path.display()),
            n => format!(
                "{} is valid, with {n} warning(s); `parallax validate` lists them",
                path.display()
            ),
        })
    } else {
        Err(format!(
            "{} is invalid:\n{}",
            path.display(),
            errors
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    };
    (Check::new(name, result), Some(config))
}

/// Parallax drives the host's network stack, which needs real root
/// privileges over the host network namespace. A process in a user namespace
/// (rootless Docker, userns-remap) only holds capabilities over namespaces it
/// owns, and rootless Docker's "host network" is a private namespace anyway.
fn check_user_namespace(sys: System<'_>) -> Result<String, String> {
    let path = Path::new("/proc/self/uid_map");
    let text = read(sys, path)?;
    let mappings: Vec<(u64, u64, u64)> = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace().map(|f| f.parse::<u64>());
            match (fields.next(), fields.next(), fields.next()) {
                (Some(Ok(inside)), Some(Ok(outside)), Some(Ok(count))) => {
                    Some((inside, outside, count))
                }
                _ => None,
            }
        })
        .collect();
    if mappings == [INIT_USERNS_UID_MAP] {
        return Ok("not in a user namespace".into());
    }
    let root = match mappings.iter().find(|(inside, _, _)| *inside == 0) {
        Some((_, outside, _)) => format!("uid 0 here is uid {outside} on the host"),
        None => "uid 0 is not mapped".into(),
    };
    Err(format!(
        "running in a user namespace ({root}). Rootless Docker is not supported: Parallax \
         needs root over the host's own network. Run it on a rootful Docker daemon (with \
         userns-remap, set `userns_mode: host` for this service) or install it natively; \
         see {SETUP_DOC}"
    ))
}

fn check_net_admin(sys: System<'_>) -> Result<String, String> {
    let path = Path::new("/proc/self/status");
    let text = read(sys, path)?;
    let effective = text
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .ok_or_else(|| format!("no readable CapEff line in {}", path.display()))?;
    if effective & (1 << CAP_NET_ADMIN_BIT) != 0 {
        Ok("held".into())
    } else {
        Err(
            "missing; run as root, give the container `cap_add: [NET_ADMIN]`, \
             or grant the native service CAP_NET_ADMIN"
                .into(),
        )
    }
}

/// The gateway shares the host's network namespace, so it can't set this
/// itself: it's a host setting.
fn check_ip_forward(sys: System<'_>) -> Result<String, String> {
    let path = Path::new("/proc/sys/net/ipv4/ip_forward");
    match read(sys, path)?.trim() {
        "1" => Ok("on".into()),
        _ => Err(
            "net.ipv4.ip_forward is 0 on the host; set `net.ipv4.ip_forward = 1` \
                  in /etc/sysctl.d/ and run `sysctl --system`"
                .into(),
        ),
    }
}

/// Interfaces the configuration expects to exist. The WireGuard and Tailscale
/// interfaces are not here: Parallax creates them.
fn interfaces(config: &Config) -> Vec<&str> {
    let mut names: Vec<&str> = Vec::new();
    let configured = config
        .networks
        .iter()
        .map(|n| n.interface.as_str())
        .chain(config.server.wan_interface.as_deref());
    for name in configured {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

fn check_interface(name: &str, sys: System<'_>) -> Result<String, String> {
    match sys
        .runner
        .run("ip", &["-o", "link", "show", "dev", name], None)
    {
        Ok(out) if out.ok() => match primary_name(&out.stdout) {
            Some(primary) if primary == name => Ok("present".into()),
            // `ip` resolves alternative names, but nftables matches only the primary one.
            Some(primary) => Err(format!(
                "{name} is an alternative name of {primary}; the firewall matches primary \
                 names only, so use {primary} in the configuration"
            )),
            None => Err(format!("unexpected `ip link` output for {name}")),
        },
        _ => Err(format!(
            "not found in this network namespace. Check the name with `ip link`; under \
             rootless Docker the host's interfaces are never visible (see {SETUP_DOC})"
        )),
    }
}

/// The name in `ip -o link show` output: `2: eth0@if3: <...>` gives `eth0`.
fn primary_name(line: &str) -> Option<&str> {
    let name = line.split(": ").nth(1)?;
    Some(name.split('@').next().unwrap_or(name))
}

fn check_wireguard(sys: System<'_>) -> Result<String, String> {
    // Never delete first: an interface with this name that isn't ours must survive.
    let added = sys.runner.run(
        "ip",
        &["link", "add", PROBE_INTERFACE, "type", "wireguard"],
        None,
    );
    match added {
        Ok(out) if out.ok() => {
            let _ = sys
                .runner
                .run("ip", &["link", "del", PROBE_INTERFACE], None);
            Ok("can create interfaces".into())
        }
        Ok(out) if not_permitted(&out.stderr) => Err(NOT_PERMITTED.into()),
        Ok(out) if out.stderr.contains("File exists") => Err(format!(
            "an interface named {PROBE_INTERFACE} already exists, so the probe can't run; \
             if a previous check left it behind, remove it with `ip link del {PROBE_INTERFACE}`"
        )),
        Ok(out) => Err(format!(
            "cannot create a WireGuard interface ({}). Load the module on the host: \
             `modprobe wireguard`, and to load it at boot put `wireguard` in \
             /etc/modules-load.d/wireguard.conf",
            one_line(&out.stderr)
        )),
        Err(e) => Err(format!("cannot create a WireGuard interface: {e}")),
    }
}

fn check_netmap(sys: System<'_>) -> Result<String, String> {
    match sys
        .runner
        .run("nft", &["-c", "-f", "-"], Some(NETMAP_PROBE))
    {
        Ok(out) if out.ok() => Ok("prefix NAT supported".into()),
        Ok(out) if not_permitted(&out.stderr) => Err(NOT_PERMITTED.into()),
        Ok(out) => Err(format!(
            "the kernel or nft rejects NETMAP (prefix NAT); it needs a newer nftables, \
             or a kernel with nf_nat prefix mapping. nft said: {}",
            one_line(&out.stderr)
        )),
        Err(e) => Err(format!("cannot run nft: {e}")),
    }
}

/// Probes fail with EPERM when privileges are missing, which says nothing
/// about the kernel feature being probed; the user namespace and
/// CAP_NET_ADMIN checks name the cause.
const NOT_PERMITTED: &str =
    "not permitted to test: needs CAP_NET_ADMIN over the host's network (see the checks above)";

fn not_permitted(stderr: &str) -> bool {
    stderr.contains("Operation not permitted")
}

fn one_line(stderr: &str) -> String {
    stderr
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" / ")
}

fn read(sys: System<'_>, path: &Path) -> Result<String, String> {
    match sys.fs.read(path) {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Err(format!("{} does not exist", path.display())),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::memory::{MemoryFs, RecordingRunner};
    use crate::io::Output;
    use crate::testing::canonical_config;

    const CONFIG: &str = "/etc/parallax/parallax.toml";
    const ROOT_STATUS: &str = "Name:\tparallax\nCapEff:\t000001ffffffffff\n";

    fn healthy_fs() -> MemoryFs {
        MemoryFs::new()
            .with_file(CONFIG, canonical_config().to_toml().unwrap())
            .with_file("/proc/self/uid_map", "         0          0 4294967295\n")
            .with_file("/proc/self/status", ROOT_STATUS)
            .with_file("/proc/sys/net/ipv4/ip_forward", "1\n")
    }

    fn failed(status: i32, stderr: &str) -> Output {
        Output {
            status,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    /// Runs the checks. Answers queued by a test take precedence over the
    /// healthy `ip link show` answer queued here.
    fn run(fs: &MemoryFs, runner: &RecordingRunner) -> Vec<Check> {
        runner.respond_to(
            "ip",
            &["-o", "link", "show", "dev", "eth0"],
            Output {
                status: 0,
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n".into(),
                stderr: String::new(),
            },
        );
        diagnose(Path::new(CONFIG), System { fs, runner })
    }

    fn problems(checks: &[Check]) -> Vec<(&str, &str)> {
        checks
            .iter()
            .filter_map(|c| {
                c.result
                    .as_ref()
                    .err()
                    .map(|e| (c.name.as_str(), e.as_str()))
            })
            .collect()
    }

    #[test]
    fn healthy_host_passes_every_check() {
        let runner = RecordingRunner::new();
        let checks = run(&healthy_fs(), &runner);
        assert_eq!(problems(&checks), vec![]);
        let names: Vec<&str> = checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "configuration",
                "user namespace",
                "CAP_NET_ADMIN",
                "ip_forward",
                "tools",
                "interface eth0",
                "wireguard",
                "NETMAP"
            ]
        );
        let lines = runner.command_lines();
        assert!(lines.contains(&"ip link add parallax-probe type wireguard".to_string()));
        assert_eq!(lines.last().map(String::as_str), Some("nft -c -f -"));
    }

    #[test]
    fn rootless_docker_is_refused() {
        let fs = healthy_fs().with_file(
            "/proc/self/uid_map",
            "         0       1000          1\n         1     100000      65536\n",
        );
        let checks = run(&fs, &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "user namespace");
        assert!(p[0].1.contains("uid 0 here is uid 1000 on the host"));
        assert!(p[0].1.contains("Rootless Docker is not supported"));
    }

    #[test]
    fn a_partial_root_mapping_is_still_a_user_namespace() {
        let fs = healthy_fs().with_file("/proc/self/uid_map", "0 0 1\n");
        let checks = run(&fs, &RecordingRunner::new());
        assert_eq!(problems(&checks)[0].0, "user namespace");
    }

    #[test]
    fn missing_net_admin_and_forwarding_are_reported_together() {
        let fs = healthy_fs()
            .with_file("/proc/self/status", "CapEff:\t0000000000000000\n")
            .with_file("/proc/sys/net/ipv4/ip_forward", "0\n");
        let checks = run(&fs, &RecordingRunner::new());
        let names: Vec<&str> = problems(&checks).iter().map(|p| p.0).collect();
        assert_eq!(names, ["CAP_NET_ADMIN", "ip_forward"]);
    }

    #[test]
    fn missing_configuration_still_checks_the_host() {
        let fs = MemoryFs::new()
            .with_file("/proc/self/uid_map", "0 0 4294967295\n")
            .with_file("/proc/self/status", ROOT_STATUS)
            .with_file("/proc/sys/net/ipv4/ip_forward", "1\n");
        let checks = run(&fs, &RecordingRunner::new());
        assert_eq!(
            problems(&checks),
            vec![(
                "configuration",
                "no configuration at /etc/parallax/parallax.toml"
            )]
        );
        assert!(checks.iter().any(|c| c.name == "wireguard"));
    }

    #[test]
    fn invalid_configuration_lists_errors_and_still_checks_interfaces() {
        let mut cfg = canonical_config();
        cfg.templates.clear();
        cfg.peers.clear();
        cfg.networks[0].subnet = "10.8.0.0/24".parse().unwrap();
        let fs = healthy_fs().with_file(CONFIG, cfg.to_toml().unwrap());
        let checks = run(&fs, &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "configuration");
        assert!(p[0].1.contains("is invalid:\n  - "));
        assert!(checks.iter().any(|c| c.name == "interface eth0"));
    }

    #[test]
    fn missing_interface_is_named() {
        let runner = RecordingRunner::new();
        runner.respond_to(
            "ip",
            &["-o", "link", "show", "dev", "eth0"],
            failed(1, "Device \"eth0\" does not exist."),
        );
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "interface eth0");
        assert!(p[0].1.contains("rootless Docker"));
    }

    #[test]
    fn alternative_interface_name_is_refused() {
        let runner = RecordingRunner::new();
        runner.respond_to(
            "ip",
            &["-o", "link", "show", "dev", "eth0"],
            Output {
                status: 0,
                stdout: "2: eno1: <BROADCAST,MULTICAST,UP> mtu 1500\\    altname eth0\n".into(),
                stderr: String::new(),
            },
        );
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert!(p[0].1.contains("use eno1"), "{}", p[0].1);
    }

    #[test]
    fn probe_never_deletes_an_interface_it_did_not_create() {
        let runner = RecordingRunner::new();
        runner.respond_to(
            "ip",
            &["link", "add", PROBE_INTERFACE, "type", "wireguard"],
            failed(2, "RTNETLINK answers: File exists"),
        );
        let checks = run(&healthy_fs(), &runner);
        assert!(!runner
            .command_lines()
            .iter()
            .any(|l| l.starts_with("ip link del")));
        assert!(problems(&checks)[0].1.contains("already exists"));
    }

    #[test]
    fn wan_interface_is_checked_once_even_if_shared() {
        let mut cfg = canonical_config();
        cfg.server.wan_interface = Some("eth0".into());
        let fs = healthy_fs().with_file(CONFIG, cfg.to_toml().unwrap());
        let checks = run(&fs, &RecordingRunner::new());
        assert_eq!(
            checks
                .iter()
                .filter(|c| c.name.starts_with("interface"))
                .count(),
            1
        );
    }

    #[test]
    fn missing_wireguard_module_points_at_modules_load_d() {
        let runner = RecordingRunner::new();
        runner.respond_to(
            "ip",
            &["link", "add", PROBE_INTERFACE, "type", "wireguard"],
            failed(2, "Error: Unknown device type."),
        );
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "wireguard");
        assert!(p[0].1.contains("Unknown device type"));
        assert!(p[0].1.contains("/etc/modules-load.d/"));
    }

    #[test]
    fn netmap_rejection_quotes_nft() {
        let runner = RecordingRunner::new();
        runner.respond_to(
            "nft",
            &["-c", "-f", "-"],
            failed(1, "Error: syntax error, unexpected prefix"),
        );
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "NETMAP");
        assert!(p[0].1.contains("unexpected prefix"));
    }

    #[test]
    fn permission_errors_do_not_blame_the_kernel() {
        let runner = RecordingRunner::new();
        let eperm = || failed(2, "RTNETLINK answers: Operation not permitted");
        runner.respond_to(
            "ip",
            &["link", "add", PROBE_INTERFACE, "type", "wireguard"],
            eperm(),
        );
        runner.respond_to("nft", &["-c", "-f", "-"], eperm());
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(
            p.iter().map(|p| p.0).collect::<Vec<_>>(),
            ["wireguard", "NETMAP"]
        );
        assert!(p.iter().all(|p| p.1 == NOT_PERMITTED));
    }

    #[test]
    fn missing_tools_are_named() {
        let runner = RecordingRunner::new();
        runner.respond("dnsmasq", failed(127, "not found"));
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "tools");
        assert!(p[0].1.contains("dnsmasq"));
    }
}
