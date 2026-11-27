//! `doctor`: check that this host can run the gateway, before `apply` touches
//! anything. Docker's entrypoint and native installs run the same checks.
//!
//! Every check runs, so one pass reports every problem. Each failure says
//! what is wrong and how to fix it.

use std::path::Path;

use crate::io::System;
use crate::model::{BackupServer, Config, FirewallBackend, LogLevel};

/// The kernel's identity mapping: the initial user namespace maps every uid to itself.
const INIT_USERNS_UID_MAP: (u64, u64, u64) = (0, 0, 4_294_967_295);
/// Bits in `/proc/self/status` capability masks.
const CAP_NET_BIND_SERVICE_BIT: u32 = 10;
const CAP_NET_ADMIN_BIT: u32 = 12;
/// Where the kernel's default puts it when the sysctl can't be read.
const DEFAULT_UNPRIVILEGED_PORT_START: u32 = 1024;
const UNIT_DOC: &str = "packaging/systemd/parallax.service";
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

/// One check and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub outcome: Outcome,
}

/// Each carries what was found, or the problem and the fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Ok(String),
    /// Worth fixing, but the gateway runs.
    Warn(String),
    /// The gateway can't run until it's fixed.
    Fail(String),
}

impl Check {
    fn new(name: impl Into<String>, result: Result<String, String>) -> Self {
        Check {
            name: name.into(),
            outcome: match result {
                Ok(found) => Outcome::Ok(found),
                Err(problem) => Outcome::Fail(problem),
            },
        }
    }
}

/// Run every check against the configuration and the host. `config` is the
/// loaded configuration, or why it couldn't be loaded; the host checks run
/// either way.
pub fn diagnose(config: Result<&Config, String>, sys: System<'_>) -> Vec<Check> {
    let mut checks = vec![
        check_config(&config),
        Check::new("user namespace", check_user_namespace(sys)),
        Check::new("CAP_NET_ADMIN", check_net_admin(sys)),
        Check::new("ip_forward", check_ip_forward(sys)),
    ];

    let config = config.ok();
    if let Some(config) = config {
        if let Some(result) = check_net_bind_service(config, sys) {
            checks.push(Check::new("CAP_NET_BIND_SERVICE", result));
        }
    }
    let backend = config.map_or(FirewallBackend::Nftables, |c| c.server.firewall.backend);
    let missing = crate::apply::preflight(backend, sys);
    checks.push(Check::new(
        "tools",
        if missing.is_empty() {
            Ok("all present".into())
        } else {
            Err(missing.join("; "))
        },
    ));

    if let Some(config) = config {
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
    if let Some(config) = config {
        checks.push(Check {
            name: "backups".into(),
            outcome: check_backup(&config.server.backup, sys),
        });
        // Also before the first peer, when the global level asks for bytes.
        let bytes = config.server.logs.level >= LogLevel::Detailed
            || config
                .peers
                .iter()
                .any(|p| p.enabled && crate::logging::level(config, p) >= LogLevel::Detailed);
        if bytes {
            checks.push(Check {
                name: "byte counts".into(),
                outcome: check_conntrack_acct(sys),
            });
        }
    }
    checks
}

/// Logging at `detailed` needs the kernel to count each connection's bytes, a
/// host setting like `ip_forward`. Only a warning: connections are still
/// logged, just without their bytes.
fn check_conntrack_acct(sys: System<'_>) -> Outcome {
    let fix =
        "set `net.netfilter.nf_conntrack_acct = 1` in /etc/sysctl.d/ and run `sysctl --system`";
    match read(sys, Path::new("/proc/sys/net/netfilter/nf_conntrack_acct")) {
        Ok(v) if v.trim() == "1" => Outcome::Ok("on".into()),
        Ok(_) => Outcome::Warn(format!(
            "net.netfilter.nf_conntrack_acct is 0 on the host, so connections are logged without their bytes; {fix}"
        )),
        Err(_) => Outcome::Warn(format!(
            "connection tracking isn't loaded yet (it is once the firewall is applied), so this can't be checked; logging bytes needs it to count them: {fix}"
        )),
    }
}

/// Backups are optional, so problems with them only warn. Also the startup
/// log line saying where they go.
fn check_backup(backup: &BackupServer, sys: System<'_>) -> Outcome {
    let dir = &backup.directory;
    let mut problems = Vec::new();
    if !backup.automatic {
        problems.push(
            "automatic backups are off (server.backup.automatic = false); make one with `parallax backup create`"
                .to_string(),
        );
    }
    // Never create the directory here: RealFs would make it 0755, and the
    // first backup creates it 0700. A directory reads as an error, a
    // missing path as nothing.
    let missing = matches!(sys.fs.read(dir), Ok(None));
    if !missing {
        // Named for this process, so it can't be a file someone else made.
        let probe = dir.join(format!(".parallax-doctor-{}", std::process::id()));
        match sys.fs.write(&probe, "", true) {
            Ok(()) => {
                let _ = sys.fs.remove(&probe);
            }
            Err(e) => problems.push(format!(
                "can't write backups to {}: {e}; fix it or change server.backup.directory",
                dir.display()
            )),
        }
    }
    if backup.encrypt {
        let set =
            matches!(sys.fs.read(&backup.passphrase_file), Ok(Some(p)) if !p.trim().is_empty());
        if !set {
            problems.push(format!(
                "backups are encrypted but no passphrase is set ({} is missing); set one with `parallax backup passphrase`",
                backup.passphrase_file.display()
            ));
        }
    } else if let Some(fstype) = network_filesystem(dir, sys) {
        problems.push(format!(
            "backups are not encrypted, and {} is on a network filesystem ({fstype}); anyone who can read it gets every key. Set server.backup.encrypt = true",
            dir.display()
        ));
    }
    if !problems.is_empty() {
        return Outcome::Warn(problems.join("; "));
    }
    Outcome::Ok(format!(
        "every {} to {}{}, keeping {}, {}",
        backup.interval,
        dir.display(),
        if missing {
            " (made by the first backup)"
        } else {
            ""
        },
        backup.keep,
        if backup.encrypt {
            "encrypted"
        } else {
            "not encrypted"
        }
    ))
}

/// The filesystem type `path` is on, when it's one reached over the network.
fn network_filesystem(path: &Path, sys: System<'_>) -> Option<String> {
    const NETWORK: &[&str] = &[
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "ceph",
        "glusterfs",
        "afs",
        "9p",
        "fuse.sshfs",
        "fuse.rclone",
        "fuse.glusterfs",
        "davfs",
        "fuse.davfs2",
    ];
    let mounts = sys.fs.read(Path::new("/proc/self/mounts")).ok()??;
    // The longest mount point holding `path` is the one it's on.
    let (_, fstype) = mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let point = unescape_mount(fields.nth(1)?);
            let fstype = fields.next()?;
            path.starts_with(&point)
                .then(|| (point.len(), fstype.to_string()))
        })
        .max_by_key(|(len, _)| *len)?;
    NETWORK.contains(&fstype.as_str()).then_some(fstype)
}

/// `/proc/self/mounts` writes a space in a mount point as `\040`, and so on.
fn unescape_mount(field: &str) -> String {
    let mut out = String::new();
    let mut rest = field;
    while let Some(i) = rest.find('\\') {
        out.push_str(&rest[..i]);
        let code = rest
            .get(i + 1..i + 4)
            .and_then(|o| u8::from_str_radix(o, 8).ok());
        match code {
            Some(c) => {
                out.push(char::from(c));
                rest = &rest[i + 4..];
            }
            None => {
                out.push('\\');
                rest = &rest[i + 1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Validate. An invalid configuration still names the interfaces to check.
fn check_config(config: &Result<&Config, String>) -> Check {
    let name = "configuration";
    let config = match config {
        Ok(c) => c,
        Err(e) => return Check::new(name, Err(e.clone())),
    };
    let (errors, warnings) = crate::validate::check(config);
    let result = if errors.is_empty() {
        Ok(match warnings.len() {
            0 => "valid".to_string(),
            n => format!("valid, with {n} warning(s); `parallax validate` lists them"),
        })
    } else {
        Err(format!(
            "invalid:\n{}",
            errors
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n")
        ))
    };
    Check::new(name, result)
}

/// Parallax drives the host's network stack, which needs real root
/// privileges over the host network namespace. A process in a user namespace
/// (rootless Docker, userns-remap) only holds capabilities over namespaces it
/// owns, and rootless Docker's "host network" is a private namespace anyway.
fn check_user_namespace(sys: System<'_>) -> Result<String, String> {
    let path = Path::new("/proc/self/uid_map");
    let text = match sys.fs.read(path) {
        // The file only exists on kernels built with user namespaces.
        Ok(None) => return Ok("user namespaces not built into this kernel".into()),
        _ => read(sys, path)?,
    };
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
        Some((_, 0, count)) => format!("only {count} uid(s) mapped"),
        Some((_, outside, _)) => format!("uid 0 here is uid {outside} on the host"),
        None => "uid 0 is not mapped".into(),
    };
    Err(format!(
        "running in a user namespace ({root}). Rootless Docker is not supported: Parallax \
         needs CAP_NET_ADMIN over the host's own network. Run it on a rootful Docker daemon (with \
         userns-remap, set `userns_mode: host` for this service) or install it natively; \
         see {SETUP_DOC}"
    ))
}

/// What `/proc/self/status` says about this process's privileges.
struct Privileges {
    effective_uid: u32,
    effective: u64,
    ambient: u64,
}

fn privileges(sys: System<'_>) -> Result<Privileges, String> {
    let path = Path::new("/proc/self/status");
    let text = read(sys, path)?;
    let field = |name: &str| text.lines().find_map(|l| l.strip_prefix(name));
    let mask = |name: &str| {
        field(name)
            .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
            .ok_or_else(|| format!("no readable {name} line in {}", path.display()))
    };
    let effective_uid = field("Uid:")
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| format!("no readable Uid: line in {}", path.display()))?;
    Ok(Privileges {
        effective_uid,
        effective: mask("CapEff:")?,
        ambient: mask("CapAmb:").unwrap_or(0),
    })
}

fn check_net_admin(sys: System<'_>) -> Result<String, String> {
    let p = privileges(sys)?;
    if p.effective & (1 << CAP_NET_ADMIN_BIT) == 0 {
        return Err(
            "missing; run as root, give the container `cap_add: [NET_ADMIN]`, \
             or grant the native service CAP_NET_ADMIN"
                .into(),
        );
    }
    if p.effective_uid == 0 {
        return Ok("held".into());
    }
    // Not root: `nft`, `ip` and `wg` keep only ambient capabilities across exec.
    if p.ambient & (1 << CAP_NET_ADMIN_BIT) == 0 {
        return Err(format!(
            "held, but not ambient: running as uid {}, so `nft`, `ip` and `wg` start \
             without it. Set `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE` \
             (see {UNIT_DOC})",
            p.effective_uid
        ));
    }
    Ok(format!(
        "held, and ambient for `nft`, `ip` and `wg` (uid {})",
        p.effective_uid
    ))
}

/// Only when a port the gateway listens on is below the unprivileged range.
/// The daemon binds the DNS server and the HTTPS proxy itself; the kernel
/// binds WireGuard's UDP port for `wg`, a subprocess, so for a non-root
/// service that one needs the capability ambient too.
fn check_net_bind_service(config: &Config, sys: System<'_>) -> Option<Result<String, String>> {
    // u32: the sysctl goes up to 65536 (no unprivileged port at all).
    let start = read(
        sys,
        Path::new("/proc/sys/net/ipv4/ip_unprivileged_port_start"),
    )
    .ok()
    .and_then(|s| s.trim().parse::<u32>().ok())
    .unwrap_or(DEFAULT_UNPRIVILEGED_PORT_START);
    let server = &config.server;
    let low: Vec<(String, bool)> = [
        ("DNS", server.dns.port, false),
        ("proxy", server.proxy.port, false),
        ("WireGuard", server.wireguard.listen_port, true),
    ]
    .into_iter()
    .filter(|(_, port, _)| u32::from(*port) < start)
    .map(|(what, port, by_wg)| (format!("{what} port {port}"), by_wg))
    .collect();
    if low.is_empty() {
        return None;
    }
    let p = match privileges(sys) {
        Ok(p) => p,
        Err(e) => return Some(Err(e)),
    };
    let bit = 1 << CAP_NET_BIND_SERVICE_BIT;
    let names = |filter: &dyn Fn(bool) -> bool| {
        low.iter()
            .filter(|(_, by_wg)| filter(*by_wg))
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let all = names(&|_| true);
    if p.effective & bit == 0 {
        return Some(Err(format!(
            "missing, and needed below net.ipv4.ip_unprivileged_port_start ({start}): \
             {all}. Run as root, or give the native service CAP_NET_BIND_SERVICE (see {UNIT_DOC})"
        )));
    }
    let by_wg = names(&|by_wg| by_wg);
    if p.effective_uid != 0 && !by_wg.is_empty() && p.ambient & bit == 0 {
        return Some(Err(format!(
            "held, but not ambient: running as uid {}, so `wg` can't bind {by_wg} \
             (below {start}). Set `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE` \
             (see {UNIT_DOC})",
            p.effective_uid
        )));
    }
    Some(Ok(format!("held, for {all}")))
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
        Err(e) => Err(format!("cannot check: {e}")),
        Ok(_) => Err(format!(
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

/// Whether the guest hairpin drop has the home's public IP to drop:
/// `known` is the address as last found. Never a failure, since the gateway
/// runs without it.
pub fn public_ip_check(config: &Config, known: Option<std::net::Ipv4Addr>) -> Check {
    let outcome = match (crate::public_ip::hairpin(config), known) {
        (false, _) if !crate::public_ip::needed(config) => {
            Outcome::Ok("not needed: no guest tier has internet, and no host is named by DNS name".into())
        }
        (false, Some(ip)) => Outcome::Ok(format!("{ip}; hosts named by DNS name may point at it (port forwards)")),
        (false, None) => Outcome::Ok(
            "not known yet; a host named by DNS name that points at it gives nothing until it is".into(),
        ),
        (true, Some(ip)) => Outcome::Ok(format!(
            "{ip}; guests with internet can't reach it"
        )),
        (true, None) => Outcome::Warn(
            "not known yet: guests with internet can reach the home through the router (hairpin). The daemon looks it up at startup and every 5 minutes; if that fails, set server.public_ip.address or server.public_ip.encrypted_dns".into(),
        ),
    };
    Check {
        name: "public IP".into(),
        outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::memory::{MemoryFs, RecordingRunner};
    use crate::io::Output;
    use crate::model::Rule;
    use crate::testing::canonical_config;

    const ROOT_STATUS: &str =
        "Name:\tparallax\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\nCapAmb:\t0000000000000000\n";
    /// The native service: uid 999 with exactly its two capabilities, both ambient.
    const SERVICE_STATUS: &str =
        "Name:\tparallax\nUid:\t999\t999\t999\t999\nCapEff:\t0000000000001400\nCapAmb:\t0000000000001400\n";

    fn healthy_fs() -> MemoryFs {
        MemoryFs::new()
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
        run_with(Ok(&canonical_config()), fs, runner)
    }

    fn run_with(
        config: Result<&Config, String>,
        fs: &MemoryFs,
        runner: &RecordingRunner,
    ) -> Vec<Check> {
        runner.respond_to(
            "ip",
            &["-o", "link", "show", "dev", "eth0"],
            Output {
                status: 0,
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n".into(),
                stderr: String::new(),
            },
        );
        diagnose(config, System { fs, runner })
    }

    fn problems(checks: &[Check]) -> Vec<(&str, &str)> {
        checks
            .iter()
            .filter_map(|c| match &c.outcome {
                Outcome::Fail(e) => Some((c.name.as_str(), e.as_str())),
                _ => None,
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
                "CAP_NET_BIND_SERVICE",
                "tools",
                "interface eth0",
                "wireguard",
                "NETMAP",
                "backups"
            ]
        );
        let lines = runner.command_lines();
        assert!(lines.contains(&"ip link add parallax-probe type wireguard".to_string()));
        assert_eq!(lines.last().map(String::as_str), Some("nft -c -f -"));
    }

    fn backup_outcome(config: &Config, fs: &MemoryFs) -> Outcome {
        let checks = run_with(Ok(config), fs, &RecordingRunner::new());
        let check = checks.iter().find(|c| c.name == "backups").unwrap();
        check.outcome.clone()
    }

    #[test]
    fn backups_report_where_they_go() {
        let fs = healthy_fs().with_file("/etc/parallax/backup.passphrase", "secret\n");
        assert_eq!(
            backup_outcome(&canonical_config(), &fs),
            Outcome::Ok("every 1d to /var/lib/parallax/backups (made by the first backup), keeping 14, encrypted"
                    .into())
        );
        // The probe file is gone again.
        assert_eq!(
            fs.paths()
                .iter()
                .filter(|p| p.to_string_lossy().contains(".parallax-doctor"))
                .count(),
            0
        );
    }

    #[test]
    fn byte_counts_are_checked_only_when_something_logs_detailed() {
        let names = |config: &Config, fs: &MemoryFs| -> Vec<(String, Outcome)> {
            run_with(Ok(config), fs, &RecordingRunner::new())
                .into_iter()
                .filter(|c| c.name == "byte counts")
                .map(|c| (c.name, c.outcome))
                .collect()
        };
        let mut config = canonical_config();
        assert!(names(&config, &healthy_fs()).is_empty());
        config.peers[0].log = Some(LogLevel::Detailed);
        let [(_, Outcome::Warn(w))] = &names(&config, &healthy_fs())[..] else {
            panic!("expected one warning");
        };
        assert!(w.contains("nf_conntrack_acct = 1"), "{w}");
        let on = healthy_fs().with_file("/proc/sys/net/netfilter/nf_conntrack_acct", "1\n");
        assert_eq!(
            names(&config, &on),
            [("byte counts".to_string(), Outcome::Ok("on".into()))]
        );
    }

    #[test]
    fn backup_problems_warn_without_failing() {
        let mut config = canonical_config();
        config.server.backup.automatic = false;
        let Outcome::Warn(w) = backup_outcome(&config, &healthy_fs()) else {
            panic!("expected a warning");
        };
        assert!(w.contains("automatic backups are off"), "{w}");
        assert!(w.contains("no passphrase is set"), "{w}");
        assert!(w.contains("`parallax backup passphrase`"), "{w}");
    }

    #[test]
    fn unencrypted_backups_on_a_network_mount_warn() {
        let mut config = canonical_config();
        config.server.backup.encrypt = false;
        config.server.backup.directory = "/mnt/nas share/parallax".into();
        let mounts = "/dev/sda1 / ext4 rw 0 0\n\
                      //nas/share /mnt/nas\\040share cifs rw 0 0\n\
                      /dev/sdb1 /mnt/nas\\040share/local ext4 rw 0 0\n";
        let fs = healthy_fs().with_file("/proc/self/mounts", mounts);
        let Outcome::Warn(w) = backup_outcome(&config, &fs) else {
            panic!("expected a warning");
        };
        assert!(w.contains("on a network filesystem (cifs)"), "{w}");

        config.server.backup.directory = "/mnt/nas share/local/parallax".into();
        assert!(matches!(backup_outcome(&config, &fs), Outcome::Ok(_)));
        config.server.backup.directory = "/var/backups".into();
        assert_eq!(
            backup_outcome(&config, &fs),
            Outcome::Ok(
                "every 1d to /var/backups (made by the first backup), keeping 14, not encrypted"
                    .into()
            )
        );
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
        let p = problems(&checks);
        assert_eq!(p[0].0, "user namespace");
        assert!(p[0].1.contains("only 1 uid(s) mapped"), "{}", p[0].1);
    }

    #[test]
    fn missing_net_admin_and_forwarding_are_reported_together() {
        let fs = healthy_fs()
            .with_file(
                "/proc/self/status",
                "Uid:\t0\t0\t0\t0\nCapEff:\t0000000000000000\n",
            )
            .with_file("/proc/sys/net/ipv4/ip_forward", "0\n");
        let checks = run(&fs, &RecordingRunner::new());
        let names: Vec<&str> = problems(&checks).iter().map(|p| p.0).collect();
        // No capabilities at all: the DNS port can't be bound either.
        assert_eq!(
            names,
            ["CAP_NET_ADMIN", "ip_forward", "CAP_NET_BIND_SERVICE"]
        );
    }

    #[test]
    fn the_native_service_with_its_two_ambient_capabilities_passes() {
        let fs = healthy_fs().with_file("/proc/self/status", SERVICE_STATUS);
        let checks = run(&fs, &RecordingRunner::new());
        assert_eq!(problems(&checks), vec![]);
        let found = |name: &str| {
            checks
                .iter()
                .find(|c| c.name == name)
                .map(|c| c.outcome.clone())
        };
        assert_eq!(
            found("CAP_NET_ADMIN"),
            Some(Outcome::Ok(
                "held, and ambient for `nft`, `ip` and `wg` (uid 999)".into()
            ))
        );
        assert_eq!(
            found("CAP_NET_BIND_SERVICE"),
            Some(Outcome::Ok("held, for DNS port 53".into()))
        );
    }

    #[test]
    fn a_non_root_service_needs_net_admin_ambient() {
        // Effective but not ambient: what `CapabilityBoundingSet=` alone, or
        // file capabilities on the binary, would give.
        let status =
            SERVICE_STATUS.replace("CapAmb:\t0000000000001400", "CapAmb:\t0000000000000000");
        let fs = healthy_fs().with_file("/proc/self/status", &status);
        let checks = run(&fs, &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!(p[0].0, "CAP_NET_ADMIN");
        assert!(
            p[0].1.contains("not ambient: running as uid 999"),
            "{}",
            p[0].1
        );
        assert!(p[0].1.contains("AmbientCapabilities="), "{}", p[0].1);
    }

    #[test]
    fn a_low_dns_port_needs_net_bind_service() {
        // CAP_NET_ADMIN only (bit 12).
        let status = SERVICE_STATUS.replace("0000000000001400", "0000000000001000");
        let fs = healthy_fs().with_file("/proc/self/status", &status);
        let checks = run(&fs, &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!(p[0].0, "CAP_NET_BIND_SERVICE");
        assert!(
            p[0].1.starts_with(
                "missing, and needed below net.ipv4.ip_unprivileged_port_start (1024): DNS port 53."
            ),
            "{}",
            p[0].1
        );

        // Unprivileged from port 0 on: nothing to check.
        let fs = fs.with_file("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0\n");
        let checks = run(&fs, &RecordingRunner::new());
        assert_eq!(problems(&checks), vec![]);
        assert!(!checks.iter().any(|c| c.name == "CAP_NET_BIND_SERVICE"));
    }

    #[test]
    fn a_low_wireguard_port_needs_net_bind_service_ambient() {
        let mut config = canonical_config();
        config.server.wireguard.listen_port = 443;
        // Effective, not ambient: the daemon could bind, `wg` couldn't.
        let status =
            SERVICE_STATUS.replace("CapAmb:\t0000000000001400", "CapAmb:\t0000000000001000");
        let fs = healthy_fs().with_file("/proc/self/status", &status);
        let checks = run_with(Ok(&config), &fs, &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!(p[0].0, "CAP_NET_BIND_SERVICE");
        assert!(
            p[0].1
                .contains("`wg` can't bind WireGuard port 443 (below 1024)"),
            "{}",
            p[0].1
        );
    }

    #[test]
    fn no_unprivileged_ports_at_all_is_understood() {
        // 65536 doesn't fit a port: every port, the proxy's 8443 too, needs the capability.
        let status = SERVICE_STATUS.replace("0000000000001400", "0000000000001000");
        let fs = healthy_fs()
            .with_file("/proc/self/status", &status)
            .with_file("/proc/sys/net/ipv4/ip_unprivileged_port_start", "65536\n");
        let checks = run(&fs, &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1, "{p:?}");
        assert!(
            p[0].1.starts_with(
                "missing, and needed below net.ipv4.ip_unprivileged_port_start (65536): DNS port 53, proxy port 8443, WireGuard port 51820."
            ),
            "{}",
            p[0].1
        );
    }

    #[test]
    fn missing_configuration_still_checks_the_host() {
        let fs = MemoryFs::new()
            .with_file("/proc/self/uid_map", "0 0 4294967295\n")
            .with_file("/proc/self/status", ROOT_STATUS)
            .with_file("/proc/sys/net/ipv4/ip_forward", "1\n");
        let checks = run_with(
            Err("no database at /var/lib/parallax/parallax.db".into()),
            &fs,
            &RecordingRunner::new(),
        );
        assert_eq!(
            problems(&checks),
            vec![(
                "configuration",
                "no database at /var/lib/parallax/parallax.db"
            )]
        );
        assert!(checks.iter().any(|c| c.name == "wireguard"));
    }

    #[test]
    fn invalid_configuration_lists_errors_and_still_checks_interfaces() {
        let mut cfg = canonical_config();
        cfg.grants.clear();
        cfg.peers.clear();
        cfg.networks[0].subnet = "10.8.0.0/24".parse().unwrap();
        let checks = run_with(Ok(&cfg), &healthy_fs(), &RecordingRunner::new());
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "configuration");
        assert!(p[0].1.starts_with("invalid:\n  - "));
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
        let checks = run_with(Ok(&cfg), &healthy_fs(), &RecordingRunner::new());
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
    fn kernel_without_user_namespaces_passes() {
        let fs = MemoryFs::new()
            .with_file("/proc/self/status", ROOT_STATUS)
            .with_file("/proc/sys/net/ipv4/ip_forward", "1\n");
        assert_eq!(problems(&run(&fs, &RecordingRunner::new())), vec![]);
    }

    #[test]
    fn iptables_backend_needs_ipset_and_skips_the_nft_probe() {
        let mut cfg = canonical_config();
        cfg.server.firewall.backend = FirewallBackend::IptablesNft;
        let runner = RecordingRunner::new();
        runner.respond("ipset", failed(127, "not found"));
        let checks = run_with(Ok(&cfg), &healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert!(p[0].1.contains("`ipset` is not available"), "{}", p[0].1);
        assert!(!checks.iter().any(|c| c.name == "NETMAP"));
    }

    #[test]
    fn missing_tools_are_named() {
        let runner = RecordingRunner::new();
        runner.respond("wg", failed(127, "not found"));
        let checks = run(&healthy_fs(), &runner);
        let p = problems(&checks);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].0, "tools");
        assert!(p[0].1.contains("wireguard-tools"), "{}", p[0].1);
    }

    #[test]
    fn public_ip_is_a_warning_only_when_guests_need_it() {
        let mut config = canonical_config();
        assert!(matches!(
            public_ip_check(&config, None).outcome,
            Outcome::Ok(_)
        ));
        config.grants[1].rules.push(Rule::Internet);
        let Outcome::Warn(w) = public_ip_check(&config, None).outcome else {
            panic!("expected a warning");
        };
        assert!(w.contains("server.public_ip.address"), "{w}");
        let known = public_ip_check(&config, Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            known.outcome,
            Outcome::Ok("1.2.3.4; guests with internet can't reach it".into())
        );
    }
}
