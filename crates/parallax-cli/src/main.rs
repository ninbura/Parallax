//! `parallax`: the command-line harness over `parallax-core`.
//!
//! The database (`parallax-store`) is the source of truth. TOML is only a
//! way in and out: `config import`, `config export` and `config edit`.
//!
//! `parallax daemon` holds the database and keeps the gateway applied. While
//! it answers on its socket, every command goes through it; otherwise
//! commands open the database themselves.

use std::io::{BufRead, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use clap::{Args, Parser, Subcommand};
use parallax_core::date::Date;
use parallax_core::doctor::Outcome;
use parallax_core::generate::{self, Export};
use parallax_core::grants;
use parallax_core::io::real::{RealFs, RealRunner};
use parallax_core::io::{FileSystem, KeyGenerator, OsKeyGenerator, System};
use parallax_core::logging;
use parallax_core::model::{
    AllowedIpsStrategy, DnsMode, LogLevel, Peer, Platform, Rule, ServerConfig, TransportKind,
};
use parallax_core::names::{self, Resolved};
use parallax_core::public_ip;
use parallax_core::secret::PrivateKey;
use parallax_core::transport::{self, ProvisionOptions};
use parallax_core::validate::ReachKind;
use parallax_core::{Config, Model};
use parallax_store::{Store, TempDir};

use crate::protocol::{Reply, Request};

// Declared before the print macros below, so they aren't in scope there: the
// daemon must outlive whoever reads its log.
mod daemon;

// `print!`, `println!`, `eprint!` and `eprintln!` for the commands, which panic
// when the reader has gone (`parallax peer show | head -1`, a pager that quits).
// stdout carries what a command produces: a lost write there is an error
// (`StdoutClosed`), so the command stops at that line and its cleanup runs
// (temp dirs hold private copies), and `main` exits with SIGPIPE's status.
// stderr only carries messages about the work: losing one never stops it, so
// `peer add` still prints its one-time config.
macro_rules! out {
    ($($arg:tt)*) => { $crate::emit(format_args!($($arg)*)) };
}
macro_rules! outln {
    () => { out!("\n") };
    ($($arg:tt)*) => { out!("{}\n", format_args!($($arg)*)) };
}
macro_rules! eout {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let mut err = std::io::stderr().lock();
        let _ = err.write_fmt(format_args!($($arg)*)).and_then(|()| err.flush());
    }};
}
macro_rules! eoutln {
    () => { eout!("\n") };
    ($($arg:tt)*) => { eout!("{}\n", format_args!($($arg)*)) };
}

/// stdout's reader went away before the command finished writing.
#[derive(Debug)]
struct StdoutClosed;

impl std::fmt::Display for StdoutClosed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stdout was closed")
    }
}

impl std::error::Error for StdoutClosed {}

/// What `out!` and `outln!` call.
fn emit(args: std::fmt::Arguments) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_fmt(args).and_then(|()| out.flush()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Err(StdoutClosed.into()),
        Err(e) => Err(anyhow::Error::new(e).context("writing to stdout")),
    }
}

mod backup;
mod owner;
mod protocol;

#[derive(Parser)]
#[command(
    name = "parallax",
    version,
    about = "WireGuard + Headscale gateway with subnet remapping, DNS rewriting and grant-based access policies"
)]
struct Cli {
    /// The database: the source of truth for the configuration.
    #[arg(
        long,
        global = true,
        default_value = "/var/lib/parallax/parallax.db",
        env = "PARALLAX_DB"
    )]
    db: PathBuf,
    /// The daemon's socket. Commands go through the daemon while it answers here.
    #[arg(
        long,
        global = true,
        default_value = "/run/parallax/parallax.sock",
        env = "PARALLAX_SOCKET"
    )]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the configuration and report every problem.
    Validate,
    /// Check this host can run the gateway: privileges, kernel features, tools, interfaces.
    Doctor,
    /// Generate everything and show what would change under the output directory.
    Plan(OutArgs),
    /// Generate everything into the output directory without touching the system.
    Generate(OutArgs),
    /// Generate, write, and reconcile the live gateway (firewall, WireGuard).
    /// With a daemon running, it applies.
    Apply(OutArgs),
    /// Run the gateway: hold the database, apply, serve DNS and the HTTPS
    /// proxy, apply every saved change, and repair drift. SIGHUP re-applies.
    Daemon {
        #[command(flatten)]
        out: OutArgs,
        /// Seconds between checks for drift and a new day.
        #[arg(long, default_value_t = 60, hide = true)]
        reconcile_every: u64,
    },
    /// Show whether a daemon is running and how its last apply went.
    Status,
    /// Create the gateway's WireGuard private key file and print its public key.
    Keygen {
        /// Also record the public key in the configuration.
        #[arg(long)]
        write_config: bool,
        /// Do nothing if the key file already exists.
        #[arg(long)]
        if_missing: bool,
    },
    /// Move the configuration in and out of the database as TOML.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Back up and restore everything Parallax keeps: the database and the server key.
    Backup {
        #[command(subcommand)]
        command: backup::BackupCommand,
    },
    /// Manage grants: named bundles of rules that peers are given.
    Grant {
        #[command(subcommand)]
        command: GrantCommand,
    },
    /// Manage peers.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    /// Per-peer activity logging (docs/logging.md).
    Log {
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Render a peer's client config for a platform.
    Export {
        peer: String,
        #[arg(long, default_value = "linux")]
        platform: Platform,
    },
}

#[derive(Args)]
struct OutArgs {
    /// Output directory for generated artifacts.
    #[arg(short, long, default_value = "/var/lib/parallax", env = "PARALLAX_OUT")]
    out: PathBuf,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Replace the configuration with a TOML file. Peers without an address get one.
    Import {
        file: PathBuf,
        /// Only import into a database that holds no configuration yet (the
        /// container's first start). Prints `imported ...` when it did.
        #[arg(long)]
        if_empty: bool,
    },
    /// Print the configuration as TOML. It holds any stored private keys.
    Export {
        /// Write to this file (mode 0600) instead of standard output.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Edit the configuration as TOML in $VISUAL or $EDITOR, then review and save it.
    Edit {
        #[command(flatten)]
        out: OutArgs,
        /// Save without asking.
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Add a peer: allocates an address, generates keys, prints the one-time client config.
    Add {
        name: String,
        /// A grant it gets (repeat, or separate with commas). Without any,
        /// it reaches only what grants for everyone give.
        #[arg(short, long = "grant", value_delimiter = ',')]
        grants: Vec<String>,
        /// DNS of its config: split, tunnel_wide or none (default:
        /// server.wireguard.peer_defaults).
        #[arg(long)]
        dns: Option<DnsMode>,
        /// What its config routes: mapped_subnets, grants_only or full_tunnel
        /// (default: server.wireguard.peer_defaults).
        #[arg(long)]
        allowed_ips: Option<AllowedIpsStrategy>,
        #[arg(long, default_value = "wireguard")]
        transport: TransportKind,
        /// Keep the private key in the configuration so configs can be regenerated.
        #[arg(long)]
        keep_private_key: bool,
        /// Also issue a preshared key.
        #[arg(long)]
        preshared_key: bool,
        /// Last valid day, YYYY-MM-DD.
        #[arg(long)]
        expires: Option<Date>,
        /// Platform flavour of the printed config.
        #[arg(long, default_value = "linux")]
        platform: Platform,
    },
    /// Remove a peer from the configuration.
    Remove { name: String },
    /// Show peers, their addresses and what they can reach.
    Show { name: Option<String> },
    /// Change which grants a peer has. Its address stays, and so does its
    /// client config unless it uses allowed_ips = grants_only.
    Grants {
        peer: String,
        #[command(subcommand)]
        change: PeerGrants,
    },
}

#[derive(Subcommand)]
enum PeerGrants {
    /// Give it exactly these grants (none: it keeps only grants for everyone).
    Set {
        #[arg(value_delimiter = ',')]
        grants: Vec<String>,
    },
    /// Attach grants to it.
    Add {
        #[arg(required = true, value_delimiter = ',')]
        grants: Vec<String>,
    },
    /// Detach grants from it. It must have each one attached.
    Remove {
        #[arg(required = true, value_delimiter = ',')]
        grants: Vec<String>,
    },
}

/// A rule on the command line: `all_networks`, `internet`, `public_dns`,
/// `network:<name>`, `service:<name>`, `host:<address or name>[:<ports>]`
/// with ufw-style ports (`host:nas.mydomain.com:139/tcp,445/tcp`).
const RULE_HELP: &str = "Rules: all_networks, internet, public_dns, network:<name>, service:<name>, host:<address or name>[:<ports>] (ports like ufw: 445/tcp,137-138/udp,25565)";

#[derive(Subcommand)]
enum GrantCommand {
    /// Create a grant with these rules. It applies to no one until attached.
    #[command(after_help = RULE_HELP)]
    Create {
        name: String,
        rules: Vec<Rule>,
        /// Apply it to every peer, current and future.
        #[arg(long)]
        everyone: bool,
    },
    /// Remove a grant and take it from everyone who has it.
    Remove {
        name: String,
        /// Remove it even though peers have it.
        #[arg(long)]
        force: bool,
    },
    /// Rename a grant; peers keep it under the new name.
    Rename { from: String, to: String },
    /// Show grants, their rules and who has them.
    Show { name: Option<String> },
    /// Change a grant's rules.
    Rule {
        #[command(subcommand)]
        change: GrantRule,
    },
    /// Attach a grant to peers.
    Attach {
        grant: String,
        /// The peers (repeat, or separate with commas).
        #[arg(long, required = true, value_delimiter = ',')]
        to: Vec<String>,
    },
    /// Detach a grant from peers. Each must have it attached.
    Detach {
        grant: String,
        /// The peers (repeat, or separate with commas).
        #[arg(long, required = true, value_delimiter = ',')]
        from: Vec<String>,
    },
    /// Whether a grant applies to every peer, current and future.
    Everyone { grant: String, switch: Switch },
}

#[derive(Subcommand)]
enum GrantRule {
    /// Add rules to a grant.
    #[command(after_help = RULE_HELP)]
    Add {
        grant: String,
        #[arg(required = true)]
        rules: Vec<Rule>,
    },
    /// Remove rules from a grant, written as `grant show` lists them.
    #[command(after_help = RULE_HELP)]
    Remove {
        grant: String,
        #[arg(required = true)]
        rules: Vec<Rule>,
    },
}

#[derive(Subcommand)]
enum LogCommand {
    /// Set how much is logged: for everyone (`server.logs.level`), for a
    /// grant's peers, or for one peer. A peer's own level wins, then the most
    /// detailed of its grants', then the global one.
    Level {
        level: LevelArg,
        /// Set this peer's own level (`inherit`: follow its grants again).
        #[arg(long, conflicts_with = "grant")]
        peer: Option<String>,
        /// Set this grant's level for the peers that have it (`inherit`: none).
        #[arg(long)]
        grant: Option<String>,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum LevelArg {
    Off,
    /// Attempts the firewall stopped.
    Blocked,
    /// Also every connection.
    Connections,
    /// Also the bytes of each connection.
    Detailed,
    /// Clear a peer's or grant's own level.
    Inherit,
}

impl LevelArg {
    fn level(self) -> Option<LogLevel> {
        match self {
            LevelArg::Off => Some(LogLevel::Off),
            LevelArg::Blocked => Some(LogLevel::Blocked),
            LevelArg::Connections => Some(LogLevel::Connections),
            LevelArg::Detailed => Some(LogLevel::Detailed),
            LevelArg::Inherit => None,
        }
    }
}

fn log_command(ctx: &Ctx, command: LogCommand) -> anyhow::Result<()> {
    let LogCommand::Level { level, peer, grant } = command;
    let target = match (peer, grant) {
        (Some(p), _) => logging::Target::Peer(p),
        (None, Some(g)) => logging::Target::Grant(g),
        (None, None) => logging::Target::Global,
    };
    let level = level.level();
    grant_change(
        ctx,
        |c| {
            let changed = logging::set_level(c, &target, level)?;
            // What a peer that went back to inheriting ends up with.
            let effective = match (&target, level) {
                (logging::Target::Peer(p), None) => c.peer(p).map(|peer| logging::level(c, peer)),
                _ => None,
            };
            Ok((changed, effective))
        },
        |(changed, effective)| {
            let what = match (&target, level) {
                (logging::Target::Global, Some(l)) => format!("everyone logs {l} by default"),
                (logging::Target::Peer(p), Some(l)) => format!("peer '{p}' logs {l}"),
                (logging::Target::Peer(p), None) => {
                    format!("peer '{p}' follows its grants and the global level")
                }
                (logging::Target::Grant(g), Some(l)) => {
                    format!("grant '{g}' logs {l} for its peers")
                }
                (logging::Target::Grant(g), None) => format!("grant '{g}' sets no level"),
                (logging::Target::Global, None) => String::new(),
            };
            if *changed {
                outln!("{what} now")?;
            } else {
                outln!("{what} already")?;
            }
            if let Some(l) = effective {
                outln!("in effect: {l}")?;
            }
            Ok(())
        },
    )
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Switch {
    On,
    Off,
}

fn main() {
    // Owner-only by default: the database and the files Turso creates next to
    // it (its log, its coordination file) hold private keys. Files Parallax
    // writes itself get explicit modes (`RealFs`).
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
    if let Err(e) = run() {
        if e.downcast_ref::<StdoutClosed>().is_some() {
            // 128 + SIGPIPE: what a shell reports for a tool the signal ended.
            std::process::exit(141);
        }
        eoutln!("error: {e:#}");
        std::process::exit(1);
    }
}

pub(crate) fn today() -> Date {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Date::from_unix_days(secs.div_euclid(86_400))
}

/// The store is async; the CLI does one thing at a time.
pub(crate) fn block_on<T>(
    f: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .context("starting the async runtime")?
        .block_on(f)
}

/// How often a change through the daemon is retried when another saved first.
const SAVE_ATTEMPTS: usize = 10;

/// Where the configuration lives: the daemon, when one answers on the
/// socket, otherwise the database itself.
pub(crate) struct Ctx {
    db: PathBuf,
    socket: PathBuf,
}

/// How a change was saved.
pub(crate) enum Saved {
    /// Into the database directly; `parallax apply` puts it into effect.
    Direct,
    /// Through the daemon, which applied it: the apply log, or why it failed.
    Applied {
        log: Vec<String>,
        error: Option<String>,
    },
}

impl Ctx {
    pub(crate) fn db(&self) -> &Path {
        &self.db
    }

    /// Ask the daemon. `None`: no daemon (no socket, or nothing listening on
    /// it). A refusal comes back as an error.
    pub(crate) fn ask(&self, request: &Request) -> anyhow::Result<Option<Reply>> {
        use std::io::ErrorKind;
        let mut stream = match std::os::unix::net::UnixStream::connect(&self.socket) {
            Ok(stream) => stream,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                return Ok(None)
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("connecting to the daemon at {}", self.socket.display())
                })
            }
        };
        stream
            .write_all(&protocol::encode_request(request, &self.db)?)
            .with_context(|| format!("writing to the daemon at {}", self.socket.display()))?;
        let line = protocol::read_line(&mut std::io::BufReader::new(&stream))
            .with_context(|| format!("the daemon at {}", self.socket.display()))?;
        match protocol::decode(&line)
            .with_context(|| format!("the daemon at {}", self.socket.display()))?
        {
            Reply::Error { message } => Err(anyhow!(message)),
            reply => Ok(Some(reply)),
        }
    }

    /// Open the database, which must exist.
    pub(crate) async fn open_store(&self) -> anyhow::Result<Store> {
        self.not_root_on_the_services_database()?;
        Store::open(&self.db).await.map_err(|e| self.locked(e))
    }

    /// Open the database, creating an empty one if there is none.
    pub(crate) async fn create_store(&self) -> anyhow::Result<Store> {
        self.not_root_on_the_services_database()?;
        Store::create(&self.db).await.map_err(|e| self.locked(e))
    }

    /// On a native install the database belongs to the service's user.
    fn not_root_on_the_services_database(&self) -> anyhow::Result<()> {
        if let Some((who, sudo_u)) = owner::database_belongs_to_another_user(&self.db) {
            bail!(
                "{} belongs to {who}, and no daemon answers on {}. Opening the database as \
                 root would leave files that user can't open. Start the service (`sudo \
                 systemctl start parallax`) so this goes through its socket, or run it as that \
                 user (`sudo -u {sudo_u} parallax ...`)",
                self.db.display(),
                self.socket.display(),
            );
        }
        Ok(())
    }

    /// Another process holds the database, yet no daemon answered.
    fn locked(&self, e: parallax_store::Error) -> anyhow::Error {
        match e {
            parallax_store::Error::InUse(_) => anyhow!(
                "the database {} is locked by another process; is a daemon running whose socket at {} isn't answering?",
                self.db.display(),
                self.socket.display()
            ),
            e => e.into(),
        }
    }

    /// The configuration, its revision when it came from the daemon, and
    /// what the gateway learned (the home's public IP, named hosts). The
    /// database is closed again before this returns.
    fn load_full(&self) -> anyhow::Result<(Config, Option<u64>, Learned)> {
        match self.ask(&Request::Load)? {
            Some(Reply::Configuration {
                configuration,
                revision,
                public_ip,
                names,
            }) => Ok((*configuration, Some(revision), Learned { public_ip, names })),
            Some(other) => Err(unexpected(other)),
            None => {
                let (config, public_ip) = block_on(async {
                    let mut store = self.open_store().await?;
                    Ok((store.load().await?, store.public_ip().await?))
                })?;
                let learned = Learned {
                    public_ip,
                    names: Resolved::new(),
                };
                Ok((config, None, learned))
            }
        }
    }

    fn load_revision(&self) -> anyhow::Result<(Config, Option<u64>)> {
        let (config, revision, _) = self.load_full()?;
        Ok((config, revision))
    }

    pub(crate) fn load(&self) -> anyhow::Result<Config> {
        Ok(self.load_revision()?.0)
    }

    /// The configuration and what the gateway learned: what generation
    /// needs. Without a daemon, the named hosts are looked up here.
    pub(crate) fn load_for_generation(&self) -> anyhow::Result<(Config, Learned)> {
        let (config, revision, mut learned) = self.load_full()?;
        if revision.is_none() {
            let home = public_ip::effective(&config.server, learned.public_ip);
            learned.names = find_names(&config, home).resolved;
        }
        Ok((config, learned))
    }

    /// What the database holds: `None` before the first import. Any other
    /// failure (unreadable, locked) is an error, never "empty". With the
    /// daemon's revision when it came from the daemon.
    pub(crate) fn current(&self) -> anyhow::Result<(Option<Config>, Option<u64>)> {
        match self.load_revision() {
            Ok((config, revision)) => Ok((Some(config), revision)),
            Err(e) => match e.downcast_ref::<parallax_store::Error>() {
                Some(parallax_store::Error::Missing(_) | parallax_store::Error::Empty(_)) => {
                    Ok((None, None))
                }
                _ => Err(e),
            },
        }
    }

    /// Change the configuration, refusing an invalid result. Directly, in
    /// one write transaction. Through the daemon, against its latest
    /// configuration, again if another change landed first; the daemon then
    /// applies it.
    fn update<T>(
        &self,
        mut change: impl FnMut(&mut Config) -> anyhow::Result<T>,
    ) -> anyhow::Result<(T, Saved)> {
        for _ in 0..SAVE_ATTEMPTS {
            let (mut config, revision) = match self.ask(&Request::Load)? {
                Some(Reply::Configuration {
                    configuration,
                    revision,
                    ..
                }) => (configuration, revision),
                Some(other) => return Err(unexpected(other)),
                None => {
                    let out = block_on(async {
                        let mut store = self.open_store().await?;
                        store
                            .update(|config| {
                                let out = change(config)?;
                                check(config)?;
                                Ok(out)
                            })
                            .await
                    })?;
                    return Ok((out, Saved::Direct));
                }
            };
            let out = change(&mut config)?;
            check(&config)?;
            match self.save(config, revision)? {
                Some(saved) => return Ok((out, saved)),
                None => continue,
            }
        }
        bail!("the configuration kept changing under this command ({SAVE_ATTEMPTS} tries); nothing saved, try again")
    }

    /// Save through the daemon. `None`: the configuration moved past `revision`.
    fn save(&self, config: Box<Config>, revision: u64) -> anyhow::Result<Option<Saved>> {
        let request = Request::Save {
            configuration: config,
            revision,
        };
        match self.ask(&request)? {
            Some(Reply::Applied { log, error, .. }) => Ok(Some(Saved::Applied { log, error })),
            Some(Reply::Conflict { .. }) => Ok(None),
            Some(other) => Err(unexpected(other)),
            None => bail!("the daemon stopped answering; nothing saved"),
        }
    }
}

/// A reply that doesn't answer the request.
pub(crate) fn unexpected(reply: Reply) -> anyhow::Error {
    let kind = match reply {
        Reply::Status { .. } => "status",
        Reply::Configuration { .. } => "configuration",
        Reply::Applied { .. } => "applied",
        Reply::Conflict { .. } => "conflict",
        Reply::Done { .. } => "done",
        Reply::Error { .. } => "error",
    };
    anyhow!("the daemon answered with an unexpected '{kind}' reply")
}

/// A change was saved, but putting it into effect failed.
pub(crate) fn apply_failed(error: &str) -> anyhow::Error {
    anyhow!("saved, but applying it failed: {error}. The daemon tries again every minute; fix the cause, or run `parallax apply`")
}

/// Say what became of a saved change: `direct` is the hint without a
/// daemon. The apply log goes to stderr, so stdout stays the command's own.
fn report(saved: Saved, direct: &str) -> anyhow::Result<()> {
    match saved {
        Saved::Direct => {
            if !direct.is_empty() {
                eoutln!("{direct}");
            }
            Ok(())
        }
        Saved::Applied { log, error } => {
            for line in log {
                eoutln!("{line}");
            }
            match error {
                None => Ok(()),
                Some(e) => Err(apply_failed(&e)),
            }
        }
    }
}

/// Validation errors, as one error.
pub(crate) fn check(config: &Config) -> anyhow::Result<()> {
    let (errors, _) = parallax_core::validate::check(config);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(parallax_core::Error::Invalid(errors).into())
    }
}

pub(crate) fn resolve(config: &Config) -> anyhow::Result<Model<'_>> {
    Model::resolve(config, today()).map_err(|e| anyhow!("{e}"))
}

/// What the gateway learned while running that generation needs besides
/// the configuration: the home's public IP as a lookup last found it, and
/// what each host named by DNS name resolved to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Learned {
    pub(crate) public_ip: Option<Ipv4Addr>,
    pub(crate) names: Resolved,
}

/// The model generation uses: validated, with what the gateway learned.
pub(crate) fn model_for<'a>(
    config: &'a Config,
    today: Date,
    learned: &Learned,
) -> anyhow::Result<Model<'a>> {
    Ok(Model::resolve(config, today)
        .map_err(|e| anyhow!("{e}"))?
        .with_public_ip(public_ip::effective(&config.server, learned.public_ip))
        .with_names(learned.names.clone()))
}

pub(crate) fn print_warnings(warnings: &[String]) {
    for w in warnings {
        eoutln!("warning: {w}");
    }
}

fn print_export(export: &Export) -> anyhow::Result<()> {
    print_warnings(&export.warnings);
    out!("{}", export.contents)
}

/// Every hostname the proxy will serve needs a usable certificate, and the
/// upstream CA bundle must load. Parallax never issues certificates, so say
/// plainly what's missing before the proxy is handed routes it would refuse.
/// Returns warnings about unreadable certificates.
fn check_certificates(model: &Model<'_>) -> anyhow::Result<Vec<String>> {
    Ok(parallax_proxy::preflight(
        &generate::proxy::certificate_check(model),
    )?)
}

/// Everything short of writing: validate, generate, check certificates.
/// The daemon refuses a change that fails here before saving it.
pub(crate) fn preview(config: &Config, today: Date, learned: &Learned) -> anyhow::Result<()> {
    check(config)?;
    let model = model_for(config, today, learned)?;
    generate::generate_all(&model, &RealFs)?;
    check_certificates(&model)?;
    Ok(())
}

/// Generate, write and reconcile the live gateway with what the gateway
/// learned. Returns the warnings and the apply log.
pub(crate) fn apply_config(
    config: &Config,
    out: &Path,
    today: Date,
    learned: &Learned,
) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let model = model_for(config, today, learned)?;
    let mut bundle = generate::generate_all(&model, &RealFs)?;
    let mut warnings = std::mem::take(&mut bundle.warnings);
    warnings.extend(public_ip_unknown(config, model.public_ip()));
    warnings.extend(model.name_problems());
    warnings.extend(check_certificates(&model)?);
    let runner = RealRunner;
    let sys = System {
        fs: &RealFs,
        runner: &runner,
    };
    let report = parallax_core::apply::apply(&model, &bundle, out, sys)?;
    Ok((warnings, report.log))
}

/// Look up the home's public IP ([`parallax_core::public_ip`]). Blocks
/// for up to a few seconds per nameserver it asks.
pub(crate) fn find_public_ip(server: &ServerConfig) -> Result<public_ip::Found, Vec<String>> {
    public_ip::find(server, &lookup(server))
}

/// Look up every host named by DNS name ([`parallax_core::names`]).
/// Blocks for up to a few seconds per resolver it asks.
/// `public_ip` is the home's public IP in effect, where a name may point.
pub(crate) fn find_names(config: &Config, public_ip: Option<Ipv4Addr>) -> names::Refreshed {
    names::refresh(config, public_ip, &lookup(&config.server))
}

/// The real resolver.
pub(crate) fn lookup(server: &ServerConfig) -> parallax_dns::Lookup {
    parallax_dns::Lookup::new(&server.proxy.upstream_ca)
}

/// `name: address, address` per named host, for `plan` and `status`.
fn name_lines(names: &Resolved) -> Vec<String> {
    names
        .iter()
        .map(|(name, addresses)| format!("{name}: {}", names::list(addresses)))
        .collect()
}

/// Why a lookup failed, and what stays in effect.
pub(crate) fn public_ip_lookup_failed(problems: &[String], known: Option<Ipv4Addr>) -> String {
    let problems = problems.join("; ");
    match known {
        Some(ip) => {
            format!("can't look up the home's public IP ({problems}); keeping the last known {ip}")
        }
        None => format!("can't look up the home's public IP ({problems})"),
    }
}

/// Guests need the home's public IP and it was never found.
fn public_ip_unknown(config: &Config, public_ip: Option<Ipv4Addr>) -> Option<String> {
    (public_ip.is_none() && public_ip::hairpin(config)).then(|| {
        "the home's public IP isn't known: until it is, guests with internet can reach the home through the router (hairpin). Set server.public_ip.address, or server.public_ip.encrypted_dns if your resolver rewrites your own hostname".to_string()
    })
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let fs = RealFs;
    let ctx = Ctx {
        db: cli.db,
        socket: cli.socket,
    };
    let db = ctx.db();
    match cli.command {
        Command::Validate => {
            let config = ctx.load()?;
            let model = resolve(&config)?;
            print_warnings(model.warnings());
            outln!(
                "{}: valid ({} networks, {} grants, {} peers, {} active)",
                db.display(),
                config.networks.len(),
                config.grants.len(),
                config.peers.len(),
                model.active_peers().count()
            )?;
        }
        Command::Doctor => doctor(&ctx)?,
        Command::Plan(out) => {
            let (config, learned) = ctx.load_for_generation()?;
            let model = model_for(&config, today(), &learned)?;
            let bundle = generate::generate_all(&model, &fs)?;
            print_warnings(&model.name_problems());
            print_warnings(&check_certificates(&model)?);
            for line in name_lines(model.names()) {
                outln!("name {line}")?;
            }
            let plan = parallax_core::plan::plan(&bundle, &out.out, &fs)?;
            out!("{}", plan.render())?;
        }
        Command::Generate(out) => {
            if let Some((who, sudo_u)) = owner::belongs_to_another_user(&out.out) {
                bail!(
                    "{} belongs to {who}: files generated there as root would be ones the \
                     service can't replace. See the changes with `parallax plan`, generate \
                     elsewhere (`-o <dir>`), or run it as that user (`sudo -u {sudo_u} parallax \
                     generate`)",
                    out.out.display()
                );
            }
            let (config, learned) = ctx.load_for_generation()?;
            let model = model_for(&config, today(), &learned)?;
            let bundle = generate::generate_all(&model, &fs)?;
            print_warnings(&bundle.warnings);
            print_warnings(&model.name_problems());
            parallax_core::plan::write_bundle(&bundle, &out.out, &fs)?;
            for a in &bundle.artifacts {
                outln!("wrote {}", out.out.join(&a.path).display())?;
            }
        }
        Command::Apply(out) => match ctx.ask(&Request::Apply)? {
            Some(Reply::Applied { log, error, .. }) => {
                for line in log {
                    outln!("{line}")?;
                }
                if let Some(e) = error {
                    bail!("apply failed: {e}");
                }
            }
            Some(other) => return Err(unexpected(other)),
            None => {
                // The database stays open (locked) through the apply, so a
                // daemon starting meanwhile can't apply something newer first.
                let (warnings, log) = block_on(async {
                    let mut store = ctx.open_store().await?;
                    let config = store.load().await?;
                    let mut known = store.public_ip().await?;
                    let mut notes = Vec::new();
                    if public_ip::needed(&config) {
                        match find_public_ip(&config.server) {
                            Ok(found) => {
                                if known != Some(found.address) {
                                    store.set_public_ip(found.address).await?;
                                    known = Some(found.address);
                                }
                            }
                            Err(problems) => notes.push(public_ip_lookup_failed(&problems, known)),
                        }
                    }
                    let home = public_ip::effective(&config.server, known);
                    let found = find_names(&config, home);
                    notes.extend(found.problems);
                    let learned = Learned {
                        public_ip: known,
                        names: found.resolved,
                    };
                    let (warnings, log) = apply_config(&config, &out.out, today(), &learned)?;
                    notes.extend(warnings);
                    anyhow::Ok((notes, log))
                })?;
                print_warnings(&warnings);
                for line in log {
                    outln!("{line}")?;
                }
            }
        },
        Command::Daemon {
            out,
            reconcile_every,
        } => daemon::run(daemon::Options {
            db: ctx.db,
            socket: ctx.socket,
            out: out.out,
            reconcile_every: Duration::from_secs(reconcile_every.max(1)),
        })?,
        Command::Status => match ctx.ask(&Request::Status)? {
            Some(Reply::Status {
                revision,
                apply_error,
                public_ip,
                names,
            }) => {
                outln!(
                    "daemon at {}: configuration revision {revision}",
                    ctx.socket.display()
                )?;
                if let Some(ip) = public_ip {
                    outln!("home public IP: {ip}")?;
                }
                for line in name_lines(&names) {
                    outln!("name {line}")?;
                }
                match apply_error {
                    None => outln!("last apply: ok")?,
                    Some(e) => bail!("last apply failed: {e}"),
                }
            }
            Some(other) => return Err(unexpected(other)),
            None => bail!(
                "no daemon is running (nothing answers at {})",
                ctx.socket.display()
            ),
        },
        Command::Keygen {
            write_config,
            if_missing,
        } => keygen(&ctx, write_config, if_missing)?,
        Command::Config { command } => config_command(&ctx, command)?,
        Command::Backup { command } => backup::run(&ctx, command)?,
        Command::Grant { command } => grant_command(&ctx, command)?,
        Command::Peer { command } => peer_command(&ctx, command)?,
        Command::Log { command } => log_command(&ctx, command)?,
        Command::Export { peer, platform } => {
            let (config, learned) = ctx.load_for_generation()?;
            let model = model_for(&config, today(), &learned)?;
            let p = model.peer(&peer)?;
            let export = transport::by_kind(p.transport).export(&model, p, platform)?;
            print_export(&export)?;
        }
    }
    Ok(())
}

fn doctor(ctx: &Ctx) -> anyhow::Result<()> {
    let runner = RealRunner;
    let sys = System {
        fs: &RealFs,
        runner: &runner,
    };
    let loaded = ctx.load_for_generation().map_err(|e| format!("{e:#}"));
    let config = loaded
        .as_ref()
        .map(|(config, _)| config)
        .map_err(Clone::clone);
    let mut checks = parallax_core::doctor::diagnose(config.clone(), sys);
    if let Ok((config, learned)) = &loaded {
        let known = public_ip::effective(&config.server, learned.public_ip);
        checks.push(parallax_core::doctor::public_ip_check(config, known));
    }
    let mut failed = 0;
    for check in &checks {
        match &check.outcome {
            Outcome::Ok(detail) => outln!("ok    {}: {detail}", check.name)?,
            Outcome::Warn(problem) => outln!("warn  {}: {problem}", check.name)?,
            Outcome::Fail(problem) => {
                failed += 1;
                outln!("FAIL  {}: {problem}", check.name)?;
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} checks failed", checks.len());
    }
    outln!("all {} checks passed", checks.len())?;
    Ok(())
}

fn keygen(ctx: &Ctx, write_config: bool, if_missing: bool) -> anyhow::Result<()> {
    let fs = RealFs;
    let db = ctx.db();
    let config = ctx.load()?;
    let path = config.server.wireguard.private_key_file.clone();
    if let Some(existing) = fs.read(&path)? {
        if if_missing {
            // Finish an earlier run that wrote the key but stopped before
            // recording its public half.
            if write_config {
                let public = existing
                    .trim()
                    .parse::<PrivateKey>()
                    .map_err(|_| anyhow!("{} does not hold a valid private key", path.display()))?
                    .public_key();
                if public != config.server.wireguard.public_key {
                    let shown = public.to_base64();
                    let ((), saved) = ctx.update(|c| {
                        c.server.wireguard.public_key = public.clone();
                        Ok(())
                    })?;
                    outln!(
                        "recorded the public key of {} ({shown}) in {}",
                        path.display(),
                        db.display()
                    )?;
                    report(saved, "")?;
                }
            }
            return Ok(());
        }
        bail!(
            "{} already exists; remove it first if you really want a new server identity (every client config would need re-export)",
            path.display()
        );
    }
    let kp = OsKeyGenerator.keypair();
    fs.write(&path, &format!("{}\n", kp.private.expose_base64()), true)?;
    owner::hand_to_directory_owner(&path)?;
    // Record the key before printing anything, so a reader that goes away
    // can't leave a new key file with the old public key in the database.
    let saved = if write_config {
        let ((), saved) = ctx.update(|c| {
            c.server.wireguard.public_key = kp.public.clone();
            Ok(())
        })?;
        Some(saved)
    } else {
        None
    };
    outln!("wrote {} (mode 0600)", path.display())?;
    outln!("public key: {}", kp.public)?;
    if let Some(saved) = saved {
        outln!("recorded server.wireguard.public_key in {}", db.display())?;
        report(saved, "")?;
    } else {
        outln!(
            "set server.wireguard.public_key = \"{}\" with `parallax config edit`",
            kp.public
        )?;
    }
    Ok(())
}

/// Parse and validate a TOML configuration, giving any WireGuard peer
/// without an address the next free one.
fn prepare(text: &str) -> anyhow::Result<Config> {
    let mut config = Config::from_toml(text)?;
    let allocated = parallax_core::alloc::allocate_missing(&mut config)?;
    let (errors, warnings) = parallax_core::validate::check(&config);
    if !errors.is_empty() {
        return Err(parallax_core::Error::Invalid(errors).into());
    }
    for (name, addr) in allocated {
        eoutln!("allocated {addr} to peer '{name}'");
    }
    print_warnings(&warnings);
    Ok(config)
}

fn config_command(ctx: &Ctx, command: ConfigCommand) -> anyhow::Result<()> {
    let db = ctx.db();
    match command {
        ConfigCommand::Import { file, if_empty } => {
            let not_imported = || {
                eoutln!(
                    "{} already holds a configuration; {} not imported",
                    db.display(),
                    file.display()
                );
            };
            // Before parsing: a file the database already replaced may be stale.
            if if_empty && ctx.current()?.0.is_some() {
                not_imported();
                return Ok(());
            }
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let config = prepare(&text).with_context(|| format!("importing {}", file.display()))?;
            let summary = format!(
                "imported {} into {} ({} networks, {} grants, {} peers)",
                file.display(),
                db.display(),
                config.networks.len(),
                config.grants.len(),
                config.peers.len()
            );
            if ctx.ask(&Request::Status)?.is_some() {
                let ((), saved) = ctx.update(|current| {
                    current.clone_from(&config);
                    Ok(())
                })?;
                outln!("{summary}")?;
                return report(saved, "run `parallax apply` to put it into effect");
            }
            let saved = block_on(async {
                let mut store = ctx.create_store().await?;
                if if_empty {
                    // Checked again inside the write: another process may
                    // have imported since.
                    Ok(store.save_if_empty(&config).await?)
                } else {
                    store.save(&config).await?;
                    Ok(true)
                }
            })?;
            if !saved {
                not_imported();
                return Ok(());
            }
            outln!("{summary}; run `parallax apply` to put it into effect")?;
        }
        ConfigCommand::Export { output } => {
            let text = ctx.load()?.to_toml()?;
            match output {
                Some(path) => {
                    RealFs.write(&path, &text, true)?;
                    eoutln!("wrote {} (mode 0600)", path.display());
                }
                None => out!("{text}")?,
            }
        }
        ConfigCommand::Edit { out, yes } => config_edit(ctx, &out.out, yes)?,
    }
    Ok(())
}

fn config_edit(ctx: &Ctx, out_dir: &Path, yes: bool) -> anyhow::Result<()> {
    // The database stays closed while the editor is open, so the gateway and
    // other commands aren't locked out; a change in the meantime is caught below.
    let (before, revision, learned) = ctx.load_full()?;
    let original = before.to_toml()?;
    // Private (0700), removed with everything in it (editor backups and swap
    // files too) unless kept.
    let dir = TempDir::new_in(&std::env::temp_dir(), "parallax-edit")?;
    let file = dir.path().join("parallax.toml");
    RealFs.write(&file, &original, true)?;

    let edited = loop {
        run_editor(&file)?;
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        if text == original {
            outln!("no changes")?;
            return Ok(());
        }
        match prepare(&text) {
            Ok(config) => break config,
            Err(e) => {
                eoutln!("error: {e:#}");
                if !std::io::stdin().is_terminal() || !confirm("edit again?", true)? {
                    bail!("nothing saved");
                }
            }
        }
    };

    let new_text = edited.to_toml()?;
    if new_text == original {
        outln!("no changes")?;
        return Ok(());
    }
    outln!("configuration:")?;
    out!(
        "{}",
        redact(&parallax_core::plan::unified_diff(&original, &new_text))
    )?;
    let model = model_for(&edited, today(), &learned)?;
    match generate::generate_all(&model, &RealFs)
        .and_then(|bundle| parallax_core::plan::plan(&bundle, out_dir, &RealFs))
    {
        Ok(plan) => {
            outln!("generated files:")?;
            out!("{}", plan.render())?;
        }
        Err(e) => eoutln!("warning: can't preview the generated files: {e}"),
    }
    if !yes && !confirm("save?", false)? {
        bail!("nothing saved");
    }
    // `None`: someone else saved first.
    let outcome = match revision {
        Some(revision) => ctx.save(Box::new(edited), revision),
        None => {
            let mut moved = false;
            block_on(async {
                let mut store = ctx.open_store().await?;
                store
                    .update(|config| {
                        if *config != before {
                            moved = true;
                            bail!("the configuration changed while you were editing");
                        }
                        *config = edited;
                        Ok(())
                    })
                    .await
            })
            .map(|()| Some(Saved::Direct))
            .or_else(|e| if moved { Ok(None) } else { Err(e) })
        }
    };
    // Whatever went wrong, the edit isn't lost.
    let keep = |why: String| {
        let kept = dir.keep().join("parallax.toml");
        anyhow!(
            "{why}; nothing saved. Your version is in {}; run `parallax config edit` again",
            kept.display()
        )
    };
    match outcome {
        Ok(Some(saved)) => {
            outln!("saved")?;
            report(saved, "run `parallax apply` to put it into effect")
        }
        Ok(None) => Err(keep(
            "the configuration changed while you were editing".into(),
        )),
        Err(e) => Err(keep(format!("{e:#}"))),
    }
}

/// `$VISUAL`, then `$EDITOR`, then `vi`. The variable may carry arguments
/// (`code --wait`).
fn run_editor(file: &Path) -> anyhow::Result<()> {
    let editor = ["VISUAL", "EDITOR"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|e| !e.trim().is_empty()))
        .unwrap_or_else(|| "vi".to_string());
    let mut words = editor.split_whitespace();
    let program = words.next().unwrap_or("vi");
    let status = std::process::Command::new(program)
        .args(words)
        .arg(file)
        .status()
        .with_context(|| format!("starting the editor `{editor}`"))?;
    if !status.success() {
        bail!("the editor `{editor}` failed ({status}); nothing saved");
    }
    Ok(())
}

/// Ask a yes/no question on the terminal. Without one, only `--yes` can say yes.
fn confirm(question: &str, default: bool) -> anyhow::Result<bool> {
    if !std::io::stdin().is_terminal() {
        bail!("{question} needs a terminal to answer; pass --yes to go ahead without asking");
    }
    eout!("{question} [{}] ", if default { "Y/n" } else { "y/N" });
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(match answer.trim().to_ascii_lowercase().as_str() {
        "" => default,
        a => a.starts_with('y'),
    })
}

/// Hide private and preshared keys in a configuration diff.
fn redact(diff: &str) -> String {
    diff.lines()
        .map(|line| {
            let body = line.trim_start_matches(['+', '-', ' ']);
            if body.starts_with("private_key =") || body.starts_with("preshared_key =") {
                let key = body.split('=').next().unwrap_or_default().trim_end();
                format!("{}{key} = (redacted)\n", &line[..line.len() - body.len()])
            } else {
                format!("{line}\n")
            }
        })
        .collect()
}

/// Make a change and return, with its result, the validation warnings it
/// adds: a grant change should say what it brought about (a grant for
/// everyone that opens a network), not repeat what was already there.
fn new_warnings<T>(
    config: &mut Config,
    change: impl FnOnce(&mut Config) -> anyhow::Result<T>,
) -> anyhow::Result<(T, Vec<String>)> {
    let (_, before) = parallax_core::validate::check(config);
    let out = change(config)?;
    let (_, after) = parallax_core::validate::check(config);
    Ok((
        out,
        after.into_iter().filter(|w| !before.contains(w)).collect(),
    ))
}

/// Save a grant change, print what it did, its new warnings, and what
/// became of it.
fn grant_change<T>(
    ctx: &Ctx,
    mut change: impl FnMut(&mut Config) -> anyhow::Result<T>,
    done: impl FnOnce(&T) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let ((out, warnings), saved) = ctx.update(|config| new_warnings(config, &mut change))?;
    done(&out)?;
    // Through the daemon, its apply log already carries every warning.
    if matches!(saved, Saved::Direct) {
        print_warnings(&warnings);
    }
    report(saved, "run `parallax apply` to put it into effect")
}

/// `'a', 'b'`, or `none`.
fn quoted(names: &[String]) -> String {
    if names.is_empty() {
        return "none".into();
    }
    names
        .iter()
        .map(|n| format!("'{n}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One line per item an addition added, and per item already there.
fn print_added(
    added: &grants::Added,
    done: impl Fn(&str) -> String,
    already: impl Fn(&str) -> String,
) -> anyhow::Result<()> {
    for item in &added.added {
        outln!("{}", done(item))?;
    }
    for item in &added.already {
        outln!("{}", already(item))?;
    }
    Ok(())
}

fn grant_command(ctx: &Ctx, command: GrantCommand) -> anyhow::Result<()> {
    match command {
        GrantCommand::Create {
            name,
            rules,
            everyone,
        } => grant_change(
            ctx,
            |c| Ok(grants::create(c, &name, everyone, &rules)?),
            |()| {
                outln!(
                    "created grant '{name}'{}",
                    if everyone {
                        " for everyone"
                    } else {
                        "; attach it with `parallax grant attach`"
                    }
                )?;
                Ok(())
            },
        ),
        GrantCommand::Remove { name, force } => grant_change(
            ctx,
            |c| {
                let holders = grants::holders(c, &name)?;
                if !force && !holders.is_empty() {
                    let names: Vec<String> = holders.iter().map(|p| p.name.clone()).collect();
                    bail!(
                        "grant '{name}' is held by {}; removing it takes it from them. Pass --force to remove it anyway",
                        quoted(&names)
                    );
                }
                Ok(grants::remove(c, &name)?)
            },
            |had| {
                outln!("removed grant '{name}'")?;
                eoutln!(
                    "note: snippets/parallax-{name}.conf stays on disk with its last allow lines; remove any nginx include of it, delete it, and reload nginx"
                );
                if !had.is_empty() {
                    outln!("taken from {}", quoted(had))?;
                }
                Ok(())
            },
        ),
        GrantCommand::Rename { from, to } => grant_change(
            ctx,
            |c| Ok(grants::rename(c, &from, &to)?),
            |peers| {
                outln!("renamed grant '{from}' to '{to}' (peers {})", quoted(peers))?;
                eoutln!(
                    "note: its nginx snippet is now snippets/parallax-{to}.conf; parallax-{from}.conf stays on disk with its last allow lines, so point any include at the new one, delete the old, and reload nginx"
                );
                Ok(())
            },
        ),
        GrantCommand::Show { name } => {
            let config = ctx.load()?;
            let shown: Vec<&parallax_core::Grant> = match &name {
                Some(n) => vec![config
                    .grant(n)
                    .ok_or_else(|| anyhow!("grant '{n}' not found"))?],
                None => config.grants.iter().collect(),
            };
            let list = |peers: Vec<&Peer>| match peers.is_empty() {
                true => "-".to_string(),
                false => peers
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
            };
            for g in shown {
                let attached = list(grants::attached(&config, &g.name)?);
                if g.everyone {
                    // Attachments still matter: they keep it when it's switched off.
                    let peers = match list(grants::holders(&config, &g.name)?).as_str() {
                        "-" => "everyone".to_string(),
                        all => format!("everyone ({all})"),
                    };
                    outln!(
                        "{}  everyone=true  peers={peers}  attached={attached}",
                        g.name
                    )?;
                } else {
                    outln!("{}  everyone=false  peers={attached}", g.name)?;
                }
                if g.rules.is_empty() {
                    outln!("    no rules: it gives nothing")?;
                }
                for rule in &g.rules {
                    outln!("    rule {rule}")?;
                }
            }
            Ok(())
        }
        GrantCommand::Rule { change } => match change {
            GrantRule::Add { grant, rules } => grant_change(
                ctx,
                |c| Ok(grants::add_rules(c, &grant, &rules)?),
                |added| {
                    print_added(
                        added,
                        |r| format!("added rule {r}"),
                        |r| format!("grant '{grant}' already has rule {r}"),
                    )?;
                    Ok(())
                },
            ),
            GrantRule::Remove { grant, rules } => grant_change(
                ctx,
                |c| Ok(grants::remove_rules(c, &grant, &rules)?),
                |()| {
                    for rule in &rules {
                        outln!("removed rule {rule}")?;
                    }
                    Ok(())
                },
            ),
        },
        GrantCommand::Attach { grant, to } => grant_change(
            ctx,
            |c| Ok(grants::attach(c, &grant, &to)?),
            |added| {
                print_added(
                    added,
                    |p| format!("attached '{grant}' to '{p}'"),
                    |p| format!("'{p}' already has '{grant}'"),
                )?;
                Ok(())
            },
        ),
        GrantCommand::Detach { grant, from } => grant_change(
            ctx,
            |c| {
                grants::detach(c, &grant, &from)?;
                Ok(c.grant(&grant).is_some_and(|g| g.everyone))
            },
            |everyone| {
                for peer in &from {
                    outln!("detached '{grant}' from '{peer}'")?;
                }
                if *everyone {
                    eoutln!(
                        "note: '{grant}' applies to everyone, so they still have it until that's switched off"
                    );
                }
                Ok(())
            },
        ),
        GrantCommand::Everyone { grant, switch } => {
            let on = matches!(switch, Switch::On);
            grant_change(
                ctx,
                |c| {
                    let changed = grants::set_everyone(c, &grant, on)?;
                    let kept: Vec<String> = grants::attached(c, &grant)?
                        .iter()
                        .map(|p| p.name.clone())
                        .collect();
                    Ok((changed, kept))
                },
                |(changed, kept)| {
                    let state = if on {
                        "applies to everyone"
                    } else {
                        "applies only to the peers it's attached to"
                    };
                    if *changed {
                        outln!("grant '{grant}' now {state}")?;
                    } else {
                        outln!("grant '{grant}' already {state}")?;
                    }
                    if !on {
                        outln!("attached to {}", quoted(kept))?;
                    }
                    Ok(())
                },
            )
        }
    }
}

fn peer_grants(ctx: &Ctx, peer: &str, change: PeerGrants) -> anyhow::Result<()> {
    let show = |config: &Config| -> String {
        let own = config
            .peer(peer)
            .map(|p| p.grants.as_slice())
            .unwrap_or_default();
        if own.is_empty() {
            format!("'{peer}' now has no grants of its own")
        } else {
            format!("'{peer}' now has {}", quoted(own))
        }
    };
    match change {
        PeerGrants::Set { grants: list } => grant_change(
            ctx,
            |c| {
                grants::set_peer(c, peer, &list)?;
                Ok(show(c))
            },
            |line| outln!("{line}"),
        ),
        PeerGrants::Add { grants: list } => grant_change(
            ctx,
            |c| {
                let added = grants::peer_add(c, peer, &list)?;
                Ok((added, show(c)))
            },
            |(added, line)| {
                print_added(
                    added,
                    |g| format!("attached '{g}' to '{peer}'"),
                    |g| format!("'{peer}' already has '{g}'"),
                )?;
                outln!("{line}")?;
                Ok(())
            },
        ),
        PeerGrants::Remove { grants: list } => grant_change(
            ctx,
            |c| {
                grants::peer_remove(c, peer, &list)?;
                Ok(show(c))
            },
            |line| outln!("{line}"),
        ),
    }
}

fn peer_command(ctx: &Ctx, command: PeerCommand) -> anyhow::Result<()> {
    match command {
        PeerCommand::Add {
            name,
            grants,
            dns,
            allowed_ips,
            transport: kind,
            keep_private_key,
            preshared_key,
            expires,
            platform,
        } => {
            // For the export: a grant by name reaches what it resolved to.
            let (_, learned) = ctx.load_for_generation()?;
            let ((peer, export), saved) = ctx.update(|config| {
                let model = resolve(config)?;
                let tr = transport::by_kind(kind);
                let opts = ProvisionOptions {
                    retain_private_key: keep_private_key,
                    preshared_key,
                    expires,
                };
                let mut peer = tr.provision(&model, &grants, &name, &OsKeyGenerator, &opts)?;
                if let Some(w) = peer.wireguard.as_mut() {
                    w.dns = dns.unwrap_or(w.dns);
                    w.allowed_ips = allowed_ips.unwrap_or(w.allowed_ips);
                }

                // One-time export against a model that includes the new peer.
                let mut with_peer = config.clone();
                with_peer.peers.push(peer.clone());
                let export =
                    tr.export(&model_for(&with_peer, today(), &learned)?, &peer, platform)?;

                let mut stored = peer.clone();
                if !keep_private_key {
                    if let Some(w) = stored.wireguard.as_mut() {
                        w.private_key = None;
                    }
                }
                config.peers.push(stored);
                Ok((peer, export))
            })?;

            eoutln!(
                "added peer '{}' (grants {}, {}, address {})",
                peer.name,
                if peer.grants.is_empty() {
                    "none".to_string()
                } else {
                    peer.grants.join(",")
                },
                peer.transport,
                peer.wireguard
                    .as_ref()
                    .and_then(|w| w.address)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".into())
            );
            if !keep_private_key {
                eoutln!("the private key below is shown once and not stored; save the config now");
            }
            // Printed before any apply error: the key isn't stored anywhere else.
            print_export(&export)?;
            report(saved, "run `parallax apply` to let the gateway accept it")?;
        }
        PeerCommand::Remove { name } => {
            let ((), saved) = ctx.update(|config| {
                let before = config.peers.len();
                config.peers.retain(|p| p.name != name);
                if config.peers.len() == before {
                    bail!("peer '{name}' not found");
                }
                Ok(())
            })?;
            outln!("removed peer '{name}'")?;
            report(saved, "run `parallax apply` to revoke it on the gateway")?;
        }
        PeerCommand::Grants { peer, change } => peer_grants(ctx, &peer, change)?,
        PeerCommand::Show { name } => {
            let (config, learned) = ctx.load_for_generation()?;
            let model = model_for(&config, today(), &learned)?;
            let peers: Vec<&Peer> = match &name {
                Some(n) => vec![model.peer(n)?],
                None => config.peers.iter().collect(),
            };
            for p in peers {
                let tier = model.tier_of(p);
                let addr = match p.transport {
                    TransportKind::WireGuard => p.wireguard.as_ref().and_then(|w| w.address),
                    TransportKind::Tailscale => p.tailscale.as_ref().and_then(|t| t.address),
                };
                outln!(
                    "{}  grants={}  transport={}  address={}  active={}{}",
                    p.name,
                    tier.map(|t| t.label().replace('+', ","))
                        .unwrap_or_else(|| "-".into()),
                    p.transport,
                    addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                    p.is_active(model.today()),
                    p.expires
                        .map(|e| format!("  expires={e}"))
                        .unwrap_or_default()
                )?;
                for r in tier.map(|t| model.reaches(t)).unwrap_or_default() {
                    let via = r
                        .client_net()
                        .map(|n| format!(" as {n}"))
                        .unwrap_or_default();
                    let proxied = match r.kind {
                        ReachKind::Lan { proxied: true, .. }
                        | ReachKind::HomePublic { proxied: true, .. } => " through the HTTPS proxy",
                        _ => "",
                    };
                    let ports = match &r.kind {
                        ReachKind::Lan {
                            ports: Some(ports), ..
                        }
                        | ReachKind::HomePublic { ports, .. } => format!(
                            " ({})",
                            ports
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        _ => String::new(),
                    };
                    outln!("    reaches {}{ports}{via}{proxied}", r.label)?;
                }
                let public = tier.is_some_and(|t| t.has(&parallax_core::Rule::PublicDns));
                match &p.wireguard {
                    Some(w) => outln!(
                        "    dns: {} public={public}; allowed_ips={}",
                        w.dns.as_str(),
                        w.allowed_ips.as_str()
                    )?,
                    None => outln!(
                        "    dns: {} public={public}",
                        model.server().headscale.dns.as_str()
                    )?,
                }
            }
        }
    }
    Ok(())
}
