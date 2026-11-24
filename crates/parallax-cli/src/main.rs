//! `parallax`: the command-line harness over `parallax-core`.
//!
//! The database (`parallax-store`) is the source of truth. TOML is only a
//! way in and out: `config import`, `config export` and `config edit`.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use clap::{Args, Parser, Subcommand};
use parallax_core::date::Date;
use parallax_core::generate::{self, Export};
use parallax_core::io::real::{RealFs, RealRunner};
use parallax_core::io::{FileSystem, KeyGenerator, OsKeyGenerator, System};
use parallax_core::model::{Peer, Platform, TransportKind};
use parallax_core::transport::{self, ProvisionOptions};
use parallax_core::validate::ReachKind;
use parallax_core::{Config, Model};
use parallax_store::Store;

#[derive(Parser)]
#[command(
    name = "parallax",
    version,
    about = "WireGuard + Headscale gateway with subnet remapping, DNS rewriting and template-based access policies"
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
    Apply(OutArgs),
    /// Run the HTTPS proxy from the routes `apply` wrote. SIGHUP re-reads them.
    Proxy(OutArgs),
    /// Run the DNS server from the routes `apply` wrote. SIGHUP re-reads them.
    Dns(OutArgs),
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
    /// Manage peers.
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
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
    Import { file: PathBuf },
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
        #[arg(short, long)]
        template: String,
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
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn today() -> Date {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    Date::from_unix_days(secs.div_euclid(86_400))
}

/// The store is async; the CLI does one thing at a time.
fn block_on<T>(f: impl std::future::Future<Output = anyhow::Result<T>>) -> anyhow::Result<T> {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .context("starting the async runtime")?
        .block_on(f)
}

/// Read the configuration. The database is closed again before this returns,
/// so long-running work (`apply`) doesn't keep other commands out.
fn load(db: &Path) -> anyhow::Result<Config> {
    block_on(async { Ok(Store::open(db).await?.load().await?) })
}

/// Change the configuration under one open database, refusing to save an
/// invalid result.
fn update<T>(
    db: &Path,
    change: impl FnOnce(&mut Config) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    block_on(async {
        let store = Store::open(db).await?;
        let mut config = store.load().await?;
        let out = change(&mut config)?;
        check(&config)?;
        store.save(&config).await?;
        Ok(out)
    })
}

/// Validation errors, as one error.
fn check(config: &Config) -> anyhow::Result<()> {
    let (errors, _) = parallax_core::validate::check(config);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(parallax_core::Error::Invalid(errors).into())
    }
}

fn resolve(config: &Config) -> anyhow::Result<Model<'_>> {
    Model::resolve(config, today()).map_err(|e| anyhow!("{e}"))
}

fn print_warnings(warnings: &[String]) {
    for w in warnings {
        eprintln!("warning: {w}");
    }
}

fn print_export(export: &Export) {
    print_warnings(&export.warnings);
    print!("{}", export.contents);
}

/// Every hostname the proxy will serve needs a usable certificate, and the
/// upstream CA bundle must load. Parallax never issues certificates, so say
/// plainly what's missing before the proxy is handed routes it would refuse.
fn check_certificates(model: &Model<'_>) -> anyhow::Result<()> {
    let warnings = parallax_proxy::preflight(&generate::proxy::build(model))?;
    print_warnings(&warnings);
    Ok(())
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let fs = RealFs;
    let db = cli.db.as_path();
    match cli.command {
        Command::Validate => {
            let config = load(db)?;
            let model = resolve(&config)?;
            print_warnings(model.warnings());
            println!(
                "{}: valid ({} networks, {} templates, {} peers, {} active)",
                db.display(),
                config.networks.len(),
                config.templates.len(),
                config.peers.len(),
                model.active_peers().count()
            );
        }
        Command::Doctor => doctor(db)?,
        Command::Plan(out) => {
            let config = load(db)?;
            let model = resolve(&config)?;
            let bundle = generate::generate_all(&model, &fs)?;
            check_certificates(&model)?;
            let plan = parallax_core::plan::plan(&bundle, &out.out, &fs)?;
            print!("{}", plan.render());
        }
        Command::Generate(out) => {
            let config = load(db)?;
            let model = resolve(&config)?;
            let bundle = generate::generate_all(&model, &fs)?;
            print_warnings(&bundle.warnings);
            parallax_core::plan::write_bundle(&bundle, &out.out, &fs)?;
            for a in &bundle.artifacts {
                println!("wrote {}", out.out.join(&a.path).display());
            }
        }
        Command::Apply(out) => {
            let config = load(db)?;
            let model = resolve(&config)?;
            let bundle = generate::generate_all(&model, &fs)?;
            print_warnings(&bundle.warnings);
            check_certificates(&model)?;
            let runner = RealRunner;
            let sys = System {
                fs: &fs,
                runner: &runner,
            };
            let report = parallax_core::apply::apply(&model, &bundle, &out.out, sys)?;
            for line in report.log {
                println!("{line}");
            }
        }
        Command::Proxy(out) => {
            parallax_proxy::serve(&out.out.join(generate::proxy::PATH))?;
        }
        Command::Dns(out) => {
            parallax_dns::serve(&out.out.join(generate::dns::PATH))?;
        }
        Command::Keygen {
            write_config,
            if_missing,
        } => keygen(db, write_config, if_missing)?,
        Command::Config { command } => config_command(db, command)?,
        Command::Peer { command } => peer_command(db, command)?,
        Command::Export { peer, platform } => {
            let config = load(db)?;
            let model = resolve(&config)?;
            let p = model.peer(&peer)?;
            let export = transport::by_kind(p.transport).export(&model, p, platform)?;
            print_export(&export);
        }
    }
    Ok(())
}

fn doctor(db: &Path) -> anyhow::Result<()> {
    let runner = RealRunner;
    let sys = System {
        fs: &RealFs,
        runner: &runner,
    };
    let config = load(db).map_err(|e| format!("{e:#}"));
    let checks = parallax_core::doctor::diagnose(config.as_ref().map_err(Clone::clone), sys);
    let mut failed = 0;
    for check in &checks {
        match &check.result {
            Ok(detail) => println!("ok    {}: {detail}", check.name),
            Err(problem) => {
                failed += 1;
                println!("FAIL  {}: {problem}", check.name);
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} checks failed", checks.len());
    }
    println!("all {} checks passed", checks.len());
    Ok(())
}

fn keygen(db: &Path, write_config: bool, if_missing: bool) -> anyhow::Result<()> {
    let fs = RealFs;
    let config = load(db)?;
    let path = config.server.wireguard.private_key_file.clone();
    if fs.read(&path)?.is_some() {
        if if_missing {
            return Ok(());
        }
        bail!(
            "{} already exists; remove it first if you really want a new server identity (every client config would need re-export)",
            path.display()
        );
    }
    let kp = OsKeyGenerator.keypair();
    fs.write(&path, &format!("{}\n", kp.private.expose_base64()), true)?;
    println!("wrote {} (mode 0600)", path.display());
    println!("public key: {}", kp.public);
    if write_config {
        update(db, |c| {
            c.server.wireguard.public_key = kp.public;
            Ok(())
        })?;
        println!("recorded server.wireguard.public_key in {}", db.display());
    } else {
        println!(
            "set server.wireguard.public_key = \"{}\" with `parallax config edit`",
            kp.public
        );
    }
    Ok(())
}

/// Parse and validate a TOML configuration, giving any WireGuard peer
/// without an address the next free one.
fn prepare(text: &str) -> anyhow::Result<Config> {
    let mut config = Config::from_toml(text)?;
    for (name, addr) in parallax_core::alloc::allocate_missing(&mut config)? {
        eprintln!("allocated {addr} to peer '{name}'");
    }
    let (errors, warnings) = parallax_core::validate::check(&config);
    if !errors.is_empty() {
        return Err(parallax_core::Error::Invalid(errors).into());
    }
    print_warnings(&warnings);
    Ok(config)
}

fn config_command(db: &Path, command: ConfigCommand) -> anyhow::Result<()> {
    match command {
        ConfigCommand::Import { file } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let config = prepare(&text).with_context(|| format!("importing {}", file.display()))?;
            let new = !db.exists();
            let saved = block_on(async {
                let store = Store::create(db).await?;
                store.save(&config).await?;
                Ok(())
            });
            if saved.is_err() && new {
                // Leave no empty database behind: the next start would take it
                // for an imported one.
                let _ = std::fs::remove_file(db);
                let mut wal = db.as_os_str().to_owned();
                wal.push("-wal");
                let _ = std::fs::remove_file(wal);
            }
            saved?;
            println!(
                "imported {} into {} ({} networks, {} templates, {} peers); run `parallax apply` to put it into effect",
                file.display(),
                db.display(),
                config.networks.len(),
                config.templates.len(),
                config.peers.len()
            );
        }
        ConfigCommand::Export { output } => {
            let text = load(db)?.to_toml()?;
            match output {
                Some(path) => {
                    RealFs.write(&path, &text, true)?;
                    eprintln!("wrote {} (mode 0600)", path.display());
                }
                None => print!("{text}"),
            }
        }
        ConfigCommand::Edit { out, yes } => config_edit(db, &out.out, yes)?,
    }
    Ok(())
}

/// Removes the temporary file holding the configuration, whatever happens.
struct TempFile(PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn config_edit(db: &Path, out_dir: &Path, yes: bool) -> anyhow::Result<()> {
    // The database stays closed while the editor is open, so the gateway and
    // other commands aren't locked out; a change in the meantime is caught below.
    let before = load(db)?;
    let original = before.to_toml()?;
    let file = TempFile(std::env::temp_dir().join(format!("parallax-{}.toml", std::process::id())));
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&file.0)
            .and_then(|mut f| f.write_all(original.as_bytes()))
            .with_context(|| format!("writing {}", file.0.display()))?;
    }

    let edited = loop {
        run_editor(&file.0)?;
        let text = std::fs::read_to_string(&file.0)
            .with_context(|| format!("reading {}", file.0.display()))?;
        if text == original {
            println!("no changes");
            return Ok(());
        }
        match prepare(&text) {
            Ok(config) => break config,
            Err(e) => {
                eprintln!("error: {e:#}");
                if !std::io::stdin().is_terminal() || !confirm("edit again?", true)? {
                    bail!("nothing saved");
                }
            }
        }
    };

    let new_text = edited.to_toml()?;
    if new_text == original {
        println!("no changes");
        return Ok(());
    }
    println!("configuration:");
    print!(
        "{}",
        redact(&parallax_core::plan::unified_diff(&original, &new_text))
    );
    let model = resolve(&edited)?;
    match generate::generate_all(&model, &RealFs)
        .and_then(|bundle| parallax_core::plan::plan(&bundle, out_dir, &RealFs))
    {
        Ok(plan) => {
            println!("generated files:");
            print!("{}", plan.render());
        }
        Err(e) => eprintln!("warning: can't preview the generated files: {e}"),
    }
    if !yes && !confirm("save?", false)? {
        bail!("nothing saved");
    }
    block_on(async {
        let store = Store::open(db).await?;
        if store.load().await? != before {
            bail!("the configuration changed while you were editing; nothing saved, run `parallax config edit` again");
        }
        store.save(&edited).await?;
        Ok(())
    })?;
    println!("saved; run `parallax apply` to put it into effect");
    Ok(())
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
        bail!("{question} needs a terminal to answer; pass --yes to save without asking");
    }
    eprint!("{question} [{}] ", if default { "Y/n" } else { "y/N" });
    std::io::stderr().flush()?;
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

fn peer_command(db: &Path, command: PeerCommand) -> anyhow::Result<()> {
    match command {
        PeerCommand::Add {
            name,
            template,
            transport: kind,
            keep_private_key,
            preshared_key,
            expires,
            platform,
        } => {
            let (peer, export) = update(db, |config| {
                let model = resolve(config)?;
                let t = model.template(&template)?;
                let tr = transport::by_kind(kind);
                let opts = ProvisionOptions {
                    retain_private_key: keep_private_key,
                    preshared_key,
                    expires,
                };
                let peer = tr.provision(&model, t, &name, &OsKeyGenerator, &opts)?;

                // One-time export against a model that includes the new peer.
                let mut with_peer = config.clone();
                with_peer.peers.push(peer.clone());
                let export = tr.export(&resolve(&with_peer)?, &peer, platform)?;

                let mut stored = peer.clone();
                if !keep_private_key {
                    if let Some(w) = stored.wireguard.as_mut() {
                        w.private_key = None;
                    }
                }
                config.peers.push(stored);
                Ok((peer, export))
            })?;

            eprintln!(
                "added peer '{}' (template {}, {}, address {})",
                peer.name,
                peer.template,
                peer.transport,
                peer.wireguard
                    .as_ref()
                    .and_then(|w| w.address)
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "-".into())
            );
            if !keep_private_key {
                eprintln!(
                    "the private key below is shown once and not stored; save the config now"
                );
            }
            eprintln!("run `parallax apply` to let the gateway accept it");
            print_export(&export);
        }
        PeerCommand::Remove { name } => {
            update(db, |config| {
                let before = config.peers.len();
                config.peers.retain(|p| p.name != name);
                if config.peers.len() == before {
                    bail!("peer '{name}' not found");
                }
                Ok(())
            })?;
            println!("removed peer '{name}'; run `parallax apply` to revoke it on the gateway");
        }
        PeerCommand::Show { name } => {
            let config = load(db)?;
            let model = resolve(&config)?;
            let peers: Vec<&Peer> = match &name {
                Some(n) => vec![model.peer(n)?],
                None => config.peers.iter().collect(),
            };
            for p in peers {
                let t = model.template(&p.template)?;
                let addr = match p.transport {
                    TransportKind::WireGuard => p.wireguard.as_ref().and_then(|w| w.address),
                    TransportKind::Tailscale => p.tailscale.as_ref().and_then(|t| t.address),
                };
                println!(
                    "{}  template={}  transport={}  address={}  active={}{}",
                    p.name,
                    p.template,
                    p.transport,
                    addr.map(|a| a.to_string()).unwrap_or_else(|| "-".into()),
                    p.is_active(model.today()),
                    p.expires
                        .map(|e| format!("  expires={e}"))
                        .unwrap_or_default()
                );
                for r in model.reaches(t) {
                    let via = r
                        .client_net()
                        .map(|n| format!(" as {n}"))
                        .unwrap_or_default();
                    let proxied = match r.kind {
                        ReachKind::Lan { proxied: true, .. } => " through the HTTPS proxy",
                        _ => "",
                    };
                    println!("    reaches {}{via}{proxied}", r.label);
                }
                println!(
                    "    dns: wireguard={} tailscale={} public={}; allowed_ips={:?}",
                    t.dns.wireguard.as_str(),
                    t.dns.tailscale.as_str(),
                    t.dns.public,
                    t.client.allowed_ips
                );
            }
        }
    }
    Ok(())
}
