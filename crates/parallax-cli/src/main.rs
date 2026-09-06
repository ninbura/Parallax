//! `parallax`: the M1 command-line harness over `parallax-core`.
//!
//! The TOML file is the source of truth. Commands that change it (`keygen
//! --write-config`, `peer add/remove/allocate`) edit it in place with
//! `toml_edit` so comments and layout survive.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use clap::{Args, Parser, Subcommand};
use parallax_core::date::Date;
use parallax_core::generate::{self, Export};
use parallax_core::io::real::{RealFs, RealRunner};
use parallax_core::io::{FileSystem, KeyGenerator, OsKeyGenerator, System};
use parallax_core::model::{Peer, Platform, TransportKind};
use parallax_core::transport::{self, ProvisionOptions};
use parallax_core::{Config, Model};

#[derive(Parser)]
#[command(
    name = "parallax",
    version,
    about = "WireGuard + Headscale gateway with subnet remapping, DNS rewriting and template-based access policies"
)]
struct Cli {
    /// Configuration file (the source of truth).
    #[arg(
        short,
        long,
        global = true,
        default_value = "parallax.toml",
        env = "PARALLAX_CONFIG"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the configuration and report every problem.
    Validate,
    /// Generate everything and show what would change under the output directory.
    Plan(OutArgs),
    /// Generate everything into the output directory without touching the system.
    Generate(OutArgs),
    /// Generate, write, and reconcile the live gateway (firewall, WireGuard, DNS shim).
    Apply(OutArgs),
    /// Create the gateway's WireGuard private key file and print its public key.
    Keygen {
        /// Also record the public key in the configuration file.
        #[arg(long)]
        write_config: bool,
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
    /// Assign addresses to WireGuard peers that have none.
    Allocate,
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

fn load(path: &Path) -> anyhow::Result<Config> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Config::from_toml(&text).map_err(|e| anyhow!("{e}"))
}

fn load_doc(path: &Path) -> anyhow::Result<toml_edit::DocumentMut> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("parsing {}", path.display()))
}

fn save_doc(path: &Path, doc: &toml_edit::DocumentMut) -> anyhow::Result<()> {
    std::fs::write(path, doc.to_string()).with_context(|| format!("writing {}", path.display()))
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

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let fs = RealFs;
    match cli.command {
        Command::Validate => {
            let config = load(&cli.config)?;
            let model = resolve(&config)?;
            print_warnings(model.warnings());
            println!(
                "{}: valid ({} networks, {} templates, {} peers, {} active)",
                cli.config.display(),
                config.networks.len(),
                config.templates.len(),
                config.peers.len(),
                model.active_peers().count()
            );
        }
        Command::Plan(out) => {
            let config = load(&cli.config)?;
            let model = resolve(&config)?;
            let bundle = generate::generate_all(&model, &fs)?;
            let plan = parallax_core::plan::plan(&bundle, &out.out, &fs)?;
            print!("{}", plan.render());
        }
        Command::Generate(out) => {
            let config = load(&cli.config)?;
            let model = resolve(&config)?;
            let bundle = generate::generate_all(&model, &fs)?;
            print_warnings(&bundle.warnings);
            parallax_core::plan::write_bundle(&bundle, &out.out, &fs)?;
            for a in &bundle.artifacts {
                println!("wrote {}", out.out.join(&a.path).display());
            }
        }
        Command::Apply(out) => {
            let config = load(&cli.config)?;
            let model = resolve(&config)?;
            let bundle = generate::generate_all(&model, &fs)?;
            print_warnings(&bundle.warnings);
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
        Command::Keygen { write_config } => {
            let config = load(&cli.config)?;
            let path = &config.server.wireguard.private_key_file;
            if fs.read(path)?.is_some() {
                bail!(
                    "{} already exists; remove it first if you really want a new server identity (every client config would need re-export)",
                    path.display()
                );
            }
            let kp = OsKeyGenerator.keypair();
            fs.write(path, &format!("{}\n", kp.private.expose_base64()), true)?;
            println!("wrote {} (mode 0600)", path.display());
            println!("public key: {}", kp.public);
            if write_config {
                let mut doc = load_doc(&cli.config)?;
                doc["server"]["wireguard"]["public_key"] = toml_edit::value(kp.public.to_base64());
                save_doc(&cli.config, &doc)?;
                println!(
                    "recorded server.wireguard.public_key in {}",
                    cli.config.display()
                );
            } else {
                println!(
                    "set server.wireguard.public_key = \"{}\" in {}",
                    kp.public,
                    cli.config.display()
                );
            }
        }
        Command::Peer { command } => peer_command(&cli.config, command)?,
        Command::Export { peer, platform } => {
            let config = load(&cli.config)?;
            let model = resolve(&config)?;
            let p = model.peer(&peer)?;
            let export = transport::by_kind(p.transport).export(&model, p, platform)?;
            print_export(&export);
        }
    }
    Ok(())
}

fn peer_command(config_path: &Path, command: PeerCommand) -> anyhow::Result<()> {
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
            let config = load(config_path)?;
            let model = resolve(&config)?;
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
            let model2 = resolve(&with_peer)?;
            let export = tr.export(&model2, &peer, platform)?;

            let mut stored = peer.clone();
            if !keep_private_key {
                if let Some(w) = stored.wireguard.as_mut() {
                    w.private_key = None;
                }
            }
            let mut doc = load_doc(config_path)?;
            append_peer(&mut doc, &stored)?;
            save_doc(config_path, &doc)?;

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
            let mut doc = load_doc(config_path)?;
            let removed = remove_peer(&mut doc, &name);
            if !removed {
                bail!("peer '{name}' not found");
            }
            save_doc(config_path, &doc)?;
            println!("removed peer '{name}'; run `parallax apply` to revoke it on the gateway");
        }
        PeerCommand::Show { name } => {
            let config = load(config_path)?;
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
                    println!("    reaches {}{via}", r.label);
                }
                println!(
                    "    dns: wireguard={} tailscale={}; allowed_ips={:?}",
                    t.dns.wireguard.as_str(),
                    t.dns.tailscale.as_str(),
                    t.client.allowed_ips
                );
            }
        }
        PeerCommand::Allocate => {
            let mut config = load(config_path)?;
            let done = parallax_core::alloc::allocate_missing(&mut config)?;
            if done.is_empty() {
                println!("every WireGuard peer already has an address");
                return Ok(());
            }
            let mut doc = load_doc(config_path)?;
            for (name, addr) in &done {
                set_peer_address(&mut doc, name, &addr.to_string())?;
                println!("{name}: {addr}");
            }
            save_doc(config_path, &doc)?;
        }
    }
    Ok(())
}

fn peers_mut(doc: &mut toml_edit::DocumentMut) -> anyhow::Result<&mut toml_edit::ArrayOfTables> {
    doc.as_table_mut()
        .entry("peer")
        .or_insert(toml_edit::Item::ArrayOfTables(
            toml_edit::ArrayOfTables::new(),
        ))
        .as_array_of_tables_mut()
        .ok_or_else(|| anyhow!("`peer` in the configuration is not an array of tables"))
}

fn append_peer(doc: &mut toml_edit::DocumentMut, peer: &Peer) -> anyhow::Result<()> {
    let rendered = toml_edit::ser::to_document(peer).context("serialising peer")?;
    let mut table = rendered.as_table().clone();
    // Nested identity blocks render as dotted sub-tables rather than [peer.wireguard] headers.
    for (_, item) in table.iter_mut() {
        if let Some(t) = item.as_table_mut() {
            t.set_dotted(true);
        }
    }
    peers_mut(doc)?.push(table);
    Ok(())
}

fn remove_peer(doc: &mut toml_edit::DocumentMut, name: &str) -> bool {
    let Some(peers) = doc.get_mut("peer").and_then(|p| p.as_array_of_tables_mut()) else {
        return false;
    };
    let idx = peers
        .iter()
        .position(|t| t.get("name").and_then(|n| n.as_str()) == Some(name));
    match idx {
        Some(i) => {
            peers.remove(i);
            true
        }
        None => false,
    }
}

fn set_peer_address(
    doc: &mut toml_edit::DocumentMut,
    name: &str,
    addr: &str,
) -> anyhow::Result<()> {
    let peers = peers_mut(doc)?;
    for t in peers.iter_mut() {
        if t.get("name").and_then(|n| n.as_str()) == Some(name) {
            let wg = t
                .entry("wireguard")
                .or_insert(toml_edit::Item::Table(toml_edit::Table::new()));
            match wg {
                toml_edit::Item::Table(tbl) => {
                    tbl["address"] = toml_edit::value(addr);
                }
                toml_edit::Item::Value(v) => {
                    if let Some(inline) = v.as_inline_table_mut() {
                        inline.insert("address", addr.into());
                    }
                }
                _ => bail!("peer '{name}': wireguard block has an unexpected shape"),
            }
            return Ok(());
        }
    }
    bail!("peer '{name}' not found in the configuration file")
}
