//! `parallax backup`: create, list and restore backups, and set their passphrase.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context};
use clap::Subcommand;
use parallax_core::generate;
use parallax_core::io::real::RealFs;
use parallax_core::io::FileSystem;
use parallax_core::model::BackupServer;
use parallax_core::secret::Secret;
use parallax_core::Config;
use parallax_store::{backup, Store, TempDir};

use crate::{block_on, confirm, current, load, print_warnings, redact, resolve, OutArgs};

#[derive(Subcommand)]
pub enum BackupCommand {
    /// Back up the database and the server key into server.backup.directory,
    /// then delete the oldest past server.backup.keep.
    Create {
        /// Only when automatic backups are on, the newest backup is at least
        /// server.backup.interval old, and something changed since (for a timer).
        #[arg(long)]
        if_due: bool,
    },
    /// List backups, oldest first.
    List {
        /// Where to look; defaults to server.backup.directory.
        directory: Option<PathBuf>,
    },
    /// Replace the database and the server key with a backup's, after showing what changes.
    Restore {
        file: PathBuf,
        #[command(flatten)]
        out: OutArgs,
        /// Restore without asking.
        #[arg(short, long)]
        yes: bool,
        /// Read the backup's passphrase from this file instead of asking for it.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Set the passphrase backups are encrypted with. Keep a copy in your password manager.
    Passphrase {
        /// Generate a strong passphrase and print it, instead of asking for one.
        #[arg(long)]
        generate: bool,
        /// Replace a passphrase that's already set. Older backups still need the old one.
        #[arg(long)]
        replace: bool,
    },
}

/// Passphrases shorter than this are refused; generated ones are longer.
const MIN_PASSPHRASE: usize = 12;

pub fn run(db: &Path, command: BackupCommand) -> anyhow::Result<()> {
    match command {
        BackupCommand::Create { if_due } => create(db, if_due),
        BackupCommand::List { directory } => list(db, directory),
        BackupCommand::Restore {
            file,
            out,
            yes,
            passphrase_file,
        } => restore(db, &file, &out.out, yes, passphrase_file.as_deref()),
        BackupCommand::Passphrase { generate, replace } => set_passphrase(db, generate, replace),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The passphrase in `path`, if one is set there.
fn read_passphrase(path: &Path) -> anyhow::Result<Option<Secret>> {
    match RealFs.read(path)? {
        Some(text) => {
            let pass = text.trim_end_matches(['\n', '\r']);
            Ok((!pass.is_empty()).then(|| Secret::new(pass)))
        }
        None => Ok(None),
    }
}

/// The passphrase new backups are encrypted with, or none when encryption is off.
fn backup_passphrase(settings: &BackupServer) -> anyhow::Result<Option<Secret>> {
    if !settings.encrypt {
        return Ok(None);
    }
    match read_passphrase(&settings.passphrase_file)? {
        Some(p) => Ok(Some(p)),
        None => bail!(
            "backups are encrypted, but no passphrase is set ({} is missing); set one with `parallax backup passphrase`, or turn encryption off with server.backup.encrypt = false",
            settings.passphrase_file.display()
        ),
    }
}

fn create(db: &Path, if_due: bool) -> anyhow::Result<()> {
    let config = load(db)?;
    let settings = &config.server.backup;
    let newest = backup::list(&settings.directory)?.pop();
    if if_due {
        if !settings.automatic {
            return Ok(());
        }
        if let Some(newest) = &newest {
            let now = now_secs();
            // A backup from the future (the clock went back) doesn't count.
            if newest.created <= now && now - newest.created < settings.interval.as_secs() {
                return Ok(());
            }
        }
    }
    let passphrase = backup_passphrase(settings)?;
    let written = block_on(async {
        let store = Store::open(db).await?;
        let snapshot = store
            .snapshot(&config.server.wireguard.private_key_file)
            .await?;
        if if_due {
            let unchanged = newest
                .as_ref()
                .and_then(|n| backup::inspect(&n.path).ok())
                .is_some_and(|m| {
                    m.contents_sha256 == snapshot.contents_sha256()
                        && m.encrypted == passphrase.is_some()
                });
            if unchanged {
                return Ok(None);
            }
        }
        Ok(Some(backup::write(
            &snapshot,
            &settings.directory,
            passphrase.as_ref(),
            SystemTime::now(),
        )?))
    })?;
    let Some((path, manifest)) = written else {
        return Ok(());
    };
    println!(
        "wrote {} ({})",
        path.display(),
        if manifest.encrypted {
            "encrypted"
        } else {
            "not encrypted"
        }
    );
    for old in backup::rotate(&settings.directory, settings.keep as usize)? {
        println!("deleted {} (keeping {})", old.display(), settings.keep);
    }
    Ok(())
}

fn list(db: &Path, directory: Option<PathBuf>) -> anyhow::Result<()> {
    let directory = match directory {
        Some(d) => d,
        None => load(db)?.server.backup.directory,
    };
    let backups = backup::list(&directory)?;
    if backups.is_empty() {
        println!("no backups in {}", directory.display());
    }
    for b in backups {
        let size = std::fs::metadata(&b.path).map_or(0, |m| m.len());
        match backup::inspect(&b.path) {
            Ok(m) => println!(
                "{}  {}  Parallax {}  schema {}  {}  {}",
                b.path.display(),
                m.created,
                m.parallax,
                m.schema,
                if m.encrypted {
                    "encrypted"
                } else {
                    "not encrypted"
                },
                human_size(size)
            ),
            Err(e) => println!("{}  can't be restored: {e}", b.path.display()),
        }
    }
    Ok(())
}

fn human_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MiB", b as f64 / f64::from(1 << 20)),
        b if b >= 1 << 10 => format!("{:.1} KiB", b as f64 / f64::from(1 << 10)),
        b => format!("{b} B"),
    }
}

fn set_passphrase(db: &Path, generate: bool, replace: bool) -> anyhow::Result<()> {
    let config = load(db)?;
    let path = &config.server.backup.passphrase_file;
    if read_passphrase(path)?.is_some() && !replace {
        bail!(
            "a backup passphrase is already set in {}; backups made with it need it to restore. Pass --replace to set a new one",
            path.display()
        );
    }
    let passphrase = if generate {
        generated_passphrase()
    } else {
        let first = read_secret("new backup passphrase: ")?;
        if first.chars().count() < MIN_PASSPHRASE {
            bail!(
                "a backup passphrase needs at least {MIN_PASSPHRASE} characters; or use --generate"
            );
        }
        if read_secret("again: ")? != first {
            bail!("the passphrases don't match; nothing changed");
        }
        first
    };
    RealFs.write(path, &format!("{passphrase}\n"), true)?;
    if generate {
        println!("{passphrase}");
    }
    eprintln!(
        "wrote {} (mode 0600). Keep the passphrase in your password manager: without it, the backups can't be restored.",
        path.display()
    );
    if !config.server.backup.encrypt {
        eprintln!("warning: server.backup.encrypt is false, so backups don't use it yet");
    } else if replace {
        eprintln!("older backups still need the old passphrase; run `parallax backup create` to make one with the new one");
    }
    Ok(())
}

/// 25 characters from an alphabet without look-alikes (125 bits), in groups of five.
fn generated_passphrase() -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
    let bytes: [u8; 25] = rand::random();
    bytes
        .chunks(5)
        .map(|group| {
            group
                .iter()
                .map(|b| char::from(ALPHABET[usize::from(b & 31)]))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Read a line from the terminal without echoing it.
fn read_secret(prompt: &str) -> anyhow::Result<String> {
    use rustix::termios::{tcgetattr, tcsetattr, LocalModes, OptionalActions};
    use std::os::fd::AsFd;
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!("asking for a passphrase needs a terminal");
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let fd = stdin.as_fd();
    let original = tcgetattr(fd).context("reading the terminal settings")?;
    let mut quiet = original.clone();
    quiet.local_modes.remove(LocalModes::ECHO);
    tcsetattr(fd, OptionalActions::Now, &quiet).context("turning off echo")?;
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    let _ = tcsetattr(fd, OptionalActions::Now, &original);
    eprintln!();
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Open a backup, finding its passphrase: `--passphrase-file`, else the
/// server's passphrase file, else asking (three tries). Returns the
/// passphrase too when it didn't come from the server's file.
fn open_backup(
    file: &Path,
    given: Option<&Path>,
    server_file: &Path,
) -> anyhow::Result<(backup::Contents, Option<Secret>)> {
    if let Some(given) = given {
        let pass = read_passphrase(given)?
            .ok_or_else(|| anyhow!("{} holds no passphrase", given.display()))?;
        let contents = backup::open(file, Some(&pass))?;
        return Ok((contents, Some(pass)));
    }
    if let Some(pass) = read_passphrase(server_file)? {
        match backup::open(file, Some(&pass)) {
            Ok(contents) => return Ok((contents, None)),
            Err(parallax_store::Error::WrongPassphrase(_)) => eprintln!(
                "the passphrase in {} doesn't open this backup",
                server_file.display()
            ),
            Err(e) => return Err(e.into()),
        }
    }
    if !std::io::stdin().is_terminal() {
        bail!(
            "backup {} is encrypted; pass --passphrase-file, or run this in a terminal to type the passphrase",
            file.display()
        );
    }
    for attempt in 1..=3 {
        let pass = Secret::new(read_secret("backup passphrase: ")?);
        match backup::open(file, Some(&pass)) {
            Ok(contents) => return Ok((contents, Some(pass))),
            Err(parallax_store::Error::WrongPassphrase(_)) if attempt < 3 => {
                eprintln!("wrong passphrase; try again");
            }
            Err(e) => return Err(e.into()),
        }
    }
    bail!("wrong passphrase; nothing restored")
}

fn restore(
    db: &Path,
    file: &Path,
    out_dir: &Path,
    yes: bool,
    passphrase_file: Option<&Path>,
) -> anyhow::Result<()> {
    // Refuses a backup from a newer Parallax before asking for anything.
    let manifest = backup::inspect(file)?;
    println!(
        "backup {}: made {} by Parallax {}, {}",
        file.display(),
        manifest.created,
        manifest.parallax,
        if manifest.encrypted {
            "encrypted"
        } else {
            "not encrypted"
        }
    );
    let before = current(db)?;
    let defaults = BackupServer::default();
    let settings = before.as_ref().map_or(&defaults, |c| &c.server.backup);
    let (contents, typed) = if manifest.encrypted {
        open_backup(file, passphrase_file, &settings.passphrase_file)?
    } else {
        (backup::open(file, None)?, None)
    };

    let db_dir = match db.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let mut dirs = std::fs::DirBuilder::new();
    dirs.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dirs.mode(0o700);
    }
    dirs.create(db_dir)
        .with_context(|| format!("creating {}", db_dir.display()))?;
    // Next to the database: it holds the same private data.
    let staging = TempDir::new_in(db_dir, ".parallax-restore")?;

    block_on(async {
        let mut staged = contents.stage(staging.path()).await?;
        let restored = staged.load().await?;
        show_changes(before.as_ref(), &restored, contents.server_key(), out_dir)?;
        if !yes && !confirm("restore?", false)? {
            bail!("nothing restored");
        }
        if let Some(before) = &before {
            save_current(db, before).await;
        }
        let mut live = Store::create(db).await?;
        live.replace_with(&staged).await?;
        let key_file = &restored.server.wireguard.private_key_file;
        RealFs
            .write(key_file, contents.server_key().expose(), true)
            .with_context(|| {
                format!(
                    "the database is restored, but writing the server key {} failed; fix that and restore again",
                    key_file.display()
                )
            })?;
        println!(
            "restored the database {} and the server key {}",
            db.display(),
            key_file.display()
        );
        let wanted = &restored.server.backup;
        if let Some(pass) = typed.filter(|_| wanted.encrypt) {
            if read_passphrase(&wanted.passphrase_file)?.is_none() {
                RealFs.write(
                    &wanted.passphrase_file,
                    &format!("{}\n", pass.expose()),
                    true,
                )?;
                println!(
                    "saved the backup passphrase to {} for the next backups",
                    wanted.passphrase_file.display()
                );
            }
        }
        Ok(())
    })?;
    println!("run `parallax apply` to put it into effect");
    Ok(())
}

/// Print what restoring `restored` changes: the configuration (keys
/// redacted), the server key, and the generated files.
fn show_changes(
    before: Option<&Config>,
    restored: &Config,
    server_key: &Secret,
    out_dir: &Path,
) -> anyhow::Result<()> {
    let (errors, warnings) = parallax_core::validate::check(restored);
    print_warnings(&warnings);
    for e in &errors {
        eprintln!("warning: the restored configuration doesn't validate: {e}; fix it with `parallax config edit` before `parallax apply`");
    }
    let old = before.map(Config::to_toml).transpose()?.unwrap_or_default();
    let new = restored.to_toml()?;
    if before.is_none() {
        println!(
            "the database holds no configuration yet; the backup brings {} networks, {} templates, {} peers",
            restored.networks.len(),
            restored.templates.len(),
            restored.peers.len()
        );
    } else if old == new {
        println!("configuration: unchanged");
    } else {
        println!("configuration:");
        print!("{}", redact(&parallax_core::plan::unified_diff(&old, &new)));
    }
    let key_file = &restored.server.wireguard.private_key_file;
    let key = match RealFs.read(key_file) {
        Ok(Some(k)) if k == server_key.expose() => "unchanged".to_string(),
        Ok(Some(_)) => format!(
            "{} is replaced with the backup's; clients made since the backup stop working, older ones work again",
            key_file.display()
        ),
        Ok(None) => format!("{} is restored", key_file.display()),
        Err(e) => format!("{} can't be read ({e}); it is replaced", key_file.display()),
    };
    println!("server key: {key}");
    if errors.is_empty() {
        let plan = resolve(restored).and_then(|model| {
            let bundle = generate::generate_all(&model, &RealFs)?;
            Ok(parallax_core::plan::plan(&bundle, out_dir, &RealFs)?)
        });
        match plan {
            Ok(plan) => {
                println!("generated files after `parallax apply`:");
                print!("{}", plan.render());
            }
            Err(e) => eprintln!("warning: can't preview the generated files: {e:#}"),
        }
    }
    Ok(())
}

/// Back up the current state before replacing it, so a restore can be
/// undone. Not rotated: that could delete the very backup being restored.
async fn save_current(db: &Path, before: &Config) {
    let settings = &before.server.backup;
    let saved = async {
        let passphrase = backup_passphrase(settings)?;
        let store = Store::open(db).await?;
        let snapshot = store
            .snapshot(&before.server.wireguard.private_key_file)
            .await?;
        let (path, _) = backup::write(
            &snapshot,
            &settings.directory,
            passphrase.as_ref(),
            SystemTime::now(),
        )?;
        anyhow::Ok(path)
    }
    .await;
    match saved {
        Ok(path) => println!("saved the current state first as {}", path.display()),
        Err(e) => eprintln!("warning: couldn't save the current state first: {e:#}"),
    }
}
