//! `parallax backup`: create, list and restore backups, and set their passphrase.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context};
use clap::Subcommand;
use parallax_core::generate;
use parallax_core::io::memory::MemoryFs;
use parallax_core::io::real::RealFs;
use parallax_core::io::FileSystem;
use parallax_core::model::BackupServer;
use parallax_core::secret::Secret;
use parallax_core::Config;
use parallax_store::{backup, Store, TempDir};

use crate::protocol::{Reply, Request};
use crate::{block_on, confirm, print_warnings, redact, resolve, unexpected, Ctx, OutArgs};

#[derive(Subcommand)]
pub enum BackupCommand {
    /// Back up the database and the server key into server.backup.directory,
    /// then delete the oldest past server.backup.keep.
    Create {
        /// Only when automatic backups are on, a whole server.backup.interval
        /// has passed since the last backup or the last look that found
        /// nothing new, and something changed (for a timer).
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

pub fn run(ctx: &Ctx, command: BackupCommand) -> anyhow::Result<()> {
    match command {
        BackupCommand::Create { if_due } => create_command(ctx, if_due),
        BackupCommand::List { directory } => list(ctx, directory),
        BackupCommand::Restore {
            file,
            out,
            yes,
            passphrase_file,
        } => restore(ctx, &file, &out.out, yes, passphrase_file.as_deref()),
        BackupCommand::Passphrase { generate, replace } => set_passphrase(ctx, generate, replace),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The passphrase in `path`, if one is set there.
pub(crate) fn read_passphrase(path: &Path) -> anyhow::Result<Option<Secret>> {
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

fn create_command(ctx: &Ctx, if_due: bool) -> anyhow::Result<()> {
    let lines = match ctx.ask(&Request::BackupCreate { if_due })? {
        Some(Reply::Done { lines }) => lines,
        Some(other) => return Err(unexpected(other)),
        None => block_on(async {
            let mut store = ctx.open_store().await?;
            let config = store.load().await?;
            match prepare(&config, if_due)? {
                Some(pending) => pending.take(&store).await?.write(),
                None => Ok(Vec::new()),
            }
        })?,
    };
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

/// A backup that is due, before the database is copied. Backing up runs in
/// three steps so the daemon holds its database only for the copy:
/// [`prepare`] (quick checks), [`Pending::take`] (the copy, milliseconds),
/// [`Taken::write`] (the slow part: encryption, writing, rotation), which
/// the daemon runs on its own thread.
pub(crate) struct Pending {
    settings: BackupServer,
    key_file: PathBuf,
    passphrase: Option<Secret>,
    newest: Option<backup::Listed>,
    if_due: bool,
}

/// A backup whose database copy is taken, ready to write.
pub(crate) struct Taken {
    pending: Pending,
    snapshot: backup::Snapshot,
}

/// Whether a backup is due as `config` says, and what it needs. `None`: an
/// `if_due` run with nothing due.
pub(crate) fn prepare(config: &Config, if_due: bool) -> anyhow::Result<Option<Pending>> {
    let settings = &config.server.backup;
    // The newest not from the future: one written while the clock was ahead
    // would otherwise stay "newest" and never match.
    let now = now_secs();
    let mut backups = backup::list(&settings.directory)?;
    let newest = match backups.iter().rposition(|b| b.created <= now) {
        Some(i) => Some(backups.swap_remove(i)),
        None => backups.pop(),
    };
    if if_due {
        if !settings.automatic {
            return Ok(None);
        }
        // Look at the database once per interval: since the newest backup,
        // or since a look that found nothing new, whichever is later. Times
        // from the future (the clock was ahead) don't count.
        let last = newest
            .as_ref()
            .map(|n| n.created)
            .into_iter()
            .chain(backup::last_check(&settings.directory))
            .filter(|&t| t <= now)
            .max();
        if last.is_some_and(|t| now - t < settings.interval.as_secs()) {
            return Ok(None);
        }
    }
    let passphrase = backup_passphrase(settings)?;
    // A backup whose key can't be used would restore a gateway no client
    // reaches. (The undo backup a restore makes takes the state as it is.)
    let key_file = &config.server.wireguard.private_key_file;
    let key = std::fs::read(key_file)
        .with_context(|| format!("reading the server key {}", key_file.display()))?;
    if backup::parse_key(&key).is_none() {
        bail!(
            "the server key {} doesn't hold a WireGuard private key; nothing backed up",
            key_file.display()
        );
    }
    Ok(Some(Pending {
        settings: settings.clone(),
        key_file: key_file.clone(),
        passphrase,
        newest,
        if_due,
    }))
}

impl Pending {
    /// Copy the database and the server key.
    pub(crate) async fn take(self, store: &Store) -> anyhow::Result<Taken> {
        let snapshot = store.snapshot(&self.key_file).await?;
        Ok(Taken {
            pending: self,
            snapshot,
        })
    }
}

impl Taken {
    /// Write the backup (skipping an `if_due` one identical to the newest)
    /// and rotate. Returns what it did, one line each.
    pub(crate) fn write(self) -> anyhow::Result<Vec<String>> {
        let Taken { pending, snapshot } = self;
        let settings = &pending.settings;
        if pending.if_due {
            let unchanged = pending
                .newest
                .as_ref()
                // The whole file, so a damaged newest backup is replaced, not trusted.
                .and_then(|n| backup::verify(&n.path).ok())
                .is_some_and(|m| {
                    m.contents_sha256 == snapshot.contents_sha256()
                        && m.encrypted == pending.passphrase.is_some()
                });
            if unchanged {
                backup::record_check(&settings.directory, SystemTime::now())?;
                return Ok(Vec::new());
            }
        }
        let (path, manifest) = backup::write(
            &snapshot,
            &settings.directory,
            pending.passphrase.as_ref(),
            SystemTime::now(),
        )?;
        let mut lines = vec![format!(
            "wrote {} ({})",
            path.display(),
            if manifest.encrypted {
                "encrypted"
            } else {
                "not encrypted"
            }
        )];
        for old in backup::rotate(&settings.directory, settings.keep as usize, &path)? {
            lines.push(format!(
                "deleted {} (keeping {})",
                old.display(),
                settings.keep
            ));
        }
        Ok(lines)
    }
}

fn list(ctx: &Ctx, directory: Option<PathBuf>) -> anyhow::Result<()> {
    let directory = match directory {
        Some(d) => d,
        None => ctx.load()?.server.backup.directory,
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

/// A native service doesn't see the host's /tmp, /var/tmp or /home
/// (`PrivateTmp`, `ProtectHome`), so it can't reopen a backup the CLI read
/// from there.
fn hidden_from_the_service(e: anyhow::Error, file: &Path) -> anyhow::Error {
    let file = std::path::absolute(file).unwrap_or_else(|_| file.to_path_buf());
    let hidden = ["/tmp", "/var/tmp", "/home", "/root"]
        .iter()
        .any(|dir| file.starts_with(dir));
    if hidden {
        e.context(format!(
            "the daemon couldn't restore {}: a native install's service can't see /tmp, \
             /var/tmp, /home or /root. Move the backup into the backup directory \
             (server.backup.directory) and restore it from there",
            file.display()
        ))
    } else {
        e
    }
}

fn human_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MiB", b as f64 / f64::from(1 << 20)),
        b if b >= 1 << 10 => format!("{:.1} KiB", b as f64 / f64::from(1 << 10)),
        b => format!("{b} B"),
    }
}

fn set_passphrase(ctx: &Ctx, generate: bool, replace: bool) -> anyhow::Result<()> {
    let config = ctx.load()?;
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
    write_atomic(path, &format!("{passphrase}\n"))?;
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
    if read? == 0 {
        bail!("no passphrase given");
    }
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
        if !given.exists() {
            bail!("the passphrase file {} doesn't exist", given.display());
        }
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
    ctx: &Ctx,
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
    let (before, revision) = ctx.current().context(
        "can't read the current database; if it's damaged, move it (parallax.db*) aside and restore as on a fresh install",
    )?;
    let defaults = BackupServer::default();
    let settings = before.as_ref().map_or(&defaults, |c| &c.server.backup);
    let (contents, typed) = if manifest.encrypted {
        open_backup(file, passphrase_file, &settings.passphrase_file)?
    } else {
        (backup::open(file, None)?, None)
    };
    // Next to the database: it holds the same private data.
    let staging = TempDir::new_in(&private_dir_of(ctx.db())?, ".parallax-restore")?;

    block_on(async {
        let (staged, restored) = stage(&contents, file, staging.path()).await?;
        show_changes(before.as_ref(), &restored, contents.server_key(), out_dir)?;
        if !yes && !confirm("restore?", false)? {
            bail!("nothing restored");
        }
        if let Some(revision) = revision {
            // The daemon restores from the file itself, into the database it holds.
            let request = Request::BackupRestore {
                path: std::path::absolute(file)
                    .with_context(|| format!("resolving {}", file.display()))?,
                passphrase: typed,
                revision,
                contents_sha256: contents.manifest.contents_sha256.clone(),
            };
            return match ctx.ask(&request).map_err(|e| hidden_from_the_service(e, file))? {
                Some(Reply::Applied { log, error, .. }) => {
                    for line in log {
                        println!("{line}");
                    }
                    match error {
                        None => Ok(()),
                        Some(e) => Err(crate::apply_failed(&e)),
                    }
                }
                Some(Reply::Conflict { .. }) => bail!(
                    "the configuration changed while the restore waited; nothing restored. Run the restore again"
                ),
                Some(other) => Err(unexpected(other)),
                None => bail!("the daemon stopped before the restore; nothing restored"),
            };
        }
        let mut live = ctx.create_store().await?;
        let lines = restore_into(
            &mut live,
            before.as_ref(),
            &contents,
            &staged,
            &restored,
            typed.as_ref(),
        )
        .await?;
        for line in lines {
            println!("{line}");
        }
        println!("run `parallax apply` to put it into effect");
        Ok(())
    })
}

/// The directory holding `db`, created owner-only if missing.
pub(crate) fn private_dir_of(db: &Path) -> anyhow::Result<PathBuf> {
    let dir = match db.parent() {
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
    dirs.create(dir)
        .with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir.to_path_buf())
}

/// Open a backup's database in `directory`, refusing one whose server key
/// doesn't match its configuration.
pub(crate) async fn stage(
    contents: &backup::Contents,
    file: &Path,
    directory: &Path,
) -> anyhow::Result<(Store, Config)> {
    let mut staged = contents.stage(directory).await?;
    let restored = staged.load().await?;
    let key = backup::parse_key(contents.server_key().expose().as_bytes()).map(|k| k.public_key());
    if key.as_ref() != Some(&restored.server.wireguard.public_key) {
        bail!(
            "backup {}: its server key doesn't match the public key in its configuration, so clients couldn't connect; nothing restored",
            file.display()
        );
    }
    Ok((staged, restored))
}

/// Replace `live` and the server key with a staged backup's. `before` is
/// what `live` must still hold (checked inside the write). Backs up the
/// current state first, and keeps a typed passphrase for later backups.
/// Returns what it did, one line each.
pub(crate) async fn restore_into(
    live: &mut Store,
    before: Option<&Config>,
    contents: &backup::Contents,
    staged: &Store,
    restored: &Config,
    typed: Option<&Secret>,
) -> anyhow::Result<Vec<String>> {
    let mut lines = Vec::new();
    // Undo first: a restore never loses the state it replaces.
    if let Some(before) = before {
        let path = save_current(live, before, typed)
            .await
            .context("couldn't save the current state first, so nothing was restored")?;
        lines.push(format!(
            "saved the current state first as {}",
            path.display()
        ));
    }
    // The key goes in first and comes back out if the database can't
    // be replaced, so the two always match.
    let key_file = &restored.server.wireguard.private_key_file;
    let old_key = RealFs.read(key_file)?;
    write_atomic(key_file, contents.server_key().expose())?;
    if let Err(e) = live.replace_with(staged, before).await {
        let undone = match &old_key {
            Some(old) => write_atomic(key_file, old),
            None => std::fs::remove_file(key_file).map_err(Into::into),
        };
        if let Err(undo) = undone {
            eprintln!(
                "warning: putting the old server key {} back failed too: {undo:#}",
                key_file.display()
            );
        }
        return Err(e.into());
    }
    lines.push(format!(
        "restored the database {} and the server key {}",
        live.path().display(),
        key_file.display()
    ));
    // The restore is done; failing to keep the passphrase only means the
    // next backups need it set again.
    let wanted = &restored.server.backup;
    if let Some(pass) = typed.filter(|_| wanted.encrypt) {
        let file = &wanted.passphrase_file;
        let kept = match read_passphrase(file) {
            Ok(Some(_)) => Ok(false),
            Ok(None) => write_atomic(file, &format!("{}\n", pass.expose())).map(|()| true),
            Err(e) => Err(e),
        };
        match kept {
            Ok(true) => lines.push(format!(
                "saved the backup passphrase to {} for the next backups",
                file.display()
            )),
            Ok(false) => {}
            Err(e) => lines.push(format!(
                "warning: couldn't save the backup passphrase to {}: {e:#}; set it with `parallax backup passphrase`",
                file.display()
            )),
        }
    }
    Ok(lines)
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
            "the database holds no configuration yet; the backup brings {} networks, {} grants, {} peers",
            restored.networks.len(),
            restored.grants.len(),
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
        // Generated with the backup's server key, compared with what's on disk.
        let with_key = MemoryFs::new().with_file(key_file, server_key.expose());
        let plan = resolve(restored).and_then(|model| {
            let bundle = generate::generate_all(&model, &with_key)?;
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
/// undone. With encryption on and no passphrase set, the one that opened the
/// backup is used. Not rotated: that could delete the very backup being restored.
async fn save_current(
    store: &Store,
    before: &Config,
    typed: Option<&Secret>,
) -> anyhow::Result<PathBuf> {
    let settings = &before.server.backup;
    let passphrase = match (backup_passphrase(settings), typed) {
        (Ok(p), _) => p,
        (Err(_), Some(typed)) => Some(Secret::new(typed.expose())),
        (Err(e), None) => return Err(e),
    };
    let snapshot = store
        .snapshot(&before.server.wireguard.private_key_file)
        .await?;
    let (path, _) = backup::write(
        &snapshot,
        &settings.directory,
        passphrase.as_ref(),
        SystemTime::now(),
    )?;
    Ok(path)
}

/// Replace `path` (mode 0600) all at once: a crash or a full disk leaves the
/// old contents, never a truncated file.
pub(crate) fn write_atomic(path: &Path, contents: &str) -> anyhow::Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let scratch = TempDir::new_in(dir, ".parallax-key")?;
    let tmp = scratch.path().join("key");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let ctx = || format!("writing {}", path.display());
    let mut f = opts.open(&tmp).with_context(ctx)?;
    f.write_all(contents.as_bytes()).with_context(ctx)?;
    f.sync_all().with_context(ctx)?;
    std::fs::rename(&tmp, path).with_context(ctx)?;
    crate::owner::hand_to_directory_owner(path)
}
