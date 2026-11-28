//! Backups: everything Parallax keeps, in one file.
//!
//! `parallax-backup-<UTC time>.tar` holds two entries:
//! - `manifest.toml`: which Parallax made it, its database schema, whether
//!   it's encrypted, and checksums. Plaintext, so backups can be listed and
//!   checked without the passphrase.
//! - `payload.tar.age` (`payload.tar` when unencrypted): `parallax.db`, a
//!   consistent copy of the database rebuilt from its rows in WAL mode (so
//!   `sqlite3` opens it; the live one runs in MVCC mode), and `wg-server.key`, the server's
//!   private key. Encrypted with `age` in passphrase mode, so
//!   `age -d payload.tar.age | tar x` opens one by hand.
//!
//! The plaintext payload's bytes depend only on what it holds, so an
//! unchanged database and key give the same `contents_sha256`, and an
//! automatic backup with nothing new can be skipped.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use parallax_core::date::Date;
use parallax_core::secret::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result, Store, TempDir, MIGRATIONS, RUNTIME_TABLES};

/// The layout described above. A backup in a newer format is refused.
pub const FORMAT: u32 = 1;
const PREFIX: &str = "parallax-backup-";
/// When an automatic backup last found nothing new (Unix seconds).
const LAST_CHECK: &str = ".last-check";
const MANIFEST: &str = "manifest.toml";
const PAYLOAD: &str = "payload.tar";
const PAYLOAD_ENCRYPTED: &str = "payload.tar.age";
const DATABASE: &str = "parallax.db";
const SERVER_KEY: &str = "wg-server.key";
/// scrypt cost 2^18 (about a second and 256 MiB), fixed rather than tuned
/// to this host, so a slower one can still restore what a fast one wrote.
const WORK_FACTOR: u8 = 18;
/// The most a restore accepts (1 GiB), so a hand-made file can't make it
/// exhaust memory.
const MAX_WORK_FACTOR: u8 = 20;
/// A manifest is a few hundred bytes; anything far bigger isn't one.
const MANIFEST_LIMIT: u64 = 64 * 1024;

/// What a backup says about itself, readable without the passphrase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    /// When it was made, like `2026-11-24T15:30:00Z`.
    pub created: String,
    /// The Parallax version that made it.
    pub parallax: String,
    /// The database's schema version (migrations applied).
    pub schema: i64,
    pub encrypted: bool,
    /// SHA-256 of the payload as stored.
    pub payload_sha256: String,
    /// SHA-256 of the plaintext payload. It reveals nothing about the
    /// contents: they include the server's private key, which can't be guessed.
    pub contents_sha256: String,
}

/// A backup file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub path: PathBuf,
    /// When it was made (Unix seconds), from its name.
    pub created: u64,
}

/// What goes into a backup, taken but not yet written.
pub struct Snapshot {
    payload: Vec<u8>,
    contents_sha256: String,
    schema: i64,
}

impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Snapshot")
            .field("contents_sha256", &self.contents_sha256)
            .finish_non_exhaustive()
    }
}

impl Snapshot {
    /// Equal for equal database contents and server key.
    pub fn contents_sha256(&self) -> &str {
        &self.contents_sha256
    }
}

/// An opened backup, checked against its checksums.
pub struct Contents {
    pub manifest: Manifest,
    database: Vec<u8>,
    server_key: Secret,
}

impl std::fmt::Debug for Contents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Contents")
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl Contents {
    /// The server's private key file, as it was.
    pub fn server_key(&self) -> &Secret {
        &self.server_key
    }

    /// Write the database into `directory` and open it there: migrated to
    /// this Parallax's schema and checked for damage. Restore it into the
    /// live database with [`Store::replace_with`].
    pub async fn stage(&self, directory: &Path) -> Result<Store> {
        let path = directory.join(DATABASE);
        write_private(&path, &self.database)?;
        let store = Store::open(&path).await?;
        store.check_integrity().await?;
        Ok(store)
    }
}

impl Store {
    /// Take what a backup holds: a consistent copy of the database (made in
    /// a private directory next to it) and the server's private key.
    pub async fn snapshot(&self, server_key: &Path) -> Result<Snapshot> {
        let key = std::fs::read(server_key).map_err(|e| {
            Error::io(
                format!("reading the server key {}", server_key.display()),
                e,
            )
        })?;

        let scratch = TempDir::new_in(parent(&self.path), ".parallax-backup")?;
        // The copy is rebuilt from the rows, not copied from the file: the
        // live database is in MVCC mode, which `sqlite3` can't open and
        // which numbers re-inserted rows anew on every save, so a file copy
        // of the same configuration would differ each time. Rebuilt in the
        // default mode, the same rows always give the same bytes.
        let rebuilt_path = scratch.path().join("rebuilt.db");
        let mut rebuilt = Store::create_plain(&rebuilt_path).await?;
        let reader = self.reader().await?;
        rebuilt
            .replace_with(&reader, None)
            .await
            .map_err(|e| self.busy(e))?;
        drop(reader);
        let copy = scratch.path().join(DATABASE);
        let target = copy.to_str().filter(|p| !p.contains('\'')).ok_or_else(|| {
            Error::Invalid(format!(
                "can't copy the database to {}: the path must be UTF-8 without quotes",
                copy.display()
            ))
        })?;
        // Compacted into one file, without the rebuild's log.
        rebuilt
            .conn
            .execute(&format!("VACUUM INTO '{target}'"), ())
            .await?;
        drop(rebuilt);
        let database = std::fs::read(&copy)
            .map_err(|e| Error::io(format!("reading {}", copy.display()), e))?;
        let payload = pack(&[(DATABASE, &database), (SERVER_KEY, &key)], 0)?;
        Ok(Snapshot {
            contents_sha256: sha256(&payload),
            payload,
            schema: self.schema_version().await?,
        })
    }

    /// Fail unless SQLite's integrity check passes.
    pub async fn check_integrity(&self) -> Result<()> {
        let problems: Vec<String> = self
            .rows("PRAGMA integrity_check", Vec::new())
            .await?
            .iter()
            .map(|r| r.get::<String>(0))
            .filter(|r| !matches!(r.as_deref(), Ok("ok")))
            .map(|r| r.unwrap_or_else(|e| e.to_string()))
            .collect();
        if problems.is_empty() {
            Ok(())
        } else {
            Err(Error::Stored(format!(
                "{} is damaged: {}",
                self.path.display(),
                problems.join("; ")
            )))
        }
    }

    /// Replace every row of this database with `source`'s, in one write
    /// transaction. Ids are copied as they are, so anything pointing at a
    /// row by id points at the same thing again. Both must be at the same
    /// schema version.
    ///
    /// `expected` is what this database must still hold, checked inside the
    /// same transaction (`None`: no configuration yet); otherwise nothing is
    /// replaced and the result is [`Error::Changed`]. So a change made after
    /// the caller looked (and backed it up) is never lost.
    pub async fn replace_with(
        &mut self,
        source: &Store,
        expected: Option<&parallax_core::Config>,
    ) -> Result<()> {
        let (ours, theirs) = (self.schema_version().await?, source.schema_version().await?);
        let tables = source.tables().await?;
        if ours != theirs || self.tables().await? != tables {
            return Err(Error::Invalid(format!(
                "{} (schema {theirs}) and {} (schema {ours}) don't have the same tables",
                source.path.display(),
                self.path.display()
            )));
        }
        self.tighten()?;
        self.begin().await.map_err(|e| self.busy(e))?;
        let result = async {
            let found = match self.load_inner().await {
                Ok(config) => Some(config),
                Err(Error::Empty(_)) => None,
                Err(e) => return Err(e),
            };
            if found.as_ref() != expected {
                return Err(Error::Changed(self.path.clone()));
            }
            // Parents before children: delete in reverse, fill in order,
            // and every reference holds throughout. This machine's runtime
            // state stays: the backup's is older.
            let tables: Vec<&String> = tables
                .iter()
                .filter(|t| !RUNTIME_TABLES.contains(&t.as_str()))
                .collect();
            for table in tables.iter().rev() {
                self.exec(&format!("DELETE FROM {table}"), Vec::new())
                    .await?;
            }
            for table in tables {
                // A busy source is named as itself, not as this database.
                let columns: Vec<String> = source
                    .rows(&format!("PRAGMA table_info({table})"), Vec::new())
                    .await
                    .map_err(|e| source.busy(e))?
                    .iter()
                    .map(|r| r.get::<String>(1))
                    .collect::<std::result::Result<_, _>>()?;
                let list = columns.join(", ");
                let slots: Vec<String> = (1..=columns.len()).map(|i| format!("?{i}")).collect();
                let insert = format!("INSERT INTO {table} ({list}) VALUES ({})", slots.join(", "));
                // In stored order, so the copy gets its rows in the same
                // order every time (a backup's bytes depend only on them).
                for row in source
                    .rows(
                        &format!("SELECT {list} FROM {table} ORDER BY rowid"),
                        Vec::new(),
                    )
                    .await
                    .map_err(|e| source.busy(e))?
                {
                    let values = (0..columns.len())
                        .map(|i| row.get_value(i))
                        .collect::<std::result::Result<Vec<_>, _>>()?;
                    self.exec(&insert, values).await?;
                }
            }
            Ok(())
        }
        .await;
        self.finish(result).await.map_err(|e| self.busy(e))?;
        self.tighten_after_commit();
        Ok(())
    }

    /// Every table holding data, each after the tables it points at.
    async fn tables(&self) -> Result<Vec<String>> {
        let mut pending = self.data_tables().await?;
        let mut parents = BTreeMap::new();
        for table in &pending {
            let refs: Vec<String> = self
                .rows(&format!("PRAGMA foreign_key_list({table})"), Vec::new())
                .await?
                .iter()
                .map(|r| r.get::<String>(2))
                .collect::<std::result::Result<_, _>>()?;
            parents.insert(table.clone(), refs);
        }
        let mut ordered: Vec<String> = Vec::new();
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .position(|t| parents[t].iter().all(|p| p == t || ordered.contains(p)));
            match ready {
                Some(i) => ordered.push(pending.remove(i)),
                None => {
                    return Err(Error::Stored(format!(
                        "{}: the tables {} point at each other",
                        self.path.display(),
                        pending.join(", ")
                    )))
                }
            }
        }
        Ok(ordered)
    }

    /// Every table holding data, in the order they were created.
    async fn data_tables(&self) -> Result<Vec<String>> {
        let names: Vec<String> = self
            .rows(
                "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY rowid",
                Vec::new(),
            )
            .await?
            .iter()
            .map(|r| r.get::<String>(0))
            .collect::<std::result::Result<_, _>>()?;
        let mut tables = Vec::new();
        for name in names {
            // Turso's MVCC bookkeeping, not ours.
            if name == "schema_version"
                || name.starts_with("sqlite_")
                || name.starts_with("__turso_internal")
            {
                continue;
            }
            // Names go into SQL unquoted; ours are all plain identifiers.
            if !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                return Err(Error::Stored(format!(
                    "{} holds a table named '{name}', which Parallax didn't create",
                    self.path.display()
                )));
            }
            tables.push(name);
        }
        Ok(tables)
    }
}

/// Write `snapshot` into `directory` (created 0700 if missing) as a new
/// backup, encrypted when there's a passphrase.
pub fn write(
    snapshot: &Snapshot,
    directory: &Path,
    passphrase: Option<&Secret>,
    now: SystemTime,
) -> Result<(PathBuf, Manifest)> {
    let secs = unix_secs(now);
    let (compact, created) = stamp(secs);
    let (name, payload) = match passphrase {
        Some(p) => (
            PAYLOAD_ENCRYPTED,
            Cow::Owned(encrypt(&snapshot.payload, p)?),
        ),
        None => (PAYLOAD, Cow::Borrowed(&snapshot.payload)),
    };
    let manifest = Manifest {
        format: FORMAT,
        created,
        parallax: env!("CARGO_PKG_VERSION").to_string(),
        schema: snapshot.schema,
        encrypted: passphrase.is_some(),
        payload_sha256: sha256(&payload),
        contents_sha256: snapshot.contents_sha256.clone(),
    };
    let text = toml::to_string(&manifest)
        .map_err(|e| Error::Invalid(format!("writing a backup manifest: {e}")))?;
    let archive = pack(&[(MANIFEST, text.as_bytes()), (name, &payload)], secs)?;
    create_dir(directory)?;
    let path = write_new(directory, &compact, &archive)?;
    Ok((path, manifest))
}

/// The backups in `directory`, oldest first. None if it doesn't exist.
pub fn list(directory: &Path) -> Result<Vec<Listed>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(format!("reading {}", directory.display()), e)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(format!("reading {}", directory.display()), e))?;
        let name = entry.file_name();
        if let Some(order) = name.to_str().and_then(parse_name) {
            found.push((order, entry.path()));
        }
    }
    found.sort();
    Ok(found
        .into_iter()
        .map(|((created, _), path)| Listed { path, created })
        .collect())
}

/// When an automatic backup last found nothing new to back up in
/// `directory` (Unix seconds); `None` if never, or if the record is unreadable
/// (then the next check just runs).
pub fn last_check(directory: &Path) -> Option<u64> {
    std::fs::read_to_string(directory.join(LAST_CHECK))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Record that an automatic backup found nothing new at `now`, so the next
/// look is a whole interval later.
pub fn record_check(directory: &Path, now: SystemTime) -> Result<()> {
    let path = directory.join(LAST_CHECK);
    std::fs::write(&path, format!("{}\n", unix_secs(now)))
        .map_err(|e| Error::io(format!("writing {}", path.display()), e))
}

/// Delete all but the newest `keep` backups in `directory`, never
/// `written` (just made; after the clock went back it may not sort newest).
/// Returns the deleted files.
pub fn rotate(directory: &Path, keep: usize, written: &Path) -> Result<Vec<PathBuf>> {
    let others: Vec<Listed> = list(directory)?
        .into_iter()
        .filter(|b| b.path != written)
        .collect();
    let excess = others.len().saturating_sub(keep.saturating_sub(1));
    let mut deleted = Vec::new();
    for old in others.into_iter().take(excess) {
        std::fs::remove_file(&old.path)
            .map_err(|e| Error::io(format!("deleting {}", old.path.display()), e))?;
        deleted.push(old.path);
    }
    Ok(deleted)
}

/// Read a backup's manifest, and refuse a backup this Parallax can't
/// restore. Needs no passphrase.
pub fn inspect(file: &Path) -> Result<Manifest> {
    let reader = std::fs::File::open(file)
        .map_err(|e| Error::io(format!("opening {}", file.display()), e))?;
    let mut archive = tar::Archive::new(std::io::BufReader::new(reader));
    let not_a_backup = || Error::backup(file, "is not a Parallax backup (no manifest.toml first)");
    let mut entries = archive.entries().map_err(|_| not_a_backup())?;
    let mut entry = match entries.next() {
        Some(Ok(entry)) => entry,
        _ => return Err(not_a_backup()),
    };
    if entry.path().ok().as_deref() != Some(Path::new(MANIFEST)) || entry.size() > MANIFEST_LIMIT {
        return Err(not_a_backup());
    }
    let mut text = String::new();
    entry
        .read_to_string(&mut text)
        .map_err(|_| not_a_backup())?;
    parse_manifest(file, &text)
}

/// Read a whole backup and check its payload against the manifest, without
/// decrypting it.
pub fn verify(file: &Path) -> Result<Manifest> {
    read_checked(file).map(|(manifest, _)| manifest)
}

/// Open a backup: check it, decrypt it with `passphrase` if it's
/// encrypted, and check the contents against the manifest.
pub fn open(file: &Path, passphrase: Option<&Secret>) -> Result<Contents> {
    let (manifest, payload) = read_checked(file)?;
    let plain = if manifest.encrypted {
        let passphrase = passphrase.ok_or_else(|| {
            Error::backup(file, "is encrypted; restoring it needs its passphrase")
        })?;
        decrypt(file, &payload, passphrase)?
    } else {
        payload
    };
    if sha256(&plain) != manifest.contents_sha256 {
        return Err(Error::backup(
            file,
            "is damaged: its contents don't match their checksum",
        ));
    }
    let mut contents = unpack(&plain).map_err(|e| Error::backup(file, e))?;
    let database = contents
        .remove(DATABASE)
        .ok_or_else(|| Error::backup(file, format!("has no {DATABASE}")))?;
    let server_key = contents
        .remove(SERVER_KEY)
        .and_then(|k| String::from_utf8(k).ok())
        .filter(|k| parse_key(k.as_bytes()).is_some())
        .ok_or_else(|| {
            Error::backup(
                file,
                format!("has no {SERVER_KEY} holding a WireGuard private key"),
            )
        })?;
    Ok(Contents {
        manifest,
        database,
        server_key: Secret::new(server_key),
    })
}

/// The server key in a key file's contents.
pub fn parse_key(contents: &[u8]) -> Option<parallax_core::secret::PrivateKey> {
    std::str::from_utf8(contents).ok()?.trim().parse().ok()
}

/// The manifest and the stored payload, checked against its checksum.
fn read_checked(file: &Path) -> Result<(Manifest, Vec<u8>)> {
    let bytes =
        std::fs::read(file).map_err(|e| Error::io(format!("reading {}", file.display()), e))?;
    let mut entries = unpack(&bytes).map_err(|e| Error::backup(file, e))?;
    let text = entries
        .remove(MANIFEST)
        .and_then(|m| String::from_utf8(m).ok())
        .ok_or_else(|| Error::backup(file, "is not a Parallax backup (no manifest.toml)"))?;
    let manifest = parse_manifest(file, &text)?;
    let name = if manifest.encrypted {
        PAYLOAD_ENCRYPTED
    } else {
        PAYLOAD
    };
    let payload = entries
        .remove(name)
        .ok_or_else(|| Error::backup(file, format!("has no {name}")))?;
    if let Some(extra) = entries.keys().next() {
        return Err(Error::backup(file, format!("holds an unexpected {extra}")));
    }
    if sha256(&payload) != manifest.payload_sha256 {
        return Err(Error::backup(
            file,
            format!("is damaged: {name} doesn't match its checksum"),
        ));
    }
    Ok((manifest, payload))
}

fn parse_manifest(file: &Path, text: &str) -> Result<Manifest> {
    let manifest: Manifest = toml::from_str(text)
        .map_err(|e| Error::backup(file, format!("has an unreadable manifest.toml: {e}")))?;
    let known = MIGRATIONS.len() as i64;
    if manifest.format > FORMAT || manifest.schema > known {
        return Err(Error::backup(
            file,
            format!(
                "was made by Parallax {} (backup format {}, database schema {}), but this is Parallax {} (format {FORMAT}, schema {known}); upgrade Parallax to {} or newer to restore it",
                manifest.parallax,
                manifest.format,
                manifest.schema,
                env!("CARGO_PKG_VERSION"),
                manifest.parallax
            ),
        ));
    }
    Ok(manifest)
}

fn encrypt(plain: &[u8], passphrase: &Secret) -> Result<Vec<u8>> {
    let mut recipient =
        age::scrypt::Recipient::new(age::secrecy::SecretString::from(passphrase.expose()));
    recipient.set_work_factor(WORK_FACTOR);
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
            .map_err(|e| Error::Invalid(format!("encrypting the backup: {e}")))?;
    let io = |e| Error::io("encrypting the backup", e);
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).map_err(io)?;
    writer.write_all(plain).map_err(io)?;
    writer.finish().map_err(io)?;
    Ok(out)
}

fn decrypt(file: &Path, payload: &[u8], passphrase: &Secret) -> Result<Vec<u8>> {
    use age::DecryptError as E;
    let failed = |e: E| match e {
        E::DecryptionFailed | E::KeyDecryptionFailed | E::NoMatchingKeys => {
            Error::WrongPassphrase(file.to_path_buf())
        }
        e => Error::backup(file, format!("can't be decrypted: {e}")),
    };
    let decryptor = age::Decryptor::new(payload).map_err(failed)?;
    if !decryptor.is_scrypt() {
        return Err(Error::backup(file, "is not encrypted with a passphrase"));
    }
    let mut identity =
        age::scrypt::Identity::new(age::secrecy::SecretString::from(passphrase.expose()));
    identity.set_max_work_factor(MAX_WORK_FACTOR);
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(failed)?;
    let mut plain = Vec::new();
    reader
        .read_to_end(&mut plain)
        .map_err(|e| Error::backup(file, format!("can't be decrypted: {e}")))?;
    Ok(plain)
}

/// A tar of owner-only files, all stamped `mtime`, so equal input gives
/// equal bytes.
fn pack(files: &[(&str, &[u8])], mtime: u64) -> Result<Vec<u8>> {
    let io = |e| Error::io("packing the backup", e);
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in files {
        let mut header = tar::Header::new_ustar();
        header.set_path(name).map_err(io)?;
        header.set_size(data.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(mtime);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, *data).map_err(io)?;
    }
    builder.into_inner().map_err(io)
}

/// The regular files in a tar, by name. Anything else, or a name twice,
/// makes it not a backup.
fn unpack(bytes: &[u8]) -> std::result::Result<BTreeMap<String, Vec<u8>>, String> {
    let unreadable = |e: std::io::Error| format!("is not a readable tar file: {e}");
    let mut archive = tar::Archive::new(bytes);
    let mut files = BTreeMap::new();
    for entry in archive.entries().map_err(unreadable)? {
        let mut entry = entry.map_err(unreadable)?;
        let name = entry
            .path()
            .ok()
            .and_then(|p| p.to_str().map(str::to_string))
            .ok_or("holds an entry with an unreadable name")?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            return Err(format!("holds {name}, which is not a regular file"));
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(unreadable)?;
        if files.insert(name.clone(), data).is_some() {
            return Err(format!("holds {name} twice"));
        }
    }
    Ok(files)
}

fn sha256(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `20261124T153000Z` for file names and `2026-11-24T15:30:00Z` for people.
fn stamp(secs: u64) -> (String, String) {
    let date = Date::from_unix_days((secs / 86_400) as i64);
    let rest = secs % 86_400;
    let (h, m, s) = (rest / 3600, rest / 60 % 60, rest % 60);
    (
        format!(
            "{:04}{:02}{:02}T{h:02}{m:02}{s:02}Z",
            date.year, date.month, date.day
        ),
        format!("{date}T{h:02}:{m:02}:{s:02}Z"),
    )
}

/// `parallax-backup-<stamp>[-<n>].tar` → (Unix seconds, n).
fn parse_name(name: &str) -> Option<(u64, u32)> {
    let rest = name.strip_prefix(PREFIX)?.strip_suffix(".tar")?;
    let (stamp, n) = match rest.split_once('-') {
        Some((stamp, n)) => (stamp, n.parse().ok()?),
        None => (rest, 0),
    };
    let b = stamp.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let num = |range: std::ops::Range<usize>| stamp.get(range)?.parse::<u32>().ok();
    let date = Date::new(num(0..4)? as i32, num(4..6)? as u8, num(6..8)? as u8).ok()?;
    let (h, m, s) = (num(9..11)?, num(11..13)?, num(13..15)?);
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    let days = u64::try_from(date.to_unix_days()).ok()?;
    Some((days * 86_400 + u64::from(h * 3600 + m * 60 + s), n))
}

/// The directory a path is in, `.` for a bare name.
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

fn create_dir(directory: &Path) -> Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .map_err(|e| Error::io(format!("creating {}", directory.display()), e))
}

/// Create `path` owner-only; fails if it exists.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let ctx = || format!("writing {}", path.display());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| Error::io(ctx(), e))?;
    f.write_all(data).map_err(|e| Error::io(ctx(), e))?;
    f.sync_all().map_err(|e| Error::io(ctx(), e))
}

/// Write a new backup file under the first free name, completely or not at
/// all: a partial file (crash, full disk) never looks like a backup, and two
/// writers at the same second never touch each other's file.
fn write_new(directory: &Path, stamp: &str, data: &[u8]) -> Result<PathBuf> {
    let scratch = TempDir::new_in(directory, ".partial")?;
    let partial = scratch.path().join("backup.tar");
    write_private(&partial, data)?;
    for n in 0..100 {
        let name = match n {
            0 => format!("{PREFIX}{stamp}.tar"),
            n => format!("{PREFIX}{stamp}-{n}.tar"),
        };
        let path = directory.join(&name);
        // A hard link never replaces an existing file.
        match std::fs::hard_link(&partial, &path) {
            Ok(()) => {
                sync_dir(directory)?;
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::io(format!("writing {}", path.display()), e)),
        }
    }
    Err(Error::Invalid(format!(
        "{} already holds 100 backups made at {stamp}",
        directory.display()
    )))
}

/// Make a new name in `directory` survive a crash.
fn sync_dir(directory: &Path) -> Result<()> {
    std::fs::File::open(directory)
        .and_then(|d| d.sync_all())
        .map_err(|e| Error::io(format!("syncing {}", directory.display()), e))
}

#[cfg(test)]
mod tests;
