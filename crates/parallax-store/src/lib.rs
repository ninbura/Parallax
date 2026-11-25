//! Parallax's database: the source of truth for the configuration.
//!
//! One file in SQLite's format, written through Turso. [`Store::load`]
//! returns the whole [`parallax_core::Config`] and [`Store::save`] writes one
//! back in a single transaction, row by row: rows keep their ids, so
//! anything pointing at them (later, the GUI's own tables) survives.
//!
//! One process at a time holds the database (Turso locks the file): the
//! daemon while it runs, otherwise each CLI command for as long as it needs.
//! Another process gets [`Error::InUse`]. Everything else asks the daemon
//! (docs/adr/0007-the-daemon.md).

#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod backup;
mod config;
mod error;
mod state;
mod tempdir;

use std::path::{Path, PathBuf};
use std::time::Duration;

pub use error::{Error, Result};
pub use tempdir::TempDir;

/// Schema migrations, applied in order. Never edit one that has shipped;
/// add the next.
const MIGRATIONS: &[&str] = &[
    include_str!("../migrations/0001_config.sql"),
    include_str!("../migrations/0002_backup.sql"),
    include_str!("../migrations/0003_public_ip.sql"),
    include_str!("../migrations/0004_host_names.sql"),
    include_str!("../migrations/0005_ports.sql"),
];

/// Tables holding what the daemon learned on this machine, not
/// configuration: a restore keeps the current rows.
const RUNTIME_TABLES: &[&str] = &["daemon_state"];

/// How long a write waits for another connection's write to commit.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// An open database.
pub struct Store {
    path: PathBuf,
    // Kept alive for as long as the connection is in use.
    _db: turso::Database,
    conn: turso::Connection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish()
    }
}

impl Store {
    /// Open an existing database and bring its schema up to date.
    pub async fn open(path: &Path) -> Result<Store> {
        if !path.exists() {
            return Err(Error::Missing(path.to_path_buf()));
        }
        Store::open_inner(path).await
    }

    /// Open a database, creating an empty one (and its directory, 0700) if
    /// there is none.
    pub async fn create(path: &Path) -> Result<Store> {
        create_file(path)?;
        Store::open_inner(path).await
    }

    /// Where the database lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn open_inner(path: &Path) -> Result<Store> {
        let name = path
            .to_str()
            .ok_or_else(|| Error::Invalid(format!("{} is not valid UTF-8", path.display())))?;
        let db = turso::Builder::new_local(name)
            .build()
            .await
            .map_err(|e| lock_error(path, e))?;
        let conn = db.connect()?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        let store = Store {
            path: path.to_path_buf(),
            _db: db,
            conn,
        };
        store.migrate().await.map_err(|e| store.busy(e))?;
        store.tighten()?;
        Ok(store)
    }

    /// The database, its log and its coordination file hold private keys:
    /// make whichever exist owner-only. By path, never by opening them:
    /// closing any descriptor of a file drops this process's locks on it.
    /// The CLI's owner-only umask covers files Turso creates later.
    fn tighten(&self) -> Result<()> {
        #[cfg(unix)]
        for suffix in ["", "-wal"] {
            use std::os::unix::fs::PermissionsExt;
            let mut file = self.path.as_os_str().to_owned();
            file.push(suffix);
            let file = Path::new(&file);
            match std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::io(format!("securing {}", file.display()), e)),
            }
        }
        Ok(())
    }

    /// Name the database when another process held it too long.
    fn busy(&self, e: Error) -> Error {
        match e {
            Error::Db(turso::Error::Busy(_)) => Error::Locked(self.path.clone()),
            e => e,
        }
    }

    /// Apply every migration the database hasn't seen. Opening an up-to-date
    /// database only reads; otherwise one write transaction re-checks the
    /// version and applies the rest, so connections opening a new database
    /// at the same time migrate it once.
    async fn migrate(&self) -> Result<()> {
        let known = MIGRATIONS.len() as i64;
        if self.check_version(known).await? == known {
            return Ok(());
        }
        self.begin().await?;
        let applied = async {
            self.conn
                .execute(
                    "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
                    (),
                )
                .await?;
            let found = self.check_version(known).await?;
            for (version, sql) in (1..).zip(MIGRATIONS).skip(found as usize) {
                self.conn.execute_batch(*sql).await?;
                self.conn
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        (version,),
                    )
                    .await?;
            }
            Ok(())
        }
        .await;
        self.finish(applied).await
    }

    /// The schema version, refusing one newer than `known`.
    async fn check_version(&self, known: i64) -> Result<i64> {
        let found = self.schema_version().await?;
        if !(0..=known).contains(&found) {
            return Err(Error::TooNew {
                path: self.path.clone(),
                found,
                known,
            });
        }
        Ok(found)
    }

    /// The highest migration applied; 0 for a new database.
    pub async fn schema_version(&self) -> Result<i64> {
        let mut rows = self
            .conn
            .query(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'schema_version'",
                (),
            )
            .await?;
        let exists = match rows.next().await? {
            Some(row) => row.get::<i64>(0)? > 0,
            None => false,
        };
        drop(rows);
        if !exists {
            return Ok(0);
        }
        let mut rows = self
            .conn
            .query("SELECT COALESCE(MAX(version), 0) FROM schema_version", ())
            .await?;
        match rows.next().await? {
            Some(row) => Ok(row.get::<i64>(0)?),
            None => Ok(0),
        }
    }

    /// Start a write transaction. Pair with [`Store::finish`].
    async fn begin(&self) -> Result<()> {
        self.conn.execute("BEGIN IMMEDIATE", ()).await?;
        Ok(())
    }

    /// Commit if `result` is `Ok`, roll back otherwise, including when the
    /// commit itself fails, so the connection never stays inside a transaction.
    async fn finish<T>(&self, result: Result<T>) -> Result<T> {
        let result = match result {
            Ok(value) => match self.conn.execute("COMMIT", ()).await {
                Ok(_) => return Ok(value),
                Err(e) => Err(e.into()),
            },
            Err(e) => Err(e),
        };
        self.rollback().await;
        result
    }

    /// Roll back, ignoring failure: the error that caused it matters more.
    async fn rollback(&self) {
        let _ = self.conn.execute("ROLLBACK", ()).await;
    }
}

/// Turso refuses a file another process holds with a plain message; name
/// the database instead.
fn lock_error(path: &Path, e: turso::Error) -> Error {
    if e.to_string().contains("locked by another process") {
        Error::InUse(path.to_path_buf())
    } else {
        Error::Db(e)
    }
}

/// Create the database file owner-only if it doesn't exist, and its
/// directory (0700) if that's missing too.
fn create_file(path: &Path) -> Result<()> {
    let ctx = || format!("creating {}", path.display());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if !dir.exists() {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(dir).map_err(|e| Error::io(ctx(), e))?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::io(ctx(), e)),
    }
}

#[cfg(test)]
mod tests;
