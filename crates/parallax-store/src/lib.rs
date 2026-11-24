//! Parallax's database: the source of truth for the configuration.
//!
//! One file in SQLite's format, written through Turso. [`Store::load`]
//! returns the whole [`parallax_core::Config`] and [`Store::save`] writes one
//! back in a single transaction, row by row: rows keep their ids, so
//! anything pointing at them (later, the GUI's own tables) survives.
//!
//! Turso takes an exclusive lock on the file, so a second process can't open
//! it while one has it. Commands open the store, do their work and drop it;
//! opening waits briefly for another holder to finish.

#![warn(missing_debug_implementations, rust_2018_idioms)]

mod config;
mod error;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use error::{Error, Result};

/// Schema migrations, applied in order. Never edit one that has shipped;
/// add the next.
const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_config.sql")];

/// How long opening waits for another process to release the database.
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_RETRY: Duration = Duration::from_millis(50);

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

    /// Open a database, creating an empty one if there is none.
    pub async fn create(path: &Path) -> Result<Store> {
        Store::open_inner(path).await
    }

    /// Where the database lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn open_inner(path: &Path) -> Result<Store> {
        prepare_files(path)?;
        let name = path
            .to_str()
            .ok_or_else(|| Error::Invalid(format!("{} is not valid UTF-8", path.display())))?;
        let deadline = Instant::now() + LOCK_WAIT;
        let db = loop {
            match turso::Builder::new_local(name).build().await {
                Ok(db) => break db,
                Err(e) if is_locked(&e) => {
                    if Instant::now() >= deadline {
                        return Err(Error::Locked(path.to_path_buf()));
                    }
                    tokio::time::sleep(LOCK_RETRY).await;
                }
                Err(e) => return Err(e.into()),
            }
        };
        let conn = db.connect()?;
        conn.execute("PRAGMA foreign_keys = ON", ()).await?;
        let store = Store {
            path: path.to_path_buf(),
            _db: db,
            conn,
        };
        store.migrate().await?;
        Ok(store)
    }

    /// Apply every migration the database hasn't seen, each in its own transaction.
    async fn migrate(&self) -> Result<()> {
        self.conn
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
                (),
            )
            .await?;
        let found = self.schema_version().await?;
        let known = MIGRATIONS.len() as i64;
        if found > known {
            return Err(Error::TooNew {
                path: self.path.clone(),
                found,
                known,
            });
        }
        for (version, sql) in (1..).zip(MIGRATIONS).skip(found as usize) {
            self.begin().await?;
            let applied = async {
                self.conn.execute_batch(*sql).await?;
                self.conn
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        (version,),
                    )
                    .await?;
                Ok(())
            }
            .await;
            self.finish(applied).await?;
        }
        Ok(())
    }

    /// The highest migration applied; 0 for a new database.
    pub async fn schema_version(&self) -> Result<i64> {
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

    /// Commit if `result` is `Ok`, roll back otherwise.
    async fn finish<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => {
                self.conn.execute("COMMIT", ()).await?;
                Ok(value)
            }
            Err(e) => {
                // The original error matters more than a failed rollback.
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(e)
            }
        }
    }
}

/// The database and its write-ahead log hold private keys: create both
/// owner-only before Turso opens them, and tighten them if they exist.
fn prepare_files(path: &Path) -> Result<()> {
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    for file in [path, Path::new(&wal)] {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let ctx = || format!("preparing {}", file.display());
        let f = opts.open(file).map_err(|e| Error::io(ctx(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| Error::io(ctx(), e))?;
        }
    }
    Ok(())
}

/// Turso reports another process's lock as a generic error; its text is the only tell.
fn is_locked(e: &turso::Error) -> bool {
    e.to_string().contains("locked by another process")
}

#[cfg(test)]
mod tests;
