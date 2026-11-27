//! The activity database, `logs.db` (docs/logging.md): what the collector
//! records about logged peers. Its own file beside the configuration, so it
//! can live on another disk and grow without touching the configuration.
//!
//! Writers each hold their own connection and commit their batches with
//! `BEGIN CONCURRENT` (docs/adr/0011-mvcc.md), so the collector's sources
//! never wait for each other.

use std::net::Ipv4Addr;
use std::path::Path;

use parallax_core::logging::{Record, RecordKind};
use turso::{Row, Value};

use crate::{create_file, Error, Result, Store, BUSY_TIMEOUT};

const MIGRATIONS: &[&str] = &[include_str!("../migrations/logs/0001_records.sql")];

/// How often a batch is retried when another writer's commit conflicts.
const RETRIES: u32 = 5;

/// Rows deleted per statement while purging, so a big purge never holds
/// a long transaction.
const PURGE_CHUNK: i64 = 5000;
/// Rounds of measuring and deleting while over the size.
const SIZE_ROUNDS: usize = 3;
const CHECKPOINT_TRIES: u32 = 10;

/// The open activity database.
#[derive(Debug)]
pub struct Logs {
    store: Store,
}

/// A connection that adds records; one per source.
pub struct Writer {
    conn: turso::Connection,
    path: std::path::PathBuf,
}

impl std::fmt::Debug for Writer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Writer").field("path", &self.path).finish()
    }
}

/// Which records to read: the newest `limit` that match, older than
/// `before` (an id) if given, for reading history a page at a time.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub peer: Option<String>,
    /// Any of these kinds; empty: every kind.
    pub kinds: Vec<RecordKind>,
    /// Unix milliseconds.
    pub since: Option<u64>,
    #[serde(default)]
    pub before: Option<i64>,
    pub limit: u32,
}

/// What a purge deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Purged {
    pub expired: u64,
    pub over_size: u64,
}

impl Logs {
    /// Open the activity database at `path`, creating it (and its
    /// directory, 0700) if there is none.
    pub async fn open(path: &Path) -> Result<Logs> {
        create_file(path)?;
        let store = Store::open_inner(path, MIGRATIONS, true).await?;
        Ok(Logs { store })
    }

    pub fn path(&self) -> &Path {
        &self.store.path
    }

    /// A new connection for one source's batches.
    pub fn writer(&self) -> Result<Writer> {
        let conn = self.store.db.connect()?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        Ok(Writer {
            conn,
            path: self.store.path.clone(),
        })
    }

    /// Records matching `query`, each with its id, oldest first.
    pub async fn query(&self, query: &Query) -> Result<Vec<(i64, Record)>> {
        let mut conditions = Vec::new();
        let mut params: Vec<Value> = Vec::new();
        if let Some(peer) = &query.peer {
            params.push(peer.clone().into());
            conditions.push(format!("peer = ?{}", params.len()));
        }
        if !query.kinds.is_empty() {
            let mut slots = Vec::new();
            for kind in &query.kinds {
                params.push(kind.as_str().into());
                slots.push(format!("?{}", params.len()));
            }
            conditions.push(format!("kind IN ({})", slots.join(", ")));
        }
        if let Some(since) = query.since {
            params.push(int(since).into());
            conditions.push(format!("time >= ?{}", params.len()));
        }
        if let Some(before) = query.before {
            params.push(before.into());
            conditions.push(format!("id < ?{}", params.len()));
        }
        let filter = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        // The newest: read backward, then turn them around.
        params.push(i64::from(query.limit).into());
        let sql = format!(
            "SELECT id, time, kind, peer, grants, source, destination, real_destination,
                    network, protocol, port, flow, bytes_out, bytes_in
             FROM records {filter} ORDER BY id DESC LIMIT ?{}",
            params.len()
        );
        let mut out = Vec::new();
        for row in self.store.rows(&sql, params).await? {
            out.push(record(&self.store.path, &row)?);
        }
        out.reverse();
        Ok(out)
    }

    /// Delete records older than `before` (Unix milliseconds), then the
    /// oldest until what's left takes up no more than 90% of `max_bytes`
    /// (so a full database isn't purged on every pass). Deleted rows free
    /// pages that new rows reuse; the file itself doesn't shrink.
    pub async fn purge(&self, before: u64, max_bytes: u64) -> Result<Purged> {
        let mut purged = Purged::default();
        let before = Value::from(int(before));
        // In chunks, each up to a cut-off id found first: plain range
        // deletes, none holding a long transaction.
        loop {
            let cut = self
                .id_at(
                    "SELECT id FROM records WHERE time < ?1 ORDER BY id LIMIT 1 OFFSET ?2",
                    vec![before.clone(), (PURGE_CHUNK - 1).into()],
                )
                .await?;
            let n = match cut {
                Some(cut) => {
                    self.store
                        .exec(
                            "DELETE FROM records WHERE time < ?1 AND id <= ?2",
                            vec![before.clone(), cut.into()],
                        )
                        .await?
                }
                None => {
                    self.store
                        .exec("DELETE FROM records WHERE time < ?1", vec![before.clone()])
                        .await?
                }
            };
            purged.expired += n;
            if cut.is_none() {
                break;
            }
        }
        // Rows differ in size, so measure again after each round.
        for _ in 0..SIZE_ROUNDS {
            let used = self.used_bytes().await?;
            if used <= max_bytes {
                break;
            }
            let count = self.count().await?;
            let target = max_bytes / 10 * 9;
            // Rows are about the same size, so drop the same share of them.
            let share = (used - target) as f64 / used as f64;
            let mut left = ((count as f64 * share).ceil() as i64).min(count);
            while left > 0 {
                let chunk = left.min(PURGE_CHUNK);
                let Some(cut) = self
                    .id_at(
                        "SELECT id FROM records ORDER BY id LIMIT 1 OFFSET ?1",
                        vec![(chunk - 1).into()],
                    )
                    .await?
                else {
                    break;
                };
                let n = self
                    .store
                    .exec("DELETE FROM records WHERE id <= ?1", vec![cut.into()])
                    .await?;
                purged.over_size += n;
                left -= chunk;
            }
        }
        Ok(purged)
    }

    /// The id a one-column query finds, if any.
    async fn id_at(&self, sql: &str, params: Vec<Value>) -> Result<Option<i64>> {
        let rows = self.store.rows(sql, params).await?;
        rows.first()
            .map(|r| r.get::<i64>(0))
            .transpose()
            .map_err(Into::into)
    }

    /// Bytes the records take up: pages in use, after moving MVCC's log
    /// into the file so the count is current.
    pub async fn used_bytes(&self) -> Result<u64> {
        // A writer's open transaction can hold the checkpoint off briefly.
        for attempt in 1..=CHECKPOINT_TRIES {
            let busy = match self
                .store
                .rows("PRAGMA wal_checkpoint(TRUNCATE)", Vec::new())
                .await
            {
                // SQLite's answer: busy, then log and checkpointed pages.
                Ok(rows) => rows
                    .first()
                    .is_some_and(|r| r.get::<i64>(0).ok() == Some(1)),
                Err(Error::Db(turso::Error::Busy(_))) => true,
                Err(e) => return Err(e),
            };
            if !busy {
                break;
            }
            if attempt == CHECKPOINT_TRIES {
                return Err(Error::Locked(self.store.path.clone()));
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        let pragma = |name: &'static str| async move {
            let rows = self
                .store
                .rows(&format!("PRAGMA {name}"), Vec::new())
                .await?;
            let value = match rows.first() {
                Some(r) => r.get::<i64>(0)?,
                None => 0,
            };
            Ok::<u64, Error>(u64::try_from(value).unwrap_or(0))
        };
        let pages = pragma("page_count").await?;
        let free = pragma("freelist_count").await?;
        let size = pragma("page_size").await?;
        Ok(pages.saturating_sub(free) * size)
    }

    async fn count(&self) -> Result<i64> {
        let rows = self
            .store
            .rows("SELECT count(*) FROM records", Vec::new())
            .await?;
        Ok(match rows.first() {
            Some(r) => r.get::<i64>(0)?,
            None => 0,
        })
    }
}

impl Writer {
    /// Add `records` in one transaction, retried when another writer's
    /// commit conflicts with it.
    pub async fn write(&self, records: &[Record]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let mut attempt = 0;
        loop {
            match self.write_once(records).await {
                Ok(()) => return Ok(()),
                // Busy already waited out its timeout: don't wait again.
                Err(Error::Db(turso::Error::Busy(_))) => {
                    return Err(Error::Locked(self.path.clone()))
                }
                Err(e) if attempt < RETRIES && conflict(&e) => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(10 * u64::from(attempt)))
                        .await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn write_once(&self, records: &[Record]) -> Result<()> {
        self.conn.execute("BEGIN CONCURRENT", ()).await?;
        let result = async {
            let mut insert = self
                .conn
                .prepare(
                    "INSERT INTO records (time, kind, peer, grants, source, destination,
                        real_destination, network, protocol, port, flow, bytes_out, bytes_in)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                )
                .await?;
            for r in records {
                insert.execute(row_values(r)).await?;
            }
            Ok::<(), Error>(())
        }
        .await;
        match result {
            Ok(()) => match self.conn.execute("COMMIT", ()).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    let _ = self.conn.execute("ROLLBACK", ()).await;
                    Err(e.into())
                }
            },
            Err(e) => {
                let _ = self.conn.execute("ROLLBACK", ()).await;
                Err(e)
            }
        }
    }
}

/// Another concurrent transaction won: try again.
fn conflict(e: &Error) -> bool {
    matches!(e, Error::Db(e) if e.to_string().to_ascii_lowercase().contains("conflict"))
}

fn row_values(r: &Record) -> Vec<Value> {
    let text_opt = |v: Option<String>| v.map_or(Value::Null, Value::from);
    let int_opt = |v: Option<u64>| v.map_or(Value::Null, |n| Value::from(int(n)));
    vec![
        int(r.time).into(),
        r.kind.as_str().into(),
        r.peer.clone().into(),
        r.grants.clone().into(),
        r.source.to_string().into(),
        r.destination.to_string().into(),
        text_opt(r.real_destination.map(|a| a.to_string())),
        text_opt(r.network.clone()),
        r.protocol.clone().into(),
        r.port.map_or(Value::Null, |p| Value::from(i64::from(p))),
        r.flow.map_or(Value::Null, |f| Value::from(i64::from(f))),
        int_opt(r.bytes_out),
        int_opt(r.bytes_in),
    ]
}

/// Stored as SQLite's signed integers; nothing we keep comes near the limit.
fn int(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn record(path: &Path, r: &Row) -> Result<(i64, Record)> {
    let at = |what: &str, value: &str| {
        Error::Stored(format!("{}: record {what} '{value}'", path.display()))
    };
    let addr = |s: String| -> Result<Ipv4Addr> { s.parse().map_err(|_| at("address", &s)) };
    let unsigned = |v: Option<i64>| v.map(|n| u64::try_from(n).unwrap_or(0));
    let kind: String = r.get(2)?;
    Ok((
        r.get(0)?,
        Record {
            time: unsigned(Some(r.get(1)?)).unwrap_or(0),
            kind: kind.parse().map_err(|_| at("kind", &kind))?,
            peer: r.get(3)?,
            grants: r.get(4)?,
            source: addr(r.get(5)?)?,
            destination: addr(r.get(6)?)?,
            real_destination: r.get::<Option<String>>(7)?.map(addr).transpose()?,
            network: r.get(8)?,
            protocol: r.get(9)?,
            port: r
                .get::<Option<i64>>(10)?
                .and_then(|p| u16::try_from(p).ok()),
            flow: r
                .get::<Option<i64>>(11)?
                .and_then(|f| u32::try_from(f).ok()),
            bytes_out: unsigned(r.get(12)?),
            bytes_in: unsigned(r.get(13)?),
        },
    ))
}

#[cfg(test)]
mod tests;
