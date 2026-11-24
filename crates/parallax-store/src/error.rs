use std::path::PathBuf;

/// Every fallible operation in the crate returns this.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the store.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The database file doesn't exist and the caller didn't ask to create it.
    #[error(
        "no database at {0}; import a configuration first with `parallax config import <file>`"
    )]
    Missing(PathBuf),

    /// The database exists but nothing has been imported into it yet.
    #[error(
        "database {0} holds no configuration yet; import one with `parallax config import <file>`"
    )]
    Empty(PathBuf),

    /// Another process kept the database open for longer than we wait.
    #[error("database {0} is in use by another Parallax process; try again in a moment")]
    Locked(PathBuf),

    /// The database was written by a newer Parallax.
    #[error("database {path} has schema version {found}, but this Parallax knows only up to {known}; upgrade Parallax")]
    TooNew {
        path: PathBuf,
        found: i64,
        known: i64,
    },

    /// A configuration the store can't represent, e.g. a grant naming a
    /// network that doesn't exist. Validation catches these first.
    #[error("{0}")]
    Invalid(String),

    /// A value in the database doesn't parse back into the model.
    #[error("database holds an invalid value: {0}")]
    Stored(String),

    /// The database engine failed.
    #[error("database: {0}")]
    Db(#[from] turso::Error),

    /// A file around the database couldn't be prepared.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    pub(crate) fn io(context: impl std::fmt::Display, source: std::io::Error) -> Self {
        Error::Io {
            context: context.to_string(),
            source,
        }
    }
}
