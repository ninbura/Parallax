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

    /// Another process kept writing for longer than we wait.
    #[error("database {0} is busy with another Parallax process's write; try again in a moment")]
    Locked(PathBuf),

    /// The database was written by a newer Parallax (or its version is garbage).
    #[error("database {path} has schema version {found}, but this Parallax knows only 0 to {known}; upgrade Parallax")]
    TooNew {
        path: PathBuf,
        found: i64,
        known: i64,
    },

    /// A backup file that can't be used, and why.
    #[error("backup {file}: {problem}")]
    Backup { file: PathBuf, problem: String },

    /// The database changed between showing a restore and doing it.
    #[error(
        "database {0} changed while the restore waited; nothing restored. Run the restore again"
    )]
    Changed(PathBuf),

    /// An encrypted backup didn't open with the passphrase given.
    #[error("backup {0} did not decrypt; the passphrase is wrong")]
    WrongPassphrase(PathBuf),

    /// A configuration the store can't represent, e.g. a grant naming a
    /// network that doesn't exist. Validation catches these first.
    #[error("{0}")]
    Invalid(String),

    /// A value in the database doesn't parse back into the model.
    #[error("database holds an invalid value: {0}")]
    Stored(String),

    /// The database engine failed. Not a `source`: the message already
    /// carries it, and `{:#}` would print it twice.
    #[error("database: {0}")]
    Db(turso::Error),

    /// A file around the database couldn't be prepared. (`error`, not
    /// `source`, for the same reason as `Db`.)
    #[error("{context}: {error}")]
    Io {
        context: String,
        error: std::io::Error,
    },
}

impl From<turso::Error> for Error {
    fn from(e: turso::Error) -> Self {
        Error::Db(e)
    }
}

impl Error {
    pub(crate) fn backup(file: &std::path::Path, problem: impl std::fmt::Display) -> Self {
        Error::Backup {
            file: file.to_path_buf(),
            problem: problem.to_string(),
        }
    }

    pub(crate) fn io(context: impl std::fmt::Display, error: std::io::Error) -> Self {
        Error::Io {
            context: context.to_string(),
            error,
        }
    }
}
