use std::fmt;

/// Every fallible operation in the crate returns this.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the engine.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration failed validation. Each entry is a specific, human-readable problem.
    #[error("configuration is invalid:\n{}", format_list(.0))]
    Invalid(Vec<String>),

    /// The TOML document could not be parsed or does not match the model.
    #[error("cannot parse configuration: {0}")]
    Parse(String),

    /// The requested named object does not exist.
    #[error("{kind} '{name}' not found")]
    NotFound { kind: &'static str, name: String },

    /// An address pool has no free host left.
    #[error("address pool {pool} of template '{template}' is exhausted")]
    PoolExhausted {
        template: String,
        pool: ipnet::Ipv4Net,
    },

    /// A key, address or other literal is malformed.
    #[error("malformed {what}: {detail}")]
    Malformed { what: &'static str, detail: String },

    /// Filesystem or process failure reported by an injected [`crate::io`] implementation.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// An external command ran but failed.
    #[error("command `{command}` failed (status {status}): {stderr}")]
    Command {
        command: String,
        status: i32,
        stderr: String,
    },

    /// The operation is defined by the design but not built in this milestone.
    #[error("not implemented yet: {0}")]
    NotImplemented(&'static str),
}

fn format_list(items: &[String]) -> String {
    items
        .iter()
        .map(|s| format!("  - {s}"))
        .collect::<Vec<_>>()
        .join("\n")
}

impl Error {
    pub(crate) fn io(context: impl fmt::Display, source: std::io::Error) -> Self {
        Error::Io {
            context: context.to_string(),
            source,
        }
    }
}
