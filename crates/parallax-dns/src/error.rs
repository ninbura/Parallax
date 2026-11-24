/// Every fallible operation in the crate returns this.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the DNS server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file, socket or runtime failure.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// The resolver for some upstream couldn't be set up, or the server stopped.
    #[error("{context}: {detail}")]
    Dns { context: String, detail: String },

    #[error(transparent)]
    Core(#[from] parallax_core::Error),
}

impl Error {
    pub(crate) fn io(context: impl std::fmt::Display, source: std::io::Error) -> Self {
        Error::Io {
            context: context.to_string(),
            source,
        }
    }

    pub(crate) fn dns(context: impl std::fmt::Display, detail: impl std::fmt::Display) -> Self {
        Error::Dns {
            context: context.to_string(),
            detail: detail.to_string(),
        }
    }
}
