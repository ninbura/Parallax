/// Every fallible operation in the crate returns this.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors raised by the proxy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file, socket or runtime failure.
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    /// A certificate, key, CA bundle or TLS setting is unusable.
    #[error("{context}: {detail}")]
    Invalid { context: String, detail: String },

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

    pub(crate) fn invalid(context: impl std::fmt::Display, detail: impl std::fmt::Display) -> Self {
        Error::Invalid {
            context: context.to_string(),
            detail: detail.to_string(),
        }
    }
}
