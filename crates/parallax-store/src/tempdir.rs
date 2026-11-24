//! Private scratch directories.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{Error, Result};

/// A new owner-only (0700) directory, removed with everything in it when
/// dropped unless [`TempDir::keep`] is called.
#[derive(Debug)]
pub struct TempDir(Option<PathBuf>);

impl TempDir {
    /// Create `<parent>/<prefix>-<pid>-<time>-<count>`. `parent` must exist.
    pub fn new_in(parent: &Path, prefix: &str) -> Result<TempDir> {
        static COUNT: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let n = COUNT.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!("{prefix}-{}-{nanos:08x}-{n}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        // Fails if the name exists, so the guard only ever removes its own.
        builder
            .create(&path)
            .map_err(|e| Error::io(format!("creating {}", path.display()), e))?;
        Ok(TempDir(Some(path)))
    }

    pub fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or(Path::new(""))
    }

    /// Leave the directory in place and return it.
    pub fn keep(mut self) -> PathBuf {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}
