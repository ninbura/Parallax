//! Root on a native install. The service runs as its own user and owns its
//! directories; root (`sudo parallax ...`) must not leave files there that the
//! service can't open. In Docker everything is root's, and none of this applies.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Owner (uid, gid) of `path`, or of its nearest existing ancestor when it
/// doesn't exist yet, when this process is root and that owner isn't.
/// Symlinks are followed: what counts is the file that would be opened.
fn foreign_owner(path: &Path) -> Option<(u32, u32)> {
    if !rustix::process::geteuid().is_root() {
        return None;
    }
    let meta = path
        .ancestors()
        .filter(|p| !p.as_os_str().is_empty())
        .find_map(|p| std::fs::metadata(p).ok())?;
    (meta.uid() != 0).then(|| (meta.uid(), meta.gid()))
}

/// The directory `path` is in.
fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// The name `/etc/passwd` gives `uid`, for messages only.
fn user_name(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        (fields.nth(1)? == uid.to_string()).then(|| name.to_string())
    })
}

/// When root is about to open or write `path` itself (the database, the
/// output directory) and it belongs to another user, the service's: who that
/// is, as "user 'name'" (or "uid N") and as a `sudo -u` argument. Root would
/// leave files there (the database's `-wal` and `.db-log`, generated files)
/// that user can't open.
pub(crate) fn belongs_to_another_user(path: &Path) -> Option<(String, String)> {
    let (uid, _) = foreign_owner(path)?;
    Some(match user_name(uid) {
        Some(name) => (format!("user '{name}'"), name),
        None => (format!("uid {uid}"), format!("#{uid}")),
    })
}

/// The same for a database: the file, or the directory its `-wal` and
/// `.db-log` files go in.
pub(crate) fn database_belongs_to_another_user(db: &Path) -> Option<(String, String)> {
    belongs_to_another_user(db).or_else(|| belongs_to_another_user(dir_of(db)))
}

/// After root wrote `path` (a key or a passphrase) into a directory another
/// user owns: give it to that user, or the service couldn't read it.
pub(crate) fn hand_to_directory_owner(path: &Path) -> anyhow::Result<()> {
    use anyhow::Context;
    if let Some((uid, gid)) = foreign_owner(dir_of(path)) {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
            .with_context(|| format!("giving {} to uid {uid}", path.display()))?;
    }
    Ok(())
}
