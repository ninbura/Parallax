//! Root on a native install. The service runs as its own user and owns its
//! directories; root (`sudo parallax ...`) must not leave files there that the
//! service can't open. In Docker everything is root's, and none of this applies.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// This process's effective uid, from `/proc/self/status` (`Uid:` holds the
/// real, effective, saved and filesystem uids).
fn effective_uid() -> Option<u32> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// The directory `path` is in.
fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// Owner (uid, gid) of `dir` when this process is root and someone else owns it.
fn foreign_owner(dir: &Path) -> Option<(u32, u32)> {
    if effective_uid()? != 0 {
        return None;
    }
    let meta = std::fs::metadata(dir).ok()?;
    (meta.uid() != 0).then(|| (meta.uid(), meta.gid()))
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

/// When root is about to open `db` itself, and the database's directory
/// belongs to another user (the service's): who that is, as "user 'name'" (or
/// "uid N") and as a `sudo -u` argument. Root opening it would leave files
/// (`-wal`, `-tshm`) that user can't open.
pub(crate) fn services_database(db: &Path) -> Option<(String, String)> {
    let (uid, _) = foreign_owner(dir_of(db))?;
    Some(match user_name(uid) {
        Some(name) => (format!("user '{name}'"), name),
        None => (format!("uid {uid}"), format!("#{uid}")),
    })
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
