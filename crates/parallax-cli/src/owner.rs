//! Root on a native install. The service runs as its own user and owns its
//! directories; root (`sudo parallax ...`) must not leave files there that the
//! service can't open, nor write anywhere just because the service's
//! configuration names it: that would hand root's power to whoever controls
//! the service. Such writes run as the service's user instead
//! ([`ConfigFiles`]). In Docker everything is root's, and none of this
//! applies.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::Context;
use parallax_core::io::real::RealFs;
use parallax_core::io::FileSystem;

/// A user other than root, that root acts as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct User {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

fn is_root() -> bool {
    rustix::process::geteuid().is_root()
}

/// When this process is root: the user other than root who owns `path` or
/// any directory on the way to it, the nearest first. Whoever owns a
/// directory can swap what's below it, so a root-owned file or directory
/// inside the service's directory is the service's to change all the same.
/// Symlinks are followed: what counts is what would be opened. The group is
/// the user's own (`/etc/passwd`), not whatever group the directory has.
fn foreign_owner(path: &Path) -> Option<User> {
    if !is_root() {
        return None;
    }
    let path = std::path::absolute(path).ok()?;
    let meta = path
        .ancestors()
        .filter_map(|p| std::fs::metadata(p).ok())
        .find(|meta| meta.uid() != 0)?;
    Some(User {
        uid: meta.uid(),
        gid: primary_gid(meta.uid()).unwrap_or(meta.gid()),
    })
}

/// The user a daemon on `stream` runs as, when this process is root and the
/// daemon isn't: the configuration it hands out is that user's to write.
/// Not knowing is an error: guessing root would hand root's writes to it.
pub(crate) fn daemon_user(
    stream: &std::os::unix::net::UnixStream,
) -> std::io::Result<Option<User>> {
    if !is_root() {
        return Ok(None);
    }
    let cred = rustix::net::sockopt::socket_peercred(stream)?;
    let user = User {
        uid: cred.uid.as_raw(),
        gid: cred.gid.as_raw(),
    };
    Ok((user.uid != 0).then_some(user))
}

/// The directory `path` is in.
fn dir_of(path: &Path) -> &Path {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    }
}

/// The fields `/etc/passwd` has for `uid`.
fn passwd_entry(uid: u32) -> Option<Vec<String>> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields: Vec<String> = line.split(':').map(str::to_string).collect();
        (fields.get(2)? == &uid.to_string()).then_some(fields)
    })
}

/// The name `/etc/passwd` gives `uid`, for messages only.
fn user_name(uid: u32) -> Option<String> {
    passwd_entry(uid)?.into_iter().next()
}

/// The primary group `/etc/passwd` gives `uid`.
fn primary_gid(uid: u32) -> Option<u32> {
    passwd_entry(uid)?.get(3)?.parse().ok()
}

/// When root is about to open or write `path` itself (the database, the
/// output directory) and it belongs to another user, the service's: who that
/// is, as "user 'name'" (or "uid N") and as a `sudo -u` argument. Root would
/// leave files there (the database's `-wal` and `.db-log`, generated files)
/// that user can't open.
pub(crate) fn belongs_to_another_user(path: &Path) -> Option<(String, String)> {
    let uid = foreign_owner(path)?.uid;
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

/// The files the configuration names (the server key, the backup
/// passphrase, the backup directory), as root should change them. When the
/// configuration came from a daemon running as another user, or the file's
/// directory belongs to one, a child of this binary writes or removes as
/// that user: then nothing that user controls (the configuration, a symlink
/// or a swapped entry in its own directory) can make root write where that
/// user couldn't, and what it writes is that user's already. Otherwise
/// [`crate::backup::write_atomic`] writes here. Plain reads stay this
/// process's (`doctor` reads `/proc/self`); a secret root sends somewhere
/// the configuration names is read with [`ConfigFiles::read_secret`].
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ConfigFiles {
    /// The user the configuration came from, when not root.
    pub(crate) from: Option<User>,
}

impl ConfigFiles {
    fn user_for(&self, path: &Path) -> Option<User> {
        if !is_root() {
            return None;
        }
        self.from.or_else(|| foreign_owner(dir_of(path)))
    }

    /// Read a secret that goes where the configuration says (the Headscale
    /// API key, to its URL) as the user the configuration is from: root
    /// must not read any file of root's on that user's say and send it on.
    pub(crate) fn read_secret(&self, path: &Path) -> parallax_core::Result<Option<String>> {
        let Some(user) = self.user_for(path) else {
            return RealFs.read(path);
        };
        let out = as_user(user, "read", path, None)?;
        match out.status.code() {
            Some(0) => String::from_utf8(out.stdout).map(Some).map_err(|e| {
                io_error(
                    format!("reading {}", path.display()),
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                )
            }),
            Some(MISSING) => Ok(None),
            _ => Err(failed("read", path, user, &out)),
        }
    }
}

/// How the child says there was no file to read or remove.
const MISSING: i32 = 4;

fn io_error(context: String, source: std::io::Error) -> parallax_core::Error {
    parallax_core::Error::Io { context, source }
}

/// Run `parallax file <op> <path>` as `user`, with `input` on stdin.
fn as_user(
    user: User,
    op: &str,
    path: &Path,
    input: Option<&str>,
) -> parallax_core::Result<std::process::Output> {
    let what = || format!("{op} {} as uid {}", path.display(), user.uid);
    let exe = std::env::current_exe().map_err(|e| io_error(what(), e))?;
    // The child starts in `/`: a relative path must mean what it means here.
    let path = std::path::absolute(path).map_err(|e| io_error(what(), e))?;
    let mut child = Command::new(exe)
        .arg("file")
        .arg(op)
        .arg(&path)
        .uid(user.uid)
        .gid(user.gid)
        .env_clear()
        .current_dir("/")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io_error(what(), e))?;
    if let (Some(input), Some(mut stdin)) = (input, child.stdin.take()) {
        // A child that stopped early says why on stderr, collected below.
        match stdin.write_all(input.as_bytes()) {
            Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io_error(what(), e));
            }
            _ => {}
        }
    }
    child.wait_with_output().map_err(|e| io_error(what(), e))
}

/// The child's failure, as the parent reports it: what it printed.
fn failed(op: &str, path: &Path, user: User, out: &std::process::Output) -> parallax_core::Error {
    let stderr = String::from_utf8_lossy(&out.stderr);
    parallax_core::Error::Command {
        command: format!(
            "parallax file {op} {} (as uid {})",
            path.display(),
            user.uid
        ),
        status: out.status.code().unwrap_or(-1),
        stderr: stderr.trim().trim_start_matches("error: ").to_string(),
    }
}

impl FileSystem for ConfigFiles {
    fn read(&self, path: &Path) -> parallax_core::Result<Option<String>> {
        RealFs.read(path)
    }

    /// Always written owner-only, all at once: everything root writes
    /// through here is a secret or a probe.
    fn write(&self, path: &Path, contents: &str, _secret: bool) -> parallax_core::Result<()> {
        let Some(user) = self.user_for(path) else {
            return crate::backup::write_atomic(path, contents).map_err(|e| {
                io_error(
                    format!("writing {}", path.display()),
                    std::io::Error::other(format!("{e:#}")),
                )
            });
        };
        let out = as_user(user, "write", path, Some(contents))?;
        match out.status.success() {
            true => Ok(()),
            false => Err(failed("write", path, user, &out)),
        }
    }

    fn remove(&self, path: &Path) -> parallax_core::Result<bool> {
        let Some(user) = self.user_for(path) else {
            return RealFs.remove(path);
        };
        let out = as_user(user, "remove", path, None)?;
        match out.status.code() {
            Some(0) => Ok(true),
            Some(MISSING) => Ok(false),
            _ => Err(failed("remove", path, user, &out)),
        }
    }
}

/// What `parallax file` does: one file operation, as whoever runs it. Only
/// [`ConfigFiles`] runs it, as the user it acts for.
#[derive(clap::Subcommand)]
pub(crate) enum FileOp {
    /// Print the file.
    Read { path: std::path::PathBuf },
    /// Replace the file (0600, all at once) with stdin.
    Write { path: std::path::PathBuf },
    /// Remove the file.
    Remove { path: std::path::PathBuf },
}

/// Run `op` in this process. A missing file exits with [`MISSING`].
pub(crate) fn file_command(op: FileOp) -> anyhow::Result<()> {
    match op {
        FileOp::Read { path } => match RealFs.read(&path)? {
            Some(text) => std::io::stdout()
                .write_all(text.as_bytes())
                .context("writing to stdout")?,
            None => std::process::exit(MISSING),
        },
        FileOp::Write { path } => {
            let mut contents = String::new();
            std::io::stdin()
                .read_to_string(&mut contents)
                .context("reading stdin")?;
            crate::backup::write_atomic(&path, &contents)?;
        }
        FileOp::Remove { path } => {
            if !RealFs.remove(&path)? {
                std::process::exit(MISSING);
            }
        }
    }
    Ok(())
}
