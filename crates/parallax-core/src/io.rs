//! Every side effect the engine needs, as injectable traits, plus in-memory
//! implementations for tests and `std`-backed ones for real use.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use std::net::Ipv4Addr;

use crate::model::EncryptedDns;
use crate::secret::{KeyPair, PresharedKey};
use crate::{Error, Result};

/// Filesystem access.
pub trait FileSystem {
    /// Read a UTF-8 file; `Ok(None)` if it does not exist.
    fn read(&self, path: &Path) -> Result<Option<String>>;
    /// Write a file, creating parents. `secret` files must be mode 0600.
    fn write(&self, path: &Path, contents: &str, secret: bool) -> Result<()>;
    /// Remove a file; `Ok(false)` if it did not exist.
    fn remove(&self, path: &Path) -> Result<bool>;
}

/// Result of running an external command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// Runs external programs (`nft`, `wg`, `ip`).
pub trait ProcessRunner {
    fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<Output>;

    /// Run and turn a non-zero status into [`Error::Command`].
    fn run_checked(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<Output> {
        let out = self.run(program, args, stdin)?;
        if out.ok() {
            Ok(out)
        } else {
            Err(Error::Command {
                command: std::iter::once(program)
                    .chain(args.iter().copied())
                    .collect::<Vec<_>>()
                    .join(" "),
                status: out.status,
                stderr: out.stderr.trim().to_string(),
            })
        }
    }
}

/// Source of WireGuard key material.
pub trait KeyGenerator {
    fn keypair(&self) -> KeyPair;
    fn preshared_key(&self) -> PresharedKey;
}

/// Where a name is looked up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nameserver {
    /// Plain DNS to this address, port 53.
    Plain(Ipv4Addr),
    /// DNS over HTTPS to this provider.
    Encrypted(EncryptedDns),
}

impl std::fmt::Display for Nameserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Nameserver::Plain(ip) => write!(f, "{ip}"),
            Nameserver::Encrypted(p) => write!(f, "{p} (encrypted)"),
        }
    }
}

/// DNS lookups. Each call gives up after a few seconds.
pub trait Resolver {
    /// The IPv4 addresses `name` has; empty when it has none.
    fn lookup_ipv4(&self, name: &str, via: Nameserver) -> Result<Vec<Ipv4Addr>>;
}

/// Everything `apply` needs, bundled.
#[derive(Clone, Copy)]
pub struct System<'a> {
    pub fs: &'a dyn FileSystem,
    pub runner: &'a dyn ProcessRunner,
}

impl std::fmt::Debug for System<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("System { .. }")
    }
}

/// CSPRNG-backed key generator.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsKeyGenerator;

impl KeyGenerator for OsKeyGenerator {
    fn keypair(&self) -> KeyPair {
        KeyPair::from_private_bytes(rand::random())
    }
    fn preshared_key(&self) -> PresharedKey {
        PresharedKey::from_bytes(rand::random())
    }
}

/// In-memory implementations for tests and dry runs.
pub mod memory {
    use super::*;

    /// A filesystem held in a map. Records whether each file was written as secret.
    #[derive(Debug, Default)]
    pub struct MemoryFs {
        files: RefCell<BTreeMap<PathBuf, (String, bool)>>,
    }

    impl MemoryFs {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with_file(self, path: impl Into<PathBuf>, contents: impl Into<String>) -> Self {
            self.files
                .borrow_mut()
                .insert(path.into(), (contents.into(), false));
            self
        }
        pub fn paths(&self) -> Vec<PathBuf> {
            self.files.borrow().keys().cloned().collect()
        }
        pub fn is_secret(&self, path: &Path) -> Option<bool> {
            self.files.borrow().get(path).map(|(_, s)| *s)
        }
    }

    impl FileSystem for MemoryFs {
        fn read(&self, path: &Path) -> Result<Option<String>> {
            Ok(self.files.borrow().get(path).map(|(c, _)| c.clone()))
        }
        fn write(&self, path: &Path, contents: &str, secret: bool) -> Result<()> {
            self.files
                .borrow_mut()
                .insert(path.to_path_buf(), (contents.to_string(), secret));
            Ok(())
        }
        fn remove(&self, path: &Path) -> Result<bool> {
            Ok(self.files.borrow_mut().remove(path).is_some())
        }
    }

    /// One recorded invocation: program, arguments, stdin.
    pub type Call = (String, Vec<String>, Option<String>);
    /// A canned answer: program, exact arguments (or any), output.
    type Canned = (String, Option<Vec<String>>, Output);

    /// Records every invocation; answers with canned outputs by program name
    /// (default: success with empty output).
    #[derive(Debug, Default)]
    pub struct RecordingRunner {
        pub calls: RefCell<Vec<Call>>,
        canned: RefCell<Vec<Canned>>,
    }

    impl RecordingRunner {
        pub fn new() -> Self {
            Self::default()
        }
        /// Queue a canned result for the next invocation of `program` (FIFO per program).
        pub fn respond(&self, program: &str, output: Output) {
            self.canned
                .borrow_mut()
                .push((program.to_string(), None, output));
        }
        /// Queue a canned result for the next invocation of `program` with exactly `args`.
        pub fn respond_to(&self, program: &str, args: &[&str], output: Output) {
            self.canned.borrow_mut().push((
                program.to_string(),
                Some(args.iter().map(|s| s.to_string()).collect()),
                output,
            ));
        }
        /// Command lines as `program arg arg ...`, in order.
        pub fn command_lines(&self) -> Vec<String> {
            self.calls
                .borrow()
                .iter()
                .map(|(p, a, _)| {
                    std::iter::once(p.as_str())
                        .chain(a.iter().map(String::as_str))
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .collect()
        }
    }

    impl ProcessRunner for RecordingRunner {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<Output> {
            self.calls.borrow_mut().push((
                program.to_string(),
                args.iter().map(|s| s.to_string()).collect(),
                stdin.map(str::to_string),
            ));
            let mut canned = self.canned.borrow_mut();
            if let Some(i) = canned.iter().position(|(p, a, _)| {
                p == program
                    && a.as_ref()
                        .is_none_or(|a| a.iter().map(String::as_str).eq(args.iter().copied()))
            }) {
                return Ok(canned.remove(i).2);
            }
            Ok(Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    /// Answers from a table of `(name, nameserver)`; anything else fails.
    /// Records every question.
    #[derive(Debug, Default)]
    pub struct FakeResolver {
        answers: BTreeMap<(String, String), Vec<Ipv4Addr>>,
        pub asked: RefCell<Vec<(String, Nameserver)>>,
    }

    impl FakeResolver {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn answer(mut self, name: &str, via: Nameserver, addresses: &[Ipv4Addr]) -> Self {
            self.answers
                .insert((name.to_string(), via.to_string()), addresses.to_vec());
            self
        }
    }

    impl Resolver for FakeResolver {
        fn lookup_ipv4(&self, name: &str, via: Nameserver) -> Result<Vec<Ipv4Addr>> {
            self.asked.borrow_mut().push((name.to_string(), via));
            self.answers
                .get(&(name.to_string(), via.to_string()))
                .cloned()
                .ok_or_else(|| Error::Lookup("no answer within 3 seconds".into()))
        }
    }

    /// Deterministic keys: every keypair derives from a counter.
    #[derive(Debug, Default)]
    pub struct SeededKeys {
        counter: RefCell<u8>,
    }

    impl KeyGenerator for SeededKeys {
        fn keypair(&self) -> KeyPair {
            let mut c = self.counter.borrow_mut();
            *c = c.wrapping_add(1);
            KeyPair::from_private_bytes([*c; 32])
        }
        fn preshared_key(&self) -> PresharedKey {
            let mut c = self.counter.borrow_mut();
            *c = c.wrapping_add(1);
            PresharedKey::from_bytes([*c; 32])
        }
    }
}

/// `std`-backed implementations.
pub mod real {
    use super::*;
    use std::io::Write;

    #[derive(Debug, Default, Clone, Copy)]
    pub struct RealFs;

    impl FileSystem for RealFs {
        fn read(&self, path: &Path) -> Result<Option<String>> {
            match std::fs::read_to_string(path) {
                Ok(s) => Ok(Some(s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(Error::io(format!("reading {}", path.display()), e)),
            }
        }

        /// Modes are set explicitly, not left to the umask: the CLI runs with
        /// an owner-only umask, but generated files that aren't secret (nginx
        /// snippets) stay readable as before.
        ///
        /// Written next to the target and renamed over it, so a reader (the
        /// DNS server or the proxy reloading its routes while the next apply
        /// writes) sees the old file or the new one, never half of one.
        fn write(&self, path: &Path, contents: &str, secret: bool) -> Result<()> {
            let ctx = || format!("writing {}", path.display());
            let dir = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => {
                    create_dirs(parent).map_err(|e| Error::io(ctx(), e))?;
                    parent
                }
                _ => Path::new("."),
            };
            let name = path
                .file_name()
                .ok_or_else(|| Error::io(ctx(), std::io::ErrorKind::InvalidInput.into()))?;
            let mut tmp_name = std::ffi::OsString::from(".");
            tmp_name.push(name);
            tmp_name.push(".tmp");
            let tmp = dir.join(tmp_name);
            let mode = if secret { 0o600 } else { 0o644 };
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(mode);
            }
            let written = (|| {
                let mut f = opts.open(&tmp)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    f.set_permissions(std::fs::Permissions::from_mode(mode))?;
                }
                f.write_all(contents.as_bytes())?;
                std::fs::rename(&tmp, path)
            })();
            if written.is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
            written.map_err(|e| Error::io(ctx(), e))
        }

        fn remove(&self, path: &Path) -> Result<bool> {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(Error::io(format!("removing {}", path.display()), e)),
            }
        }
    }

    /// `create_dir_all`, with every directory it creates mode 0755.
    fn create_dirs(dir: &Path) -> std::io::Result<()> {
        let missing: Vec<&Path> = dir
            .ancestors()
            .take_while(|d| !d.as_os_str().is_empty() && !d.exists())
            .collect();
        for d in missing.into_iter().rev() {
            match std::fs::create_dir(d) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))?;
            }
        }
        Ok(())
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct RealRunner;

    impl ProcessRunner for RealRunner {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<Output> {
            use std::process::{Command, Stdio};
            let mut cmd = Command::new(program);
            // Callers match error text (e.g. EPERM), so keep it untranslated.
            cmd.env("LC_ALL", "C")
                .args(args)
                .stdin(if stdin.is_some() {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = cmd
                .spawn()
                .map_err(|e| Error::io(format!("spawning {program}"), e))?;
            // Input goes in on its own thread while this one drains stdout and
            // stderr: a child that fills an output pipe before it has read all
            // of its input would otherwise wait on us while we wait on it.
            let pipe = child.stdin.take();
            let (fed, out) = std::thread::scope(|s| {
                // Builder, not `s.spawn`: no panic if no thread can be made.
                // Then the closure and the pipe drop, the child sees end of
                // input, and is still reaped below.
                let writer =
                    std::thread::Builder::new().spawn_scoped(s, move || match (pipe, stdin) {
                        (Some(mut pipe), Some(input)) => match pipe.write_all(input.as_bytes()) {
                            // It stopped reading (usually exited on an error):
                            // its own output says why.
                            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
                            other => other,
                        },
                        // The pipe drops at the end of the thread: end of input.
                        _ => Ok(()),
                    });
                let out = child.wait_with_output();
                let fed = writer.and_then(|w| {
                    w.join()
                        .unwrap_or_else(|_| Err(std::io::Error::other("the stdin writer panicked")))
                });
                (fed, out)
            });
            // The child is reaped either way before an error returns.
            let out = out.map_err(|e| Error::io(format!("waiting for {program}"), e))?;
            fed.map_err(|e| Error::io(format!("feeding stdin to {program}"), e))?;
            Ok(Output {
                status: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // More than a pipe buffer (64 KiB on Linux): a large gateway's WireGuard config.
        const BIG: usize = 1 << 20;

        #[test]
        fn feeds_input_larger_than_a_pipe_buffer() {
            let input = "x".repeat(BIG);
            let out = RealRunner.run("wc", &["-c"], Some(&input)).unwrap();
            assert!(out.ok(), "{out:?}");
            assert_eq!(out.stdout.trim(), BIG.to_string());
        }

        #[test]
        fn a_child_that_writes_a_lot_before_reading_does_not_deadlock() {
            let input = "x".repeat(BIG);
            let script = format!("head -c {BIG} /dev/zero >&2; wc -c");
            let out = RealRunner
                .run("sh", &["-c", &script], Some(&input))
                .unwrap();
            assert_eq!(
                (out.stdout.trim(), out.stderr.len()),
                (BIG.to_string().as_str(), BIG)
            );
        }

        #[test]
        fn a_child_that_stops_reading_still_reports_its_own_result() {
            let input = "x".repeat(BIG);
            let out = RealRunner
                .run("sh", &["-c", "echo refused >&2; exit 3"], Some(&input))
                .unwrap();
            assert_eq!((out.status, out.stderr.trim()), (3, "refused"));
        }
    }
}
