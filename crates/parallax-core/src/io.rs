//! Every side effect the engine needs, as injectable traits, plus in-memory
//! implementations for tests and `std`-backed ones for real use.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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

/// Runs external programs (`nft`, `wg`, `ip`, `dnsmasq`).
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

        fn write(&self, path: &Path, contents: &str, secret: bool) -> Result<()> {
            let ctx = || format!("writing {}", path.display());
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|e| Error::io(ctx(), e))?;
                }
            }
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(if secret { 0o600 } else { 0o644 });
            }
            let mut f = opts.open(path).map_err(|e| Error::io(ctx(), e))?;
            #[cfg(unix)]
            if secret {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .map_err(|e| Error::io(ctx(), e))?;
            }
            f.write_all(contents.as_bytes())
                .map_err(|e| Error::io(ctx(), e))
        }

        fn remove(&self, path: &Path) -> Result<bool> {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(Error::io(format!("removing {}", path.display()), e)),
            }
        }
    }

    #[derive(Debug, Default, Clone, Copy)]
    pub struct RealRunner;

    impl ProcessRunner for RealRunner {
        fn run(&self, program: &str, args: &[&str], stdin: Option<&str>) -> Result<Output> {
            use std::process::{Command, Stdio};
            let mut cmd = Command::new(program);
            cmd.args(args)
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
            if let Some(input) = stdin {
                if let Some(mut pipe) = child.stdin.take() {
                    pipe.write_all(input.as_bytes())
                        .map_err(|e| Error::io(format!("feeding stdin to {program}"), e))?;
                }
            }
            let out = child
                .wait_with_output()
                .map_err(|e| Error::io(format!("waiting for {program}"), e))?;
            Ok(Output {
                status: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            })
        }
    }
}
