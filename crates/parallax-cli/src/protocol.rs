//! The daemon's socket protocol: one JSON request and one JSON reply per
//! connection, each a single line. Every message carries `protocol`; a side
//! that speaks another version is refused, naming both.
//!
//! Secrets cross the socket (private keys in the configuration, a backup
//! passphrase). It is root-only (0600 in a 0700 directory), the types keep
//! their redacted `Debug`, and nothing logs a message.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use anyhow::{bail, Context};
use parallax_core::secret::Secret;
use parallax_core::Config;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The version this build speaks.
pub const PROTOCOL: u64 = 1;
/// The largest message either side accepts, newline included.
pub const MAX_MESSAGE: usize = 16 << 20;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Whether the daemon runs and how its last apply went.
    Status,
    /// The configuration and its revision.
    Load,
    /// Replace the configuration, if it is still at `revision`, and apply it.
    Save {
        configuration: Box<Config>,
        revision: u64,
    },
    /// Apply now.
    Apply,
    /// `parallax backup create [--if-due]`, on the daemon's open database.
    BackupCreate { if_due: bool },
    /// Restore a backup the caller already showed and confirmed, if the
    /// configuration is still at `revision`, and apply it. Without a
    /// passphrase the server's own is used.
    BackupRestore {
        path: PathBuf,
        passphrase: Option<Secret>,
        revision: u64,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Status {
        revision: u64,
        /// Why the last apply failed; `None` when it worked.
        apply_error: Option<String>,
    },
    Configuration {
        configuration: Box<Config>,
        revision: u64,
    },
    /// A change was saved (or nothing was asked to change), then applied.
    /// `error` says why the apply failed; the change stays saved either way.
    Applied {
        revision: u64,
        log: Vec<String>,
        error: Option<String>,
    },
    /// The configuration moved on from the revision the request named.
    Conflict { revision: u64 },
    /// Output of a request that changes no configuration.
    Done { lines: Vec<String> },
    /// The request was refused; nothing changed.
    Error { message: String },
}

/// One message as a line: the JSON object with `protocol` added.
pub fn encode(message: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    let mut value = serde_json::to_value(message).context("encoding a message")?;
    let Some(object) = value.as_object_mut() else {
        bail!("a message must be a JSON object");
    };
    object.insert("protocol".into(), PROTOCOL.into());
    let mut line = serde_json::to_vec(&value).context("encoding a message")?;
    line.push(b'\n');
    if line.len() > MAX_MESSAGE {
        bail!(
            "the message is {} bytes, more than the {MAX_MESSAGE} the socket carries",
            line.len()
        );
    }
    Ok(line)
}

/// Parse one line, refusing another protocol version before anything else.
pub fn decode<T: DeserializeOwned>(line: &[u8]) -> anyhow::Result<T> {
    let mut value: serde_json::Value =
        serde_json::from_slice(line).context("the message is not JSON")?;
    let theirs = value
        .as_object_mut()
        .and_then(|o| o.remove("protocol"))
        .and_then(|p| p.as_u64());
    match theirs {
        Some(PROTOCOL) => {}
        Some(other) => bail!(
            "protocol mismatch: this Parallax speaks protocol {PROTOCOL}, the other side {other}; run the same version on both sides"
        ),
        None => bail!("the message names no protocol version"),
    }
    serde_json::from_value(value).context("the message does not match the protocol")
}

/// Read one line of at most [`MAX_MESSAGE`] bytes.
pub fn read_line(reader: impl BufRead) -> anyhow::Result<Vec<u8>> {
    let mut line = Vec::new();
    reader
        .take(MAX_MESSAGE as u64)
        .read_until(b'\n', &mut line)
        .context("reading from the socket")?;
    check_line(&line)?;
    Ok(line)
}

/// A whole line, not one cut short by the size limit or a closed socket.
pub fn check_line(line: &[u8]) -> anyhow::Result<()> {
    if line.last() != Some(&b'\n') {
        if line.len() >= MAX_MESSAGE {
            bail!("the message is larger than the {MAX_MESSAGE} bytes the socket carries");
        }
        bail!("the connection closed before a whole message arrived");
    }
    Ok(())
}

/// Write one message as a line.
pub fn write_message(writer: &mut impl Write, message: &impl Serialize) -> anyhow::Result<()> {
    writer
        .write_all(&encode(message)?)
        .context("writing to the socket")?;
    writer.flush().context("writing to the socket")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "tests")]

    use super::*;
    use parallax_core::testing::canonical_config;

    fn round_trip<T: Serialize + DeserializeOwned>(message: &T) -> T {
        let line = encode(message).unwrap();
        let mut reader = std::io::Cursor::new(line);
        decode(&read_line(&mut reader).unwrap()).unwrap()
    }

    #[test]
    fn a_configuration_survives_the_socket() {
        let config = canonical_config();
        let Request::Save {
            configuration,
            revision,
        } = round_trip(&Request::Save {
            configuration: Box::new(config.clone()),
            revision: 7,
        })
        else {
            panic!("not a save");
        };
        assert_eq!(*configuration, config);
        assert_eq!(revision, 7);
        let Reply::Configuration { configuration, .. } = round_trip(&Reply::Configuration {
            configuration: Box::new(config.clone()),
            revision: 1,
        }) else {
            panic!("not a configuration");
        };
        assert_eq!(*configuration, config);
    }

    #[test]
    fn requests_are_tagged_and_carry_the_protocol() {
        let line = encode(&Request::BackupCreate { if_due: true }).unwrap();
        let text = String::from_utf8(line).unwrap();
        assert_eq!(
            text,
            "{\"if_due\":true,\"protocol\":1,\"request\":\"backup_create\"}\n"
        );
        let Request::BackupRestore { passphrase, .. } = round_trip(&Request::BackupRestore {
            path: "/b.tar".into(),
            passphrase: Some(Secret::new("correct horse")),
            revision: 2,
        }) else {
            panic!("not a restore");
        };
        assert_eq!(passphrase.unwrap().expose(), "correct horse");
    }

    #[test]
    fn another_protocol_is_refused_naming_both() {
        let e = decode::<Request>(b"{\"protocol\":2,\"request\":\"status\"}")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("protocol 1") && e.contains("other side 2"),
            "{e}"
        );
        let e = decode::<Request>(b"{\"request\":\"status\"}").unwrap_err();
        assert!(e.to_string().contains("no protocol"), "{e}");
        let e = decode::<Request>(
            b"{\"protocol\":1,\"request\":\"backup_create\",\"if_due\":true,\"x\":1}",
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("unknown field"), "{e:#}");
    }

    #[test]
    fn an_oversized_or_cut_message_is_refused() {
        let mut big = std::io::Cursor::new(vec![b'x'; MAX_MESSAGE + 10]);
        let e = read_line(&mut big).unwrap_err().to_string();
        assert!(e.contains("larger than"), "{e}");
        let mut cut = std::io::Cursor::new(b"{\"protocol\":1".to_vec());
        let e = read_line(&mut cut).unwrap_err().to_string();
        assert!(e.contains("closed before"), "{e}");
    }
}
