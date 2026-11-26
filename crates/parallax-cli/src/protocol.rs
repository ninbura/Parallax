//! The daemon's socket protocol: one JSON request and one JSON reply per
//! connection, each a single line. Every message carries `protocol`; a side
//! that speaks another version is refused, naming both.
//!
//! Secrets cross the socket (private keys in the configuration, a backup
//! passphrase). It is owner-only (0600 in a 0700 directory: the daemon's user,
//! root in Docker or `parallax` natively; root reaches it either way), the types keep
//! their redacted `Debug`, and nothing logs a message.

use std::io::BufRead;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use parallax_core::logging::Record;
use parallax_core::names::Resolved;
use parallax_core::secret::Secret;
use parallax_core::Config;
use parallax_store::logs::Query;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The version this build speaks. 2: replies carry the home's public IP.
/// 3: and what hosts named by DNS name resolved to. 4: services and host
/// grants carry port lists. 5: the configuration carries log levels.
/// 6: activity records (`logs`).
pub const PROTOCOL: u64 = 6;
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
    /// configuration is still at `revision` and the file still holds what
    /// was shown (`contents_sha256`), and apply it. Without a passphrase the
    /// server's own is used.
    BackupRestore {
        path: PathBuf,
        passphrase: Option<Secret>,
        revision: u64,
        contents_sha256: String,
    },
    /// Activity records (`parallax log show`).
    Logs { query: Query },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reply {
    Status {
        revision: u64,
        /// Why the last apply failed; `None` when it worked.
        apply_error: Option<String>,
        /// The home's public IP in effect: the configured one, else the
        /// last one found. `None` if neither.
        public_ip: Option<Ipv4Addr>,
        /// What each host named by DNS name last resolved to.
        names: Resolved,
    },
    Configuration {
        configuration: Box<Config>,
        revision: u64,
        /// What generation also needs: the home's public IP as a lookup
        /// last found it, and what named hosts resolved to.
        public_ip: Option<Ipv4Addr>,
        names: Resolved,
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
    /// Activity records, oldest first, each with its id.
    Logs { records: Vec<(i64, Record)> },
    /// The request was refused; nothing changed.
    Error { message: String },
}

/// One message as a line: the JSON object with `protocol` added.
pub fn encode(message: &impl Serialize) -> anyhow::Result<Vec<u8>> {
    encode_with(message, None)
}

/// A request as a line. It names the database the caller means, so a daemon
/// holding another one refuses it instead of changing the wrong gateway.
pub fn encode_request(request: &Request, database: &Path) -> anyhow::Result<Vec<u8>> {
    encode_with(request, Some(database))
}

fn encode_with(message: &impl Serialize, database: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    let mut value = serde_json::to_value(message).context("encoding a message")?;
    let Some(object) = value.as_object_mut() else {
        bail!("a message must be a JSON object");
    };
    object.insert("protocol".into(), PROTOCOL.into());
    if let Some(database) = database {
        object.insert(
            "database".into(),
            serde_json::to_value(database).context("encoding a message")?,
        );
    }
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
    let value = checked(line)?;
    serde_json::from_value(value).context("the message does not match the protocol")
}

/// Parse a request line, with the database it names.
pub fn decode_request(line: &[u8]) -> anyhow::Result<(PathBuf, Request)> {
    let mut value = checked(line)?;
    let database = value
        .as_object_mut()
        .and_then(|o| o.remove("database"))
        .and_then(|d| d.as_str().map(PathBuf::from))
        .ok_or_else(|| anyhow::anyhow!("the request names no database"))?;
    let request =
        serde_json::from_value(value).context("the request does not match the protocol")?;
    Ok((database, request))
}

/// The message as JSON, its protocol version checked and removed.
fn checked(line: &[u8]) -> anyhow::Result<serde_json::Value> {
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
    Ok(value)
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
        let mut config = canonical_config();
        // Every kind of log level: the socket reads peers through the same
        // form as TOML.
        config.server.logs.level = parallax_core::model::LogLevel::Connections;
        config.grants[1].log = Some(parallax_core::model::LogLevel::Denied);
        config.peers[0].log = Some(parallax_core::model::LogLevel::Off);
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
        let found: Resolved = [(
            "nas.mydomain.com".to_string(),
            vec![Ipv4Addr::new(192, 168, 1, 9)],
        )]
        .into();
        let Reply::Configuration {
            configuration,
            public_ip,
            names,
            ..
        } = round_trip(&Reply::Configuration {
            configuration: Box::new(config.clone()),
            revision: 1,
            public_ip: Some(Ipv4Addr::new(1, 2, 3, 4)),
            names: found.clone(),
        })
        else {
            panic!("not a configuration");
        };
        assert_eq!(*configuration, config);
        assert_eq!(public_ip, Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(names, found);
    }

    #[test]
    fn requests_are_tagged_and_carry_the_protocol() {
        let line = encode(&Request::BackupCreate { if_due: true }).unwrap();
        let text = String::from_utf8(line).unwrap();
        assert_eq!(
            text,
            "{\"if_due\":true,\"protocol\":6,\"request\":\"backup_create\"}\n"
        );
        let Request::BackupRestore { passphrase, .. } = round_trip(&Request::BackupRestore {
            path: "/b.tar".into(),
            passphrase: Some(Secret::new("correct horse")),
            revision: 2,
            contents_sha256: "ab".into(),
        }) else {
            panic!("not a restore");
        };
        assert_eq!(passphrase.unwrap().expose(), "correct horse");
    }

    #[test]
    fn a_request_names_its_database() {
        let line =
            encode_request(&Request::Status, Path::new("/var/lib/parallax/parallax.db")).unwrap();
        let (database, request) = decode_request(&line).unwrap();
        assert_eq!(database, Path::new("/var/lib/parallax/parallax.db"));
        assert!(matches!(request, Request::Status));
        let e = decode_request(&encode(&Request::Status).unwrap()).unwrap_err();
        assert!(e.to_string().contains("names no database"), "{e}");
    }

    #[test]
    fn another_protocol_is_refused_naming_both() {
        let e = decode::<Request>(b"{\"protocol\":1,\"request\":\"status\"}")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("protocol 6") && e.contains("other side 1"),
            "{e}"
        );
        let e = decode::<Request>(b"{\"request\":\"status\"}").unwrap_err();
        assert!(e.to_string().contains("no protocol"), "{e}");
        let e = decode::<Request>(
            b"{\"protocol\":6,\"request\":\"backup_create\",\"if_due\":true,\"x\":1}",
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
