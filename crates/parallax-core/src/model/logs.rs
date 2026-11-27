//! Per-peer activity logging settings (docs/logging.md).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::Interval;

/// How much the gateway records about a peer's traffic, like log
/// verbosity: each level includes the ones before it, and the first is the
/// one that matters most (what the firewall stopped).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    /// Nothing. Costs nothing: no firewall rules, no events read.
    #[default]
    Off,
    /// Attempts the firewall stopped (rate-limited): like warnings.
    Blocked,
    /// Also one record per new connection: peer, destination, port.
    Connections,
    /// Also the bytes each way when a connection ends.
    Detailed,
}

impl LogLevel {
    pub const ALL: [LogLevel; 4] = [
        LogLevel::Off,
        LogLevel::Blocked,
        LogLevel::Connections,
        LogLevel::Detailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Off => "off",
            LogLevel::Blocked => "blocked",
            LogLevel::Connections => "connections",
            LogLevel::Detailed => "detailed",
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        LogLevel::ALL
            .into_iter()
            .find(|l| l.as_str() == s)
            .ok_or_else(|| crate::Error::Malformed {
                what: "log level",
                detail: format!("'{s}' is not one of off, blocked, connections, detailed"),
            })
    }
}

/// `[server.logs]`: the global level and where and how long records are kept.
/// A peer's own `log` wins over this, then the most detailed `log` among its
/// grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsServer {
    #[serde(default)]
    pub level: LogLevel,
    /// Whether to log peers' DNS queries. Separate from `level`, which never
    /// implies it: the names someone looks up say more about them than
    /// their connections do.
    #[serde(default)]
    pub dns: bool,
    /// The activity database, kept apart from the configuration so it can
    /// live on another disk (an SSD instead of a Pi's SD card) or `tmpfs`.
    #[serde(default = "default_logs_path")]
    pub path: PathBuf,
    /// Records older than this are deleted.
    #[serde(default = "default_logs_keep")]
    pub keep: Interval,
    /// The most the records may take up; the oldest go first past it.
    #[serde(default = "default_logs_max_size")]
    pub max_size: ByteSize,
}

impl Default for LogsServer {
    fn default() -> Self {
        LogsServer {
            level: LogLevel::Off,
            dns: false,
            path: default_logs_path(),
            keep: default_logs_keep(),
            max_size: default_logs_max_size(),
        }
    }
}

fn default_logs_path() -> PathBuf {
    PathBuf::from("/var/lib/parallax/logs.db")
}
fn default_logs_keep() -> Interval {
    Interval::from_secs(30 * 24 * 60 * 60)
}
fn default_logs_max_size() -> ByteSize {
    ByteSize::from_bytes(ByteSize::GIB)
}

/// A size in bytes, written in binary units: `512MiB`, `1GiB` (or `B` for
/// a size that isn't a whole KiB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ByteSize(u64);

impl ByteSize {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * ByteSize::KIB;
    const GIB: u64 = 1024 * ByteSize::MIB;
    const TIB: u64 = 1024 * ByteSize::GIB;
    // Largest first; `B` last, since every other suffix ends in it.
    const UNITS: [(&'static str, u64); 5] = [
        ("TiB", ByteSize::TIB),
        ("GiB", ByteSize::GIB),
        ("MiB", ByteSize::MIB),
        ("KiB", ByteSize::KIB),
        ("B", 1),
    ];

    pub const fn from_bytes(bytes: u64) -> Self {
        ByteSize(bytes)
    }
    pub fn as_bytes(self) -> u64 {
        self.0
    }
}

impl std::str::FromStr for ByteSize {
    type Err = crate::Error;
    fn from_str(s: &str) -> crate::Result<Self> {
        let malformed = || crate::Error::Malformed {
            what: "size",
            detail: format!("'{s}' is not a size like 512MiB or 1GiB"),
        };
        let s = s.trim();
        let (number, unit) = ByteSize::UNITS
            .iter()
            .find_map(|&(suffix, unit)| s.strip_suffix(suffix).map(|n| (n, unit)))
            .ok_or_else(malformed)?;
        let n: u64 = number.parse().map_err(|_| malformed())?;
        match n.checked_mul(unit) {
            Some(bytes) if bytes > 0 => Ok(ByteSize(bytes)),
            _ => Err(malformed()),
        }
    }
}

impl TryFrom<String> for ByteSize {
    type Error = crate::Error;
    fn try_from(s: String) -> crate::Result<Self> {
        s.parse()
    }
}

impl From<ByteSize> for String {
    fn from(b: ByteSize) -> String {
        b.to_string()
    }
}

impl std::fmt::Display for ByteSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (suffix, unit) = ByteSize::UNITS
            .into_iter()
            .find(|&(_, unit)| self.0.is_multiple_of(unit))
            .unwrap_or(("B", 1));
        write!(f, "{}{suffix}", self.0 / unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_order_from_off_to_detailed() {
        assert!(LogLevel::Off < LogLevel::Blocked);
        assert!(LogLevel::Blocked < LogLevel::Connections);
        assert!(LogLevel::Connections < LogLevel::Detailed);
        for level in LogLevel::ALL {
            assert_eq!(level.as_str().parse::<LogLevel>().unwrap(), level);
        }
        assert!("verbose".parse::<LogLevel>().is_err());
    }

    #[test]
    fn sizes_parse_and_print_in_their_largest_unit() {
        for (text, bytes, shown) in [
            ("512MiB", 512 * ByteSize::MIB, "512MiB"),
            ("1024MiB", ByteSize::GIB, "1GiB"),
            ("1GiB", ByteSize::GIB, "1GiB"),
            ("64KiB", 64 * ByteSize::KIB, "64KiB"),
            ("2TiB", 2 * ByteSize::TIB, "2TiB"),
            ("1500B", 1500, "1500B"),
            ("2048B", 2048, "2KiB"),
        ] {
            let b: ByteSize = text.parse().unwrap();
            assert_eq!(b.as_bytes(), bytes, "{text}");
            assert_eq!(b.to_string(), shown, "{text}");
        }
        for bad in [
            "", "0GiB", "0B", "1", "GiB", "B", "1GB", "1gib", "-1MiB", "1.5GiB",
        ] {
            assert!(bad.parse::<ByteSize>().is_err(), "{bad}");
        }
    }
}
