use serde::{Deserialize, Serialize};

use super::{Network, Peer, ServerConfig, Service, Template};

/// The whole configuration. Stored in the database (`parallax-store`); TOML
/// is its import/export form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default, rename = "network")]
    pub networks: Vec<Network>,
    #[serde(default, rename = "service")]
    pub services: Vec<Service>,
    #[serde(default, rename = "template")]
    pub templates: Vec<Template>,
    #[serde(default, rename = "peer")]
    pub peers: Vec<Peer>,
}

impl Config {
    /// Parse a configuration. Errors give a line and column but never quote
    /// the source or a value: the offending line may hold a private or
    /// preshared key.
    pub fn from_toml(text: &str) -> crate::Result<Self> {
        toml::from_str(text).map_err(|e| {
            let at = e
                .span()
                .and_then(|span| text.get(..span.start))
                .map(|before| {
                    let line = before.matches('\n').count() + 1;
                    let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                    format!("line {line}, column {column}: ")
                })
                .unwrap_or_default();
            crate::Error::Parse(format!("{at}{}", redact_quoted(e.message().trim())))
        })
    }

    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(|e| crate::Error::Parse(e.to_string()))
    }

    pub fn network(&self, name: &str) -> Option<&Network> {
        self.networks.iter().find(|n| n.name == name)
    }
    pub fn template(&self, name: &str) -> Option<&Template> {
        self.templates.iter().find(|t| t.name == name)
    }
    pub fn service(&self, name: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.name == name)
    }
    pub fn peer(&self, name: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.name == name)
    }
    pub fn peer_mut(&mut self, name: &str) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|p| p.name == name)
    }
}

/// Replace every double-quoted part of a parser message ("invalid type:
/// string \"<value>\"") with `"…"`. Field names are quoted with backticks
/// and stay.
fn redact_quoted(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for (i, part) in message.split('"').enumerate() {
        if i % 2 == 0 {
            out.push_str(part);
        } else {
            out.push_str("\"…\"");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_errors_locate_without_quoting_the_source() {
        let text = "[server.wireguard]\nprivate_key = \"SYNTHETIC-SECRET-VALUE\" oops\n";
        let err = Config::from_toml(text).unwrap_err().to_string();
        assert!(err.contains("line 2, column"), "{err}");
        assert!(!err.contains("SYNTHETIC-SECRET-VALUE"), "{err}");
    }

    #[test]
    fn parse_errors_never_echo_a_value() {
        let text = "[server.wireguard]\nlisten_port = \"SYNTHETIC-SECRET-VALUE\"\n";
        let err = Config::from_toml(text).unwrap_err().to_string();
        assert!(err.contains("line 2, column"), "{err}");
        assert!(!err.contains("SYNTHETIC-SECRET-VALUE"), "{err}");
    }
}
