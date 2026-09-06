use serde::{Deserialize, Serialize};

use super::{Network, Peer, ServerConfig, Service, Template};

/// The whole configuration: the M1 source of truth, loaded from TOML.
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
    pub fn from_toml(text: &str) -> crate::Result<Self> {
        toml::from_str(text).map_err(|e| crate::Error::Parse(e.to_string()))
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
