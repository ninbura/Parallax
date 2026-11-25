use std::net::Ipv4Addr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A host as a grant or service names it: a real address, or a DNS name the
/// gateway looks up through its network's resolvers ([`crate::names`]).
///
/// TOML form: a string either way (`host = "192.168.1.5"`,
/// `host = "nas.mydomain.com"`); whatever doesn't parse as an IPv4 address
/// is a name, which validation checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Host {
    Ip(Ipv4Addr),
    Name(String),
}

impl Host {
    pub fn ip(&self) -> Option<Ipv4Addr> {
        match self {
            Host::Ip(ip) => Some(*ip),
            Host::Name(_) => None,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Host::Ip(_) => None,
            Host::Name(name) => Some(name),
        }
    }
}

impl From<Ipv4Addr> for Host {
    fn from(ip: Ipv4Addr) -> Self {
        Host::Ip(ip)
    }
}

impl std::str::FromStr for Host {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.parse()
            .map_or_else(|_| Host::Name(s.to_string()), Host::Ip))
    }
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Name(name) => f.write_str(name),
        }
    }
}

impl Serialize for Host {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Host {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        let Ok(host) = text.parse();
        Ok(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_or_a_name() {
        assert_eq!(
            "192.168.1.5".parse::<Host>(),
            Ok(Host::Ip(Ipv4Addr::new(192, 168, 1, 5)))
        );
        assert_eq!(
            "nas.mydomain.com".parse::<Host>(),
            Ok(Host::Name("nas.mydomain.com".into()))
        );
        // Not an IPv4 address, so a name; validation refuses it.
        assert_eq!(
            "192.168.1.300".parse::<Host>(),
            Ok(Host::Name("192.168.1.300".into()))
        );
    }
}
