use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Proto;

/// One entry of a `ports` list, written the way ufw writes them: `445/tcp`,
/// `137-138/udp`, or a bare `25565` for TCP and UDP both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortSpec {
    pub first: u16,
    pub last: u16,
    /// `None`: TCP and UDP.
    pub proto: Option<Proto>,
}

/// A [`PortSpec`] for one protocol: what the firewall matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    pub proto: Proto,
    pub first: u16,
    pub last: u16,
}

impl PortSpec {
    /// One port on one protocol.
    pub fn one(proto: Proto, port: u16) -> Self {
        PortSpec {
            first: port,
            last: port,
            proto: Some(proto),
        }
    }

    /// The ranges it stands for, TCP before UDP.
    pub fn ranges(self) -> impl Iterator<Item = PortRange> {
        let protos: &[Proto] = match self.proto {
            Some(Proto::Tcp) => &[Proto::Tcp],
            Some(Proto::Udp) => &[Proto::Udp],
            None => &[Proto::Tcp, Proto::Udp],
        };
        protos.iter().map(move |&proto| PortRange {
            proto,
            first: self.first,
            last: self.last,
        })
    }
}

impl PortRange {
    pub fn contains(self, proto: Proto, port: u16) -> bool {
        self.proto == proto && (self.first..=self.last).contains(&port)
    }

    /// Same protocol, and some port in both.
    pub fn overlaps(self, other: PortRange) -> bool {
        self.proto == other.proto && self.first <= other.last && other.first <= self.last
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        PortSpec {
            first: self.first,
            last: self.last,
            proto: Some(self.proto),
        }
        .fmt(f)
    }
}

/// Every range a list of specs stands for, in order, without repeats.
pub fn ranges(specs: &[PortSpec]) -> Vec<PortRange> {
    let mut out: Vec<PortRange> = Vec::new();
    for r in specs.iter().flat_map(|s| s.ranges()) {
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}

impl std::fmt::Display for PortSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.first)?;
        if self.last != self.first {
            write!(f, "-{}", self.last)?;
        }
        if let Some(proto) = self.proto {
            write!(f, "/{}", proto.as_str())?;
        }
        Ok(())
    }
}

impl std::str::FromStr for PortSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (range, proto) = match s.split_once('/') {
            Some((range, "tcp")) => (range, Some(Proto::Tcp)),
            Some((range, "udp")) => (range, Some(Proto::Udp)),
            Some((_, other)) => {
                return Err(format!(
                    "'{s}': the protocol '{other}' is neither tcp nor udp"
                ))
            }
            None => (s, None),
        };
        let port = |p: &str| {
            p.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("'{s}': '{p}' is not a port (1-65535)"))
        };
        let (first, last) = match range.split_once('-') {
            Some((a, b)) => (port(a)?, port(b)?),
            None => (port(range)?, port(range)?),
        };
        if first > last {
            return Err(format!("'{s}': the range runs backwards"));
        }
        Ok(PortSpec { first, last, proto })
    }
}

impl Serialize for PortSpec {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortSpec {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_like_ufw() {
        let spec = |s: &str| s.parse::<PortSpec>();
        assert_eq!(spec("445/tcp"), Ok(PortSpec::one(Proto::Tcp, 445)));
        assert_eq!(
            spec("137-138/udp"),
            Ok(PortSpec {
                first: 137,
                last: 138,
                proto: Some(Proto::Udp)
            })
        );
        assert_eq!(
            spec("25565").map(|s| s.ranges().collect::<Vec<_>>()),
            Ok(vec![
                PortRange {
                    proto: Proto::Tcp,
                    first: 25565,
                    last: 25565
                },
                PortRange {
                    proto: Proto::Udp,
                    first: 25565,
                    last: 25565
                }
            ])
        );
        for s in ["137-138/udp", "445/tcp", "25565", "8000-8100"] {
            assert_eq!(spec(s).unwrap().to_string(), s);
        }
        for (bad, why) in [
            ("0/tcp", "not a port"),
            ("70000", "not a port"),
            ("445/sctp", "neither tcp nor udp"),
            ("200-100", "runs backwards"),
            ("http", "not a port"),
            ("", "not a port"),
        ] {
            let e = spec(bad).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn ranges_keep_order_and_drop_repeats() {
        let specs: Vec<PortSpec> = ["445/tcp", "25565", "445/tcp"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let r = ranges(&specs);
        assert_eq!(r.len(), 3);
        assert!(r[0].contains(Proto::Tcp, 445));
        assert!(r[2].contains(Proto::Udp, 25565));
        assert!(!r[0].contains(Proto::Udp, 445));
    }
}
