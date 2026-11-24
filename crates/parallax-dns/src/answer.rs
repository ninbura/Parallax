//! What goes back to the client: home answers moved into mapped space,
//! public answers without addresses that point inward.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_server::proto::rr::rdata::svcb::{SvcParamValue, SVCB};
use hickory_server::proto::rr::rdata::{A, AAAA};
use hickory_server::proto::rr::{Name, RData, Record, RecordType};
use parallax_core::generate::firewall::NOT_PUBLIC;
use parallax_core::netmap::Mapping;

/// Answers from a home resolver. A records in a mapped network move into
/// its virtual prefix (the DNS mirror of the NETMAP rule). AAAA records are
/// dropped: tunnel peers can't send IPv6, and a home address on a prefix the
/// visited network also uses would send the client somewhere else.
/// SVCB/HTTPS records go too: their address hints would carry real,
/// unmapped addresses.
pub fn home(records: &[Record], mappings: &[Mapping]) -> Vec<Record> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(A(addr)) => {
                let mut r = r.clone();
                if let Some(v) = mappings.iter().find_map(|m| m.to_virtual(*addr)) {
                    r.data = RData::A(A(v));
                }
                Some(r)
            }
            RData::AAAA(_) | RData::SVCB(_) | RData::HTTPS(_) => None,
            _ => Some(r.clone()),
        })
        .collect()
}

/// Only the records of the asked type, as if they sat under `name`: drops
/// the CNAME chain, whose targets are names the tier may not see.
pub fn flatten(records: Vec<Record>, name: &Name, qtype: RecordType) -> Vec<Record> {
    records
        .into_iter()
        .filter(|r| r.record_type() == qtype)
        .map(|mut r| {
            r.name = name.clone();
            r
        })
        .collect()
}

/// Answers from the public resolver, without private, reserved or mapped
/// addresses: a public name must not point a client's browser at the home
/// network or the gateway (DNS rebinding). That includes the address hints
/// in SVCB/HTTPS records.
pub fn public(records: &[Record]) -> Vec<Record> {
    records
        .iter()
        .filter(|r| match &r.data {
            RData::A(A(addr)) => is_public_v4(*addr),
            RData::AAAA(AAAA(addr)) => is_public_v6(*addr),
            RData::SVCB(svcb) => public_hints(svcb),
            RData::HTTPS(https) => public_hints(&https.0),
            _ => true,
        })
        .cloned()
        .collect()
}

fn public_hints(svcb: &SVCB) -> bool {
    svcb.svc_params.iter().all(|(_, value)| match value {
        SvcParamValue::Ipv4Hint(hint) => hint.0.iter().all(|A(a)| is_public_v4(*a)),
        SvcParamValue::Ipv6Hint(hint) => hint.0.iter().all(|AAAA(a)| is_public_v6(*a)),
        _ => true,
    })
}

fn is_public_v4(addr: Ipv4Addr) -> bool {
    !NOT_PUBLIC.iter().any(|net| net.contains(&addr))
}

fn is_public_v6(addr: Ipv6Addr) -> bool {
    let first = addr.segments()[0];
    // An IPv4 address in IPv6 clothing (mapped, or NAT64's well-known prefix)
    // is judged as the IPv4 address it carries.
    if let Some(v4) = addr.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    if addr.segments()[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [.., a, b, c, d] = addr.octets();
        return is_public_v4(Ipv4Addr::new(a, b, c, d));
    }
    !(addr.is_unspecified()
        || addr.is_loopback()
        || addr.is_multicast()
        || first & 0xfe00 == 0xfc00 // unique local
        || first & 0xffc0 == 0xfe80 // link-local
        || (first == 0x2001 && addr.segments()[1] == 0x0db8)) // documentation
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::rr::rdata::{CNAME, HTTPS};
    use hickory_server::proto::rr::Name;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }
    fn a(s: &str) -> Record {
        Record::from_rdata(name("x.mydomain.com."), 60, RData::A(A(s.parse().unwrap())))
    }
    fn aaaa(s: &str) -> Record {
        Record::from_rdata(
            name("x.mydomain.com."),
            60,
            RData::AAAA(AAAA(s.parse().unwrap())),
        )
    }
    fn addrs(records: &[Record]) -> Vec<String> {
        records
            .iter()
            .map(|r| match &r.data {
                RData::A(A(a)) => a.to_string(),
                RData::AAAA(AAAA(a)) => a.to_string(),
                RData::CNAME(c) => format!("cname {}", c.0),
                other => format!("{other:?}"),
            })
            .collect()
    }
    fn home_mapping() -> Vec<Mapping> {
        vec![Mapping::new(
            "192.168.1.0/24".parse().unwrap(),
            "198.18.1.0/24".parse().unwrap(),
        )
        .unwrap()]
    }

    #[test]
    fn home_answers_move_into_mapped_space() {
        let cname = Record::from_rdata(
            name("photos.mydomain.com."),
            60,
            RData::CNAME(CNAME(name("x.mydomain.com."))),
        );
        let records = [
            cname,
            a("192.168.1.5"),
            a("192.168.7.7"),
            a("9.9.9.9"),
            aaaa("fd00::5"),
            Record::from_rdata(
                name("x.mydomain.com."),
                60,
                RData::HTTPS(HTTPS(SVCB::new(1, Name::root(), Vec::new()))),
            ),
        ];
        let out = home(&records, &home_mapping());
        assert_eq!(
            addrs(&out),
            [
                "cname x.mydomain.com.",
                "198.18.1.5",
                "192.168.7.7",
                "9.9.9.9"
            ]
        );
        assert_eq!(out[1].ttl, 60);
    }

    #[test]
    fn flattening_keeps_only_the_asked_type_under_the_asked_name() {
        let photos = name("photos.mydomain.com.");
        let records = vec![
            Record::from_rdata(
                photos.clone(),
                60,
                RData::CNAME(CNAME(name("x.mydomain.com."))),
            ),
            a("192.168.1.5"),
        ];
        let out = flatten(home(&records, &home_mapping()), &photos, RecordType::A);
        assert_eq!(addrs(&out), ["198.18.1.5"]);
        assert_eq!(out[0].name, photos);
    }

    #[test]
    fn public_https_records_lose_inward_hints() {
        use hickory_server::proto::rr::rdata::svcb::{IpHint, SvcParamKey};
        let https = |hint: &str| {
            Record::from_rdata(
                name("example.org."),
                60,
                RData::HTTPS(HTTPS(SVCB::new(
                    1,
                    Name::root(),
                    vec![(
                        SvcParamKey::Ipv4Hint,
                        SvcParamValue::Ipv4Hint(IpHint(vec![A(hint.parse().unwrap())])),
                    )],
                ))),
            )
        };
        assert_eq!(public(&[https("9.9.9.9")]).len(), 1);
        assert!(public(&[https("192.168.1.5")]).is_empty());
    }

    #[test]
    fn public_answers_lose_inward_addresses() {
        let records = [
            a("9.9.9.9"),
            a("192.168.1.5"),
            a("10.8.0.1"),
            a("198.18.1.5"),
            a("127.0.0.1"),
            aaaa("2606:4700::1111"),
            aaaa("fd00::5"),
            aaaa("fe80::1"),
            aaaa("::1"),
            aaaa("::ffff:192.168.1.5"),
            aaaa("::ffff:9.9.9.9"),
            aaaa("64:ff9b::c0a8:105"),
        ];
        assert_eq!(
            addrs(&public(&records)),
            ["9.9.9.9", "2606:4700::1111", "::ffff:9.9.9.9"]
        );
    }
}
