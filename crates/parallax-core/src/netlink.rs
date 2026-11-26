//! The two netlink feeds activity logging reads (docs/adr/0012), parsed
//! from bytes: connection tracking's events (new and ended flows) and the
//! firewall's nflog group (blocked packets). Pure: the daemon owns the
//! sockets and hands their bytes here, so this is tested with byte
//! fixtures.
//!
//! Layout: a netlink message is a 16-byte header (length, type, flags,
//! sequence, port, in host byte order), then netfilter's 4-byte header
//! (family, version, resource id in network order), then attributes:
//! 2-byte length, 2-byte type, payload, padded to 4 bytes. Attribute
//! payloads are in network byte order.

use std::net::Ipv4Addr;

use crate::logging::{Blocked, Event, Flow};

const HEADER: usize = 16;
const NFGEN: usize = 4;

/// Netlink control messages.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// Netfilter subsystems, the high byte of a message type.
const SUBSYS_CTNETLINK: u16 = 1;
const SUBSYS_ULOG: u16 = 4;
const CT_NEW: u16 = 0;
const CT_DELETE: u16 = 2;
const ULOG_PACKET: u16 = 0;
const ULOG_CONFIG: u16 = 1;
const AF_INET: u8 = 2;
/// Request flags: a request, and acknowledge it.
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;

/// Conntrack's attributes.
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_ID: u16 = 12;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_COUNTERS_BYTES: u16 = 2;

/// nflog's attributes.
const NFULA_PAYLOAD: u16 = 9;
const NFULA_PREFIX: u16 = 10;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;

/// Connection tracking's multicast groups for new (1) and destroyed (3)
/// flows, as a bind mask: group n is bit n - 1.
const NFNLGRP_CONNTRACK_NEW: u32 = 1;
const NFNLGRP_CONNTRACK_DESTROY: u32 = 3;
pub const CONNTRACK_GROUPS: u32 =
    1 << (NFNLGRP_CONNTRACK_NEW - 1) | 1 << (NFNLGRP_CONNTRACK_DESTROY - 1);

/// Enough of each blocked packet for its addresses and ports.
const COPY_RANGE: u32 = 64;

/// The message that binds this socket to nflog `group`, copying the first
/// bytes of each packet. The kernel answers with an acknowledgement
/// ([`acknowledged`]).
pub fn nflog_bind(group: u16) -> Vec<u8> {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND]);
    let mut mode = COPY_RANGE.to_be_bytes().to_vec();
    mode.extend([NFULNL_COPY_PACKET, 0]);
    push_attr(&mut attrs, NFULA_CFG_MODE, &mode);

    let length = HEADER + NFGEN + attrs.len();
    let mut out = Vec::with_capacity(length);
    out.extend((length as u32).to_ne_bytes());
    out.extend((SUBSYS_ULOG << 8 | ULOG_CONFIG).to_ne_bytes());
    out.extend((NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    out.extend(1u32.to_ne_bytes()); // sequence
    out.extend(0u32.to_ne_bytes()); // port: the kernel fills it in
    out.extend([0, 0]); // family AF_UNSPEC, version 0
    out.extend(group.to_be_bytes());
    out.extend(attrs);
    out
}

/// The kernel's answer to a request: `Ok` for an acknowledgement, the
/// error number for a refusal (`EBUSY`: another program holds the group).
pub fn acknowledged(bytes: &[u8]) -> Result<(), i32> {
    for (kind, body) in messages(bytes) {
        if kind == NLMSG_ERROR {
            let code = body
                .get(..4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, i32::from_ne_bytes);
            return if code == 0 { Ok(()) } else { Err(-code) };
        }
    }
    Ok(())
}

/// The events in a buffer read from the conntrack socket. Anything else
/// (IPv6 flows, updates, control messages) is skipped.
pub fn conntrack_events(bytes: &[u8]) -> Vec<Event> {
    let mut out = Vec::new();
    for (kind, body) in messages(bytes) {
        if kind >> 8 != SUBSYS_CTNETLINK || body.first() != Some(&AF_INET) {
            continue;
        }
        let Some(flow) = body.get(NFGEN..).and_then(flow) else {
            continue;
        };
        match kind & 0xff {
            CT_NEW => out.push(Event::Opened(flow)),
            CT_DELETE => out.push(Event::Closed(flow)),
            _ => {}
        }
    }
    out
}

/// The blocked packets in a buffer read from the nflog socket. `prefix`
/// tells drops apart: the gateway host's is [`crate::generate::firewall::DENIED_GATEWAY`].
pub fn nflog_packets(bytes: &[u8]) -> Vec<Event> {
    let mut out = Vec::new();
    for (kind, body) in messages(bytes) {
        if kind != (SUBSYS_ULOG << 8 | ULOG_PACKET) {
            continue;
        }
        let mut payload = None;
        let mut prefix = None;
        for (t, v) in attrs(body.get(NFGEN..).unwrap_or_default()) {
            match t {
                NFULA_PAYLOAD => payload = Some(v),
                // Null-terminated.
                NFULA_PREFIX => prefix = Some(v.split(|&b| b == 0).next().unwrap_or_default()),
                _ => {}
            }
        }
        let Some(packet) = payload.and_then(ipv4) else {
            continue;
        };
        let to_gateway = prefix == Some(crate::generate::firewall::DENIED_GATEWAY.as_bytes());
        out.push(Event::Blocked(Blocked {
            to_gateway,
            ..packet
        }));
    }
    out
}

/// Each message's type and the bytes after its header.
fn messages(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while bytes.len() >= HEADER {
        let length = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if length < HEADER || length > bytes.len() {
            break;
        }
        let kind = u16::from_ne_bytes([bytes[4], bytes[5]]);
        if kind == NLMSG_DONE {
            break;
        }
        out.push((kind, &bytes[HEADER..length]));
        bytes = bytes.get(align(length)..).unwrap_or_default();
    }
    out
}

/// Each attribute's type (flags masked off) and payload.
fn attrs(mut bytes: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while bytes.len() >= 4 {
        let length = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        if length < 4 || length > bytes.len() {
            break;
        }
        // Without NLA_F_NESTED (0x8000) and NLA_F_NET_BYTEORDER (0x4000).
        let kind = u16::from_ne_bytes([bytes[2], bytes[3]]) & 0x3fff;
        out.push((kind, &bytes[4..length]));
        bytes = bytes.get(align(length)..).unwrap_or_default();
    }
    out
}

fn align(n: usize) -> usize {
    n.div_ceil(4) * 4
}

fn push_attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = 4 + payload.len();
    out.extend((length as u16).to_ne_bytes());
    out.extend(kind.to_ne_bytes());
    out.extend(payload);
    out.resize(align(out.len()), 0);
}

fn find<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(t, _)| *t == kind).map(|(_, v)| *v)
}

fn be_u16(v: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(v.get(..2)?.try_into().ok()?))
}
fn be_u32(v: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(v.get(..4)?.try_into().ok()?))
}
fn be_u64(v: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(v.get(..8)?.try_into().ok()?))
}
fn addr(v: &[u8]) -> Option<Ipv4Addr> {
    be_u32(v).map(Ipv4Addr::from)
}

/// Source, destination, protocol and destination port of a tuple.
struct Tuple {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    port: Option<u16>,
}

fn tuple(v: &[u8]) -> Option<Tuple> {
    let parts = attrs(v);
    let ip = attrs(find(&parts, CTA_TUPLE_IP)?);
    let proto = attrs(find(&parts, CTA_TUPLE_PROTO)?);
    Some(Tuple {
        src: addr(find(&ip, CTA_IP_V4_SRC)?)?,
        dst: addr(find(&ip, CTA_IP_V4_DST)?)?,
        protocol: *find(&proto, CTA_PROTO_NUM)?.first()?,
        port: find(&proto, CTA_PROTO_DST_PORT).and_then(be_u16),
    })
}

fn flow(v: &[u8]) -> Option<Flow> {
    let parts = attrs(v);
    let orig = tuple(find(&parts, CTA_TUPLE_ORIG)?)?;
    let reply = tuple(find(&parts, CTA_TUPLE_REPLY)?)?;
    let bytes = |kind| {
        find(&parts, kind)
            .map(attrs)
            .and_then(|c| find(&c, CTA_COUNTERS_BYTES).and_then(be_u64))
    };
    Some(Flow {
        id: find(&parts, CTA_ID).and_then(be_u32).unwrap_or(0),
        protocol: orig.protocol,
        src: orig.src,
        dst: orig.dst,
        answered_by: reply.src,
        port: orig.port,
        mark: find(&parts, CTA_MARK).and_then(be_u32).unwrap_or(0),
        bytes: bytes(CTA_COUNTERS_ORIG).zip(bytes(CTA_COUNTERS_REPLY)),
    })
}

/// Addresses, protocol and destination port of an IPv4 packet.
fn ipv4(p: &[u8]) -> Option<Blocked> {
    let first = *p.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let header = usize::from(first & 0x0f) * 4;
    let protocol = *p.get(9)?;
    // TCP, UDP and SCTP all start with the source and destination ports.
    let port = match protocol {
        6 | 17 | 132 => p.get(header + 2..header + 4).and_then(be_u16),
        _ => None,
    };
    Some(Blocked {
        protocol,
        src: addr(p.get(12..16)?)?,
        dst: addr(p.get(16..20)?)?,
        port,
        to_gateway: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, family: u8, attrs: &[u8]) -> Vec<u8> {
        let length = HEADER + NFGEN + attrs.len();
        let mut out = Vec::new();
        out.extend((length as u32).to_ne_bytes());
        out.extend(kind.to_ne_bytes());
        out.extend(0u16.to_ne_bytes());
        out.extend(0u32.to_ne_bytes());
        out.extend(0u32.to_ne_bytes());
        out.extend([family, 0, 0, 0]);
        out.extend(attrs);
        out
    }

    fn nested(kind: u16, inner: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_attr(&mut out, kind | 0x8000, inner);
        out
    }

    fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        push_attr(&mut out, kind, payload);
        out
    }

    fn tuple_attr(kind: u16, src: [u8; 4], dst: [u8; 4], proto: u8, dport: u16) -> Vec<u8> {
        let ip = [attr(CTA_IP_V4_SRC, &src), attr(CTA_IP_V4_DST, &dst)].concat();
        let pr = [
            attr(CTA_PROTO_NUM, &[proto]),
            attr(2, &40000u16.to_be_bytes()),
            attr(CTA_PROTO_DST_PORT, &dport.to_be_bytes()),
        ]
        .concat();
        nested(
            kind,
            &[nested(CTA_TUPLE_IP, &ip), nested(CTA_TUPLE_PROTO, &pr)].concat(),
        )
    }

    fn counters(kind: u16, bytes: u64) -> Vec<u8> {
        nested(
            kind,
            &[
                attr(1, &3u64.to_be_bytes()),
                attr(CTA_COUNTERS_BYTES, &bytes.to_be_bytes()),
            ]
            .concat(),
        )
    }

    /// A flow from 10.8.2.1 to 198.18.1.5:2283, answered by 192.168.1.5.
    fn ct_message(msg: u16, family: u8, with_counters: bool) -> Vec<u8> {
        let mut a = [
            tuple_attr(CTA_TUPLE_ORIG, [10, 8, 2, 1], [198, 18, 1, 5], 6, 2283),
            tuple_attr(CTA_TUPLE_REPLY, [192, 168, 1, 5], [10, 8, 2, 1], 6, 40000),
            attr(CTA_MARK, &0x2000_0001u32.to_be_bytes()),
            attr(CTA_ID, &99u32.to_be_bytes()),
        ]
        .concat();
        if with_counters {
            a.extend(counters(CTA_COUNTERS_ORIG, 1200));
            a.extend(counters(CTA_COUNTERS_REPLY, 34_000));
        }
        message(SUBSYS_CTNETLINK << 8 | msg, family, &a)
    }

    #[test]
    fn conntrack_events_give_both_tuples_the_mark_and_the_bytes() {
        let buf = [
            ct_message(CT_NEW, AF_INET, false),
            ct_message(CT_DELETE, AF_INET, true),
            // IPv6 and other message kinds are skipped.
            ct_message(CT_NEW, 10, false),
            ct_message(1, AF_INET, false),
        ]
        .concat();
        let events = conntrack_events(&buf);
        let expected = Flow {
            id: 99,
            protocol: 6,
            src: Ipv4Addr::new(10, 8, 2, 1),
            dst: Ipv4Addr::new(198, 18, 1, 5),
            answered_by: Ipv4Addr::new(192, 168, 1, 5),
            port: Some(2283),
            mark: 0x2000_0001,
            bytes: None,
        };
        assert_eq!(
            events,
            [
                Event::Opened(expected.clone()),
                Event::Closed(Flow {
                    bytes: Some((1200, 34_000)),
                    ..expected
                })
            ]
        );
    }

    #[test]
    fn truncated_or_garbled_buffers_give_what_parses_and_never_panic() {
        let whole = ct_message(CT_NEW, AF_INET, true);
        for cut in 0..whole.len() {
            let _ = conntrack_events(&whole[..cut]);
            let _ = nflog_packets(&whole[..cut]);
        }
        let mut lying = whole.clone();
        lying[0] = 0xff; // a length past the end
        assert!(conntrack_events(&lying).is_empty());
    }

    fn ip_packet(proto: u8, src: [u8; 4], dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend(src);
        p.extend(dst);
        p.extend(51000u16.to_be_bytes());
        p.extend(dport.to_be_bytes());
        p
    }

    fn nflog_message(prefix: &str, packet: &[u8]) -> Vec<u8> {
        let mut text = prefix.as_bytes().to_vec();
        text.push(0);
        let a = [
            attr(1, &[0x08, 0x00, 2, 0]),
            attr(NFULA_PREFIX, &text),
            attr(NFULA_PAYLOAD, packet),
        ]
        .concat();
        message(SUBSYS_ULOG << 8 | ULOG_PACKET, AF_INET, &a)
    }

    #[test]
    fn nflog_packets_give_addresses_ports_and_which_drop() {
        use crate::generate::firewall::{DENIED_FORWARD, DENIED_GATEWAY};
        let buf = [
            nflog_message(
                DENIED_FORWARD,
                &ip_packet(6, [10, 8, 2, 1], [192, 168, 1, 9], 22),
            ),
            nflog_message(
                DENIED_GATEWAY,
                &ip_packet(17, [10, 8, 2, 1], [10, 8, 0, 1], 8080),
            ),
            nflog_message(
                DENIED_FORWARD,
                &ip_packet(1, [10, 8, 2, 1], [9, 9, 9, 9], 0),
            ),
        ]
        .concat();
        let events = nflog_packets(&buf);
        let blocked = |protocol, dst: [u8; 4], port, to_gateway| {
            Event::Blocked(Blocked {
                protocol,
                src: Ipv4Addr::new(10, 8, 2, 1),
                dst: Ipv4Addr::from(dst),
                port,
                to_gateway,
            })
        };
        assert_eq!(
            events,
            [
                blocked(6, [192, 168, 1, 9], Some(22), false),
                blocked(17, [10, 8, 0, 1], Some(8080), true),
                blocked(1, [9, 9, 9, 9], None, false),
            ]
        );
    }

    #[test]
    fn the_bind_request_and_its_answer() {
        let m = nflog_bind(20568);
        assert_eq!(
            u32::from_ne_bytes(m[..4].try_into().unwrap()) as usize,
            m.len()
        );
        assert_eq!(
            u16::from_ne_bytes([m[4], m[5]]),
            SUBSYS_ULOG << 8 | ULOG_CONFIG
        );
        assert_eq!(&m[18..20], &20568u16.to_be_bytes());
        let parsed = attrs(&m[HEADER + NFGEN..]);
        assert_eq!(
            find(&parsed, NFULA_CFG_CMD),
            Some(&[NFULNL_CFG_CMD_BIND][..])
        );

        let answer = |code: i32| {
            let mut out = Vec::new();
            out.extend(36u32.to_ne_bytes());
            out.extend(NLMSG_ERROR.to_ne_bytes());
            out.extend([0; 10]);
            out.extend(code.to_ne_bytes());
            out.extend([0; 16]);
            out
        };
        assert_eq!(acknowledged(&answer(0)), Ok(()));
        assert_eq!(acknowledged(&answer(-16)), Err(16));
    }
}
