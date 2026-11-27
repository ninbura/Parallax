//! Fixtures shared by unit, golden and CLI tests. Public so downstream crates
//! can reuse the canonical scenario.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures: a broken fixture should panic loudly"
)]

use std::net::Ipv4Addr;

use crate::date::Date;
use crate::model::*;
use crate::secret::KeyPair;

/// The date every deterministic test evaluates at.
pub fn today() -> Date {
    Date::new(2026, 9, 6).expect("date")
}

/// Deterministic keypair `n` (private key = 32 bytes of `n`, clamped).
pub fn keypair(n: u8) -> KeyPair {
    KeyPair::from_private_bytes([n; 32])
}

/// The canonical scenario from the design: home LAN 192.168.1.0/24 mapped to
/// 198.18.1.0/24, grants `personal` and `family`, three WireGuard peers.
pub fn canonical_config() -> Config {
    let server_key = keypair(200);
    let router = keypair(1);
    let laptop = keypair(2);
    let sister = keypair(3);
    Config {
        server: ServerConfig {
            wireguard: WireGuardServer {
                interface: "wg0".into(),
                listen_port: 51820,
                supernet: "10.8.0.0/16".parse().unwrap(),
                endpoint: "vpn.mydomain.com:51820".into(),
                public_key: server_key.public,
                private_key_file: "/etc/parallax/wg-server.key".into(),
                peer_defaults: PeerDefaults::default(),
            },
            headscale: HeadscaleServer {
                server_url: "https://headscale.mydomain.com".into(),
                ..Default::default()
            },
            dns: DnsServer::default(),
            firewall: FirewallServer {
                backend: FirewallBackend::Nftables,
                docker_coexistence: true,
            },
            proxy: ProxyServer::default(),
            backup: BackupServer::default(),
            public_ip: PublicIpServer::default(),
            logs: Default::default(),
            wan_interface: None,
        },
        networks: vec![Network {
            name: "home".into(),
            interface: "eth0".into(),
            gateway_address: None,
            subnet: "192.168.1.0/24".parse().unwrap(),
            mapped_to: Some("198.18.1.0/24".parse().unwrap()),
            upstream_dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
            domains: vec!["mydomain.com".into()],
            masquerade: false,
        }],
        services: vec![Service {
            name: "immich".into(),
            host: Host::Ip(Ipv4Addr::new(192, 168, 1, 5)),
            ports: vec![PortSpec::one(Proto::Tcp, 443)],
            nginx_vhost: true,
            hostnames: Vec::new(),
        }],
        grants: vec![
            Grant {
                name: "personal".into(),
                everyone: false,
                log: None,
                rules: vec![Rule::AllNetworks, Rule::PublicDns],
            },
            Grant {
                name: "family".into(),
                everyone: false,
                log: None,
                rules: vec![Rule::Service {
                    name: "immich".into(),
                }],
            },
        ],
        peers: vec![
            Peer {
                name: "router".into(),
                grants: vec!["personal".into()],
                log: None,
                transport: TransportKind::WireGuard,
                enabled: true,
                expires: None,
                wireguard: Some(WireGuardPeer {
                    public_key: router.public,
                    address: Some(Ipv4Addr::new(10, 8, 1, 1)),
                    private_key: None,
                    preshared_key: None,
                    dns: DnsMode::Split,
                    allowed_ips: AllowedIpsStrategy::MappedSubnets,
                    mtu: None,
                    persistent_keepalive: Some(25),
                    visible_networks: None,
                }),
                tailscale: None,
            },
            Peer {
                name: "laptop".into(),
                grants: vec!["personal".into()],
                log: None,
                transport: TransportKind::WireGuard,
                enabled: true,
                expires: None,
                wireguard: Some(WireGuardPeer {
                    public_key: laptop.public,
                    address: Some(Ipv4Addr::new(10, 8, 1, 2)),
                    private_key: Some(laptop.private),
                    preshared_key: None,
                    dns: DnsMode::Split,
                    allowed_ips: AllowedIpsStrategy::MappedSubnets,
                    mtu: None,
                    persistent_keepalive: Some(25),
                    visible_networks: None,
                }),
                tailscale: None,
            },
            Peer {
                name: "sister-phone".into(),
                grants: vec!["family".into()],
                log: None,
                transport: TransportKind::WireGuard,
                enabled: true,
                expires: Some(Date::new(2027, 12, 31).unwrap()),
                wireguard: Some(WireGuardPeer {
                    public_key: sister.public,
                    address: Some(Ipv4Addr::new(10, 8, 2, 1)),
                    private_key: Some(sister.private),
                    preshared_key: Some(crate::secret::PresharedKey::from_bytes([9; 32])),
                    dns: DnsMode::TunnelWide,
                    allowed_ips: AllowedIpsStrategy::GrantsOnly,
                    mtu: None,
                    persistent_keepalive: Some(25),
                    visible_networks: None,
                }),
                tailscale: None,
            },
        ],
    }
}

/// The tier of `model` whose grants are `label` (`family`, `family+photos`).
pub fn tier<'m, 'a>(model: &'m crate::Model<'a>, label: &str) -> &'m crate::Tier<'a> {
    model
        .tiers()
        .iter()
        .find(|t| t.label() == label)
        .unwrap_or_else(|| panic!("no tier '{label}'"))
}
