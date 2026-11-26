use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use parallax_core::generate;
use parallax_core::io::memory::MemoryFs;
use parallax_core::model::*;
use parallax_core::testing::{canonical_config, keypair, today};
use parallax_core::{Config, Model};

use crate::{Error, Store, MVCC};

pub(crate) const LATEST: i64 = crate::MIGRATIONS.len() as i64;

/// A fresh directory per test, removed on drop.
pub(crate) struct TempDir(pub(crate) PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "parallax-store-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    pub(crate) fn db(&self) -> PathBuf {
        self.0.join("parallax.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn round_trip(config: &Config) -> Config {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    store.save(config).await.unwrap();
    drop(store);
    Store::open(&dir.db()).await.unwrap().load().await.unwrap()
}

/// Every optional field set, every rule kind, both visibility forms.
pub(crate) fn everything_config() -> Config {
    let mut c = canonical_config();
    c.server.wan_interface = Some("eth1".into());
    c.server.dns.listen = Some(Ipv4Addr::new(10, 8, 0, 1));
    c.server.proxy.listen = Some(Ipv4Addr::new(10, 8, 0, 1));
    c.server.firewall.backend = FirewallBackend::IptablesNft;
    c.server.headscale.derp = DerpMode::Tailscale;
    c.server.backup = BackupServer {
        directory: "/srv/backups/parallax".into(),
        automatic: false,
        interval: "6h".parse().unwrap(),
        keep: 3,
        encrypt: false,
        passphrase_file: "/root/backup.passphrase".into(),
    };
    c.server.public_ip = PublicIpServer {
        address: Some(Ipv4Addr::new(1, 2, 3, 4)),
        // Not in declaration order: the order is the try order.
        encrypted_dns: vec![EncryptedDns::Cloudflare, EncryptedDns::Quad9],
    };
    c.server.logs = LogsServer {
        level: LogLevel::Connections,
        path: "/mnt/ssd/parallax-logs.db".into(),
        keep: "7d".parse().unwrap(),
        max_size: "256MiB".parse().unwrap(),
    };
    c.networks.push(Network {
        name: "lab".into(),
        interface: "eth1".into(),
        gateway_address: Some(Ipv4Addr::new(192, 168, 2, 2)),
        subnet: "192.168.2.0/24".parse().unwrap(),
        mapped_to: None,
        upstream_dns: vec![Ipv4Addr::new(192, 168, 2, 1), Ipv4Addr::new(192, 168, 2, 3)],
        domains: vec!["lab.mydomain.com".into(), "lab.internal".into()],
        masquerade: true,
    });
    c.services.push(Service {
        name: "photos".into(),
        host: Host::Name("photos.mydomain.com".into()),
        ports: vec![
            "8443/udp".parse().unwrap(),
            "137-138/udp".parse().unwrap(),
            "25565".parse().unwrap(),
        ],
        nginx_vhost: false,
        hostnames: vec!["photos.mydomain.com".into(), "img.mydomain.com".into()],
    });
    c.server.wireguard.peer_defaults = PeerDefaults {
        dns: DnsMode::None,
        allowed_ips: AllowedIpsStrategy::GrantsOnly,
        mtu: Some(1400),
        persistent_keepalive: Some(15),
    };
    c.server.headscale.dns = DnsMode::TunnelWide;
    c.grants[0].rules = vec![
        Rule::AllNetworks,
        Rule::Network { name: "lab".into() },
        Rule::Host {
            host: Ipv4Addr::new(192, 168, 1, 9).into(),
            ports: Vec::new(),
        },
        Rule::Host {
            host: Host::Name("dns.lab.mydomain.com".into()),
            ports: vec![PortSpec::one(Proto::Udp, 53)],
        },
        Rule::Service {
            name: "photos".into(),
        },
        Rule::Internet,
        Rule::PublicDns,
    ];
    c.grants.push(Grant {
        name: "public".into(),
        everyone: true,
        log: Some(LogLevel::Denied),
        rules: Vec::new(),
    });
    let wg = c.peers[0].wireguard.as_mut().unwrap();
    wg.visible_networks = Some(vec!["lab".into(), "home".into()]);
    wg.dns = DnsMode::TunnelWide;
    wg.allowed_ips = AllowedIpsStrategy::FullTunnel;
    wg.mtu = Some(1380);
    c.peers[1].grants = vec!["family".into(), "personal".into()];
    c.peers[2].wireguard.as_mut().unwrap().visible_networks = Some(Vec::new());
    c.peers.push(Peer {
        name: "tv".into(),
        grants: vec!["family".into()],
        log: Some(LogLevel::Off),
        transport: TransportKind::Tailscale,
        enabled: false,
        expires: Some(today()),
        wireguard: None,
        tailscale: Some(TailscalePeer::default()),
    });
    c.peers.push(Peer {
        name: "tablet".into(),
        grants: Vec::new(),
        log: None,
        transport: TransportKind::Tailscale,
        enabled: true,
        expires: None,
        wireguard: None,
        tailscale: Some(TailscalePeer {
            node_id: Some(42),
            address: Some(Ipv4Addr::new(100, 64, 0, 7)),
        }),
    });
    let wg = c.peers[0].wireguard.as_mut().unwrap();
    wg.private_key = Some(keypair(9).private);
    wg.preshared_key = Some(parallax_core::secret::PresharedKey::from_bytes([7; 32]));
    c
}

#[tokio::test]
async fn canonical_config_round_trips() {
    let config = canonical_config();
    assert_eq!(round_trip(&config).await, config);
}

#[tokio::test]
async fn every_field_round_trips() {
    let config = everything_config();
    assert_eq!(round_trip(&config).await, config);
}

#[tokio::test]
async fn importing_the_example_exports_the_same_toml() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../example/parallax.toml"),
    )
    .unwrap();
    let parsed = Config::from_toml(&text).unwrap();
    let loaded = round_trip(&parsed).await;
    assert_eq!(loaded.to_toml().unwrap(), parsed.to_toml().unwrap());
}

#[tokio::test]
async fn generation_from_the_database_matches_the_goldens() {
    let loaded = round_trip(&canonical_config()).await;
    let model = Model::resolve(&loaded, today()).unwrap();
    let fs = MemoryFs::new().with_file(
        "/etc/parallax/wg-server.key",
        keypair(200).private.expose_base64(),
    );
    let bundle = generate::generate_all(&model, &fs).unwrap();
    let golden =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../parallax-core/tests/golden/canonical");
    for a in &bundle.artifacts {
        let expected = std::fs::read_to_string(golden.join(&a.path)).unwrap();
        assert_eq!(a.contents, expected, "{}", a.path.display());
    }
}

async fn id_of(store: &Store, table: &str, name: &str) -> i64 {
    let rows = store
        .rows(
            &format!("SELECT id FROM {table} WHERE name = ?1"),
            vec![name.into()],
        )
        .await
        .unwrap();
    rows[0].get::<i64>(0).unwrap()
}

#[tokio::test]
async fn saving_keeps_ids_and_follows_renames_and_removals() {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    let mut config = everything_config();
    store.save(&config).await.unwrap();
    let laptop = id_of(&store, "peers", "laptop").await;
    let home = id_of(&store, "networks", "home").await;

    // Rename a grant its peers move to, drop a network and a service the
    // rules no longer mention, reorder and edit peers.
    config.grants[1].name = "guests".into();
    for p in &mut config.peers {
        for g in &mut p.grants {
            if g == "family" {
                *g = "guests".into();
            }
        }
    }
    config.grants[0]
        .rules
        .retain(|r| !matches!(r, Rule::Network { .. } | Rule::Service { .. }));
    config.peers[0].wireguard.as_mut().unwrap().visible_networks = None;
    config.grants.retain(|g| g.name != "public");
    config.networks.retain(|n| n.name != "lab");
    config.services.retain(|s| s.name != "photos");
    config.peers.reverse();
    config.peers.retain(|p| p.name != "tv");
    config.peers[0].enabled = false;
    store.save(&config).await.unwrap();

    assert_eq!(store.load().await.unwrap(), config);
    assert_eq!(id_of(&store, "peers", "laptop").await, laptop);
    assert_eq!(id_of(&store, "networks", "home").await, home);
}

#[tokio::test]
async fn a_failed_save_changes_nothing() {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    let config = canonical_config();
    store.save(&config).await.unwrap();

    let mut broken = config.clone();
    broken.peers.clear();
    broken.grants[0].rules.push(Rule::Network {
        name: "nowhere".into(),
    });
    let err = store.save(&broken).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("grant 'personal': rule refers to unknown network 'nowhere'"),
        "{err}"
    );
    assert_eq!(store.load().await.unwrap(), config);

    let mut twice = config.clone();
    twice.peers.push(twice.peers[0].clone());
    let err = store.save(&twice).await.unwrap_err();
    assert!(err.to_string().contains("defined twice"), "{err}");
    assert_eq!(store.load().await.unwrap(), config);
}

#[tokio::test]
async fn missing_and_empty_databases_say_what_to_do() {
    let dir = TempDir::new();
    let err = Store::open(&dir.db()).await.unwrap_err();
    assert!(matches!(err, Error::Missing(_)), "{err}");
    assert!(err.to_string().contains("parallax config import"));

    let mut store = Store::create(&dir.db()).await.unwrap();
    let err = store.load().await.unwrap_err();
    assert!(matches!(err, Error::Empty(_)), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn the_database_and_its_log_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    store.save(&everything_config()).await.unwrap();
    for file in ["parallax.db", "parallax.db-wal", "parallax.db-log"] {
        let mode = std::fs::metadata(dir.0.join(file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }

    // Turso names MVCC's log by replacing the extension.
    let other = dir.0.join("state.sqlite");
    let mut store = Store::create(&other).await.unwrap();
    store.save(&everything_config()).await.unwrap();
    let mode = std::fs::metadata(dir.0.join("state.db-log"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "state.db-log");
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let dir = TempDir::new();
    let store = Store::create(&dir.db()).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), LATEST);
    store
        .exec(
            "INSERT INTO schema_version (version) VALUES (99)",
            Vec::new(),
        )
        .await
        .unwrap();
    drop(store);
    let err = Store::open(&dir.db()).await.unwrap_err();
    assert!(
        matches!(
            err,
            Error::TooNew {
                found: 99,
                known: LATEST,
                ..
            }
        ),
        "{err}"
    );
}

/// Before the daemon (step 7) the database was opened in Turso's
/// multi-process mode; such a file must still open, and keep its data.
#[tokio::test]
async fn a_database_written_in_multi_process_mode_opens() {
    let dir = TempDir::new();
    let path = dir.db();
    {
        let db = turso::Builder::new_local(path.to_str().unwrap())
            .experimental_multiprocess_wal(true)
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        conn.execute_batch("CREATE TABLE t (x INTEGER); INSERT INTO t VALUES (7);")
            .await
            .unwrap();
    }
    let mut tshm = path.as_os_str().to_owned();
    tshm.push("-tshm");
    assert!(
        Path::new(&tshm).exists(),
        "the old mode leaves its coordination file"
    );
    let store = Store::open(&path).await.unwrap();
    let rows = store.rows("SELECT x FROM t", Vec::new()).await.unwrap();
    assert_eq!(rows[0].get::<i64>(0).unwrap(), 7);
    assert_eq!(store.journal_mode(None).await.unwrap(), MVCC);
}

/// Databases from before 7c are in WAL mode: opening one switches it to
/// MVCC, once, and keeps what it holds.
#[tokio::test]
async fn an_older_database_switches_to_mvcc_and_keeps_its_data() {
    let dir = TempDir::new();
    {
        let mut store = Store::create_plain(&dir.db()).await.unwrap();
        assert_eq!(store.journal_mode(None).await.unwrap(), "wal");
        store.save(&everything_config()).await.unwrap();
    }
    for _ in 0..2 {
        let mut store = Store::open(&dir.db()).await.unwrap();
        assert_eq!(store.journal_mode(None).await.unwrap(), MVCC);
        assert_eq!(store.load().await.unwrap(), everything_config());
    }
    let created = Store::create(&dir.0.join("new.db")).await.unwrap();
    assert_eq!(created.journal_mode(None).await.unwrap(), MVCC);
}

/// A database from a newer Parallax is refused before anything changes it,
/// so the newer build can still open it as it was.
#[tokio::test]
async fn a_newer_database_is_refused_without_switching_it() {
    let dir = TempDir::new();
    let store = Store::create_plain(&dir.db()).await.unwrap();
    store
        .exec(
            "INSERT INTO schema_version (version) VALUES (99)",
            Vec::new(),
        )
        .await
        .unwrap();
    drop(store);
    let err = Store::open(&dir.db()).await.unwrap_err();
    assert!(matches!(err, Error::TooNew { found: 99, .. }), "{err}");
    let db = turso::Builder::new_local(dir.db().to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    let mut rows = conn.query("PRAGMA journal_mode", ()).await.unwrap();
    let mode = rows
        .next()
        .await
        .unwrap()
        .unwrap()
        .get::<String>(0)
        .unwrap();
    assert_eq!(mode, "wal");
}

#[tokio::test]
async fn reopening_does_not_migrate_twice() {
    let dir = TempDir::new();
    drop(Store::create(&dir.db()).await.unwrap());
    let store = Store::open(&dir.db()).await.unwrap();
    let rows = store
        .rows("SELECT count(*) FROM schema_version", Vec::new())
        .await
        .unwrap();
    assert_eq!(rows[0].get::<i64>(0).unwrap(), LATEST);
}

/// A database as Parallax wrote it before backups (schema 1), holding the
/// canonical configuration's server row.
pub(crate) async fn schema_1_database(path: &Path) {
    let db = turso::Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    conn.execute_batch(crate::MIGRATIONS[0]).await.unwrap();
    conn.execute_batch(
        "CREATE TABLE schema_version (version INTEGER NOT NULL);
         INSERT INTO schema_version (version) VALUES (1);",
    )
    .await
    .unwrap();
    let c = canonical_config();
    conn.execute(
        "INSERT INTO server (id, wireguard_interface, wireguard_listen_port,
            wireguard_supernet, wireguard_endpoint, wireguard_public_key,
            wireguard_private_key_file, headscale_interface, headscale_server_url,
            headscale_api_key_file, headscale_derp, headscale_subnet_router_node,
            dns_port, dns_public_resolver, firewall_backend,
            firewall_docker_coexistence, proxy_port, proxy_certificates,
            proxy_upstream_ca)
         VALUES (1, 'wg0', 51820, '10.8.0.0/16', 'vpn.mydomain.com:51820', ?1,
            '/etc/parallax/wg-server.key', 'tailscale0', 'https://headscale.mydomain.com',
            '/etc/parallax/headscale-api.key', 'embedded', 'parallax-gateway',
            53, '1.1.1.1', 'nftables', 1, 8443, '/etc/parallax/certs',
            '/etc/ssl/certs/ca-certificates.crt')",
        (c.server.wireguard.public_key.to_base64(),),
    )
    .await
    .unwrap();
    // Into the file itself, so a copy of the file alone holds it.
    let mut rows = conn
        .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
        .await
        .unwrap();
    while rows.next().await.unwrap().is_some() {}
}

#[tokio::test]
async fn a_database_from_before_backups_gets_their_defaults() {
    let dir = TempDir::new();
    schema_1_database(&dir.db()).await;
    let mut store = Store::open(&dir.db()).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), LATEST);
    let loaded = store.load().await.unwrap();
    assert_eq!(loaded.server, canonical_config().server);
}

#[tokio::test]
async fn the_public_ip_is_kept_apart_from_the_configuration() {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    store.save(&canonical_config()).await.unwrap();
    assert_eq!(store.public_ip().await.unwrap(), None);
    store
        .set_public_ip(Ipv4Addr::new(1, 2, 3, 4))
        .await
        .unwrap();
    store
        .set_public_ip(Ipv4Addr::new(1, 2, 3, 5))
        .await
        .unwrap();
    // Saving the configuration leaves it alone.
    store.save(&canonical_config()).await.unwrap();
    drop(store);
    let mut store = Store::open(&dir.db()).await.unwrap();
    assert_eq!(
        store.public_ip().await.unwrap(),
        Some(Ipv4Addr::new(1, 2, 3, 5))
    );
    assert_eq!(store.load().await.unwrap(), canonical_config());
}

#[tokio::test]
async fn grants_and_services_from_before_port_lists_keep_their_ports() {
    let dir = TempDir::new();
    schema_1_database(&dir.db()).await;
    {
        let db = turso::Builder::new_local(dir.db().to_str().unwrap())
            .build()
            .await
            .unwrap();
        let conn = db.connect().unwrap();
        conn.execute_batch(
            "INSERT INTO templates (id, name, position, wireguard_pool, headscale_user,
                visible_networks_limited, dns_wireguard, dns_tailscale, dns_public,
                client_allowed_ips)
             VALUES (1, 'guests', 0, '10.8.2.0/24', 'guest', 0, 'split', 'split', 0,
                'mapped_subnets');
             INSERT INTO template_grants (template_id, position, kind, ip, proto, port)
             VALUES (1, 0, 'host_port', '192.168.1.9', 'udp', 25565);
             INSERT INTO template_grants (template_id, position, kind, ip)
             VALUES (1, 1, 'host', '192.168.1.10');
             INSERT INTO services (id, name, position, host, proto, port, nginx_vhost)
             VALUES (1, 'smb', 0, '192.168.1.9', 'tcp', 445, 0);",
        )
        .await
        .unwrap();
        let mut rows = conn
            .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
            .await
            .unwrap();
        while rows.next().await.unwrap().is_some() {}
    }
    let mut store = Store::open(&dir.db()).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), LATEST);
    let loaded = store.load().await.unwrap();
    assert_eq!(
        loaded.grants[0].rules,
        [
            Rule::Host {
                host: Ipv4Addr::new(192, 168, 1, 9).into(),
                ports: vec![PortSpec::one(Proto::Udp, 25565)],
            },
            Rule::Host {
                host: Ipv4Addr::new(192, 168, 1, 10).into(),
                ports: Vec::new(),
            }
        ]
    );
    assert_eq!(loaded.services[0].ports, [PortSpec::one(Proto::Tcp, 445)]);
    // And it saves back in the new shape.
    store.save(&loaded).await.unwrap();
    assert_eq!(store.load().await.unwrap(), loaded);
}

#[tokio::test]
async fn duplicate_names_are_refused_before_anything_is_written() {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    let config = canonical_config();
    store.save(&config).await.unwrap();
    let mut twice = config.clone();
    twice.grants.push(twice.grants[0].clone());
    let err = store.save(&twice).await.unwrap_err();
    assert!(
        matches!(&err, Error::Invalid(m) if m == "grant 'personal' is defined twice"),
        "{err}"
    );
    assert_eq!(store.load().await.unwrap(), config);
}

#[tokio::test]
async fn save_if_empty_saves_only_into_an_empty_database() {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    let config = canonical_config();
    assert!(store.save_if_empty(&config).await.unwrap());
    let mut other = config.clone();
    other.peers.clear();
    assert!(!store.save_if_empty(&other).await.unwrap());
    assert_eq!(store.load().await.unwrap(), config);
}

#[tokio::test]
async fn update_saves_the_change_or_nothing() {
    let dir = TempDir::new();
    let mut store = Store::create(&dir.db()).await.unwrap();
    store.save(&canonical_config()).await.unwrap();

    let removed = store
        .update(|c| -> Result<usize, Error> {
            c.peers.retain(|p| p.name != "router");
            Ok(c.peers.len())
        })
        .await
        .unwrap();
    assert_eq!(removed, 2);
    assert!(store.load().await.unwrap().peer("router").is_none());

    let err = store
        .update(|c| -> Result<(), Error> {
            c.peers.clear();
            Err(Error::Invalid("refused".into()))
        })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Invalid(_)), "{err}");
    assert_eq!(store.load().await.unwrap().peers.len(), 2);
}

/// The canonical configuration as Parallax stored it before grants replaced
/// templates (schema 5), with a third, unattached template that has a port
/// list, a gap in its rule positions and `dns.public`, and every template on
/// tunnel-wide Tailscale DNS.
async fn schema_5_database(path: &Path) {
    let db = turso::Builder::new_local(path.to_str().unwrap())
        .build()
        .await
        .unwrap();
    let conn = db.connect().unwrap();
    for sql in &crate::MIGRATIONS[..5] {
        conn.execute_batch(sql).await.unwrap();
    }
    conn.execute_batch(
        "CREATE TABLE schema_version (version INTEGER NOT NULL);
         INSERT INTO schema_version (version) VALUES (5);",
    )
    .await
    .unwrap();
    let c = canonical_config();
    let key = |n: usize| c.peers[n].wireguard.as_ref().unwrap();
    conn.execute(
        "INSERT INTO server (id, wireguard_interface, wireguard_listen_port,
            wireguard_supernet, wireguard_endpoint, wireguard_public_key,
            wireguard_private_key_file, headscale_interface, headscale_server_url,
            headscale_api_key_file, headscale_derp, headscale_subnet_router_node,
            dns_port, dns_public_resolver, firewall_backend,
            firewall_docker_coexistence, proxy_port, proxy_certificates,
            proxy_upstream_ca)
         VALUES (1, 'wg0', 51820, '10.8.0.0/16', 'vpn.mydomain.com:51820', ?1,
            '/etc/parallax/wg-server.key', 'tailscale0', 'https://headscale.mydomain.com',
            '/etc/parallax/headscale-api.key', 'embedded', 'parallax-gateway',
            53, '1.1.1.1', 'nftables', 1, 8443, '/etc/parallax/certs',
            '/etc/ssl/certs/ca-certificates.crt')",
        (c.server.wireguard.public_key.to_base64(),),
    )
    .await
    .unwrap();
    conn.execute_batch(
        "INSERT INTO networks (id, name, position, interface, subnet, mapped_to, masquerade)
         VALUES (1, 'home', 0, 'eth0', '192.168.1.0/24', '198.18.1.0/24', 0);
         INSERT INTO network_upstream_dns (network_id, position, address)
         VALUES (1, 0, '192.168.1.1');
         INSERT INTO network_domains (network_id, position, domain)
         VALUES (1, 0, 'mydomain.com');
         INSERT INTO services (id, name, position, host, nginx_vhost)
         VALUES (1, 'immich', 0, '192.168.1.5', 1);
         INSERT INTO service_ports (service_id, position, ports) VALUES (1, 0, '443/tcp');
         INSERT INTO templates (id, name, position, wireguard_pool, headscale_user,
            headscale_tag, visible_networks_limited, dns_wireguard, dns_tailscale,
            dns_public, client_allowed_ips, client_mtu, client_persistent_keepalive)
         VALUES
            (1, 'personal', 0, '10.8.1.0/24', 'someone', NULL, 1, 'split',
                'tunnel_wide', 1, 'mapped_subnets', NULL, 25),
            (2, 'family', 1, '10.8.2.0/24', NULL, 'tag:family', 1, 'tunnel_wide',
                'tunnel_wide', 0, 'grants_only', NULL, 25),
            (3, 'spare', 2, '10.8.3.0/24', 'spare', NULL, 0, 'split',
                'tunnel_wide', 1, 'mapped_subnets', 1380, NULL);
         INSERT INTO template_grants (template_id, position, kind, network_id, service_id, host)
         VALUES (1, 0, 'all_networks', NULL, NULL, NULL),
            (2, 0, 'service', NULL, 1, NULL),
            (3, 0, 'host', NULL, NULL, '192.168.1.9'),
            (3, 2, 'network', 1, NULL, NULL);
         INSERT INTO template_grant_ports (template_id, grant_position, position, ports)
         VALUES (3, 0, 0, '25565/udp'), (3, 0, 1, '25565/tcp');
         INSERT INTO template_visible_networks (template_id, position, network_id)
         VALUES (1, 0, 1);
         INSERT INTO peers (id, name, position, template_id, transport, enabled,
            tailscale, tailscale_node_id, tailscale_address)
         VALUES (3, 'tv', 3, 1, 'tailscale', 1, 1, 5, '100.64.0.5');",
    )
    .await
    .unwrap();
    for (n, template) in [(0, 1), (1, 1), (2, 2)] {
        let p = &c.peers[n];
        let w = key(n);
        conn.execute(
            "INSERT INTO peers (id, name, position, template_id, transport, enabled, expires,
                wireguard_public_key, wireguard_address, wireguard_private_key,
                wireguard_preshared_key, tailscale)
             VALUES (?1, ?2, ?1, ?3, 'wireguard', 1, ?4, ?5, ?6, ?7, ?8, 0)",
            vec![
                turso::Value::from(n as i64),
                p.name.clone().into(),
                turso::Value::from(template),
                p.expires.map(|d| d.to_string()).into(),
                w.public_key.to_base64().into(),
                w.address.map(|a| a.to_string()).into(),
                w.private_key.as_ref().map(|k| k.expose_base64()).into(),
                w.preshared_key.as_ref().map(|k| k.expose_base64()).into(),
            ],
        )
        .await
        .unwrap();
    }
    let mut rows = conn
        .query("PRAGMA wal_checkpoint(TRUNCATE)", ())
        .await
        .unwrap();
    while rows.next().await.unwrap().is_some() {}
}

#[tokio::test]
async fn templates_become_grants_with_the_same_access() {
    let dir = TempDir::new();
    schema_5_database(&dir.db()).await;
    let mut store = Store::open(&dir.db()).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), LATEST);
    let loaded = store.load().await.unwrap();

    let mut expected = canonical_config();
    // `personal` showed only `home` and `family` no network: their
    // WireGuard peers keep that; the Tailscale one has no such setting.
    for p in &mut expected.peers[..2] {
        p.wireguard.as_mut().unwrap().visible_networks = Some(vec!["home".into()]);
    }
    expected.peers[2]
        .wireguard
        .as_mut()
        .unwrap()
        .visible_networks = Some(Vec::new());
    expected.peers.push(Peer {
        name: "tv".into(),
        grants: vec!["personal".into()],
        log: None,
        transport: TransportKind::Tailscale,
        enabled: true,
        expires: None,
        wireguard: None,
        tailscale: Some(TailscalePeer {
            node_id: Some(5),
            address: Some(Ipv4Addr::new(100, 64, 0, 5)),
        }),
    });
    expected.server.headscale.dns = DnsMode::TunnelWide;
    expected.grants.push(Grant {
        name: "spare".into(),
        everyone: false,
        log: None,
        rules: vec![
            Rule::Host {
                host: Ipv4Addr::new(192, 168, 1, 9).into(),
                ports: vec![
                    PortSpec::one(Proto::Udp, 25565),
                    PortSpec::one(Proto::Tcp, 25565),
                ],
            },
            Rule::Network {
                name: "home".into(),
            },
            Rule::PublicDns,
        ],
    });
    assert_eq!(loaded, expected);
    // No template table is left behind.
    let left = store
        .rows(
            "SELECT name FROM sqlite_schema WHERE type = 'table'
             AND (name LIKE 'template%' OR name LIKE 'migrate%')",
            Vec::new(),
        )
        .await
        .unwrap();
    assert!(left.is_empty(), "{} tables left behind", left.len());
    // And it saves back in the new shape.
    store.save(&loaded).await.unwrap();
    assert_eq!(store.load().await.unwrap(), loaded);
}
