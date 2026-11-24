use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use parallax_core::generate;
use parallax_core::io::memory::MemoryFs;
use parallax_core::model::*;
use parallax_core::testing::{canonical_config, keypair, today};
use parallax_core::{Config, Model};

use crate::{Error, Store};

/// A fresh directory per test, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "parallax-store-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn db(&self) -> PathBuf {
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
    let store = Store::create(&dir.db()).await.unwrap();
    store.save(config).await.unwrap();
    drop(store);
    Store::open(&dir.db()).await.unwrap().load().await.unwrap()
}

/// Every optional field set, every grant kind, both visibility forms.
fn everything_config() -> Config {
    let mut c = canonical_config();
    c.server.wan_interface = Some("eth1".into());
    c.server.dns.listen = Some(Ipv4Addr::new(10, 8, 0, 1));
    c.server.proxy.listen = Some(Ipv4Addr::new(10, 8, 0, 1));
    c.server.firewall.backend = FirewallBackend::IptablesNft;
    c.server.headscale.derp = DerpMode::Tailscale;
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
        host: Ipv4Addr::new(192, 168, 1, 6),
        proto: Proto::Udp,
        port: 8443,
        nginx_vhost: false,
        hostnames: vec!["photos.mydomain.com".into(), "img.mydomain.com".into()],
    });
    let t = &mut c.templates[0];
    t.grants = vec![
        Grant::AllNetworks,
        Grant::Network { name: "lab".into() },
        Grant::Host {
            ip: Ipv4Addr::new(192, 168, 1, 9),
        },
        Grant::HostPort {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            proto: Proto::Udp,
            port: 53,
        },
        Grant::Service {
            name: "photos".into(),
        },
        Grant::Internet,
    ];
    t.visible_networks = Some(vec!["lab".into(), "home".into()]);
    t.dns = DnsPolicy {
        wireguard: DnsMode::TunnelWide,
        tailscale: DnsMode::None,
        public: true,
    };
    t.client = ClientDefaults {
        allowed_ips: AllowedIpsStrategy::FullTunnel,
        mtu: Some(1380),
        persistent_keepalive: Some(25),
    };
    c.templates[1].visible_networks = Some(Vec::new());
    c.peers.push(Peer {
        name: "tv".into(),
        template: "family".into(),
        transport: TransportKind::Tailscale,
        enabled: false,
        expires: Some(today()),
        wireguard: None,
        tailscale: Some(TailscalePeer::default()),
    });
    c.peers.push(Peer {
        name: "tablet".into(),
        template: "family".into(),
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
    let store = Store::create(&dir.db()).await.unwrap();
    let mut config = everything_config();
    store.save(&config).await.unwrap();
    let laptop = id_of(&store, "peers", "laptop").await;
    let home = id_of(&store, "networks", "home").await;

    // Rename a template its peers move to, drop a network and a service the
    // grants no longer mention, reorder and edit peers.
    config.templates[1].name = "guests".into();
    for p in &mut config.peers {
        if p.template == "family" {
            p.template = "guests".into();
        }
    }
    config.templates[0]
        .grants
        .retain(|g| !matches!(g, Grant::Network { .. } | Grant::Service { .. }));
    config.templates[0].visible_networks = None;
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
    let store = Store::create(&dir.db()).await.unwrap();
    let config = canonical_config();
    store.save(&config).await.unwrap();

    let mut broken = config.clone();
    broken.peers.clear();
    broken.templates[0].grants.push(Grant::Network {
        name: "nowhere".into(),
    });
    let err = store.save(&broken).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("template 'personal': grant refers to unknown network 'nowhere'"),
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

    let store = Store::create(&dir.db()).await.unwrap();
    let err = store.load().await.unwrap_err();
    assert!(matches!(err, Error::Empty(_)), "{err}");
}

#[cfg(unix)]
#[tokio::test]
async fn the_database_and_its_log_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let store = Store::create(&dir.db()).await.unwrap();
    store.save(&everything_config()).await.unwrap();
    for file in ["parallax.db", "parallax.db-wal"] {
        let mode = std::fs::metadata(dir.0.join(file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }
}

#[tokio::test]
async fn a_newer_schema_is_refused() {
    let dir = TempDir::new();
    let store = Store::create(&dir.db()).await.unwrap();
    assert_eq!(store.schema_version().await.unwrap(), 1);
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
                known: 1,
                ..
            }
        ),
        "{err}"
    );
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
    assert_eq!(rows[0].get::<i64>(0).unwrap(), 1);
}
