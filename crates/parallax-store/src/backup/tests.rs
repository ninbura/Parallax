use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parallax_core::secret::Secret;
use parallax_core::testing::canonical_config;

use super::*;
use crate::tests::{everything_config, schema_1_database, TempDir, LATEST};

/// 2026-11-24T15:30:00Z.
const NOW: u64 = 1_795_534_200;

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn passphrase() -> Secret {
    Secret::new("correct horse battery staple")
}

/// A database holding `config`, and a server key file next to it.
async fn gateway(dir: &TempDir, config: &parallax_core::Config) -> (Store, PathBuf) {
    let mut store = Store::create(&dir.db()).await.unwrap();
    store.save(config).await.unwrap();
    let key = dir.0.join("wg-server.key");
    std::fs::write(&key, "c2VydmVyIGtleSBmb3IgdGVzdHMgb25seSBwYWRkaW5nIQ==\n").unwrap();
    (store, key)
}

async fn backup(dir: &TempDir, passphrase: Option<&Secret>) -> PathBuf {
    let (store, key) = gateway(dir, &everything_config()).await;
    let snapshot = store.snapshot(&key).await.unwrap();
    write(&snapshot, &dir.0.join("backups"), passphrase, at(NOW))
        .unwrap()
        .0
}

/// Restore `file` into a database that holds something else, the way the
/// CLI does, and return what it holds afterwards.
async fn restore(file: &Path, passphrase: Option<&Secret>) -> parallax_core::Config {
    let contents = open(file, passphrase).unwrap();
    let target = TempDir::new();
    let mut live = Store::create(&target.db()).await.unwrap();
    live.save(&canonical_config()).await.unwrap();
    let staging = crate::TempDir::new_in(&target.0, "restore").unwrap();
    let staged = contents.stage(staging.path()).await.unwrap();
    live.replace_with(&staged).await.unwrap();
    live.load().await.unwrap()
}

#[test]
fn names_carry_the_time_and_sort_by_it() {
    let (compact, iso) = stamp(NOW);
    assert_eq!(compact, "20261124T153000Z");
    assert_eq!(iso, "2026-11-24T15:30:00Z");
    assert_eq!(
        parse_name("parallax-backup-20261124T153000Z.tar"),
        Some((NOW, 0))
    );
    assert_eq!(
        parse_name("parallax-backup-20261124T153000Z-2.tar"),
        Some((NOW, 2))
    );
    for other in [
        "parallax-backup-20261124T153000Z.tar.partial",
        ".parallax-backup-20261124T153000Z.tar.partial",
        "parallax-backup-20261124T253000Z.tar",
        "parallax-backup-2026-11-24.tar",
        "notes.txt",
    ] {
        assert_eq!(parse_name(other), None, "{other}");
    }
}

#[tokio::test]
async fn an_unencrypted_backup_restores_everything_with_its_ids() {
    let dir = TempDir::new();
    let file = backup(&dir, None).await;
    let manifest = inspect(&file).unwrap();
    assert!(!manifest.encrypted);
    assert_eq!(manifest.schema, LATEST);
    assert_eq!(manifest.created, "2026-11-24T15:30:00Z");
    assert_eq!(restore(&file, None).await, everything_config());

    // The ids too: the source and the restored database agree row for row.
    let contents = open(&file, None).unwrap();
    let staging = crate::TempDir::new_in(&dir.0, "check").unwrap();
    let staged = contents.stage(staging.path()).await.unwrap();
    let source = Store::open(&dir.db()).await.unwrap();
    assert_eq!(peer_ids(&staged).await, peer_ids(&source).await);
    assert_eq!(
        contents.server_key().expose(),
        "c2VydmVyIGtleSBmb3IgdGVzdHMgb25seSBwYWRkaW5nIQ==\n"
    );
}

async fn peer_ids(s: &Store) -> Vec<(i64, String)> {
    s.rows("SELECT id, name FROM peers ORDER BY id", Vec::new())
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get::<i64>(0).unwrap(), r.get::<String>(1).unwrap()))
        .collect()
}

#[tokio::test]
async fn an_encrypted_backup_needs_its_passphrase() {
    let dir = TempDir::new();
    let file = backup(&dir, Some(&passphrase())).await;
    let manifest = inspect(&file).unwrap();
    assert!(manifest.encrypted);

    let err = open(&file, None).unwrap_err().to_string();
    assert!(err.contains("is encrypted"), "{err}");
    let err = open(&file, Some(&Secret::new("wrong"))).unwrap_err();
    assert!(matches!(err, Error::WrongPassphrase(_)), "{err}");
    assert_eq!(
        restore(&file, Some(&passphrase())).await,
        everything_config()
    );

    // Nothing private is readable without the passphrase.
    let bytes = std::fs::read(&file).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(!text.contains("c2VydmVyIGtleSBm"));
    assert!(!text.contains("SQLite format"));
}

#[tokio::test]
async fn unchanged_contents_give_the_same_checksum() {
    let dir = TempDir::new();
    let (mut store, key) = gateway(&dir, &canonical_config()).await;
    let first = store.snapshot(&key).await.unwrap();
    // Saving the same configuration again rewrites rows but changes nothing.
    store.save(&canonical_config()).await.unwrap();
    let again = store.snapshot(&key).await.unwrap();
    assert_eq!(first.contents_sha256(), again.contents_sha256());

    let mut changed = canonical_config();
    changed.peers.pop();
    store.save(&changed).await.unwrap();
    let after = store.snapshot(&key).await.unwrap();
    assert_ne!(first.contents_sha256(), after.contents_sha256());

    std::fs::write(&key, "another key\n").unwrap();
    store.save(&canonical_config()).await.unwrap();
    let new_key = store.snapshot(&key).await.unwrap();
    assert_ne!(first.contents_sha256(), new_key.contents_sha256());
}

#[tokio::test]
async fn a_damaged_backup_is_refused() {
    let dir = TempDir::new();
    let file = backup(&dir, None).await;
    let mut bytes = std::fs::read(&file).unwrap();
    // Inside the payload: the database's first page, past both tar headers.
    let at = bytes.len() / 2;
    bytes[at] ^= 0xff;
    std::fs::write(&file, &bytes).unwrap();
    let err = open(&file, None).unwrap_err().to_string();
    assert!(err.contains("is damaged"), "{err}");

    std::fs::write(&file, "not a tar").unwrap();
    let err = inspect(&file).unwrap_err().to_string();
    assert!(err.contains("is not a Parallax backup"), "{err}");
}

/// Rewrite a backup's manifest.
fn edit_manifest(file: &Path, change: impl FnOnce(&mut Manifest)) {
    let mut entries = unpack(&std::fs::read(file).unwrap()).unwrap();
    let mut manifest: Manifest =
        toml::from_str(std::str::from_utf8(&entries[MANIFEST]).unwrap()).unwrap();
    change(&mut manifest);
    entries.insert(
        MANIFEST.to_string(),
        toml::to_string(&manifest).unwrap().into_bytes(),
    );
    let payload = entries.remove(PAYLOAD).unwrap();
    let text = entries.remove(MANIFEST).unwrap();
    std::fs::write(
        file,
        pack(&[(MANIFEST, &text), (PAYLOAD, &payload)], 0).unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn a_backup_from_a_newer_parallax_names_the_version_needed() {
    let dir = TempDir::new();
    let file = backup(&dir, None).await;
    edit_manifest(&file, |m| {
        m.schema = 99;
        m.parallax = "9.0.0".into();
    });
    for err in [
        inspect(&file).unwrap_err().to_string(),
        open(&file, None).unwrap_err().to_string(),
    ] {
        assert!(
            err.contains("was made by Parallax 9.0.0")
                && err.contains("upgrade Parallax to 9.0.0 or newer"),
            "{err}"
        );
    }
}

#[tokio::test]
async fn an_older_backup_is_migrated_forward() {
    let dir = TempDir::new();
    let old = dir.0.join("old.db");
    schema_1_database(&old).await;
    let database = std::fs::read(&old).unwrap();
    let payload = pack(&[(DATABASE, &database), (SERVER_KEY, b"key\n")], 0).unwrap();
    let snapshot = Snapshot {
        contents_sha256: sha256(&payload),
        payload,
        schema: 1,
    };
    let (file, manifest) = write(&snapshot, &dir.0, None, at(NOW)).unwrap();
    assert_eq!(manifest.schema, 1);
    let restored = restore(&file, None).await;
    assert_eq!(restored.server, canonical_config().server);
}

#[tokio::test]
async fn rotation_keeps_the_newest() {
    let dir = TempDir::new();
    let (store, key) = gateway(&dir, &canonical_config()).await;
    let snapshot = store.snapshot(&key).await.unwrap();
    let backups = dir.0.join("backups");
    let mut made = Vec::new();
    for t in [NOW, NOW + 60, NOW + 60, NOW + 120] {
        made.push(write(&snapshot, &backups, None, at(t)).unwrap().0);
    }
    let names: Vec<_> = made
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        [
            "parallax-backup-20261124T153000Z.tar",
            "parallax-backup-20261124T153100Z.tar",
            "parallax-backup-20261124T153100Z-1.tar",
            "parallax-backup-20261124T153200Z.tar",
        ]
    );
    std::fs::write(backups.join("notes.txt"), "kept").unwrap();

    let deleted = rotate(&backups, 2).unwrap();
    assert_eq!(deleted, made[..2]);
    let left: Vec<_> = list(&backups)
        .unwrap()
        .into_iter()
        .map(|l| l.path)
        .collect();
    assert_eq!(left, made[2..]);
    assert!(backups.join("notes.txt").exists());
    assert_eq!(list(&dir.0.join("missing")).unwrap(), Vec::new());
}

#[cfg(unix)]
#[tokio::test]
async fn backups_and_their_directory_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new();
    let file = backup(&dir, None).await;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&file), 0o600);
    assert_eq!(mode(file.parent().unwrap()), 0o700);
}
