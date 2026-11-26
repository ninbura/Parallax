use std::net::Ipv4Addr;

use parallax_core::logging::{Record, RecordKind};

use super::*;
use crate::tests::TempDir;

fn record(time: u64, peer: &str, kind: RecordKind) -> Record {
    Record {
        time,
        kind,
        peer: peer.into(),
        grants: "family".into(),
        source: Ipv4Addr::new(10, 8, 2, 1),
        destination: Ipv4Addr::new(198, 18, 1, 5),
        real_destination: Some(Ipv4Addr::new(192, 168, 1, 5)),
        network: Some("home".into()),
        protocol: "tcp".into(),
        port: Some(2283),
        flow: Some(42),
        bytes_out: (kind == RecordKind::Closed).then_some(1200),
        bytes_in: (kind == RecordKind::Closed).then_some(u64::from(u32::MAX) + 1),
    }
}

async fn logs(dir: &TempDir) -> Logs {
    Logs::open(&dir.0.join("logs.db")).await.unwrap()
}

fn all() -> Query {
    Query {
        limit: 100_000,
        ..Query::default()
    }
}

#[tokio::test]
async fn records_come_back_as_written_oldest_first() {
    let dir = TempDir::new();
    let logs = logs(&dir).await;
    assert_eq!(logs.store.journal_mode(None).await.unwrap(), crate::MVCC);
    let written = vec![
        record(1000, "sister-phone", RecordKind::Opened),
        record(2000, "sister-phone", RecordKind::Closed),
        Record {
            real_destination: None,
            network: None,
            port: None,
            flow: None,
            protocol: "icmp".into(),
            ..record(3000, "laptop", RecordKind::DeniedGateway)
        },
    ];
    logs.writer().unwrap().write(&written).await.unwrap();
    let read: Vec<Record> = logs
        .query(&all())
        .await
        .unwrap()
        .into_iter()
        .map(|(_, r)| r)
        .collect();
    assert_eq!(read, written);
    // Reopening finds them, and the files are owner-only.
    drop(logs);
    assert_eq!(
        super::Logs::open(&dir.0.join("logs.db"))
            .await
            .unwrap()
            .query(&all())
            .await
            .unwrap()
            .len(),
        3
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.0.join("logs.db"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn queries_filter_and_follow() {
    let dir = TempDir::new();
    let logs = logs(&dir).await;
    let w = logs.writer().unwrap();
    for t in 1..=10 {
        let peer = if t % 2 == 0 { "laptop" } else { "sister-phone" };
        let kind = if t % 3 == 0 {
            RecordKind::Denied
        } else {
            RecordKind::Opened
        };
        w.write(&[record(t * 1000, peer, kind)]).await.unwrap();
    }
    let q = |query: Query| {
        let logs = &logs;
        async move {
            logs.query(&query)
                .await
                .unwrap()
                .into_iter()
                .map(|(_, r)| r.time / 1000)
                .collect::<Vec<_>>()
        }
    };
    assert_eq!(
        q(Query {
            peer: Some("laptop".into()),
            ..all()
        })
        .await,
        [2, 4, 6, 8, 10]
    );
    assert_eq!(
        q(Query {
            kinds: vec![RecordKind::Denied],
            ..all()
        })
        .await,
        [3, 6, 9]
    );
    assert_eq!(
        q(Query {
            since: Some(8000),
            ..all()
        })
        .await,
        [8, 9, 10]
    );
    // The newest few, still oldest first.
    assert_eq!(q(Query { limit: 3, ..all() }).await, [8, 9, 10]);
    // Following: what came after an id.
    let ids: Vec<i64> = logs
        .query(&all())
        .await
        .unwrap()
        .iter()
        .map(|(id, _)| *id)
        .collect();
    assert_eq!(
        q(Query {
            after: Some(ids[6]),
            ..all()
        })
        .await,
        [8, 9, 10]
    );
}

/// Each source writes on its own connection, at the same time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writers_commit_concurrently_and_lose_nothing() {
    let dir = TempDir::new();
    let logs = std::sync::Arc::new(logs(&dir).await);
    let mut tasks = Vec::new();
    for source in 0..4u64 {
        let w = logs.writer().unwrap();
        tasks.push(tokio::spawn(async move {
            for batch in 0..20u64 {
                let records: Vec<Record> = (0..25u64)
                    .map(|i| {
                        record(
                            source * 100_000 + batch * 100 + i,
                            "laptop",
                            RecordKind::Opened,
                        )
                    })
                    .collect();
                w.write(&records).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(logs.count().await.unwrap(), 4 * 20 * 25);
}

#[tokio::test]
async fn purging_drops_the_expired_then_the_oldest_past_the_size() {
    let dir = TempDir::new();
    let logs = logs(&dir).await;
    let w = logs.writer().unwrap();
    let records: Vec<Record> = (1..=4000u64)
        .map(|t| record(t, "laptop", RecordKind::Opened))
        .collect();
    for chunk in records.chunks(500) {
        w.write(chunk).await.unwrap();
    }
    // By age: everything before t=1001.
    let purged = logs.purge(1001, u64::MAX).await.unwrap();
    assert_eq!(
        purged,
        Purged {
            expired: 1000,
            over_size: 0
        }
    );
    assert_eq!(logs.count().await.unwrap(), 3000);

    // By size: down to 90% of half of what's used, oldest first.
    let used = logs.used_bytes().await.unwrap();
    let purged = logs.purge(0, used / 2).await.unwrap();
    assert_eq!(purged.expired, 0);
    assert!(purged.over_size > 1000, "{purged:?}");
    let left = logs.query(&all()).await.unwrap();
    assert_eq!(left.len() as u64, 3000 - purged.over_size);
    assert_eq!(
        left[0].1.time,
        1001 + purged.over_size,
        "the oldest went first"
    );
}
