//! The activity collector (docs/logging.md, docs/adr/0012-netlink-collector.md).
//! Reads connection tracking's events and the firewall's nflog group,
//! attributes each to its peer ([`logging::attribute`]) and writes the
//! records to `logs.db`, each source on its own thread and connection.
//!
//! A source runs only while some peer is logged at its level: with nobody
//! logged the kernel isn't asked for a single event.

use std::io;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parallax_core::generate::firewall::LOG_GROUP;
use parallax_core::logging::{self, Event};
use parallax_core::model::LogLevel;
use parallax_core::netlink;
use parallax_store::logs::{Logs, Writer};
use rustix::net::netlink::{SocketAddrNetlink, NETFILTER};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketType};

use super::{log, warn, Views};

/// Records are written at least this often...
const FLUSH_EVERY: Duration = Duration::from_secs(1);
/// ...or once this many wait.
const BATCH: usize = 2000;
/// How long a read waits before the thread checks whether to stop.
const READ_TIMEOUT: Duration = Duration::from_secs(1);
/// Room for bursts between reads: what the kernel drops past this is
/// counted and reported.
const RECEIVE_BUFFER: usize = 8 << 20;
const PURGE_EVERY: Duration = Duration::from_secs(10 * 60);

/// The open activity database, for answering `parallax log` too.
pub type Slot = Arc<RwLock<Option<Arc<Logs>>>>;

/// What runs now.
struct Running {
    path: std::path::PathBuf,
    flows: bool,
    denied: bool,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

/// Keep the sources in line with the configuration, and purge.
pub async fn supervise(mut views: Views, slot: Slot) {
    let mut running: Option<Running> = None;
    let mut purge = tokio::time::interval(PURGE_EVERY);
    loop {
        tokio::select! {
            changed = views.changed() => if changed.is_err() { break },
            _ = purge.tick() => {
                purge_now(&views, &slot).await;
                continue;
            }
        }
        let Some(config) = views.borrow().as_ref().map(|v| Arc::clone(&v.config)) else {
            continue;
        };
        let flows = logging::configured(&config, LogLevel::Connections);
        let denied = logging::configured(&config, LogLevel::Denied);
        let path = config.server.logs.path.clone();
        let same = running
            .as_ref()
            .is_some_and(|r| r.flows == flows && r.denied == denied && r.path == path);
        if same {
            continue;
        }
        if let Some(old) = running.take() {
            stop(old).await;
        }
        // Keep the database open while it holds records, so they can be
        // read with logging off.
        let logs = match open(&path, flows || denied, &slot).await {
            Ok(logs) => logs,
            Err(e) => {
                warn(format!("activity logging: {e:#}"));
                continue;
            }
        };
        let Some(logs) = logs else {
            continue;
        };
        running = Some(start(&logs, &views, path, flows, denied));
    }
    if let Some(old) = running.take() {
        stop(old).await;
    }
}

/// The database at `path`: opened if logging needs it or it already
/// exists, and shared through `slot`.
async fn open(
    path: &std::path::Path,
    needed: bool,
    slot: &Slot,
) -> anyhow::Result<Option<Arc<Logs>>> {
    let current = slot.read().ok().and_then(|s| s.clone());
    if let Some(logs) = current.filter(|l| l.path() == path) {
        return Ok(Some(logs));
    }
    if !needed && !path.exists() {
        set(slot, None);
        return Ok(None);
    }
    let logs = Arc::new(
        Logs::open(path)
            .await
            .map_err(|e| anyhow::anyhow!("opening {}: {e}", path.display()))?,
    );
    set(slot, Some(Arc::clone(&logs)));
    log(format!("activity records in {}", path.display()));
    Ok(Some(logs))
}

fn set(slot: &Slot, logs: Option<Arc<Logs>>) {
    if let Ok(mut s) = slot.write() {
        *s = logs;
    }
}

fn start(
    logs: &Arc<Logs>,
    views: &Views,
    path: std::path::PathBuf,
    flows: bool,
    denied: bool,
) -> Running {
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();
    let sources: [(bool, &'static str, Open, Parse); 2] = [
        (
            flows,
            "connections",
            open_conntrack,
            netlink::conntrack_events,
        ),
        (
            denied,
            "blocked attempts",
            open_nflog,
            netlink::nflog_packets,
        ),
    ];
    for (wanted, name, open, parse) in sources {
        if !wanted {
            continue;
        }
        let socket = match open() {
            Ok(s) => s,
            Err(e) => {
                warn(format!("activity logging: can't read {name}: {e}"));
                continue;
            }
        };
        let writer = match logs.writer() {
            Ok(w) => w,
            Err(e) => {
                warn(format!("activity logging: {e}"));
                continue;
            }
        };
        let source = Source {
            name,
            socket,
            parse,
            views: views.clone(),
            writer,
            stop: Arc::clone(&stop),
            runtime: tokio::runtime::Handle::current(),
        };
        match std::thread::Builder::new()
            .name(format!("parallax {name}"))
            .spawn(move || source.run())
        {
            Ok(t) => threads.push(t),
            Err(e) => warn(format!("activity logging: starting {name}: {e}")),
        }
        log(format!("activity logging: reading {name}"));
    }
    Running {
        path,
        flows,
        denied,
        stop,
        threads,
    }
}

async fn stop(old: Running) {
    old.stop.store(true, Ordering::Relaxed);
    let threads = old.threads;
    // Each notices within a read timeout and writes what it holds.
    let _ = tokio::task::spawn_blocking(move || {
        for t in threads {
            let _ = t.join();
        }
    })
    .await;
}

async fn purge_now(views: &Views, slot: &Slot) {
    let Some(logs) = slot.read().ok().and_then(|s| s.clone()) else {
        return;
    };
    let Some(limits) = views
        .borrow()
        .as_ref()
        .map(|v| (v.config.server.logs.keep, v.config.server.logs.max_size))
    else {
        return;
    };
    let (keep, max) = limits;
    let before = now_ms().saturating_sub(keep.as_secs().saturating_mul(1000));
    match logs.purge(before, max.as_bytes()).await {
        Ok(p) if p.expired + p.over_size > 0 => log(format!(
            "activity records: deleted {} older than {keep} and {} past {max}",
            p.expired, p.over_size
        )),
        Ok(_) => {}
        Err(e) => warn(format!("activity records: purging failed: {e}")),
    }
}

type Parse = fn(&[u8]) -> Vec<Event>;
type Open = fn() -> io::Result<OwnedFd>;

/// One feed: reads, attributes, batches, writes.
struct Source {
    name: &'static str,
    socket: OwnedFd,
    parse: Parse,
    views: Views,
    writer: Writer,
    stop: Arc<AtomicBool>,
    runtime: tokio::runtime::Handle,
}

impl Source {
    fn run(self) {
        let mut buf = vec![0u8; 256 * 1024];
        let mut batch = Vec::new();
        let mut flushed = Instant::now();
        let mut lost: u64 = 0;
        let mut reported_lost = 0;
        while !self.stop.load(Ordering::Relaxed) {
            match rustix::net::recv(&self.socket, &mut buf[..], RecvFlags::empty()) {
                Ok((n, _)) => {
                    let events = (self.parse)(&buf[..n]);
                    if !events.is_empty() {
                        let config = self.views.borrow().as_ref().map(|v| Arc::clone(&v.config));
                        if let Some(config) = config {
                            let time = now_ms();
                            batch.extend(
                                events
                                    .iter()
                                    .filter_map(|e| logging::attribute(&config, e, time)),
                            );
                        }
                    }
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                // The kernel dropped events while we were behind.
                Err(rustix::io::Errno::NOBUFS) => lost += 1,
                Err(e) => {
                    warn(format!(
                        "activity logging: reading {} stopped: {e}",
                        self.name
                    ));
                    break;
                }
            }
            if batch.len() >= BATCH || (!batch.is_empty() && flushed.elapsed() >= FLUSH_EVERY) {
                self.flush(&mut batch);
                flushed = Instant::now();
                if lost != reported_lost {
                    warn(format!(
                        "activity logging: the kernel dropped {} bursts of {} while the collector was behind",
                        lost - reported_lost,
                        self.name
                    ));
                    reported_lost = lost;
                }
            }
        }
        self.flush(&mut batch);
    }

    fn flush(&self, batch: &mut Vec<logging::Record>) {
        if batch.is_empty() {
            return;
        }
        if let Err(e) = self.runtime.block_on(self.writer.write(batch)) {
            warn(format!(
                "activity logging: writing {} records of {} failed: {e}",
                batch.len(),
                self.name
            ));
        }
        batch.clear();
    }
}

fn netlink_socket() -> io::Result<OwnedFd> {
    let fd = rustix::net::socket(AddressFamily::NETLINK, SocketType::RAW, Some(NETFILTER))?;
    // Past the system's limit needs CAP_NET_ADMIN, which the gateway has;
    // fall back to the most the limit allows.
    if rustix::net::sockopt::set_socket_recv_buffer_size_force(&fd, RECEIVE_BUFFER).is_err() {
        let _ = rustix::net::sockopt::set_socket_recv_buffer_size(&fd, RECEIVE_BUFFER);
    }
    rustix::net::sockopt::set_socket_timeout(
        &fd,
        rustix::net::sockopt::Timeout::Recv,
        Some(READ_TIMEOUT),
    )?;
    Ok(fd)
}

/// Connection tracking's new and destroyed flows.
fn open_conntrack() -> io::Result<OwnedFd> {
    let fd = netlink_socket()?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, netlink::CONNTRACK_GROUPS))?;
    Ok(fd)
}

/// The firewall's nflog group for blocked attempts.
fn open_nflog() -> io::Result<OwnedFd> {
    let fd = netlink_socket()?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
    rustix::net::sendto(
        &fd,
        &netlink::nflog_bind(LOG_GROUP),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    let mut buf = [0u8; 4096];
    let (n, _) = rustix::net::recv(&fd, &mut buf[..], RecvFlags::empty())?;
    match netlink::acknowledged(&buf[..n]) {
        Ok(()) => Ok(fd),
        Err(16) => Err(io::Error::other(format!(
            "nflog group {LOG_GROUP} is taken by another program (EBUSY)"
        ))),
        Err(code) => Err(io::Error::from_raw_os_error(code)),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
