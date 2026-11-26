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
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

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
/// How often the supervisor checks its feeds are alive.
const CHECK_EVERY: Duration = Duration::from_secs(5);
/// Waits before trying a failed feed again, doubling up to the most.
const RETRY_FIRST: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(5 * 60);

/// The open activity database, for answering `parallax log` too.
pub type Slot = Arc<RwLock<Option<Arc<Logs>>>>;

/// One feed and its thread, when it runs.
struct Feed {
    name: &'static str,
    /// The level a peer needs for this feed to run.
    level: LogLevel,
    open: Open,
    parse: Parse,
    wanted: bool,
    running: Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)>,
    /// After a failure: when to try again, and how long the wait was.
    retry: Option<(Instant, Duration)>,
}

impl Feed {
    fn new(name: &'static str, level: LogLevel, open: Open, parse: Parse) -> Self {
        Feed {
            name,
            level,
            open,
            parse,
            wanted: false,
            running: None,
            retry: None,
        }
    }

    fn alive(&self) -> bool {
        self.running.as_ref().is_some_and(|(_, t)| !t.is_finished())
    }

    /// Start it: on failure, say so and wait longer before the next try.
    fn start(&mut self, logs: &Logs, views: &Views) {
        match self.spawn(logs, views) {
            Ok(running) => {
                self.running = Some(running);
                self.retry = None;
                log(format!("activity logging: reading {}", self.name));
            }
            Err(e) => {
                let wait = self
                    .retry
                    .map_or(RETRY_FIRST, |(_, w)| (w * 2).min(RETRY_MAX));
                warn(format!(
                    "activity logging: can't read {}: {e}; trying again in {}s",
                    self.name,
                    wait.as_secs()
                ));
                self.retry = Some((Instant::now() + wait, wait));
            }
        }
    }

    fn spawn(
        &self,
        logs: &Logs,
        views: &Views,
    ) -> anyhow::Result<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
        let socket = (self.open)()?;
        let stop = Arc::new(AtomicBool::new(false));
        let source = Source {
            name: self.name,
            socket,
            parse: self.parse,
            views: views.clone(),
            writer: logs.writer()?,
            stop: Arc::clone(&stop),
            runtime: tokio::runtime::Handle::current(),
        };
        let thread = std::thread::Builder::new()
            .name(format!("parallax {}", self.name))
            .spawn(move || source.run())?;
        Ok((stop, thread))
    }

    /// Stop it and wait while it writes what it holds (within a read timeout).
    async fn stop(&mut self) {
        if let Some((stop, thread)) = self.running.take() {
            stop.store(true, Ordering::Relaxed);
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
    }
}

/// Keep the feeds in line with the configuration, restart any that fail,
/// and purge.
pub async fn supervise(mut views: Views, slot: Slot) {
    let mut feeds = [
        Feed::new(
            "connections",
            LogLevel::Connections,
            open_conntrack,
            netlink::conntrack_events,
        ),
        Feed::new(
            "blocked attempts",
            LogLevel::Denied,
            open_nflog,
            netlink::nflog_packets,
        ),
    ];
    let mut path: Option<std::path::PathBuf> = None;
    let mut purge = tokio::time::interval(PURGE_EVERY);
    let mut check = tokio::time::interval(CHECK_EVERY);
    loop {
        tokio::select! {
            changed = views.changed() => if changed.is_err() { break },
            _ = purge.tick() => {
                purge_now(&views, &slot).await;
                continue;
            }
            _ = check.tick() => {}
        }
        let Some(config) = views.borrow().as_ref().map(|v| Arc::clone(&v.config)) else {
            continue;
        };
        for feed in &mut feeds {
            feed.wanted = logging::configured(&config, feed.level);
        }
        let wanted = feeds.iter().any(|f| f.wanted);
        // A new place for the records: the old database is let go first, so
        // nothing reads or purges it under the new settings.
        if path.as_ref() != Some(&config.server.logs.path) {
            for feed in &mut feeds {
                feed.stop().await;
            }
            set(&slot, None);
            path = Some(config.server.logs.path.clone());
        }
        let current = slot.read().ok().and_then(|s| s.clone());
        let logs = match current {
            Some(logs) => Some(logs),
            None => match open(&config.server.logs.path, wanted, &slot).await {
                Ok(logs) => logs,
                Err(e) => {
                    warn(format!("activity logging: {e:#}"));
                    None
                }
            },
        };
        for feed in &mut feeds {
            if !feed.wanted {
                feed.stop().await;
                feed.retry = None;
                continue;
            }
            if feed.alive() {
                continue;
            }
            // Stopped on its own (it said why): clear it, then start again.
            feed.stop().await;
            let due = feed.retry.is_none_or(|(at, _)| Instant::now() >= at);
            if let (Some(logs), true) = (&logs, due) {
                feed.start(logs, &views);
            }
        }
    }
    for feed in &mut feeds {
        feed.stop().await;
    }
}

/// The database at `path`, shared through `slot`: opened if logging needs
/// it or it already exists, so records can be read with logging off.
async fn open(
    path: &std::path::Path,
    needed: bool,
    slot: &Slot,
) -> anyhow::Result<Option<Arc<Logs>>> {
    if !needed && !path.exists() {
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
        let mut open = logging::OpenFlows::default();
        while !self.stop.load(Ordering::Relaxed) {
            match rustix::net::recv(&self.socket, &mut buf[..], RecvFlags::empty()) {
                Ok((n, _)) => {
                    let events = (self.parse)(&buf[..n]);
                    if !events.is_empty() {
                        let config = self.views.borrow().as_ref().map(|v| Arc::clone(&v.config));
                        if let Some(config) = config {
                            let time = now_ms();
                            batch.extend(events.iter().filter_map(|e| {
                                open.settle(e, logging::attribute(&config, e, time))
                            }));
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
            if batch.len() >= BATCH || flushed.elapsed() >= FLUSH_EVERY {
                self.flush(&mut batch);
                flushed = Instant::now();
                // At most once a second, written or not.
                self.report_lost(lost, &mut reported_lost);
            }
        }
        self.flush(&mut batch);
        self.report_lost(lost, &mut reported_lost);
    }

    fn report_lost(&self, lost: u64, reported: &mut u64) {
        if lost != *reported {
            warn(format!(
                "activity logging: the kernel dropped {} bursts of {} while the collector was behind",
                lost - *reported,
                self.name
            ));
            *reported = lost;
        }
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
    // Close-on-exec, so the tools apply runs never inherit it (a lingering
    // one could hold the nflog group).
    let fd = rustix::net::socket_with(
        AddressFamily::NETLINK,
        SocketType::RAW,
        SocketFlags::CLOEXEC,
        Some(NETFILTER),
    )?;
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

/// The firewall's nflog group for blocked attempts, with each packet's
/// connection-tracking entry (where the peer sent it); kernels that can't
/// add it get the packet alone.
fn open_nflog() -> io::Result<OwnedFd> {
    const EBUSY: i32 = 16;
    let busy = || {
        io::Error::other(format!(
            "nflog group {LOG_GROUP} is taken by another program (EBUSY)"
        ))
    };
    match bind_nflog(true) {
        Ok(fd) => Ok(fd),
        Err(e) if e.raw_os_error() == Some(EBUSY) => Err(busy()),
        Err(_) => bind_nflog(false).map_err(|e| {
            if e.raw_os_error() == Some(EBUSY) {
                busy()
            } else {
                e
            }
        }),
    }
}

fn bind_nflog(conntrack: bool) -> io::Result<OwnedFd> {
    let fd = netlink_socket()?;
    rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
    rustix::net::sendto(
        &fd,
        &netlink::nflog_bind(LOG_GROUP, conntrack),
        SendFlags::empty(),
        &SocketAddrNetlink::new(0, 0),
    )?;
    // The answer, within a few read timeouts.
    let mut buf = [0u8; 4096];
    for _ in 0..3 {
        let n = match rustix::net::recv(&fd, &mut buf[..], RecvFlags::empty()) {
            Ok((n, _)) => n,
            Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        };
        match netlink::acknowledgement(&buf[..n]) {
            Some(Ok(())) => return Ok(fd),
            Some(Err(code)) => return Err(io::Error::from_raw_os_error(code)),
            None => {}
        }
    }
    Err(io::Error::other(format!(
        "the kernel didn't answer binding nflog group {LOG_GROUP}"
    )))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
