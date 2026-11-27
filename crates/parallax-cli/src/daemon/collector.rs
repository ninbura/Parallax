//! The activity collector (docs/logging.md, docs/adr/0012-netlink-collector.md).
//! Reads connection tracking's events and the firewall's nflog group, and
//! what the HTTPS proxy and the DNS server hand over through their taps;
//! attributes each to its peer ([`logging::attribute`]) and writes the
//! records to `logs.db`, each source on its own thread and connection.
//!
//! A source runs only while some peer is logged at its level: with nobody
//! logged the kernel isn't asked for a single event, and the taps want
//! nobody's.
//!
//! It goes by the configuration of the last apply that worked, since that's
//! who WireGuard gives each address to, and logs an address only where the
//! saved configuration gives it to the same peer: while a save that moves
//! an address isn't applied yet, or its apply is under way, nothing from
//! that address is logged rather than put under the wrong peer (issue #37).

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parallax_core::generate::firewall::LOG_GROUP;
use parallax_core::logging::{self, Event, Logged, Record, Tap};
use parallax_core::model::{Config, LogLevel, TransportKind};
use parallax_core::netlink;
use parallax_core::secret::PublicKey;
use parallax_store::logs::{Logs, Writer};
use rustix::net::netlink::{SocketAddrNetlink, NETFILTER};
use rustix::net::{AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};

use super::{log, warn, Views};

/// What the log goes by: the last configuration that applied, and the
/// saved one. `None` before the first apply has worked.
fn configs(views: &Views) -> Option<(Arc<Config>, Arc<Config>)> {
    let view = views.borrow();
    let view = view.as_ref()?;
    Some((Arc::clone(view.applied.as_ref()?), Arc::clone(&view.config)))
}

/// The WireGuard peer `config` gives `address` to: its name and key (a
/// peer added again under its old name has a new key).
fn holder(config: &Config, address: Ipv4Addr) -> Option<(&str, &PublicKey)> {
    config.peers.iter().find_map(|p| {
        let wg = p.wireguard.as_ref()?;
        (p.transport == TransportKind::WireGuard && wg.address == Some(address))
            .then_some((p.name.as_str(), &wg.public_key))
    })
}

/// Both configurations give `address` to `peer`, under the same key.
fn same_holder(applied: &Config, saved: &Config, address: Ipv4Addr, peer: &str) -> bool {
    let now = holder(applied, address);
    now.is_some_and(|(name, _)| name == peer) && now == holder(saved, address)
}

/// `record` if the saved configuration gives its address to the same peer.
fn agreed(record: Option<Record>, applied: &Config, saved: &Config) -> Option<Record> {
    record.filter(|r| same_holder(applied, saved, r.source, &r.peer))
}

/// What a connection tracking or nflog event records. Flows are settled
/// before the check: one opened under one owner and closed under another
/// is dropped, even if its opening wasn't logged.
fn kernel_record(
    open: &mut logging::OpenFlows,
    event: &Event,
    applied: &Config,
    saved: &Config,
    time: u64,
) -> Option<Record> {
    let record = open.settle(event, logging::attribute(applied, event, time));
    agreed(record, applied, saved)
}

/// The clients a tap wants, less those the saved configuration gives to
/// another peer.
fn agreed_clients(
    clients: HashMap<Ipv4Addr, Logged>,
    applied: &Config,
    saved: &Config,
) -> HashMap<Ipv4Addr, Logged> {
    clients
        .into_iter()
        .filter(|(address, logged)| same_holder(applied, saved, *address, &logged.peer))
        .collect()
}

/// Records are written at least this often...
const FLUSH_EVERY: Duration = Duration::from_secs(1);
/// ...or once this many wait.
const BATCH: usize = 2000;
/// Batches waiting for the writer before new ones are dropped: a few
/// seconds of a flood.
const QUEUE: usize = 32;
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

/// Events a tap holds before more are dropped: several seconds of a busy
/// peer's requests or lookups.
const TAP_QUEUE: usize = 16 * 1024;

/// Where the HTTPS proxy and the DNS server hand over what logged peers do.
pub struct Taps {
    pub proxy: Tap,
    pub dns: Tap,
    proxy_events: Receiver<Event>,
    dns_events: Receiver<Event>,
}

impl Taps {
    pub fn new() -> Taps {
        let (proxy, proxy_events) = Tap::new(TAP_QUEUE);
        let (dns, dns_events) = Tap::new(TAP_QUEUE);
        Taps {
            proxy,
            dns,
            proxy_events,
            dns_events,
        }
    }
}

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

/// Keep the feeds and taps in line with the configuration, restart any
/// feed that fails, and purge.
pub async fn supervise(mut views: Views, slot: Slot, taps: Taps) {
    let stop = Arc::new(AtomicBool::new(false));
    let Taps {
        proxy,
        dns,
        proxy_events,
        dns_events,
    } = taps;
    let mut tapped = Vec::new();
    for (name, tap, events) in [
        ("proxied requests", &proxy, proxy_events),
        ("DNS queries", &dns, dns_events),
    ] {
        let sink = Sink {
            name,
            events,
            tap: tap.clone(),
            views: views.clone(),
            slot: Arc::clone(&slot),
            stop: Arc::clone(&stop),
            runtime: tokio::runtime::Handle::current(),
        };
        match std::thread::Builder::new()
            .name(format!("parallax {name}"))
            .spawn(move || sink.run())
        {
            Ok(thread) => tapped.push(thread),
            Err(e) => warn(format!("activity logging: can't record {name}: {e}")),
        }
    }
    let mut feeds = [
        Feed::new(
            "connections",
            LogLevel::Connections,
            open_conntrack,
            netlink::conntrack_events,
        ),
        Feed::new(
            "blocked attempts",
            LogLevel::Blocked,
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
        let Some((config, saved)) = configs(&views) else {
            continue;
        };
        for feed in &mut feeds {
            feed.wanted = logging::configured(&config, feed.level);
        }
        // The proxy's refusals are blocked attempts, so whoever logs at
        // `blocked` or more.
        proxy.set_clients(agreed_clients(
            logging::level_clients(&config, LogLevel::Blocked),
            &config,
            &saved,
        ));
        let dns_clients = agreed_clients(logging::dns_clients(&config), &config, &saved);
        let wanted = feeds.iter().any(|f| f.wanted) || !dns_clients.is_empty();
        dns.set_clients(dns_clients);
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
    proxy.set_clients(Default::default());
    dns.set_clients(Default::default());
    // Every thread told first, so their last reads and writes overlap.
    stop.store(true, Ordering::Relaxed);
    for feed in &feeds {
        if let Some((stop, _)) = &feed.running {
            stop.store(true, Ordering::Relaxed);
        }
    }
    for feed in &mut feeds {
        feed.stop().await;
    }
    for thread in tapped {
        let _ = tokio::task::spawn_blocking(move || thread.join()).await;
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
    // The open database is the applied configuration's, and so are its
    // limits: a saved change not applied yet mustn't purge it by its own.
    let Some(limits) = views
        .borrow()
        .as_ref()
        .and_then(|v| v.applied.as_ref())
        .map(|c| (c.server.logs.keep, c.server.logs.max_size))
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

/// What a feed lost, reported at most once a second.
#[derive(Default)]
struct Lost {
    /// Times the kernel's buffer overflowed (`ENOBUFS`).
    overflows: u64,
    /// Records dropped because the writer was behind.
    records: u64,
}

impl Source {
    /// Read on this thread, write on another: the reader only drains the
    /// kernel and attributes, so a slow write never backs the kernel up.
    fn run(self) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<logging::Record>>(QUEUE);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for batch in rx {
                    self.write(&batch);
                }
            });
            self.read(tx);
        });
    }

    fn read(&self, tx: std::sync::mpsc::SyncSender<Vec<logging::Record>>) {
        let mut buf = vec![0u8; 256 * 1024];
        let mut batch = Vec::new();
        let mut flushed = Instant::now();
        let mut lost = Lost::default();
        let mut reported = Lost::default();
        let mut open = logging::OpenFlows::default();
        while !self.stop.load(Ordering::Relaxed) {
            match rustix::net::recv(&self.socket, &mut buf[..], RecvFlags::empty()) {
                Ok((n, _)) => {
                    let events = (self.parse)(&buf[..n]);
                    if !events.is_empty() {
                        if let Some((config, saved)) = configs(&self.views) {
                            let time = now_ms();
                            batch.extend(events.iter().filter_map(|e| {
                                kernel_record(&mut open, e, &config, &saved, time)
                            }));
                        }
                    }
                }
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                // The kernel dropped events while we were behind.
                Err(rustix::io::Errno::NOBUFS) => lost.overflows += 1,
                Err(e) => {
                    warn(format!(
                        "activity logging: reading {} stopped: {e}",
                        self.name
                    ));
                    break;
                }
            }
            if batch.len() >= BATCH || flushed.elapsed() >= FLUSH_EVERY {
                hand_over(&tx, &mut batch, &mut lost);
                flushed = Instant::now();
                self.report(&lost, &mut reported);
            }
        }
        hand_over(&tx, &mut batch, &mut lost);
        self.report(&lost, &mut reported);
    }

    fn report(&self, lost: &Lost, reported: &mut Lost) {
        if lost.overflows != reported.overflows {
            warn(format!(
                "activity logging: the kernel dropped {} bursts of {} while the collector was behind",
                lost.overflows - reported.overflows,
                self.name
            ));
            reported.overflows = lost.overflows;
        }
        if lost.records != reported.records {
            warn(format!(
                "activity logging: {} records of {} dropped while writing to the database was behind",
                lost.records - reported.records,
                self.name
            ));
            reported.records = lost.records;
        }
    }

    fn write(&self, batch: &[logging::Record]) {
        if let Err(e) = self.runtime.block_on(self.writer.write(batch)) {
            warn(format!(
                "activity logging: writing {} records of {} failed: {e}",
                batch.len(),
                self.name
            ));
        }
    }
}

/// Queue `batch` for the writer; when it's full, drop and count.
fn hand_over(
    tx: &std::sync::mpsc::SyncSender<Vec<logging::Record>>,
    batch: &mut Vec<logging::Record>,
    lost: &mut Lost,
) {
    if batch.is_empty() {
        return;
    }
    let n = batch.len() as u64;
    if tx.try_send(std::mem::take(batch)).is_err() {
        lost.records += n;
    }
}

/// One tap's records: attributes what it hands over, batches, writes.
struct Sink {
    name: &'static str,
    events: Receiver<Event>,
    tap: Tap,
    views: Views,
    slot: Slot,
    stop: Arc<AtomicBool>,
    runtime: tokio::runtime::Handle,
}

/// A sink's records on their way to the database. While none takes them,
/// only the newest [`BATCH`] are kept, the rest counted and reported at
/// most once a flush interval (#66), not once an event.
#[derive(Default)]
struct Pending {
    records: Vec<logging::Record>,
    /// The last flush found no database to write to.
    none_open: bool,
    /// Dropped since they were last reported.
    dropped: u64,
}

impl Pending {
    fn push(&mut self, record: logging::Record) {
        self.records.push(record);
    }

    /// Time to flush before the timer: a batch's worth to write, or, with
    /// nowhere to write, twice that. That flush looks for a database again
    /// before anything's dropped, once every batch's worth, not every event.
    fn full(&self) -> bool {
        let limit = if self.none_open { 2 * BATCH } else { BATCH };
        self.records.len() >= limit
    }

    /// No database took them: keep the newest batch's worth, count the rest.
    fn unwritten(&mut self) {
        self.none_open = true;
        let excess = self.records.len().saturating_sub(BATCH);
        self.records.drain(..excess);
        self.dropped += excess as u64;
    }

    /// A database took them.
    fn written(&mut self) {
        self.records.clear();
        self.none_open = false;
    }

    /// How many were dropped since the last time this was asked.
    fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }
}

impl Sink {
    fn run(self) {
        let mut pending = Pending::default();
        let mut flushed = Instant::now();
        let mut writer: Option<(Arc<Logs>, Writer)> = None;
        loop {
            match self.events.recv_timeout(READ_TIMEOUT) {
                Ok(event) => self.attribute(event, &mut pending),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if self.stop.load(Ordering::Relaxed) {
                break;
            }
            let timed = flushed.elapsed() >= FLUSH_EVERY;
            if timed || pending.full() {
                self.flush(&mut pending, &mut writer, timed);
                // A flush that only trimmed doesn't put the timed one off:
                // that's the one that says what was dropped.
                if timed || !pending.none_open {
                    flushed = Instant::now();
                }
            }
        }
        // What was handed over before the stop.
        while let Ok(event) = self.events.try_recv() {
            self.attribute(event, &mut pending);
        }
        self.flush(&mut pending, &mut writer, true);
        // Kept for a database that never came: they go with the process.
        if !pending.records.is_empty() {
            warn(format!(
                "activity logging: {} records of {} not written: no database to write to",
                pending.records.len(),
                self.name
            ));
        }
    }

    fn attribute(&self, event: Event, pending: &mut Pending) {
        let Some((config, saved)) = configs(&self.views) else {
            return;
        };
        if let Some(record) = agreed(
            logging::attribute(&config, &event, now_ms()),
            &config,
            &saved,
        ) {
            pending.push(record);
        }
    }

    /// Write what's pending to the open database. Records accepted before
    /// the supervisor moved to a new path go to the old one, and the old one
    /// is let go after, so its file is never held past the next flush. With
    /// none to write to, keep a batch's worth (the newest) and drop the
    /// rest. `report`: a timed flush, which says what was dropped (an
    /// overflow flush only trims).
    fn flush(&self, pending: &mut Pending, writer: &mut Option<(Arc<Logs>, Writer)>, report: bool) {
        let dropped = self.tap.take_dropped();
        if dropped > 0 {
            warn(format!(
                "activity logging: {dropped} {} dropped while the collector was behind",
                self.name
            ));
        }
        let current = self.slot.read().ok().and_then(|s| s.clone());
        if !pending.records.is_empty() {
            if let (None, Some(logs)) = (writer.as_ref(), &current) {
                match logs.writer() {
                    Ok(w) => *writer = Some((Arc::clone(logs), w)),
                    Err(e) if report => {
                        warn(format!("activity logging: writing {}: {e}", self.name));
                    }
                    Err(_) => {}
                }
            }
            match writer.as_ref() {
                Some((_, w)) => {
                    if let Err(e) = self.runtime.block_on(w.write(&pending.records)) {
                        warn(format!(
                            "activity logging: writing {} records of {} failed: {e}",
                            pending.records.len(),
                            self.name
                        ));
                    }
                    pending.written();
                    // Said now, once there's a database again.
                    let dropped = pending.take_dropped();
                    if dropped > 0 {
                        warn(format!(
                            "activity logging: {dropped} records of {} were dropped while there was no database to write to",
                            self.name
                        ));
                    }
                }
                None => {
                    pending.unwritten();
                    let dropped = if report { pending.take_dropped() } else { 0 };
                    if dropped > 0 {
                        warn(format!(
                            "activity logging: {dropped} records of {} dropped: no database to write to",
                            self.name
                        ));
                    }
                }
            }
        }
        let stale = writer
            .as_ref()
            .is_some_and(|(l, _)| !current.as_ref().is_some_and(|c| Arc::ptr_eq(l, c)));
        if stale {
            *writer = None;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #37: 10.8.1.1 is `router`'s in the applied configuration, and the
    /// saved one gives it to a new peer. Until that's applied, nothing from
    /// it is logged under either.
    #[test]
    fn an_address_changing_hands_logs_nothing_until_applied() {
        let applied = parallax_core::testing::canonical_config();
        let router = holder(&applied, "10.8.1.1".parse().unwrap())
            .unwrap()
            .0
            .to_string();
        let mut saved = applied.clone();
        saved.peers[0].name = "new-key".into();
        let mut r = record(1);
        r.peer = router.clone();
        r.source = "10.8.1.1".parse().unwrap();
        assert!(agreed(Some(r.clone()), &applied, &applied).is_some());
        assert!(agreed(Some(r.clone()), &applied, &saved).is_none());
        // Added again under its old name: a new key, so not the same peer.
        let mut rekeyed = applied.clone();
        let other = applied.peers[1]
            .wireguard
            .as_ref()
            .unwrap()
            .public_key
            .clone();
        rekeyed.peers[0].wireguard.as_mut().unwrap().public_key = other;
        assert!(agreed(Some(r), &applied, &rekeyed).is_none());
        let clients: HashMap<Ipv4Addr, Logged> = [(
            "10.8.1.1".parse().unwrap(),
            Logged {
                peer: router,
                level: LogLevel::Detailed,
            },
        )]
        .into();
        assert_eq!(agreed_clients(clients.clone(), &applied, &applied), clients);
        assert!(agreed_clients(clients, &applied, &saved).is_empty());
    }

    /// A connection `router` opens while its address is changing hands, and
    /// that closes once the new peer has it, is logged under neither.
    #[test]
    fn a_flow_across_a_hand_over_is_logged_under_neither_peer() {
        let mut applied = parallax_core::testing::canonical_config();
        applied.peers[0].log = Some(LogLevel::Detailed);
        let mut saved = applied.clone();
        saved.peers[0].name = "new-key".into();
        let other = applied.peers[1]
            .wireguard
            .as_ref()
            .unwrap()
            .public_key
            .clone();
        saved.peers[0].wireguard.as_mut().unwrap().public_key = other;
        let flow = logging::Flow {
            id: 42,
            protocol: 6,
            src: "10.8.1.1".parse().unwrap(),
            dst: "198.18.1.5".parse().unwrap(),
            answered_by: "192.168.1.5".parse().unwrap(),
            port: Some(443),
            mark: parallax_core::generate::firewall::FLOW_MARK,
            bytes: Some((1, 1)),
        };
        let mut open = logging::OpenFlows::default();
        let opened = Event::Opened(flow.clone());
        assert!(kernel_record(&mut open, &opened, &applied, &saved, 1).is_none());
        // Applied: both say `new-key` now.
        let closed = Event::Closed(flow);
        assert!(kernel_record(&mut open, &closed, &saved, &saved, 2).is_none());
    }

    fn record(n: u64) -> logging::Record {
        logging::Record {
            time: n,
            kind: logging::RecordKind::Query,
            peer: "guest".into(),
            grants: String::new(),
            source: std::net::Ipv4Addr::new(10, 8, 0, 2),
            destination: std::net::Ipv4Addr::new(10, 8, 0, 1),
            real_destination: None,
            network: None,
            protocol: "udp".into(),
            port: Some(53),
            flow: None,
            bytes_out: None,
            bytes_in: None,
            hostname: Some("immich.example.test.".into()),
            method: None,
            status: None,
            query_type: Some("A".into()),
            outcome: Some("answered".into()),
        }
    }

    /// No database: the newest batch's worth stays, the rest is counted,
    /// and a full batch doesn't flush on every event (#66).
    #[test]
    fn with_no_database_the_newest_stay_and_drops_are_counted() {
        let mut pending = Pending::default();
        (0..BATCH as u64).for_each(|n| pending.push(record(n)));
        assert!(pending.full());
        // The flush finds no database.
        pending.unwritten();
        assert_eq!(pending.take_dropped(), 0);
        // Past a batch's worth: no flush on each event any more.
        (BATCH as u64..BATCH as u64 + 5).for_each(|n| pending.push(record(n)));
        assert!(!pending.full());
        // The timed flush finds none either: five dropped, said once.
        pending.unwritten();
        assert_eq!(pending.take_dropped(), 5);
        assert_eq!(pending.take_dropped(), 0);
        assert_eq!(pending.records.len(), BATCH);
        assert_eq!(pending.records[0].time, 5, "the oldest go, the newest stay");
        assert_eq!(pending.records[BATCH - 1].time, BATCH as u64 + 4);
    }

    /// A flood with no database: a flush (which looks for a database
    /// again) every batch's worth, never more than twice a batch pending.
    #[test]
    fn with_no_database_pending_records_stay_bounded() {
        let mut pending = Pending::default();
        pending.unwritten();
        let mut flushes = 0;
        for n in 0..10 * BATCH as u64 {
            pending.push(record(n));
            assert!(pending.records.len() <= 2 * BATCH);
            if pending.full() {
                flushes += 1;
                pending.unwritten();
            }
        }
        // At 4,000, then every 2,000 more: 9 over 20,000.
        assert_eq!(flushes, 9);
        pending.unwritten();
        assert_eq!(pending.records.len(), BATCH);
        assert_eq!(pending.take_dropped(), 9 * BATCH as u64);
        assert_eq!(pending.records[0].time, 9 * BATCH as u64);
    }

    /// A database again: what was dropped meanwhile is still there to
    /// report, and a full batch flushes early again.
    #[test]
    fn a_database_again_reports_the_drops_and_flushes_a_full_batch() {
        let mut pending = Pending::default();
        (0..BATCH as u64 + 3).for_each(|n| pending.push(record(n)));
        pending.unwritten();
        pending.written();
        assert_eq!(pending.take_dropped(), 3);
        (0..BATCH as u64).for_each(|n| pending.push(record(n)));
        assert!(pending.full());
    }
}
