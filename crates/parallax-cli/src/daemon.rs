//! `parallax daemon`: the gateway as one long-running process.
//!
//! It holds the database (no other process can open it meanwhile), keeps
//! the configuration in memory, and applies it: at startup, after every
//! saved change, on SIGHUP, when the UTC date changes, and when the live
//! firewall or WireGuard interface drifts. The DNS server and the HTTPS
//! proxy run as tasks, and both get their routes from the engine around
//! each apply. The CLI
//! talks to it over a Unix socket ([`crate::protocol`]).
//!
//! When guests have `internet`, it looks up the home's public IP
//! (for their hairpin drop) at startup, every 5 minutes, and when a saved
//! change alters what the lookup depends on; it re-applies when the address
//! changes, and keeps the last one found across restarts. Hosts named by
//! DNS name are looked up right after startup, every 5 minutes and when
//! they change; only the latest answer counts. A save that adds a name looks
//! it up before saving, and refuses the change if it doesn't resolve
//! ([`parallax_core::names`]).
//!
//! When a Tailscale peer names a Headscale node, it asks Headscale for its
//! nodes' addresses before the first apply and every 10 seconds, and
//! re-applies when one changes ([`parallax_core::headscale`]). When
//! Headscale doesn't answer, the last answer stays in effect.
//!
//! While a peer is on Tailscale, it keeps the subnet router (the
//! `tailscaled` at `--tailscale-socket`) logged in and routing what the
//! configuration says: every 30 seconds and after each saved change
//! ([`parallax_core::subnet_router`]). The machine's own Tailscale is left
//! alone; what its operator has to run is logged. Parallax's own router
//! follows route changes even with no peer on Tailscale, but isn't logged in.
//! On shutdown its routes are taken away before the firewall is.
//!
//! One engine thread owns the database and does everything that changes
//! state (saves, applies, backups), one batch at a time: requests that
//! arrive during an apply queue up, and a batch of them shares one apply.
//! It runs off the async threads, so blocking work (`nft`, `wg`, `ip`) never
//! stalls DNS or the proxy. Reads (`status`, `load`) are answered from the
//! last published view without waiting. A backup holds the engine only for
//! the database copy; its encryption and writing run on a backup thread of
//! their own, so they never delay a save.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use parallax_core::generate;
use parallax_core::generate::dns::DnsRoutes;
use parallax_core::generate::proxy::{Holders, ProxyRoutes};
use parallax_core::headscale::{self, Tailnet};
use parallax_core::io::real::{RealFs, RealRunner};
use parallax_core::io::System;
use parallax_core::model::{Network, PublicIpServer, ServerConfig};
use parallax_core::names::{self, Refreshed, Resolved};
use parallax_core::public_ip::{self, Found};
use parallax_core::reconcile::{self, Reconciler};
use parallax_core::secret::Secret;
use parallax_core::subnet_router;
use parallax_core::Config;
use parallax_store::{backup, Store, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket, UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::protocol::{self, Reply, Request};

mod collector;

/// How `parallax daemon` was started.
#[derive(Debug)]
pub struct Options {
    pub db: PathBuf,
    pub socket: PathBuf,
    pub out: PathBuf,
    /// The subnet router's `tailscaled`.
    pub tailscale_socket: String,
    /// Between checks for drift and a new day.
    pub reconcile_every: Duration,
}

/// How often automatic backups are looked at; `backup create --if-due`
/// decides whether one is due.
const BACKUP_EVERY: Duration = Duration::from_secs(600);
/// How often the home's public IP is looked up.
const PUBLIC_IP_EVERY: Duration = Duration::from_secs(300);
/// How often hosts named by DNS name are looked up.
const NAMES_EVERY: Duration = Duration::from_secs(300);
/// How often Headscale is asked for its nodes.
const TAILNET_EVERY: Duration = Duration::from_secs(headscale::POLL_SECONDS);
/// How often the subnet router is looked at.
const ROUTER_EVERY: Duration = Duration::from_secs(subnet_router::POLL_SECONDS);
/// How soon it's looked at again after a change, so a router that just
/// logged in gets its routes approved without waiting a whole poll.
const ROUTER_SOON: Duration = Duration::from_secs(2);
/// The longest wait between looks while the router keeps failing.
const ROUTER_BACKOFF: Duration = Duration::from_secs(900);
/// How long shutdown waits for the router to withdraw its routes: a look in
/// flight may be a `tailscale up` with its 30 s timeout. Inside systemd's
/// default 90 s stop timeout.
const ROUTER_STOP: Duration = Duration::from_secs(45);
/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// A log line nobody can read is dropped: `println!` would panic, possibly in a
// task, leaving the rest of the daemon running without it.
fn log(msg: impl std::fmt::Display) {
    let _ = writeln!(std::io::stdout(), "parallax: {msg}");
}

fn warn(msg: impl std::fmt::Display) {
    let _ = writeln!(std::io::stderr(), "parallax: {msg}");
}

fn sys() -> System<'static> {
    System {
        fs: &RealFs,
        runner: &RealRunner,
    }
}

/// What the engine tells everyone else: the configuration and how the last
/// apply went. Cheap to clone.
#[derive(Debug, Clone)]
struct View {
    config: Arc<Config>,
    revision: u64,
    apply_error: Option<String>,
    /// The configuration of the last apply that worked: what the activity
    /// log attributes by, since WireGuard holds its peers.
    applied: Option<Arc<Config>>,
    /// The home's public IP as last found.
    public_ip: Option<Ipv4Addr>,
    /// Bumped when a save looks the public IP up itself: lookups that
    /// started before then are older than its answer.
    public_ip_set: u64,
    /// What each host named by DNS name last resolved to.
    names: Resolved,
    /// Bumped when a save or a restore sets `names` itself: lookups that
    /// started before then are older than its answers.
    names_set: u64,
    /// The addresses Headscale last gave its nodes; `None` until it answers.
    tailnet: Option<Tailnet>,
}

impl View {
    fn learned(&self) -> crate::Learned {
        crate::Learned {
            public_ip: self.public_ip,
            names: self.names.clone(),
            tailnet: self.tailnet.clone(),
        }
    }
}

/// Work for the engine thread.
enum Msg {
    Request(Request, oneshot::Sender<Reply>),
    Hangup,
    Tick,
    BackupTick,
    /// The DNS server and the proxy are up.
    Serving(Reloaders),
    /// A lookup of the home's public IP finished, for these inputs.
    PublicIp(Inputs, Result<Found, Vec<String>>),
    /// The named hosts were looked up, for these inputs.
    Names(NameInputs, Refreshed),
    /// Headscale was asked for its nodes, for these inputs.
    Tailnet(TailnetInputs, Result<Option<Tailnet>, String>),
    /// Stop; `teardown` false leaves the gateway as it is, firewall included.
    Shutdown {
        teardown: bool,
    },
}

type Views = watch::Receiver<Option<View>>;

pub fn run(opts: Options) -> anyhow::Result<()> {
    not_root_in_anothers_place(&opts)?;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    let result = rt.block_on(serve(opts));
    // A lookup still blocking a thread (a wedged `tailscale`, a slow
    // Headscale) mustn't keep the process from exiting.
    rt.shutdown_timeout(Duration::from_secs(5));
    result
}

/// Before anything: a daemon run as root where another user's files are
/// (the service's, on a native install) would leave its database files,
/// generated files and socket as root's there.
fn not_root_in_anothers_place(opts: &Options) -> anyhow::Result<()> {
    use crate::owner::{belongs_to_another_user, database_belongs_to_another_user};
    let start = |sudo_u: &str| {
        format!(
            "Start the service instead (`sudo systemctl start parallax`), or run it as that user \
             (`sudo -u {sudo_u} parallax daemon ...`)"
        )
    };
    if let Some((who, sudo_u)) = database_belongs_to_another_user(&opts.db) {
        bail!(
            "{} belongs to {who}: a daemon run as root would leave files that user can't open. {}",
            opts.db.display(),
            start(&sudo_u)
        );
    }
    if let Some((who, sudo_u)) = belongs_to_another_user(&opts.out) {
        bail!(
            "{} belongs to {who}: a daemon run as root would write files there that user can't \
             replace. {}",
            opts.out.display(),
            start(&sudo_u)
        );
    }
    if let Some((who, sudo_u)) = belongs_to_another_user(&opts.socket) {
        bail!(
            "{} belongs to {who}: a daemon run as root would manage its socket there. {}",
            opts.socket.display(),
            start(&sudo_u)
        );
    }
    Ok(())
}

async fn serve(opts: Options) -> anyhow::Result<()> {
    // First: from here on SIGHUP re-applies instead of ending the process.
    let mut hangup = signal(SignalKind::hangup()).context("watching SIGHUP")?;
    let mut terminate = signal(SignalKind::terminate()).context("watching SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("watching SIGINT")?;
    // Before touching anything: a daemon for another database may own this socket.
    if std::os::unix::net::UnixStream::connect(&opts.socket).is_ok() {
        bail!(
            "a daemon already answers on {}; stop it, or give this one another --socket",
            opts.socket.display()
        );
    }
    let database = Arc::new(same_file(&opts.db));

    let (tx, rx) = mpsc::unbounded_channel();
    let (publish, views) = watch::channel(None);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = oneshot::channel::<()>();
    let (db, out) = (opts.db.clone(), opts.out.clone());
    std::thread::Builder::new()
        .name("parallax-engine".into())
        .spawn(move || {
            engine_thread(&db, out, publish, rx, ready_tx);
            // Dropped without sending if the thread panics: either way the
            // main task learns the engine is gone.
            let _ = done_tx.send(());
        })
        .context("starting the engine thread")?;
    let routes = match ready_rx.await {
        Ok(Ok(routes)) => routes,
        Ok(Err(e)) => return Err(e),
        Err(_) => bail!("the engine stopped during startup"),
    };

    let mut engine_alive = true;
    let taps = collector::Taps::new();
    let started = async {
        let servers = start_servers(routes, &taps).await?;
        let listener = bind_socket(&opts.socket)?;
        anyhow::Ok((servers, listener))
    }
    .await;
    let ((mut dns, mut proxy, reloaders), (listener, socket_id)) = match started {
        Ok(started) => started,
        Err(e) => {
            // The router may still route from a run before (one that
            // crashed): take that away too before this teardown.
            let config = views.borrow().as_ref().map(|v| Arc::clone(&v.config));
            let withdrawn = withdraw(config, opts.tailscale_socket.clone(), None);
            let teardown = withdrawn_in_time(tokio::time::timeout(ROUTER_STOP, withdrawn).await);
            stop_engine(&tx, &mut done_rx, teardown).await;
            return Err(e);
        }
    };
    let _ = tx.send(Msg::Serving(reloaders));
    let refresher = tokio::spawn(refresh_public_ip(tx.clone(), views.clone()));
    let names = tokio::spawn(refresh_names(tx.clone(), views.clone()));
    let tailnet = tokio::spawn(refresh_tailnet(tx.clone(), views.clone()));
    let (stop_router, router_stop) = watch::channel(false);
    let router = tokio::spawn(keep_router(
        views.clone(),
        opts.tailscale_socket.clone(),
        router_stop,
    ));
    let logs = collector::Slot::default();
    let collecting = tokio::spawn(collector::supervise(views.clone(), Arc::clone(&logs), taps));
    let server = tokio::spawn(accept(listener, tx.clone(), views, database, logs));
    let timers = tokio::spawn(timers(tx.clone(), opts.reconcile_every));
    log(format!(
        "gateway up; listening for commands on {}. Saved changes apply at once; SIGHUP re-applies",
        opts.socket.display()
    ));
    notify_ready();

    let result = loop {
        tokio::select! {
            _ = terminate.recv() => break Ok(()),
            _ = interrupt.recv() => break Ok(()),
            _ = hangup.recv() => {
                let _ = tx.send(Msg::Hangup);
            }
            r = &mut dns => break Err(stopped("the DNS server", r)),
            r = &mut proxy => break Err(stopped("the HTTPS proxy", r)),
            _ = &mut done_rx => {
                engine_alive = false;
                break Err(anyhow!("the engine stopped unexpectedly"));
            }
        }
    };
    log("shutting down");
    server.abort();
    timers.abort();
    refresher.abort();
    names.abort();
    tailnet.abort();
    // Before teardown removes the firewall: the router stops routing first.
    // Until it's known to have, the firewall stays, as after a crash (#75).
    let _ = stop_router.send(true);
    let teardown = withdrawn_in_time(match tokio::time::timeout(ROUTER_STOP, router).await {
        Ok(Ok(withdrawn)) => Ok(withdrawn),
        Ok(Err(e)) => {
            warn(format!("warning: the subnet router's task failed: {e}"));
            Ok(false)
        }
        Err(e) => Err(e),
    });
    // Only our own: another daemon may have bound the path since.
    if file_id(&opts.socket) == Some(socket_id) {
        if let Err(e) = std::fs::remove_file(&opts.socket) {
            warn(format!("could not remove {}: {e}", opts.socket.display()));
        }
    }
    dns.abort();
    proxy.abort();
    if engine_alive {
        stop_engine(&tx, &mut done_rx, teardown).await;
    }
    // With the engine gone its view closes, so the collector stops its
    // sources and writes what they hold; don't wait long for it.
    if tokio::time::timeout(Duration::from_secs(5), collecting)
        .await
        .is_err()
    {
        warn("the activity collector didn't stop in time; its last records may be lost");
    }
    result
}

/// Whether teardown may remove the firewall, given how the router's
/// withdraw went within [`ROUTER_STOP`]; says why not when it may not.
fn withdrawn_in_time(withdrawn: Result<bool, tokio::time::error::Elapsed>) -> bool {
    let teardown = withdrawn.unwrap_or_else(|_| {
        warn("warning: the subnet router didn't withdraw its routes in time");
        false
    });
    if !teardown {
        warn("warning: leaving the firewall and wg0 in place: Parallax's subnet router may still route Tailscale peers, and without the firewall they'd reach the networks unfiltered. Start Parallax again, or stop the router, then stop Parallax");
    }
    teardown
}

/// Ask the engine to stop, tearing the gateway down if `teardown`, and
/// wait until it has.
async fn stop_engine(
    tx: &mpsc::UnboundedSender<Msg>,
    done: &mut oneshot::Receiver<()>,
    teardown: bool,
) {
    if tx.send(Msg::Shutdown { teardown }).is_ok() {
        let _ = done.await;
    }
}

fn stopped(what: &str, r: Result<anyhow::Result<()>, tokio::task::JoinError>) -> anyhow::Error {
    match r {
        Ok(Ok(())) => anyhow!("{what} stopped"),
        Ok(Err(e)) => e.context(format!("{what} stopped")),
        Err(e) => anyhow!("{what} stopped: {e}"),
    }
}

type Servers = (
    JoinHandle<anyhow::Result<()>>,
    JoinHandle<anyhow::Result<()>>,
    Reloaders,
);

/// How the engine hands the running DNS server and HTTPS proxy new routes.
struct Reloaders {
    dns: parallax_dns::Reload,
    proxy: parallax_proxy::Reload,
}

/// Start the HTTPS proxy and the DNS server on the routes the first apply
/// made. Both listen on the gateway address, which the WireGuard interface
/// carries since that apply.
async fn start_servers(
    (routes, dns_routes): (ProxyRoutes, DnsRoutes),
    taps: &collector::Taps,
) -> anyhow::Result<Servers> {
    let dns = parallax_dns::Dns::new(dns_routes, 53)?.tap(taps.dns.clone());
    let listen = dns.listen();
    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("the DNS server can't listen on udp {listen}"))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("the DNS server can't listen on tcp {listen}"))?;
    let proxy = parallax_proxy::Proxy::new(routes)?.tap(taps.proxy.clone());
    let listen = proxy.listen();
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("the HTTPS proxy can't listen on {listen}"))?;
    let reloaders = Reloaders {
        dns: dns.reloader(),
        proxy: proxy.reloader(),
    };
    let dns = tokio::spawn(async move { Ok(dns.run(udp, tcp).await?) });
    let proxy = tokio::spawn(async move { Ok(proxy.run(listener).await?) });
    Ok((dns, proxy, reloaders))
}

/// A path as the daemon compares it: resolved when it exists.
fn same_file(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Device and inode of `path`, to tell our socket from a later one.
fn file_id(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Tell systemd the gateway is up (`Type=notify` in the native unit): applied,
/// serving, and answering on its socket, so `systemctl start` returns only
/// then. Outside systemd there's no `NOTIFY_SOCKET`, and nothing to do.
fn notify_ready() {
    let Some(target) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let sent = (|| -> std::io::Result<()> {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};
        // "@name" is an abstract socket, anything else a path.
        let addr = match target.as_encoded_bytes().strip_prefix(b"@") {
            Some(name) => SocketAddr::from_abstract_name(name)?,
            None => SocketAddr::from_pathname(Path::new(&target))?,
        };
        UnixDatagram::unbound()?.send_to_addr(b"READY=1", &addr)?;
        Ok(())
    })();
    if let Err(e) = sent {
        warn(format!(
            "warning: couldn't tell systemd the gateway is up: {e}"
        ));
    }
}

/// Listen on `path`: directory 0700 when it's made here, socket 0600.
/// Returns the socket's identity, so shutdown removes only this one. A
/// socket file nobody answers on belongs to a daemon that's gone.
fn bind_socket(path: &Path) -> anyhow::Result<(UnixListener, (u64, u64))> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!(
                    "a daemon already answers on {}; stop it, or give this one another --socket",
                    path.display()
                );
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing the stale socket {}", path.display()))?
        }
        Ok(_) => bail!(
            "{} exists and is not a socket; remove it or pick another --socket",
            path.display()
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("listening on {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("securing {}", path.display()))?;
    let id = file_id(path).ok_or_else(|| anyhow!("{} vanished after binding", path.display()))?;
    Ok((listener, id))
}

async fn accept(
    listener: UnixListener,
    tx: mpsc::UnboundedSender<Msg>,
    views: Views,
    database: Arc<PathBuf>,
    logs: collector::Slot,
) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(answer(
                    stream,
                    tx.clone(),
                    views.clone(),
                    Arc::clone(&database),
                    Arc::clone(&logs),
                ));
            }
            Err(e) => {
                // Usually out of file descriptors; back off rather than spin.
                warn(format!("accepting a command failed: {e}"));
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// One connection: one request, one reply.
async fn answer(
    stream: UnixStream,
    tx: mpsc::UnboundedSender<Msg>,
    views: Views,
    database: Arc<PathBuf>,
    logs: collector::Slot,
) {
    let (read, mut write) = stream.into_split();
    let reply = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(read)).await {
        Err(_) => return,
        Ok(Err(e)) => Reply::Error {
            message: format!("{e:#}"),
        },
        Ok(Ok((theirs, _))) if same_file(&theirs) != *database => Reply::Error {
            message: format!(
                "this daemon holds the database {}, not {}; pass the matching --db, or --socket to reach another daemon",
                database.display(),
                theirs.display()
            ),
        },
        Ok(Ok((_, request))) => dispatch(request, &tx, &views, &logs).await,
    };
    let line = protocol::encode(&reply).or_else(|e| {
        protocol::encode(&Reply::Error {
            message: format!("{e:#}"),
        })
    });
    if let Ok(line) = line {
        let _ = write.write_all(&line).await;
    }
}

async fn read_request(read: tokio::net::unix::OwnedReadHalf) -> anyhow::Result<(PathBuf, Request)> {
    let mut reader = tokio::io::BufReader::new(read.take(protocol::MAX_MESSAGE as u64));
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .await
        .context("reading the request")?;
    protocol::check_line(&line)?;
    protocol::decode_request(&line)
}

async fn dispatch(
    request: Request,
    tx: &mpsc::UnboundedSender<Msg>,
    views: &Views,
    logs: &collector::Slot,
) -> Reply {
    let view = views.borrow().clone();
    let Some(view) = view else {
        return Reply::Error {
            message: "the daemon is still starting; try again in a moment".into(),
        };
    };
    match request {
        Request::Status => Reply::Status {
            revision: view.revision,
            apply_error: view.apply_error,
            public_ip: public_ip::effective(&view.config.server, view.public_ip),
            names: view.names,
            tailnet: view.tailnet,
        },
        Request::Load => Reply::Configuration {
            configuration: Box::new((*view.config).clone()),
            revision: view.revision,
            public_ip: view.public_ip,
            names: view.names,
            tailnet: view.tailnet,
        },
        Request::Logs { query } => {
            let open = logs.read().ok().and_then(|l| l.clone());
            match open {
                Some(logs) => match logs.query(&query).await {
                    Ok(records) => Reply::Logs { records },
                    Err(e) => Reply::Error {
                        message: format!("reading {}: {e}", logs.path().display()),
                    },
                },
                None => Reply::Logs {
                    records: Vec::new(),
                },
            }
        }
        request => {
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(Msg::Request(request, reply_tx)).is_err() {
                return shutting_down();
            }
            reply_rx.await.unwrap_or_else(|_| shutting_down())
        }
    }
}

fn shutting_down() -> Reply {
    Reply::Error {
        message: "the daemon is shutting down; nothing changed".into(),
    }
}

async fn timers(tx: mpsc::UnboundedSender<Msg>, every: Duration) {
    let mut reconcile = tokio::time::interval(every);
    reconcile.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // The first tick is immediate; startup has just applied.
    reconcile.tick().await;
    // Its first tick is immediate too: a backup when one is due at startup.
    let mut backups = tokio::time::interval(BACKUP_EVERY);
    backups.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        let msg = tokio::select! {
            _ = reconcile.tick() => Msg::Tick,
            _ = backups.tick() => Msg::BackupTick,
        };
        if tx.send(msg).is_err() {
            return;
        }
    }
}

/// Where the home's public IP comes from: a change to any of it looks again.
type Source = (bool, String, Ipv4Addr, PublicIpServer, PathBuf);

fn public_ip_source(config: &Config) -> Source {
    (
        public_ip::needed(config),
        config.server.wireguard.endpoint.clone(),
        config.server.dns.public_resolver,
        config.server.public_ip.clone(),
        config.server.proxy.upstream_ca.clone(),
    )
}

/// What a public IP lookup depends on: where it comes from, and the last
/// save that looked it up itself (its answer is newer than a lookup that
/// started before it). A result for other inputs than the current ones is
/// stale.
type Inputs = (Source, u64);

fn lookup_inputs(view: &View) -> Inputs {
    (public_ip_source(&view.config), view.public_ip_set)
}

/// Look up the home's public IP every [`PUBLIC_IP_EVERY`], and when a saved
/// change alters what the lookup depends on. Startup has just looked. The
/// lookup blocks for seconds, so it runs here, never on the engine thread.
async fn refresh_public_ip(tx: mpsc::UnboundedSender<Msg>, mut views: Views) {
    let mut every = tokio::time::interval(PUBLIC_IP_EVERY);
    every.set_missed_tick_behavior(MissedTickBehavior::Delay);
    every.tick().await;
    let inputs = |views: &Views| views.borrow().as_ref().map(lookup_inputs);
    let mut last = inputs(&views);
    loop {
        tokio::select! {
            _ = every.tick() => {}
            changed = views.changed() => {
                if changed.is_err() {
                    return;
                }
                let now = inputs(&views);
                if now == last {
                    continue;
                }
                last = now;
            }
        }
        let view = views.borrow().clone();
        let Some(view) = view.filter(|v| public_ip::needed(&v.config)) else {
            continue;
        };
        let asked = lookup_inputs(&view);
        let config = view.config;
        // A tick that won the race with a change has looked at it already.
        last = Some(asked.clone());
        let found =
            tokio::task::spawn_blocking(move || crate::find_public_ip(&config.server)).await;
        if let Ok(found) = found {
            if tx.send(Msg::PublicIp(asked, found)).is_err() {
                return;
            }
        }
    }
}

/// What the name lookups depend on: the names, the networks that say which
/// resolvers to ask and which answers are allowed, the home's public IP (an
/// answer may be it), and the last time a save set the names (its answers
/// are newer than lookups that started before it).
type NameInputs = (Vec<String>, Vec<Network>, Option<Ipv4Addr>, u64);

fn name_inputs(view: &View) -> NameInputs {
    (
        names::used(&view.config)
            .into_iter()
            .map(str::to_string)
            .collect(),
        view.config.networks.clone(),
        public_ip::effective(&view.config.server, view.public_ip),
        view.names_set,
    )
}

/// Look the named hosts up right away (startup applied with what the
/// database remembered), then every [`NAMES_EVERY`], and when a change
/// alters what the lookups depend on. Blocks for seconds, so it runs here.
async fn refresh_names(tx: mpsc::UnboundedSender<Msg>, mut views: Views) {
    let mut every = tokio::time::interval(NAMES_EVERY);
    every.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let inputs = |views: &Views| views.borrow().as_ref().map(name_inputs);
    let mut last = inputs(&views);
    loop {
        tokio::select! {
            _ = every.tick() => {}
            changed = views.changed() => {
                if changed.is_err() {
                    return;
                }
                let now = inputs(&views);
                if now == last {
                    continue;
                }
                last = now;
            }
        }
        let view = views.borrow().clone();
        let Some(view) = view.filter(|v| !names::used(&v.config).is_empty()) else {
            continue;
        };
        let asked = name_inputs(&view);
        last = Some(asked.clone());
        let found = tokio::task::spawn_blocking(move || {
            let home = public_ip::effective(&view.config.server, view.public_ip);
            crate::find_names(&view.config, home)
        })
        .await;
        if let Ok(found) = found {
            if tx.send(Msg::Names(asked, found)).is_err() {
                return;
            }
        }
    }
}

/// What asking Headscale depends on: whether any peer needs it, and where
/// it is and how to reach it.
type TailnetInputs = (bool, String, PathBuf, PathBuf);

fn tailnet_inputs(config: &Config) -> TailnetInputs {
    (
        headscale::needed(config),
        config.server.headscale.server_url.clone(),
        config.server.headscale.api_key_file.clone(),
        config.server.proxy.upstream_ca.clone(),
    )
}

/// Ask Headscale every [`TAILNET_EVERY`] (startup asked before the first
/// apply), and when a change alters what asking depends on. Blocks for up
/// to seconds, so it runs here.
async fn refresh_tailnet(tx: mpsc::UnboundedSender<Msg>, mut views: Views) {
    let mut every = tokio::time::interval(TAILNET_EVERY);
    every.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let inputs = |views: &Views| views.borrow().as_ref().map(|v| tailnet_inputs(&v.config));
    let mut last = inputs(&views);
    loop {
        tokio::select! {
            _ = every.tick() => {}
            changed = views.changed() => {
                if changed.is_err() {
                    return;
                }
                let now = inputs(&views);
                if now == last {
                    continue;
                }
                last = now;
            }
        }
        let config = views.borrow().as_ref().map(|v| Arc::clone(&v.config));
        let Some(config) = config.filter(|c| headscale::needed(c)) else {
            continue;
        };
        let asked = tailnet_inputs(&config);
        last = Some(asked.clone());
        let found = tokio::task::spawn_blocking(move || crate::find_tailnet(&config)).await;
        if let Ok(found) = found {
            if tx.send(Msg::Tailnet(asked, found)).is_err() {
                return;
            }
        }
    }
}

/// Keep the subnet router as the configuration says, every
/// [`ROUTER_EVERY`] and when the configuration changes. Logs what it did,
/// and each problem (or what the operator still has to do) once. After a
/// failure it waits longer each time, up to [`ROUTER_BACKOFF`], so a login
/// that keeps failing doesn't mint a pre-auth key every poll.
///
/// When `stop` changes (or the engine is gone), it lets a look in flight
/// finish without changing anything more, takes Parallax's own router's
/// routes away ([`crate::withdraw_router`]) and returns whether the router
/// is known to route nothing now: only then may the caller remove the
/// firewall (#75).
async fn keep_router(mut views: Views, socket: String, mut stop: watch::Receiver<bool>) -> bool {
    let config = |views: &Views| views.borrow().as_ref().map(|v| Arc::clone(&v.config));
    let mut last = config(&views);
    let mut said: Option<String> = None;
    // A kept deadline: a publish that doesn't change the configuration
    // (a node's address, a name's answer) mustn't put the next look off (#78).
    let mut next = tokio::time::Instant::now();
    let mut pace = Pace::default();
    // The node key the last look found as Parallax's own router.
    let mut ours: Option<String> = None;
    'looking: loop {
        tokio::select! {
            // Stopping wins over a look that's due.
            biased;
            _ = stop.changed() => break,
            _ = tokio::time::sleep_until(next) => {}
            changed = views.changed() => {
                if changed.is_err() {
                    break;
                }
                // Every apply publishes; only a new configuration counts.
                if config(&views) == last {
                    continue;
                }
                pace = Pace::default();
            }
        }
        next = tokio::time::Instant::now() + ROUTER_EVERY;
        last = config(&views);
        let Some(looking_at) = last.clone() else {
            continue;
        };
        if !subnet_router::needed(&looking_at) {
            // Nothing to report: the machine may have no Tailscale at all.
            said = None;
        }
        // Cleared when the configuration is replaced or the daemon stops:
        // the look then changes nothing more (#82).
        let current = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut look = tokio::task::spawn_blocking({
            let (current, socket) = (Arc::clone(&current), socket.clone());
            move || {
                let still = || current.load(std::sync::atomic::Ordering::SeqCst);
                crate::sync_router(&looking_at, &socket, &still)
            }
        });
        let mut stopping = false;
        let looked = loop {
            let watching = current.load(std::sync::atomic::Ordering::SeqCst);
            tokio::select! {
                looked = &mut look => break looked,
                _ = stop.changed(), if !stopping => {
                    stopping = true;
                    current.store(false, std::sync::atomic::Ordering::SeqCst);
                }
                changed = views.changed(), if watching => {
                    if changed.is_err() {
                        stopping = true;
                    }
                    if changed.is_err() || config(&views) != last {
                        current.store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                }
            }
        };
        if stopping {
            break;
        }
        if !current.load(std::sync::atomic::Ordering::SeqCst) {
            // Replaced meanwhile (even if changed back): look again at once.
            pace = Pace::default();
            next = tokio::time::Instant::now();
            continue;
        }
        let Ok(looked) = looked else {
            continue;
        };
        let (wait, note) = match looked {
            Ok(look) if !look.done.is_empty() => {
                ours = look.ours;
                look.done.iter().for_each(log);
                next = tokio::time::Instant::now() + pace.after(Looked::Changed);
                continue 'looking;
            }
            Ok(look) => {
                ours = look.ours;
                (pace.after(Looked::Fine), look.note)
            }
            Err(e) => (pace.after(Looked::Failed), Some(e)),
        };
        next = tokio::time::Instant::now() + wait;
        if note != said {
            match &note {
                Some(note) => warn(format!("subnet router: {note}")),
                None => log("subnet router: in place"),
            }
            said = note;
        }
    }
    // The latest configuration: a change that came in during the last look
    // may be what makes the router reachable.
    withdraw(config(&views).or(last), socket, ours).await
}

/// Take Parallax's own router's routes away ([`crate::withdraw_router`]).
/// True if it's known to route nothing now, so the firewall may go.
async fn withdraw(config: Option<Arc<Config>>, socket: String, ours: Option<String>) -> bool {
    let Some(config) = config else {
        return true;
    };
    let withdrawn = tokio::task::spawn_blocking(move || {
        crate::withdraw_router(&config, &socket, ours.as_deref())
    })
    .await;
    match withdrawn {
        Ok(Ok(true)) => {
            log("subnet router: withdrew its routes");
            true
        }
        Ok(Ok(false)) => true,
        Ok(Err(e)) => {
            warn(format!(
                "warning: subnet router: could not withdraw its routes: {e}"
            ));
            false
        }
        Err(e) => {
            warn(format!(
                "warning: subnet router: could not withdraw its routes: {e}"
            ));
            false
        }
    }
}

/// What a look at the router came to, for [`Pace`].
#[derive(Debug, Clone, Copy)]
enum Looked {
    /// It changed something.
    Changed,
    /// Nothing to change.
    Fine,
    Failed,
}

/// How long the router waits after each look (#78). Starts afresh with
/// each new configuration.
#[derive(Debug, Default)]
struct Pace {
    failures: u32,
    /// The last look was the quick one after a change.
    quick: bool,
}

impl Pace {
    fn after(&mut self, looked: Looked) -> Duration {
        match looked {
            // Once more soon (a router that just logged in gets its routes
            // approved), then the usual pace. A step that worked ends a run
            // of failures.
            Looked::Changed => {
                self.failures = 0;
                self.quick = !self.quick;
                if self.quick {
                    ROUTER_SOON
                } else {
                    ROUTER_EVERY
                }
            }
            Looked::Fine => {
                *self = Pace::default();
                ROUTER_EVERY
            }
            Looked::Failed => {
                self.quick = false;
                self.failures = self.failures.saturating_add(1);
                (ROUTER_EVERY * 2u32.saturating_pow(self.failures.min(5))).min(ROUTER_BACKOFF)
            }
        }
    }
}

fn engine_thread(
    db: &Path,
    out: PathBuf,
    publish: watch::Sender<Option<View>>,
    mut rx: mpsc::UnboundedReceiver<Msg>,
    ready: oneshot::Sender<anyhow::Result<(ProxyRoutes, DnsRoutes)>>,
) {
    let (jobs, queue) = std::sync::mpsc::channel::<BackupJob>();
    let writer = match std::thread::Builder::new()
        .name("parallax-backup".into())
        .spawn(move || queue.into_iter().for_each(finish_backup))
    {
        Ok(writer) => writer,
        Err(e) => {
            let _ = ready.send(Err(anyhow!("starting the backup thread: {e}")));
            return;
        }
    };
    let mut engine = match Engine::start(db, out, publish, jobs) {
        Ok(engine) => engine,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    if public_ip::needed(&engine.view.config) {
        let found = crate::find_public_ip(&engine.view.config.server);
        let from = public_ip_source(&engine.view.config);
        engine.note_public_ip(found, from);
    }
    // Before the first apply: a peer that names a node has no address
    // until Headscale answers, so a restart mustn't wait a poll for it.
    let found = crate::find_tailnet(&engine.view.config);
    engine.note_tailnet(found);
    // A failed first apply takes down what it set up before failing: the
    // process exits, and nothing else would ever remove a table and an
    // interface left behind (#53). What was there before it started stays,
    // whoever set it up. Docker or systemd starts it again.
    let before = reconcile::parts_present(&engine.view.config.server, sys());
    if let Err(e) = engine.first_apply() {
        for line in reconcile::teardown_added(&engine.view.config.server, before, sys()) {
            log(line);
        }
        let _ = ready.send(Err(e));
        return;
    }
    let routes = engine
        .proxy_routes
        .clone()
        .zip(engine.dns_routes.clone())
        .ok_or_else(|| anyhow!("the first apply made no proxy or DNS routes"));
    let _ = ready.send(routes);
    // With its channel gone, nothing said otherwise.
    let mut teardown = true;
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while let Ok(msg) = rx.try_recv() {
            batch.push(msg);
        }
        if let Some(down) = engine.handle(batch) {
            teardown = down;
            break;
        }
    }
    if teardown {
        engine.teardown();
    }
    // Let a backup being written finish: the process ends when this returns.
    drop(engine);
    let _ = writer.join();
}

/// A backup whose database copy is taken, and who asked for it (`None`:
/// the timer, which logs instead).
type BackupJob = (crate::backup::Taken, Option<oneshot::Sender<Reply>>);

/// On the backup thread: write it, then answer or log.
fn finish_backup((taken, reply): BackupJob) {
    let written = taken.write();
    match reply {
        Some(reply) => {
            let _ = reply.send(match written {
                Ok(lines) => Reply::Done { lines },
                Err(e) => Reply::Error {
                    message: format!("{e:#}"),
                },
            });
        }
        None => match written {
            Ok(lines) => lines.iter().for_each(log),
            Err(e) => warn(format!("warning: automatic backup failed: {e:#}")),
        },
    }
}

struct Engine {
    /// The store is async; the engine waits on it here, on its own thread.
    rt: tokio::runtime::Runtime,
    store: Store,
    view: View,
    publish: watch::Sender<Option<View>>,
    out: PathBuf,
    reconciler: Reconciler,
    /// What the last successful apply set up, for teardown.
    applied: Option<ServerConfig>,
    /// The backup thread's queue.
    backups: std::sync::mpsc::Sender<BackupJob>,
    /// The DNS server and the proxy, once they run.
    servers: Option<Reloaders>,
    /// The routes the proxy serves, or will next: they're taken in the
    /// order sent. Only what a good apply made, or what that and every
    /// apply since, failed ones too, all grant (issue #71).
    proxy_routes: Option<ProxyRoutes>,
    /// Whether the proxy has confirmed `proxy_routes`: in force, and no open
    /// connection on older ones. Until it has, the next apply waits for it
    /// again, even with nothing new to narrow (#103).
    proxy_confirmed: bool,
    /// Who may hold each tunnel address live: what a good apply set up,
    /// and what every apply since may have, failed ones too. Narrowing
    /// allows an address nothing while someone else may hold it (#115).
    holders: Holders,
    /// The routes the DNS server answers by, or will next, likewise: an
    /// address that changes hands answers neither owner's names beyond
    /// what both may see until the apply has worked (issue #37).
    dns_routes: Option<DnsRoutes>,
    /// Why the last public IP lookup failed, so the same failure is
    /// logged once, not every 5 minutes.
    public_ip_problems: Option<Vec<String>>,
    /// The database holds `view.public_ip`; false after a failed write, so
    /// the next lookup writes it again.
    public_ip_saved: bool,
    /// The settings `view.public_ip` was last found from; `None` when it
    /// came from the database (before a restart) or was never found.
    public_ip_from: Option<Source>,
    /// Why the last name lookups failed, logged once.
    name_problems: Vec<String>,
    /// Why Headscale didn't answer last time, logged once.
    tailnet_problem: Option<String>,
}

/// How long the proxy may take to serve the routes an apply needs first
/// (its own wait for open connections is shorter).
const PROXY_TAKES: Duration = Duration::from_secs(10);
/// The same for the DNS server (its own wait for queries under the old
/// routes is shorter).
const DNS_TAKES: Duration = Duration::from_secs(8);

/// Before the apply writes or changes anything, like [`narrow_proxy`]: the
/// DNS server answers each member only what both its routes `served` and
/// the `new` ones let it look up (issue #37), so an address that changes
/// hands answers neither owner's names beyond that while WireGuard may
/// still give it to either. Waits until it does; if it doesn't in time,
/// nothing has changed and the apply stops.
fn narrow_dns(
    rt: &tokio::runtime::Runtime,
    dns: Option<&parallax_dns::Reload>,
    served: &mut Option<DnsRoutes>,
    new: &DnsRoutes,
) -> anyhow::Result<()> {
    // No DNS server runs before the first apply has worked.
    let (Some(dns), Some(before)) = (dns, served.as_ref()) else {
        return Ok(());
    };
    let both = parallax_dns::overlap(before, new);
    if both == *before {
        return Ok(());
    }
    let taken = dns.send(both.clone());
    match rt.block_on(async { tokio::time::timeout(DNS_TAKES, taken).await }) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => bail!(
            "the DNS server couldn't take its routes for the change (stopped); the firewall and WireGuard weren't changed"
        ),
        Err(_) => bail!(
            "the DNS server didn't take its routes for the change within {} s; the firewall and WireGuard weren't changed",
            DNS_TAKES.as_secs()
        ),
    }
    *served = Some(both);
    Ok(())
}

/// What a proxy serving `before` serves once routes it was handed don't
/// load: no site at all, on the listener, certificates and CA bundle it
/// had (#114).
fn nothing_served(before: &ProxyRoutes) -> ProxyRoutes {
    ProxyRoutes {
        sites: Vec::new(),
        ..before.clone()
    }
}

/// Before the apply writes or changes anything: one that fails partway can
/// leave the old firewall, the new one or (iptables) a mix, so the proxy
/// first serves only what both its routes `served` and the `new` ones grant
/// (issue #71), and nothing to an address in `moved` (#115). Waits until it
/// does; if it doesn't in time, the apply stops before anything else has
/// changed. `confirmed` says whether the proxy has confirmed `served`.
///
/// Routes that don't load leave the proxy serving nothing, which grants
/// less than either, so the apply goes on, recorded as just that (#114).
fn narrow_proxy(
    rt: &tokio::runtime::Runtime,
    proxy: Option<&parallax_proxy::Reload>,
    served: &mut Option<ProxyRoutes>,
    confirmed: &mut bool,
    new: &ProxyRoutes,
    moved: &[std::net::Ipv4Addr],
) -> anyhow::Result<()> {
    // No proxy runs before the first apply has worked.
    let (Some(proxy), Some(before)) = (proxy, served.as_ref()) else {
        return Ok(());
    };
    let both = generate::proxy::overlap(before, new, moved);
    if *confirmed && both.serves_alike(before) {
        return Ok(());
    }
    let refused = nothing_served(before);
    let parallax_proxy::Taking { loaded, checked } = proxy.send(both.clone());
    // The proxy serves them next whatever comes of the wait: routes go in
    // in the order sent, even once nobody waits for them (#103). Its wait
    // for open connections also covers every older routes still held.
    *served = Some(both);
    *confirmed = false;
    // Inside the runtime: a timer needs its clock. One deadline for both.
    let taken = rt.block_on(async {
        tokio::time::timeout(PROXY_TAKES, async { (loaded.await, checked.await) }).await
    });
    const LEFT: &str =
        "the firewall and WireGuard weren't changed, and the next try waits for the proxy again";
    let (loaded, checked) = match taken {
        Ok((Ok(loaded), Ok(checked))) => (loaded, checked),
        Ok(_) => bail!("the HTTPS proxy has stopped; the firewall and WireGuard weren't changed"),
        Err(_) => bail!(
            "the HTTPS proxy didn't take its routes for the change within {} s; {LEFT}",
            PROXY_TAKES.as_secs()
        ),
    };
    if let Err(why) = loaded {
        warn(format!(
            "the HTTPS proxy couldn't load its routes for the change ({why}); it refuses every connection until a reload works"
        ));
        *served = Some(refused);
    }
    if !checked {
        bail!(
            "the HTTPS proxy's open connections didn't all move on to its routes for the change in time; {LEFT}"
        );
    }
    *confirmed = true;
    Ok(())
}

/// After a good apply: the proxy serves the new `routes` in full, recorded
/// in `served`. Waits only until they're in force, not for open
/// connections, which they grant at least as much as the narrowed ones.
/// When they don't load, the proxy refuses every connection, `served` says
/// so (#114), and the apply counts as failed so the next tick tries again
/// (#103). Not taken in time: the proxy takes them later, or refuses
/// everything, so `served` says the wider, the new routes.
fn widen_proxy(
    rt: &tokio::runtime::Runtime,
    proxy: &parallax_proxy::Reload,
    served: &mut Option<ProxyRoutes>,
    routes: ProxyRoutes,
) -> anyhow::Result<()> {
    let loaded = proxy.load(routes.clone());
    let refused = served.as_ref().map(nothing_served);
    *served = Some(routes);
    match rt.block_on(async { tokio::time::timeout(PROXY_TAKES, loaded).await }) {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(why))) => {
            if refused.is_some() {
                *served = refused;
            }
            bail!(
                "the HTTPS proxy couldn't load its new routes ({why}); it refuses every connection until a reload works"
            )
        }
        Ok(Err(_)) => bail!("the HTTPS proxy has stopped"),
        Err(_) => bail!(
            "the HTTPS proxy didn't take its new routes within {} s; it will serve them, or refuse every connection, once it does",
            PROXY_TAKES.as_secs()
        ),
    }
}

impl Engine {
    fn start(
        db: &Path,
        out: PathBuf,
        publish: watch::Sender<Option<View>>,
        backups: std::sync::mpsc::Sender<BackupJob>,
    ) -> anyhow::Result<Engine> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .context("starting the engine's runtime")?;
        let mut store = rt.block_on(Store::open(db)).map_err(|e| match e {
            parallax_store::Error::InUse(_) => anyhow!(
                "the database {} is open in another process; is another daemon running?",
                db.display()
            ),
            e => e.into(),
        })?;
        let config = rt.block_on(store.load())?;
        let public_ip = rt.block_on(store.public_ip())?;
        let engine = Engine {
            rt,
            store,
            view: View {
                config: Arc::new(config),
                // Random, so a revision from before a restart never matches.
                revision: rand::random::<u64>() >> 1,
                apply_error: None,
                applied: None,
                public_ip,
                public_ip_set: 0,
                // Looked up right after the first apply: an answer from
                // before a restart may be stale.
                names: Resolved::new(),
                names_set: 0,
                // Asked before the first apply.
                tailnet: None,
            },
            publish,
            out,
            reconciler: Reconciler::new(),
            applied: None,
            servers: None,
            proxy_routes: None,
            // The proxy starts on the routes the first apply made.
            proxy_confirmed: true,
            // Set by the first apply that works, before the proxy starts.
            holders: Holders::default(),
            dns_routes: None,
            backups,
            public_ip_problems: None,
            public_ip_saved: true,
            public_ip_from: None,
            name_problems: Vec::new(),
            tailnet_problem: None,
        };
        engine.publish();
        Ok(engine)
    }

    fn publish(&self) {
        self.publish.send_replace(Some(self.view.clone()));
    }

    fn first_apply(&mut self) -> anyhow::Result<()> {
        match self.apply("startup") {
            (_, None) => Ok(()),
            (_, Some(e)) => bail!("the first apply failed: {e}"),
        }
    }

    /// Handle a batch of work. Returns `Some(teardown)` to shut down.
    fn handle(&mut self, batch: Vec<Msg>) -> Option<bool> {
        // Shutting down: change nothing, refuse whatever else is queued.
        let stop = batch.iter().find_map(|m| match m {
            Msg::Shutdown { teardown } => Some(*teardown),
            _ => None,
        });
        if let Some(teardown) = stop {
            for msg in batch {
                if let Msg::Request(_, reply) = msg {
                    let _ = reply.send(shutting_down());
                }
            }
            return Some(teardown);
        }
        // Requests answered after the apply, with their own lines first.
        let mut waiting: Vec<(oneshot::Sender<Reply>, Vec<String>)> = Vec::new();
        let mut why: Option<&str> = None;
        let (mut tick, mut backup_due) = (false, false);
        for msg in batch {
            match msg {
                Msg::Request(request, reply) => match request {
                    Request::Save {
                        configuration,
                        revision,
                    } => match self.save(*configuration, revision) {
                        Ok(()) => {
                            waiting.push((reply, Vec::new()));
                            why.get_or_insert("a saved change");
                        }
                        Err(refused) => {
                            let _ = reply.send(refused);
                        }
                    },
                    Request::Apply => {
                        waiting.push((reply, Vec::new()));
                        why.get_or_insert("asked by `parallax apply`");
                    }
                    Request::BackupRestore {
                        path,
                        passphrase,
                        revision,
                        contents_sha256,
                    } => match self.restore(&path, passphrase, revision, &contents_sha256) {
                        Ok(lines) => {
                            waiting.push((reply, lines));
                            why.get_or_insert("a restored backup");
                        }
                        Err(refused) => {
                            let _ = reply.send(refused);
                        }
                    },
                    Request::BackupCreate { if_due } => self.backup(if_due, Some(reply)),
                    // Answered by the socket task, from the view and logs.db.
                    Request::Status | Request::Load | Request::Logs { .. } => {
                        let _ = reply.send(Reply::Error {
                            message: "status, load and logs aren't queued".into(),
                        });
                    }
                },
                Msg::Hangup => {
                    why.get_or_insert("SIGHUP");
                }
                Msg::Tick => tick = true,
                Msg::BackupTick => backup_due = true,
                Msg::Serving(reloaders) => self.servers = Some(reloaders),
                // A save changed the inputs, or looked itself, while this
                // lookup ran: the lookup for the new ones is already on its way.
                Msg::PublicIp(asked, _) if asked != lookup_inputs(&self.view) => {}
                Msg::PublicIp((from, _), found) => {
                    let server = &self.view.config.server;
                    let before = public_ip::effective(server, self.view.public_ip);
                    self.note_public_ip(found, from);
                    let server = &self.view.config.server;
                    if public_ip::effective(server, self.view.public_ip) != before {
                        why.get_or_insert("the home's public IP changed");
                    }
                }
                // The names, their resolvers or the networks changed while
                // these lookups ran, or a save looked names up since: the
                // lookups for the new ones are coming.
                Msg::Names(asked, _) if asked != name_inputs(&self.view) => {}
                Msg::Names(_, found) => {
                    if self.note_names(found) {
                        why.get_or_insert("a named host's address changed");
                    }
                }
                // Where Headscale is changed while it was asked.
                Msg::Tailnet(asked, _) if asked != tailnet_inputs(&self.view.config) => {}
                Msg::Tailnet(_, found) => {
                    if self.note_tailnet(found) {
                        why.get_or_insert("Headscale gave a Tailscale node another address");
                    }
                }
                Msg::Shutdown { .. } => {}
            }
        }
        if let Some(why) = why {
            let (log, error) = self.apply(why);
            for (reply, mut lines) in waiting {
                lines.extend(log.iter().cloned());
                let _ = reply.send(Reply::Applied {
                    revision: self.view.revision,
                    log: lines,
                    error: error.clone(),
                });
            }
        } else if tick {
            let server = &self.view.config.server;
            let due = self
                .reconciler
                .on_tick(crate::today(), || reconcile::live_state(server, sys()));
            if let Some(reason) = due {
                self.apply(&reason.to_string());
            }
        }
        if backup_due {
            self.backup(true, None);
        }
        None
    }

    /// Apply the configuration. Returns the log, and why it failed.
    fn apply(&mut self, why: &str) -> (Vec<String>, Option<String>) {
        log(format!("applying ({why})"));
        let today = crate::today();
        let mut made = None;
        let (servers, rt) = (&self.servers, &self.rt);
        let (served, dns_served) = (&mut self.proxy_routes, &mut self.dns_routes);
        let (confirmed, holders) = (&mut self.proxy_confirmed, &self.holders);
        let applied = crate::apply_config(
            &self.view.config,
            &self.out,
            today,
            &self.view.learned(),
            |model| {
                let new = generate::proxy::build(model);
                let new_dns = generate::dns::build(model);
                let new_holders = Holders::of(model);
                narrow_proxy(
                    rt,
                    servers.as_ref().map(|s| &s.proxy),
                    served,
                    confirmed,
                    &new,
                    &holders.moved(&new_holders),
                )?;
                narrow_dns(rt, servers.as_ref().map(|s| &s.dns), dns_served, &new_dns)?;
                made = Some((new, new_dns, new_holders));
                Ok(())
            },
        );
        match applied {
            Ok((warnings, applied)) => {
                let lines: Vec<String> = warnings
                    .into_iter()
                    .map(|w| format!("warning: {w}"))
                    .chain(applied)
                    .collect();
                lines.iter().for_each(log);
                let server = &self.view.config.server;
                self.reconciler
                    .applied(today, reconcile::live_state(server, sys()));
                self.applied = Some(server.clone());
                let mut proxy_failed = None;
                if let Some((routes, dns, holders)) = made {
                    if let Some(servers) = &self.servers {
                        // DNS not waited for: the next apply's narrowing is
                        // taken after these.
                        drop(servers.dns.send(dns.clone()));
                        proxy_failed =
                            widen_proxy(&self.rt, &servers.proxy, &mut self.proxy_routes, routes)
                                .err();
                        // In force, and wider than anything older an open
                        // connection may still hold.
                        self.proxy_confirmed = proxy_failed.is_none();
                    } else {
                        self.proxy_routes = Some(routes);
                    }
                    self.dns_routes = Some(dns);
                    // WireGuard holds what this configuration says.
                    self.holders = holders;
                }
                // What the activity log attributes by from now on.
                self.view.applied = Some(Arc::clone(&self.view.config));
                if let Some(e) = proxy_failed {
                    let e = format!("{e:#}");
                    warn(format!(
                        "apply failed after the firewall changed, trying again in a minute: {e}"
                    ));
                    self.reconciler.failed();
                    self.view.apply_error = Some(e.clone());
                    self.publish();
                    return (lines, Some(e));
                }
                self.view.apply_error = None;
                self.publish();
                (lines, None)
            }
            Err(e) => {
                // Past the narrowing, WireGuard may have changed hands.
                if let Some((_, _, holders)) = made {
                    self.holders.add(holders);
                }
                let e = format!("{e:#}");
                warn(format!("apply failed, trying again in a minute: {e}"));
                self.reconciler.failed();
                self.set_apply_error(Some(e.clone()));
                (Vec::new(), Some(e))
            }
        }
    }

    /// Take a lookup's result, from the settings `from`: a new address is
    /// published and remembered in the database; a failure is logged once.
    fn note_public_ip(&mut self, found: Result<Found, Vec<String>>, from: Source) {
        if self.record_public_ip(found, from) {
            self.publish();
        }
    }

    /// [`Engine::note_public_ip`] without publishing. Returns whether the
    /// address changed.
    fn record_public_ip(&mut self, found: Result<Found, Vec<String>>, from: Source) -> bool {
        match found {
            Ok(found) => {
                self.public_ip_problems = None;
                self.public_ip_from = Some(from);
                let changed = self.view.public_ip != Some(found.address);
                if changed {
                    log(format!(
                        "the home's public IP is {} (from {})",
                        found.address, found.source
                    ));
                    self.view.public_ip = Some(found.address);
                }
                if changed || !self.public_ip_saved {
                    let saved = self.rt.block_on(self.store.set_public_ip(found.address));
                    if let Err(e) = &saved {
                        warn(format!(
                            "warning: could not remember the home's public IP in the database {}: {e}",
                            self.store.path().display()
                        ));
                    }
                    self.public_ip_saved = saved.is_ok();
                }
                changed
            }
            Err(problems) => {
                if self.public_ip_problems.as_ref() != Some(&problems) {
                    warn(format!(
                        "warning: {}",
                        crate::public_ip_lookup_failed(&problems, self.view.public_ip)
                    ));
                    self.public_ip_problems = Some(problems);
                }
                false
            }
        }
    }

    /// Take the name lookups' results, for the configuration as it is:
    /// what they found replaces what was there, and a name that didn't
    /// resolve grants nothing. Returns whether anything changed.
    fn note_names(&mut self, found: Refreshed) -> bool {
        if found.problems != self.name_problems {
            for problem in &found.problems {
                warn(format!("warning: {problem}"));
            }
            self.name_problems = found.problems;
        }
        self.set_names(found.resolved)
    }

    /// What a save or a restore found the names resolve to: newer than any
    /// lookup still running, so those are dropped when they finish. `asked`:
    /// it looked names up, so even an unchanged answer is newer.
    /// Doesn't publish: its caller does, once, with the rest of the change.
    fn set_names_from_save(&mut self, resolved: Resolved, asked: bool) {
        if asked || resolved != self.view.names {
            self.view.names_set = self.view.names_set.wrapping_add(1);
        }
        self.record_names(resolved);
    }

    /// Publish what the names resolve to now. Returns whether it changed.
    fn set_names(&mut self, resolved: Resolved) -> bool {
        let changed = self.record_names(resolved);
        if changed {
            self.publish();
        }
        changed
    }

    /// [`Engine::set_names`] without publishing.
    fn record_names(&mut self, resolved: Resolved) -> bool {
        if resolved == self.view.names {
            return false;
        }
        for (name, addresses) in &resolved {
            if self.view.names.get(name) != Some(addresses) {
                log(format!("{name} is {}", names::list(addresses)));
            }
        }
        for name in self
            .view
            .names
            .keys()
            .filter(|n| !resolved.contains_key(*n))
        {
            log(format!("{name} no longer grants anything"));
        }
        self.view.names = resolved;
        true
    }

    /// Take Headscale's answer: new addresses are published; a failure is
    /// logged once and the last answer stays. Returns whether the addresses
    /// changed.
    fn note_tailnet(&mut self, found: Result<Option<Tailnet>, String>) -> bool {
        let found = match found {
            Ok(found) => found,
            Err(problem) => {
                if self.tailnet_problem.as_ref() != Some(&problem) {
                    let keeping = match self.view.tailnet {
                        Some(_) => "keeping the addresses it gave last",
                        None => "Tailscale peers that name a node get no access until it answers",
                    };
                    warn(format!("warning: {problem}; {keeping}"));
                    self.tailnet_problem = Some(problem);
                }
                return false;
            }
        };
        if self.tailnet_problem.take().is_some() {
            log("Headscale answers again");
        }
        if found == self.view.tailnet {
            return false;
        }
        if let Some(after) = &found {
            headscale::changes(self.view.tailnet.as_ref(), after)
                .iter()
                .for_each(log);
        }
        self.view.tailnet = found;
        self.publish();
        true
    }

    /// What Headscale said, if `config` names the same Headscale (node ids
    /// mean nothing on another one) and still asks it (an answer nobody
    /// refreshes would come back stale with the next node peer).
    fn tailnet_for(&self, config: &Config) -> Option<Tailnet> {
        let same =
            config.server.headscale.server_url == self.view.config.server.headscale.server_url;
        self.view
            .tailnet
            .clone()
            .filter(|_| same && headscale::needed(config))
    }

    fn set_apply_error(&mut self, error: Option<String>) {
        if self.view.apply_error != error {
            self.view.apply_error = error;
            self.publish();
        }
    }

    /// The configuration changed: remember it, for the caller to publish.
    /// Addresses from another Headscale than the new one's are forgotten.
    fn replace(&mut self, config: Config) {
        self.view.tailnet = self.tailnet_for(&config);
        self.view.config = Arc::new(config);
        self.view.revision = self.view.revision.wrapping_add(1);
    }

    /// Validate, look up names it adds, generate and check certificates;
    /// only then save. Returns the reply refusing the change. Warnings come
    /// with the apply that follows.
    fn save(&mut self, config: Config, revision: u64) -> Result<(), Reply> {
        if revision != self.view.revision {
            return Err(Reply::Conflict {
                revision: self.view.revision,
            });
        }
        let refuse = |e: anyhow::Error| Reply::Error {
            message: format!("{e:#}"),
        };
        crate::check(&config).map_err(refuse)?;
        let old_ip = public_ip::effective(&self.view.config.server, self.view.public_ip);
        // A name may point at the home's public IP. Look before telling
        // where a name points (a few seconds at most, and only then): when
        // this change looks names up and the address known wasn't found
        // from its settings (nothing looked while nothing needed it, an
        // earlier change or a restore moved the endpoint, or it's from
        // before a restart), and when this change moves the endpoint of a
        // configuration that uses names. What it finds is kept only if the
        // change is.
        let source = public_ip_source(&config);
        let asked = !names::asked_on_save(Some(&self.view.config), &config).is_empty();
        let unverified = public_ip::effective(&config.server, self.view.public_ip).is_none()
            || self.public_ip_from.as_ref() != Some(&source);
        let elsewhere = public_ip_source(&self.view.config) != source;
        let found = ((asked && unverified) || (elsewhere && !names::used(&config).is_empty()))
            .then(|| crate::find_public_ip(&config.server));
        let known_ip = match &found {
            Some(Ok(found)) => Some(found.address),
            _ => self.view.public_ip,
        };
        // Blocks this thread for those names' lookups only, up to a few
        // seconds per resolver asked (a name the new resolvers can't answer
        // and nothing knows is asked through the old ones too): known names
        // aren't asked again.
        let resolved = names::check_save(
            Some(&self.view.config),
            old_ip,
            &config,
            public_ip::effective(&config.server, known_ip),
            &crate::lookup(&config.server),
            &self.view.names,
        )
        .map_err(|mut problems| {
            // Why a name at the home's public IP may have been refused.
            if let Some(Err(why)) = &found {
                problems.push(crate::public_ip_lookup_failed(why, self.view.public_ip));
            }
            refuse(anyhow!("{}", problems.join("; ")))
        })?;
        let learned = crate::Learned {
            public_ip: known_ip,
            names: resolved,
            tailnet: self.tailnet_for(&config),
        };
        crate::preview(&config, crate::today(), &learned).map_err(refuse)?;
        self.rt
            .block_on(self.store.save(&config))
            .map_err(|e| refuse(e.into()))?;
        if let Some(found) = found {
            if found.is_ok() {
                self.view.public_ip_set = self.view.public_ip_set.wrapping_add(1);
            }
            self.record_public_ip(found, source);
        }
        self.replace(config);
        self.set_names_from_save(learned.names, asked);
        self.publish();
        log(format!(
            "saved a change (configuration revision {})",
            self.view.revision
        ));
        Ok(())
    }

    fn restore(
        &mut self,
        path: &Path,
        passphrase: Option<Secret>,
        revision: u64,
        shown: &str,
    ) -> Result<Vec<String>, Reply> {
        if revision != self.view.revision {
            return Err(Reply::Conflict {
                revision: self.view.revision,
            });
        }
        match self.restore_inner(path, passphrase, shown) {
            Ok(lines) => {
                lines.iter().for_each(log);
                Ok(lines)
            }
            Err(e) => Err(Reply::Error {
                message: format!("{e:#}"),
            }),
        }
    }

    fn restore_inner(
        &mut self,
        path: &Path,
        passphrase: Option<Secret>,
        shown: &str,
    ) -> anyhow::Result<Vec<String>> {
        let manifest = backup::inspect(path)?;
        let server_file = &self.view.config.server.backup.passphrase_file;
        let key = match (&passphrase, manifest.encrypted) {
            (_, false) => None,
            (Some(given), true) => Some(given.clone()),
            (None, true) => {
                Some(crate::backup::read_passphrase(server_file)?.ok_or_else(|| {
                    anyhow!(
                        "backup {} is encrypted and no passphrase is set in {}",
                        path.display(),
                        server_file.display()
                    )
                })?)
            }
        };
        let contents = backup::open(path, key.as_ref())?;
        if contents.manifest.contents_sha256 != shown {
            bail!(
                "backup {} changed since it was shown; nothing restored. Run the restore again",
                path.display()
            );
        }
        let staging = TempDir::new_in(
            &crate::backup::private_dir_of(self.store.path())?,
            ".parallax-restore",
        )?;
        let before = Arc::clone(&self.view.config);
        let (rt, store) = (&self.rt, &mut self.store);
        let (lines, config) = rt.block_on(async {
            let (staged, restored) = crate::backup::stage(&contents, path, staging.path()).await?;
            let lines = crate::backup::restore_into(
                store,
                Some(&before),
                &contents,
                &staged,
                &restored,
                passphrase.as_ref(),
            )
            .await?;
            // The rows just copied in: what the database now holds.
            anyhow::Ok((lines, restored))
        })?;
        // What the restored configuration doesn't use, or asks other
        // resolvers for, goes; the lookups for those follow.
        let used = names::used(&config);
        let elsewhere = names::asked_on_save(Some(before.as_ref()), &config);
        let mut resolved = self.view.names.clone();
        resolved
            .retain(|name, _| used.contains(name.as_str()) && !elsewhere.contains(name.as_str()));
        self.replace(config);
        self.set_names_from_save(resolved, false);
        self.publish();
        Ok(lines)
    }

    /// Copy the database here, then hand the backup to the backup thread.
    /// The answer goes to `reply`, or to the log for the timer.
    fn backup(&mut self, if_due: bool, reply: Option<oneshot::Sender<Reply>>) {
        let taken = crate::backup::prepare(&self.view.config, if_due).and_then(|pending| {
            pending
                .map(|p| self.rt.block_on(p.take(&self.store)))
                .transpose()
        });
        match taken {
            // If the backup thread is gone, write it here rather than lose it.
            Ok(Some(taken)) => {
                if let Err(std::sync::mpsc::SendError(job)) = self.backups.send((taken, reply)) {
                    finish_backup(job);
                }
            }
            Ok(None) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Reply::Done { lines: Vec::new() });
                }
            }
            Err(e) => match reply {
                Some(reply) => {
                    let _ = reply.send(Reply::Error {
                        message: format!("{e:#}"),
                    });
                }
                None => warn(format!("warning: automatic backup failed: {e:#}")),
            },
        }
    }

    /// Take down what the last successful apply set up; nothing if none did.
    fn teardown(&self) {
        let Some(server) = &self.applied else {
            return;
        };
        for line in reconcile::teardown(server, sys()) {
            log(line);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test")]

    use super::*;

    #[test]
    fn the_router_backs_off_and_a_step_that_worked_ends_it() {
        // #78: a recovered router that changed something starts its
        // failures afresh, so one more error isn't the 15-minute wait.
        let mut pace = Pace::default();
        let waits: Vec<u64> = (0..6)
            .map(|_| pace.after(Looked::Failed).as_secs())
            .collect();
        assert_eq!(waits, [60, 120, 240, 480, 900, 900]);
        assert_eq!(pace.after(Looked::Changed), ROUTER_SOON);
        assert_eq!(pace.after(Looked::Failed).as_secs(), 60);
        // After a change: soon once, then the usual pace.
        let mut pace = Pace::default();
        assert_eq!(pace.after(Looked::Changed), ROUTER_SOON);
        assert_eq!(pace.after(Looked::Changed), ROUTER_EVERY);
        assert_eq!(pace.after(Looked::Changed), ROUTER_SOON);
        assert_eq!(pace.after(Looked::Fine), ROUTER_EVERY);
        // A new configuration starts afresh (`Pace::default()`), so the
        // look after its first change is the quick one again.
        let mut pace = Pace::default();
        assert_eq!(pace.after(Looked::Changed), ROUTER_SOON);
        pace = Pace::default();
        assert_eq!(pace.after(Looked::Changed), ROUTER_SOON);
    }
    use parallax_core::generate::proxy::ProxySite;

    /// `immich.mydomain.com` for `allowed`, or no site for none; neither
    /// needs a CA bundle loaded.
    fn routes(allowed: &[&str]) -> ProxyRoutes {
        ProxyRoutes {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificates: "/nonexistent/certs".into(),
            upstream_ca: "/nonexistent/ca.pem".into(),
            sites: (!allowed.is_empty())
                .then(|| ProxySite {
                    hostname: "immich.mydomain.com".into(),
                    service: "immich".into(),
                    upstream: "192.168.1.5:443".parse().unwrap(),
                    allowed: allowed.iter().map(|a| a.parse().unwrap()).collect(),
                })
                .into_iter()
                .collect(),
        }
    }

    fn engine_rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
    }

    /// A proxy that has stopped: anything sent to it fails.
    fn stopped() -> parallax_proxy::Reload {
        let proxy = parallax_proxy::Proxy::new(routes(&[])).unwrap();
        let reload = proxy.reloader();
        drop(proxy);
        reload
    }

    /// #71: a change that takes `immich` away has the running proxy drop it
    /// before anything live changes.
    #[test]
    fn the_proxy_takes_the_overlap_before_the_apply_goes_on() {
        let proxy_rt = tokio::runtime::Runtime::new().unwrap();
        // Sites would need a CA bundle; the engine's side is what's tested.
        let proxy = parallax_proxy::Proxy::new(routes(&[])).unwrap();
        let reload = proxy.reloader();
        let listener = proxy_rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        proxy_rt.spawn(proxy.run(listener));
        let mut served = Some(routes(&["10.8.2.1/32"]));
        let mut confirmed = true;
        narrow_proxy(
            &engine_rt(),
            Some(&reload),
            &mut served,
            &mut confirmed,
            &routes(&[]),
            &[],
        )
        .unwrap();
        assert_eq!(served, Some(routes(&[])));
    }

    /// Nothing to take away: the proxy isn't asked, so a stopped one
    /// doesn't stop the apply.
    #[test]
    fn an_unchanged_proxy_is_not_asked() {
        let mut served = Some(routes(&["10.8.2.1/32"]));
        let mut confirmed = true;
        let wider = routes(&["10.8.2.1/32", "10.8.3.0/24"]);
        narrow_proxy(
            &engine_rt(),
            Some(&stopped()),
            &mut served,
            &mut confirmed,
            &wider,
            &[],
        )
        .unwrap();
        assert_eq!(served, Some(routes(&["10.8.2.1/32"])));
    }

    /// A proxy that can't take the overlap stops the apply before anything
    /// else changes. The overlap is what it's recorded to serve next: a
    /// proxy that's slow, not stopped, still puts it in (#103).
    #[test]
    fn a_stopped_proxy_stops_the_apply() {
        let mut served = Some(routes(&["10.8.2.1/32"]));
        let mut confirmed = true;
        let err = narrow_proxy(
            &engine_rt(),
            Some(&stopped()),
            &mut served,
            &mut confirmed,
            &routes(&[]),
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("the HTTPS proxy has stopped"), "{err}");
        assert!(err.contains("weren't changed"), "{err}");
        assert_eq!(served, Some(routes(&[])));
        // Unconfirmed: a retry of the same change asks again, rather than
        // taking an overlap it was never told is in force (#103).
        assert!(!confirmed);
        narrow_proxy(
            &engine_rt(),
            Some(&stopped()),
            &mut served,
            &mut confirmed,
            &routes(&[]),
            &[],
        )
        .unwrap_err();
    }

    /// #104: routes that differ only in order aren't a change to narrow.
    #[test]
    fn reordered_routes_are_not_narrowed() {
        let mut served = Some(routes(&["10.8.2.1/32", "10.8.3.0/24"]));
        let mut confirmed = true;
        let reordered = routes(&["10.8.3.0/24", "10.8.2.1/32"]);
        narrow_proxy(
            &engine_rt(),
            Some(&stopped()),
            &mut served,
            &mut confirmed,
            &reordered,
            &[],
        )
        .unwrap();
    }

    /// #103: after a good apply, routes the proxy can't load fail it (the
    /// next tick tries again), and routes it loads don't.
    #[test]
    fn the_full_routes_must_load() {
        let proxy_rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = parallax_proxy::Proxy::new(routes(&[])).unwrap();
        let reload = proxy.reloader();
        let listener = proxy_rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        proxy_rt.spawn(proxy.run(listener));
        // A site needs the CA bundle, and `/nonexistent/ca.pem` isn't there.
        let mut served = Some(routes(&[]));
        let err = widen_proxy(&engine_rt(), &reload, &mut served, routes(&["10.8.2.1/32"]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("couldn't load its new routes"), "{err}");
        assert!(err.contains("ca.pem"), "{err}");
        // #114: recorded as serving nothing, not the routes that didn't load.
        assert_eq!(served, Some(routes(&[])));
        let mut empty = routes(&[]);
        empty.upstream_ca = "/elsewhere/ca.pem".into();
        widen_proxy(&engine_rt(), &reload, &mut served, empty.clone()).unwrap();
        assert_eq!(served, Some(empty));
        let err = widen_proxy(&engine_rt(), &stopped(), &mut served, routes(&[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("stopped"), "{err}");
    }

    /// #114: narrowed routes the proxy can't load leave it serving nothing,
    /// which is what's recorded; the apply goes on, since nothing is less
    /// than either.
    #[test]
    fn narrowed_routes_that_fail_to_load_are_recorded_as_nothing() {
        let proxy_rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = parallax_proxy::Proxy::new(routes(&[])).unwrap();
        let reload = proxy.reloader();
        let listener = proxy_rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        proxy_rt.spawn(proxy.run(listener));
        // The overlap keeps a site, which needs the missing CA bundle.
        let mut served = Some(routes(&["10.8.2.1/32", "10.8.3.0/24"]));
        let mut confirmed = true;
        narrow_proxy(
            &engine_rt(),
            Some(&reload),
            &mut served,
            &mut confirmed,
            &routes(&["10.8.2.1/32"]),
            &[],
        )
        .unwrap();
        assert_eq!(served, Some(routes(&[])));
        assert!(confirmed);
    }

    /// #115: an address changing hands is narrowed away, though both
    /// routes allow it.
    #[test]
    fn a_moved_address_is_narrowed_away() {
        let proxy_rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = parallax_proxy::Proxy::new(routes(&[])).unwrap();
        let reload = proxy.reloader();
        let listener = proxy_rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        proxy_rt.spawn(proxy.run(listener));
        let mut served = Some(routes(&["10.8.2.1/32"]));
        let mut confirmed = true;
        narrow_proxy(
            &engine_rt(),
            Some(&reload),
            &mut served,
            &mut confirmed,
            &routes(&["10.8.2.1/32"]),
            &["10.8.2.1".parse().unwrap()],
        )
        .unwrap();
        assert_eq!(served, Some(routes(&[])));
    }

    /// The proxy task ended (the daemon aborts it on shutdown): its reloader
    /// went with it, so nothing is confirmed.
    #[test]
    fn a_proxy_task_that_ended_confirms_nothing() {
        let proxy_rt = tokio::runtime::Runtime::new().unwrap();
        let proxy = parallax_proxy::Proxy::new(routes(&[])).unwrap();
        let reload = proxy.reloader();
        let listener = proxy_rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
        let task = proxy_rt.spawn(proxy.run(listener));
        // Running: it confirms.
        let mut served = Some(routes(&["10.8.2.1/32"]));
        let mut confirmed = true;
        narrow_proxy(
            &engine_rt(),
            Some(&reload),
            &mut served,
            &mut confirmed,
            &routes(&[]),
            &[],
        )
        .unwrap();
        task.abort();
        let _ = proxy_rt.block_on(task);
        let mut served = Some(routes(&["10.8.2.1/32"]));
        let mut confirmed = true;
        narrow_proxy(
            &engine_rt(),
            Some(&reload),
            &mut served,
            &mut confirmed,
            &routes(&[]),
            &[],
        )
        .unwrap_err();
    }

    /// Routes where `personal` (10.8.1.1) has the whole zone and public
    /// names, and `family` (10.8.2.1) only immich, `members` of each.
    fn dns_routes(personal: &[&str], family: &[&str]) -> DnsRoutes {
        let tier =
            |name: &str, members: &[&str], whole: bool| parallax_core::generate::dns::DnsTier {
                tier: name.into(),
                members: members.iter().map(|m| m.parse().unwrap()).collect(),
                zones: if whole {
                    vec!["mydomain.com".into()]
                } else {
                    Vec::new()
                },
                names: if whole {
                    Vec::new()
                } else {
                    vec!["immich.mydomain.com".into()]
                },
                public: whole,
            };
        DnsRoutes {
            listen: "127.0.0.1:0".parse().unwrap(),
            public_resolver: "127.0.0.1".parse().unwrap(),
            unmapped: Vec::new(),
            zones: vec![parallax_core::generate::dns::DnsZone {
                name: "mydomain.com".into(),
                network: "home".into(),
                upstream: vec!["127.0.0.1".parse().unwrap()],
            }],
            mappings: Vec::new(),
            tiers: vec![
                tier("personal", personal, true),
                tier("family", family, false),
            ],
        }
    }

    /// A DNS server running on `rt`, answering by `routes`.
    fn running_dns(
        rt: &tokio::runtime::Runtime,
        routes: DnsRoutes,
    ) -> (parallax_dns::Reload, tokio::task::JoinHandle<()>) {
        let dns = parallax_dns::Dns::new(routes, 53).unwrap();
        let reload = dns.reloader();
        let (udp, tcp) = rt.block_on(async {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let tcp = TcpListener::bind(udp.local_addr().unwrap()).await.unwrap();
            (udp, tcp)
        });
        let task = rt.spawn(async move {
            let _ = dns.run(udp, tcp).await;
        });
        (reload, task)
    }

    /// #37: 10.8.1.1 moves from `personal` to `family`. Before anything
    /// live changes, the DNS server answers it only what both give it.
    #[test]
    fn the_dns_server_takes_the_overlap_before_the_apply_goes_on() {
        let dns_rt = tokio::runtime::Runtime::new().unwrap();
        let before = dns_routes(&["10.8.1.1/32"], &["10.8.2.1/32"]);
        let (reload, _task) = running_dns(&dns_rt, before.clone());
        let after = dns_routes(&[], &["10.8.1.1/32", "10.8.2.1/32"]);
        let mut served = Some(before);
        narrow_dns(&engine_rt(), Some(&reload), &mut served, &after).unwrap();
        let both = served.unwrap();
        let client = "10.8.1.1".parse().unwrap();
        assert!(matches!(
            both.route(client, "immich.mydomain.com"),
            parallax_core::generate::dns::Route::Home {
                whole_zone: false,
                ..
            }
        ));
        assert_eq!(
            both.route(client, "nas.mydomain.com"),
            parallax_core::generate::dns::Route::Refused
        );
        assert_eq!(
            both.route(client, "example.org"),
            parallax_core::generate::dns::Route::Refused
        );
    }

    /// Nothing changes for anyone: a stopped DNS server isn't asked.
    #[test]
    fn unchanged_dns_routes_are_not_handed_over() {
        let dns_rt = tokio::runtime::Runtime::new().unwrap();
        let before = dns_routes(&["10.8.1.1/32"], &["10.8.2.1/32"]);
        let (reload, task) = running_dns(&dns_rt, before.clone());
        task.abort();
        let _ = dns_rt.block_on(task);
        let mut served = Some(before.clone());
        narrow_dns(&engine_rt(), Some(&reload), &mut served, &before).unwrap();
        assert_eq!(served, Some(before));
    }

    /// A DNS server that stopped (its task ended) confirms nothing: the
    /// apply stops before anything changes, and the routes stay.
    #[test]
    fn a_stopped_dns_server_stops_the_apply() {
        let dns_rt = tokio::runtime::Runtime::new().unwrap();
        let before = dns_routes(&["10.8.1.1/32"], &["10.8.2.1/32"]);
        let (reload, task) = running_dns(&dns_rt, before.clone());
        task.abort();
        let _ = dns_rt.block_on(task);
        let after = dns_routes(&[], &["10.8.1.1/32", "10.8.2.1/32"]);
        let mut served = Some(before.clone());
        let err = narrow_dns(&engine_rt(), Some(&reload), &mut served, &after)
            .unwrap_err()
            .to_string();
        assert!(err.contains("the DNS server couldn't take"), "{err}");
        assert_eq!(served, Some(before));
    }
}
