//! `parallax daemon`: the gateway as one long-running process.
//!
//! It holds the database (no other process can open it meanwhile), keeps
//! the configuration in memory, and applies it: at startup, after every
//! saved change, on SIGHUP, when the UTC date changes, and when the live
//! firewall or WireGuard interface drifts. The DNS server and the HTTPS
//! proxy run as tasks and re-read their routes after each apply. The CLI
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
use tokio::sync::{mpsc, oneshot, watch, Notify};
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
    /// The home's public IP as last found.
    public_ip: Option<Ipv4Addr>,
    /// What each host named by DNS name last resolved to.
    names: Resolved,
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
    /// The DNS server and the proxy are up: notify these after each apply.
    Serving(Vec<Arc<Notify>>),
    /// A lookup of the home's public IP finished, for these inputs.
    PublicIp(Inputs, Result<Found, Vec<String>>),
    /// The named hosts were looked up, for these inputs.
    Names(NameInputs, Refreshed),
    /// Headscale was asked for its nodes, for these inputs.
    Tailnet(TailnetInputs, Result<Option<Tailnet>, String>),
    Shutdown,
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
    match ready_rx.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => bail!("the engine stopped during startup"),
    }

    let mut engine_alive = true;
    let taps = collector::Taps::new();
    let started = async {
        let servers = start_servers(&opts.out, &taps).await?;
        let listener = bind_socket(&opts.socket)?;
        anyhow::Ok((servers, listener))
    }
    .await;
    let ((mut dns, mut proxy, reloaders), (listener, socket_id)) = match started {
        Ok(started) => started,
        Err(e) => {
            stop_engine(&tx, &mut done_rx).await;
            return Err(e);
        }
    };
    let _ = tx.send(Msg::Serving(reloaders));
    let refresher = tokio::spawn(refresh_public_ip(tx.clone(), views.clone()));
    let names = tokio::spawn(refresh_names(tx.clone(), views.clone()));
    let tailnet = tokio::spawn(refresh_tailnet(tx.clone(), views.clone()));
    let router = tokio::spawn(keep_router(views.clone(), opts.tailscale_socket.clone()));
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
    router.abort();
    // Only our own: another daemon may have bound the path since.
    if file_id(&opts.socket) == Some(socket_id) {
        if let Err(e) = std::fs::remove_file(&opts.socket) {
            warn(format!("could not remove {}: {e}", opts.socket.display()));
        }
    }
    dns.abort();
    proxy.abort();
    if engine_alive {
        stop_engine(&tx, &mut done_rx).await;
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

/// Ask the engine to tear the gateway down, and wait until it has.
async fn stop_engine(tx: &mpsc::UnboundedSender<Msg>, done: &mut oneshot::Receiver<()>) {
    if tx.send(Msg::Shutdown).is_ok() {
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
    Vec<Arc<Notify>>,
);

/// Start the DNS server and the HTTPS proxy on the routes the first apply
/// wrote. Both listen on the gateway address, which the WireGuard interface
/// carries since that apply.
async fn start_servers(out: &Path, taps: &collector::Taps) -> anyhow::Result<Servers> {
    let dns = parallax_dns::Dns::load(&out.join(generate::dns::PATH), 53)?.tap(taps.dns.clone());
    let listen = dns.listen();
    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("the DNS server can't listen on udp {listen}"))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("the DNS server can't listen on tcp {listen}"))?;
    let proxy =
        parallax_proxy::Proxy::load(&out.join(generate::proxy::PATH))?.tap(taps.proxy.clone());
    let listen = proxy.listen();
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("the HTTPS proxy can't listen on {listen}"))?;
    let reloaders = vec![dns.reload_trigger(), proxy.reload_trigger()];
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

/// What a public IP lookup depends on: a change to any of it looks again,
/// and a result for other inputs than the current ones is stale.
type Inputs = (bool, String, Ipv4Addr, PublicIpServer, PathBuf);

fn lookup_inputs(config: &Config) -> Inputs {
    (
        public_ip::needed(config),
        config.server.wireguard.endpoint.clone(),
        config.server.dns.public_resolver,
        config.server.public_ip.clone(),
        config.server.proxy.upstream_ca.clone(),
    )
}

/// Look up the home's public IP every [`PUBLIC_IP_EVERY`], and when a saved
/// change alters what the lookup depends on. Startup has just looked. The
/// lookup blocks for seconds, so it runs here, never on the engine thread.
async fn refresh_public_ip(tx: mpsc::UnboundedSender<Msg>, mut views: Views) {
    let mut every = tokio::time::interval(PUBLIC_IP_EVERY);
    every.set_missed_tick_behavior(MissedTickBehavior::Delay);
    every.tick().await;
    let inputs = |views: &Views| views.borrow().as_ref().map(|v| lookup_inputs(&v.config));
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
        let Some(config) = config.filter(|c| public_ip::needed(c)) else {
            continue;
        };
        let asked = lookup_inputs(&config);
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
/// resolvers to ask and which answers are allowed, and the home's public
/// IP (an answer may be it).
type NameInputs = (Vec<String>, Vec<Network>, Option<Ipv4Addr>);

fn name_inputs(view: &View) -> NameInputs {
    (
        names::used(&view.config)
            .into_iter()
            .map(str::to_string)
            .collect(),
        view.config.networks.clone(),
        public_ip::effective(&view.config.server, view.public_ip),
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
async fn keep_router(mut views: Views, socket: String) {
    let config = |views: &Views| views.borrow().as_ref().map(|v| Arc::clone(&v.config));
    let mut last = config(&views);
    let mut said: Option<String> = None;
    let mut wait = Duration::ZERO;
    let mut failures: u32 = 0;
    // The last look was the quick one after a change.
    let mut quick = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            changed = views.changed() => {
                if changed.is_err() {
                    return;
                }
                // Every apply publishes; only a new configuration counts.
                if config(&views) == last {
                    continue;
                }
                failures = 0;
            }
        }
        wait = ROUTER_EVERY;
        last = config(&views);
        let Some(config) = last.clone() else {
            continue;
        };
        if !subnet_router::needed(&config) {
            // Nothing to report: the machine may have no Tailscale at all.
            said = None;
        }
        let socket = socket.clone();
        let Ok(looked) =
            tokio::task::spawn_blocking(move || crate::sync_router(&config, &socket)).await
        else {
            continue;
        };
        let note = match looked {
            Ok((done, _)) if !done.is_empty() => {
                done.iter().for_each(log);
                // Once more soon (a router that just logged in gets its
                // routes approved), then the usual pace.
                quick = !quick;
                if quick {
                    wait = ROUTER_SOON;
                }
                continue;
            }
            Ok((_, note)) => {
                (failures, quick) = (0, false);
                note
            }
            Err(e) => {
                quick = false;
                failures = failures.saturating_add(1);
                wait = (ROUTER_EVERY * 2u32.saturating_pow(failures.min(5))).min(ROUTER_BACKOFF);
                Some(e)
            }
        };
        if note != said {
            match &note {
                Some(note) => warn(format!("subnet router: {note}")),
                None => log("subnet router: in place"),
            }
            said = note;
        }
    }
}

fn engine_thread(
    db: &Path,
    out: PathBuf,
    publish: watch::Sender<Option<View>>,
    mut rx: mpsc::UnboundedReceiver<Msg>,
    ready: oneshot::Sender<anyhow::Result<()>>,
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
        engine.note_public_ip(found);
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
    let _ = ready.send(Ok(()));
    while let Some(first) = rx.blocking_recv() {
        let mut batch = vec![first];
        while let Ok(msg) = rx.try_recv() {
            batch.push(msg);
        }
        if engine.handle(batch) {
            break;
        }
    }
    engine.teardown();
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
    reloaders: Vec<Arc<Notify>>,
    /// Why the last public IP lookup failed, so the same failure is
    /// logged once, not every 5 minutes.
    public_ip_problems: Option<Vec<String>>,
    /// The database holds `view.public_ip`; false after a failed write, so
    /// the next lookup writes it again.
    public_ip_saved: bool,
    /// Why the last name lookups failed, logged once.
    name_problems: Vec<String>,
    /// Why Headscale didn't answer last time, logged once.
    tailnet_problem: Option<String>,
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
                public_ip,
                // Looked up right after the first apply: an answer from
                // before a restart may be stale.
                names: Resolved::new(),
                // Asked before the first apply.
                tailnet: None,
            },
            publish,
            out,
            reconciler: Reconciler::new(),
            applied: None,
            reloaders: Vec::new(),
            backups,
            public_ip_problems: None,
            public_ip_saved: true,
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

    /// Handle a batch of work. Returns true to shut down.
    fn handle(&mut self, batch: Vec<Msg>) -> bool {
        // Shutting down: change nothing, refuse whatever else is queued.
        if batch.iter().any(|m| matches!(m, Msg::Shutdown)) {
            for msg in batch {
                if let Msg::Request(_, reply) = msg {
                    let _ = reply.send(shutting_down());
                }
            }
            return true;
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
                Msg::Serving(reloaders) => self.reloaders = reloaders,
                // A save changed the inputs while this lookup ran: the
                // lookup for the new ones is already on its way.
                Msg::PublicIp(asked, _) if asked != lookup_inputs(&self.view.config) => {}
                Msg::PublicIp(_, found) => {
                    let server = &self.view.config.server;
                    let before = public_ip::effective(server, self.view.public_ip);
                    self.note_public_ip(found);
                    let server = &self.view.config.server;
                    if public_ip::effective(server, self.view.public_ip) != before {
                        why.get_or_insert("the home's public IP changed");
                    }
                }
                // The names, their resolvers or the networks changed while
                // these lookups ran: the lookups for the new ones are coming.
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
                Msg::Shutdown => {}
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
        false
    }

    /// Apply the configuration. Returns the log, and why it failed.
    fn apply(&mut self, why: &str) -> (Vec<String>, Option<String>) {
        log(format!("applying ({why})"));
        let today = crate::today();
        match crate::apply_config(&self.view.config, &self.out, today, &self.view.learned()) {
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
                for reload in &self.reloaders {
                    reload.notify_one();
                }
                self.set_apply_error(None);
                (lines, None)
            }
            Err(e) => {
                let e = format!("{e:#}");
                warn(format!("apply failed, trying again in a minute: {e}"));
                self.reconciler.failed();
                self.set_apply_error(Some(e.clone()));
                (Vec::new(), Some(e))
            }
        }
    }

    /// Take a lookup's result: a new address is published and remembered
    /// in the database; a failure is logged once.
    fn note_public_ip(&mut self, found: Result<Found, Vec<String>>) {
        match found {
            Ok(found) => {
                self.public_ip_problems = None;
                let changed = self.view.public_ip != Some(found.address);
                if changed {
                    log(format!(
                        "the home's public IP is {} (from {})",
                        found.address, found.source
                    ));
                    self.view.public_ip = Some(found.address);
                    self.publish();
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
            }
            Err(problems) => {
                if self.public_ip_problems.as_ref() != Some(&problems) {
                    warn(format!(
                        "warning: {}",
                        crate::public_ip_lookup_failed(&problems, self.view.public_ip)
                    ));
                    self.public_ip_problems = Some(problems);
                }
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

    /// Publish what the names resolve to now. Returns whether it changed.
    fn set_names(&mut self, resolved: Resolved) -> bool {
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
        self.publish();
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

    /// The configuration changed: remember and publish it. Addresses from
    /// another Headscale than the new one's are forgotten.
    fn replace(&mut self, config: Config) {
        self.view.tailnet = self.tailnet_for(&config);
        self.view.config = Arc::new(config);
        self.view.revision = self.view.revision.wrapping_add(1);
        self.publish();
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
        // A name may point at the home's public IP. Nothing looked for it
        // while nothing needed it, so look before telling where a new name
        // points (a few seconds at most, and only then).
        let had = names::used(&self.view.config);
        if names::used(&config).iter().any(|n| !had.contains(n))
            && public_ip::effective(&config.server, self.view.public_ip).is_none()
        {
            self.note_public_ip(crate::find_public_ip(&config.server));
        }
        // Blocks this thread for a new name's lookup only (a few seconds at
        // most): known names aren't asked again.
        let resolved = names::check_save(
            Some(&self.view.config),
            public_ip::effective(&self.view.config.server, self.view.public_ip),
            &config,
            public_ip::effective(&config.server, self.view.public_ip),
            &crate::lookup(&config.server),
            &self.view.names,
        )
        .map_err(|problems| refuse(anyhow!("{}", problems.join("; "))))?;
        let learned = crate::Learned {
            public_ip: self.view.public_ip,
            names: resolved,
            tailnet: self.tailnet_for(&config),
        };
        crate::preview(&config, crate::today(), &learned).map_err(refuse)?;
        self.rt
            .block_on(self.store.save(&config))
            .map_err(|e| refuse(e.into()))?;
        self.replace(config);
        self.set_names(learned.names);
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
        // What the restored configuration doesn't use goes; the lookups for
        // what it adds follow.
        let used = names::used(&config);
        let mut resolved = self.view.names.clone();
        resolved.retain(|name, _| used.contains(name.as_str()));
        self.replace(config);
        self.set_names(resolved);
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
