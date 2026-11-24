//! `parallax daemon`: the gateway as one long-running process.
//!
//! It holds the database (no other process can open it meanwhile), keeps
//! the configuration in memory, and applies it: at startup, after every
//! saved change, on SIGHUP, when the UTC date changes, and when the live
//! firewall or WireGuard interface drifts. The DNS server and the HTTPS
//! proxy run as tasks and re-read their routes after each apply. The CLI
//! talks to it over a Unix socket ([`crate::protocol`]).
//!
//! One engine thread owns the database and does everything that changes
//! state (saves, applies, backups), one batch at a time: requests that
//! arrive during an apply queue up, and a batch of them shares one apply.
//! It runs off the async threads, so blocking work (`nft`, `wg`, `ip`,
//! backup encryption) never stalls DNS or the proxy. Reads (`status`,
//! `load`) are answered from the last published view without waiting.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use parallax_core::generate;
use parallax_core::io::real::{RealFs, RealRunner};
use parallax_core::io::System;
use parallax_core::model::ServerConfig;
use parallax_core::reconcile::{self, Reconciler};
use parallax_core::secret::Secret;
use parallax_core::Config;
use parallax_store::{backup, Store, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket, UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::protocol::{self, Reply, Request};

/// How `parallax daemon` was started.
#[derive(Debug)]
pub struct Options {
    pub db: PathBuf,
    pub socket: PathBuf,
    pub out: PathBuf,
    /// Between checks for drift and a new day.
    pub reconcile_every: Duration,
}

/// How often automatic backups are looked at; `backup create --if-due`
/// decides whether one is due.
const BACKUP_EVERY: Duration = Duration::from_secs(600);
/// How long a client may take to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn log(msg: impl std::fmt::Display) {
    println!("parallax: {msg}");
}

fn warn(msg: impl std::fmt::Display) {
    eprintln!("parallax: {msg}");
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
}

/// Work for the engine thread.
enum Msg {
    Request(Request, oneshot::Sender<Reply>),
    Hangup,
    Tick,
    BackupTick,
    /// The DNS server and the proxy are up: notify these after each apply.
    Serving(Vec<Arc<Notify>>),
    Shutdown,
}

type Views = watch::Receiver<Option<View>>;

pub fn run(opts: Options) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?
        .block_on(serve(opts))
}

async fn serve(opts: Options) -> anyhow::Result<()> {
    // First: from here on SIGHUP re-applies instead of ending the process.
    let mut hangup = signal(SignalKind::hangup()).context("watching SIGHUP")?;
    let mut terminate = signal(SignalKind::terminate()).context("watching SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("watching SIGINT")?;

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
    let started = async {
        let servers = start_servers(&opts.out).await?;
        let listener = bind_socket(&opts.socket)?;
        anyhow::Ok((servers, listener))
    }
    .await;
    let ((mut dns, mut proxy, reloaders), listener) = match started {
        Ok(started) => started,
        Err(e) => {
            stop_engine(&tx, &mut done_rx).await;
            return Err(e);
        }
    };
    let _ = tx.send(Msg::Serving(reloaders));
    let server = tokio::spawn(accept(listener, tx.clone(), views));
    let timers = tokio::spawn(timers(tx.clone(), opts.reconcile_every));
    log(format!(
        "gateway up; listening for commands on {}. Saved changes apply at once; SIGHUP re-applies",
        opts.socket.display()
    ));

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
    if let Err(e) = std::fs::remove_file(&opts.socket) {
        warn(format!("could not remove {}: {e}", opts.socket.display()));
    }
    dns.abort();
    proxy.abort();
    if engine_alive {
        stop_engine(&tx, &mut done_rx).await;
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
async fn start_servers(out: &Path) -> anyhow::Result<Servers> {
    let dns = parallax_dns::Dns::load(&out.join(generate::dns::PATH), 53)?;
    let listen = dns.listen();
    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("the DNS server can't listen on udp {listen}"))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("the DNS server can't listen on tcp {listen}"))?;
    let proxy = parallax_proxy::Proxy::load(&out.join(generate::proxy::PATH))?;
    let listen = proxy.listen();
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("the HTTPS proxy can't listen on {listen}"))?;
    let reloaders = vec![dns.reload_trigger(), proxy.reload_trigger()];
    let dns = tokio::spawn(async move { Ok(dns.run(udp, tcp).await?) });
    let proxy = tokio::spawn(async move { Ok(proxy.run(listener).await?) });
    Ok((dns, proxy, reloaders))
}

/// Listen on `path`: directory 0700 when it's made here, socket 0600.
/// Called while the engine holds the database, so a socket file already
/// there belongs to a daemon that's gone.
fn bind_socket(path: &Path) -> anyhow::Result<UnixListener> {
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
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)
            .with_context(|| format!("removing the stale socket {}", path.display()))?,
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
    Ok(listener)
}

async fn accept(listener: UnixListener, tx: mpsc::UnboundedSender<Msg>, views: Views) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(answer(stream, tx.clone(), views.clone()));
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
async fn answer(stream: UnixStream, tx: mpsc::UnboundedSender<Msg>, views: Views) {
    let (read, mut write) = stream.into_split();
    let reply = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(read)).await {
        Err(_) => return,
        Ok(Err(e)) => Reply::Error {
            message: format!("{e:#}"),
        },
        Ok(Ok(request)) => dispatch(request, &tx, &views).await,
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

async fn read_request(read: tokio::net::unix::OwnedReadHalf) -> anyhow::Result<Request> {
    let mut reader = tokio::io::BufReader::new(read.take(protocol::MAX_MESSAGE as u64));
    let mut line = Vec::new();
    reader
        .read_until(b'\n', &mut line)
        .await
        .context("reading the request")?;
    protocol::check_line(&line)?;
    protocol::decode(&line)
}

async fn dispatch(request: Request, tx: &mpsc::UnboundedSender<Msg>, views: &Views) -> Reply {
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
        },
        Request::Load => Reply::Configuration {
            configuration: Box::new((*view.config).clone()),
            revision: view.revision,
        },
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

fn engine_thread(
    db: &Path,
    out: PathBuf,
    publish: watch::Sender<Option<View>>,
    mut rx: mpsc::UnboundedReceiver<Msg>,
    ready: oneshot::Sender<anyhow::Result<()>>,
) {
    let mut engine = match Engine::start(db, out, publish) {
        Ok(engine) => engine,
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };
    if let Err(e) = engine.first_apply() {
        engine.teardown();
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
    reloaders: Vec<Arc<Notify>>,
}

impl Engine {
    fn start(
        db: &Path,
        out: PathBuf,
        publish: watch::Sender<Option<View>>,
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
        let engine = Engine {
            rt,
            store,
            view: View {
                config: Arc::new(config),
                revision: 0,
                apply_error: None,
            },
            publish,
            out,
            reconciler: Reconciler::new(),
            applied: None,
            reloaders: Vec::new(),
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
        // Requests answered after the apply, with their own lines first.
        let mut waiting: Vec<(oneshot::Sender<Reply>, Vec<String>)> = Vec::new();
        let mut why: Option<&str> = None;
        let (mut tick, mut backup_due, mut shutdown) = (false, false, false);
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
                    } => match self.restore(&path, passphrase, revision) {
                        Ok(lines) => {
                            waiting.push((reply, lines));
                            why.get_or_insert("a restored backup");
                        }
                        Err(refused) => {
                            let _ = reply.send(refused);
                        }
                    },
                    Request::BackupCreate { if_due } => {
                        let answer = match self.backup(if_due) {
                            Ok(lines) => Reply::Done { lines },
                            Err(e) => Reply::Error {
                                message: format!("{e:#}"),
                            },
                        };
                        let _ = reply.send(answer);
                    }
                    // Answered from the view by the socket task.
                    Request::Status | Request::Load => {
                        let _ = reply.send(Reply::Error {
                            message: "status and load aren't queued".into(),
                        });
                    }
                },
                Msg::Hangup => {
                    why.get_or_insert("SIGHUP");
                }
                Msg::Tick => tick = true,
                Msg::BackupTick => backup_due = true,
                Msg::Serving(reloaders) => self.reloaders = reloaders,
                Msg::Shutdown => shutdown = true,
            }
        }
        if shutdown {
            for (reply, log) in waiting {
                let _ = reply.send(Reply::Applied {
                    revision: self.view.revision,
                    log,
                    error: Some(
                        "the daemon shut down first; the change is saved and applies when it starts again"
                            .into(),
                    ),
                });
            }
            return true;
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
            match self.backup(true) {
                Ok(lines) => lines.iter().for_each(log),
                Err(e) => warn(format!("warning: automatic backup failed: {e:#}")),
            }
        }
        false
    }

    /// Apply the configuration. Returns the log, and why it failed.
    fn apply(&mut self, why: &str) -> (Vec<String>, Option<String>) {
        log(format!("applying ({why})"));
        let today = crate::today();
        match crate::apply_config(&self.view.config, &self.out, today) {
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

    fn set_apply_error(&mut self, error: Option<String>) {
        if self.view.apply_error != error {
            self.view.apply_error = error;
            self.publish();
        }
    }

    /// The configuration changed: remember and publish it.
    fn replace(&mut self, config: Config) {
        self.view.config = Arc::new(config);
        self.view.revision += 1;
        self.publish();
    }

    /// Validate, generate and check certificates; only then save. Returns
    /// the reply refusing the change. Warnings come with the apply that follows.
    fn save(&mut self, config: Config, revision: u64) -> Result<(), Reply> {
        if revision != self.view.revision {
            return Err(Reply::Conflict {
                revision: self.view.revision,
            });
        }
        let refuse = |e: anyhow::Error| Reply::Error {
            message: format!("{e:#}"),
        };
        crate::preview(&config, crate::today()).map_err(refuse)?;
        self.rt
            .block_on(self.store.save(&config))
            .map_err(|e| refuse(e.into()))?;
        self.replace(config);
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
    ) -> Result<Vec<String>, Reply> {
        if revision != self.view.revision {
            return Err(Reply::Conflict {
                revision: self.view.revision,
            });
        }
        match self.restore_inner(path, passphrase) {
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
            anyhow::Ok((lines, store.load().await?))
        })?;
        self.replace(config);
        Ok(lines)
    }

    fn backup(&mut self, if_due: bool) -> anyhow::Result<Vec<String>> {
        self.rt.block_on(crate::backup::create(
            &self.store,
            &self.view.config,
            if_due,
        ))
    }

    /// Take down what the last successful apply set up (or, if none
    /// worked, what the configuration names).
    fn teardown(&self) {
        let server = self.applied.as_ref().unwrap_or(&self.view.config.server);
        for line in reconcile::teardown(server, sys()) {
            log(line);
        }
    }
}
