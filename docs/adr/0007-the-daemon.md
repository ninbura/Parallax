# ADR 0007: The daemon

Status: accepted (step 7). Changes the concurrency part of ADR 0005. Its
rejection of MVCC is reversed by ADR 0011.

## Decision

`parallax daemon` is the gateway: one long-running process that holds the
database, keeps the configuration in memory and keeps it applied. The
container's entrypoint does its first-start work (import, `doctor`,
`keygen`, `tailscaled`) and then `exec`s it. The CLI talks to it over a Unix
socket.

- **One process owns the database.** It opens it in Turso's default,
  single-process mode (the file is locked to one process; the multi-process
  WAL mode of ADR 0005 is gone). A second daemon fails on that lock before
  it touches anything; one for another database refuses a socket a daemon
  already answers on, and a daemon removes only the socket it bound.
- **Everything runs inside it.** The DNS server and the HTTPS proxy are tasks
  in its runtime, not separate processes; `parallax dns` and `parallax
  proxy` are gone. The DNS server still reads the routes file `apply`
  writes, and the daemon tells it to re-read after each successful apply
  (no SIGHUP). Generated files are written aside and renamed into place, so
  a reload never reads half a file while the next apply writes.
  *Amended (issue #71):* the daemon hands the proxy its routes itself, with
  no file. Before an apply changes anything live, the proxy gets only what
  the old and the new routes both grant, and the daemon waits until it
  serves them. It gets the new routes in full once the apply has worked.
  *Amended (issues #102, #103):* the daemon records the narrowed routes as
  served even when the wait fails, since the proxy puts routes in force in
  the order sent, and waits for them again on the next try; new routes that don't load after an apply count as a
  failed apply, retried like any other. When the proxy stops, its open
  connections close instead of keeping their last routes.
  *Amended (issue #37):* the DNS server gets its routes the same way. Before
  an apply changes anything live, each member is answered only what both
  routes let it look up, so an address moving to another peer answers
  neither owner's names beyond that while WireGuard may give it to either.
  The activity log goes by the last configuration that applied, and logs
  nothing from an address the saved configuration gives to another peer.
  A failed reload still refuses everything until one works. If either task
  stops, the daemon exits non-zero and Docker's restart policy takes over.
  Automatic backups (`backup create --if-due` every 10 minutes) run inside
  it too, on its open database.
- **The reconcile loop applies one at a time.** It applies at startup, right
  after a saved change, on SIGHUP, when the UTC date changes (peer expiry is
  in UTC days), and when the live state drifts: after each apply it lists
  the nftables table and the WireGuard interface (`nft -s list table`, `wg
  show ... allowed-ips`, the address, its own DOCKER-USER accepts), and
  every 60 s it lists them again
  and re-applies only on a difference. A failed apply is retried on the next
  tick. Requests that arrive during an apply queue up and share the next one.
  The decision logic (`parallax_core::reconcile`) takes the date and the
  listing as inputs, so it's tested without timers.
- **Saves are checked before they're written.** A change is validated,
  generated and certificate-checked first; only then is it saved, and then
  applied. If the apply fails, the change stays saved, the caller sees the
  error, and the loop retries.
- **One writer, in order.** A dedicated engine thread owns the database and
  does everything that changes state (saves, applies, restores), so blocking
  work (`nft`, `wg`, `ip`) never stalls DNS or the proxy. Only that has to
  go one at a time: the nft table and the interface are one global state,
  and each save is validated against the whole configuration. Reads
  (`status`, `load`) are answered from memory without waiting for an apply.
  A backup holds the engine only for the database copy (milliseconds); its
  encryption, writing and rotation run on a backup thread of their own, so
  a save never waits behind one. A restore's undo backup stays in line.
- **The socket** is `/run/parallax/parallax.sock` (`--socket`,
  `PARALLAX_SOCKET`): directory 0700, socket 0600, owned by the daemon's
  user. One JSON request and one JSON reply per connection, each a single
  line of at most 16 MiB, each carrying `protocol` (2 since the home's
  public IP joined the replies, ADR 0008); a mismatch is refused
  naming both versions. Requests also name the database the caller means
  (`--db`); a daemon holding another one refuses them. Requests: `status`, `load`, `save` (a whole
  configuration plus the revision it was based on), `apply`,
  `backup_create`, `backup_restore`. Private keys and a backup passphrase
  cross it; it's root-only, and nothing logs a message.
- **Conflicts by revision.** The daemon counts saves in memory, from a
  random start, so a revision read before a restart never matches after it. A `save`
  based on an older revision is refused; `peer add` and friends load,
  change and save again, and `config edit` tells the user their version is
  kept. Without a daemon, `config edit` still compares whole configurations.
- **The CLI routes itself.** When the socket answers, every command goes
  through the daemon. With no socket, or nothing listening on it (a daemon
  that died leaves the file), the CLI opens the database itself as before.
  If that hits the lock, it says so and names the socket that should have
  answered. `backup restore` reads and shows the backup itself, asks, then
  has the daemon do the restore and apply, if the file still holds what was
  shown (its contents checksum).
- **Shutdown.** SIGTERM or SIGINT stops the socket, DNS and the proxy,
  deletes the nftables table and the WireGuard interface
  (`parallax_core::reconcile::teardown`, through the same `System` runner as
  apply), removes the socket and exits 0. The image's init (tini) forwards
  the signal and reaps `tailscaled`.

## Why

- Changes go live when they're saved, with no SIGHUP to remember; expired
  peers drop at midnight; a deleted table or interface comes back.
- One process fits the native install's systemd unit (step 8), and the GUI
  (M3) can live inside it and call the engine directly.
- Configuration writes have to go one at a time anyway: each change is
  validated against the whole configuration, and applying it to the live
  system (nft, wg) is serial whatever the database does.

## Rejected

- **MVCC (`BEGIN CONCURRENT`) now.** It only lets several write transactions
  run at once; reads are already concurrent, and the daemon serves them from
  memory. Two concurrent configuration writes would just conflict and retry,
  and under snapshot isolation two saves could each pass validation and
  together break a rule that spans rows (write skew). It's experimental and
  stops `sqlite3` opening the file. Revisit for the activity logs (step 7b),
  which get their own database with many small writes, with a benchmark.
  (Revisited in step 7c: ADR 0011 turns it on. It wasn't experimental by
  then, and the writer task stays for the write-skew reason above.)
- **DNS and the proxy as separate processes.** Three processes to supervise
  from a shell script, and SIGHUP to deliver to each after every apply.
- **HTTP over the socket.** More dependencies and framing for six requests
  from one local client. The GUI runs inside the daemon and needs none of it.
- **Always requiring the daemon.** `doctor`, the first-start import and
  `keygen` run before it starts, and a broken daemon must not lock the
  operator out of their own configuration.
