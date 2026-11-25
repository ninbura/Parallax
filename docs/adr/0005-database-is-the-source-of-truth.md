# ADR 0005: The database is the source of truth

Status: accepted (step 6a, before M2). Supersedes ADR 0002. Its
multi-process and MVCC paragraphs are superseded by ADR 0007 (the daemon).

## Decision

The configuration lives in one database file (`/var/lib/parallax/parallax.db`,
mode 0600), written through Turso, the Rust rewrite of SQLite, in SQLite's
file format. Crate `parallax-store` loads a whole `Config` and saves one back
in a single transaction. There is no TOML mode: TOML is only a way in and out
(`parallax config import`, `export`, `edit`). The server's private key stays
a file next to it.

- **Tables follow the model.** One table per part of `Config`, ordered lists
  in child tables with a `position`. Addresses, prefixes, keys and enum values
  are TEXT in their TOML spelling, so the SQL stays portable to Postgres.
- **Rows have ids; the model has names.** Every row gets a hidden integer id
  beside its unique name. References between tables (grants, peers) use the
  id. Saving matches rows by name: a kept name keeps its id, a missing one is
  deleted, so nothing is wiped and refilled. Ids never reach `parallax-core`
  or TOML, which stay keyed by name.
- **GUI data gets its own tables** (logins, sessions, labels, layout), which
  point at configuration rows by id, so renaming a peer in the GUI keeps its
  labels. TOML export never includes them.
- **Migrations** are numbered SQL files compiled into the binary, applied in
  order on open, each in its own transaction. A database newer than the binary
  is refused, naming both versions.
- **Many processes at once** *(superseded by ADR 0007: the daemon holds the
  database alone, in Turso's single-process mode, and the CLI goes through
  it)* (the user, 2026-11-24: concurrency now, as
  fast as possible). By default Turso locks the file to one process; we open
  it in its multi-process WAL mode (experimental, a `-tshm` coordination file
  beside the database), so the gateway, the CLI and anything else read
  concurrently and never wait for each other's reads. Writers take turns: a
  write waits up to ten seconds for another to commit. Measured 2026-11-24:
  4 processes × 300 writes at once, no errors, integrity check passes, and
  `sqlite3` still reads the file; CI runs 8 concurrent `peer add`s.
- **Every change is one write transaction.** `Store::update` reads, changes
  and writes inside the same transaction, so concurrent commands can't lose
  each other's changes (two `peer add`s can't take the same address).
  `config edit` saves only if nobody changed the configuration while the
  editor was open, and keeps the edited file if someone did.
- **Parallel writers (MVCC, `BEGIN CONCURRENT`) wait for the daemon.**
  *(Decided in ADR 0007: not now.)* Turso's
  MVCC refuses multi-process access (its bookkeeping lives in one process's
  memory), and while it's on `sqlite3` can't open the file. Once the daemon
  (step 7) is the only process holding the database and the CLI talks to it,
  MVCC is an option; until then writes are short and rare.
- **Existing installs:** on its first start the container runs `config
  import --if-empty` on `/etc/parallax/parallax.toml` (it imports only into a
  database without a configuration, decided inside the write) and renames the
  file to `parallax.toml.imported`.
- **Files are owner-only.** The database and its log hold private keys: the
  CLI runs with an owner-only umask and the store tightens both to 0600;
  generated files get explicit modes.

## Why

- **The GUI (M3) and the daemon (step 7) edit the configuration** while the
  gateway runs, and Tailscale tier membership changes as nodes join (M2). A
  file edited in place by hand and by programs doesn't hold up.
- **Ids let other data point at the configuration** and survive renames,
  which names alone can't.
- **Turso over SQLite in C:** the user wants to end up on Turso and would
  rather start there than migrate. It reads and writes SQLite's file format
  (the `sqlite3` tool opens a Parallax database), so going back stays cheap.
  It's pre-1.0, hence the exact version pin. (Multi-process access, the one
  experimental feature this used, is off since ADR 0007.)

## Rejected

- **TOML stays the source of truth, the database mirrors it.** Two sources
  that drift, and the GUI would have to edit TOML.
- **`sqlx` with SQLite.** Mature, but has no Turso support; with Turso we
  write the small migration runner ourselves.
- **A storage trait for a later Postgres backend.** No second backend exists
  yet (AGENTS.md: no trait without a second use). Portable SQL keeps it
  possible.
- **Serialising the whole `Config` into one column.** No ids to point at, no
  way for a migration to change data in SQL.
- **Keeping comments.** The database can't hold a file's comments; exports
  list every setting in a fixed order instead.
