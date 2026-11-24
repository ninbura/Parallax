# ADR 0005: The database is the source of truth

Status: accepted (step 6a, before M2). Supersedes ADR 0002.

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
- **One process at a time.** Turso locks the file to one process. Commands
  open the database, do their work and close it; opening waits up to ten
  seconds for another holder. `apply` reads the configuration and closes the
  database before touching the system. Turso's multi-process mode is
  experimental and stays off. Once the daemon exists (step 7) it holds the
  database and the CLI talks to it.
- **Existing installs:** the container imports `/etc/parallax/parallax.toml`
  on its first start with no database, then renames it to
  `parallax.toml.imported`.

## Why

- **The GUI (M3) and the daemon (step 7) edit the configuration** while the
  gateway runs, and Tailscale tier membership changes as nodes join (M2). A
  file edited in place by hand and by programs doesn't hold up.
- **Ids let other data point at the configuration** and survive renames,
  which names alone can't.
- **Turso over SQLite in C:** the user wants to end up on Turso and would
  rather start there than migrate. It reads and writes SQLite's file format
  (the `sqlite3` tool opens a Parallax database), so going back stays cheap.
  It's pre-1.0, hence the exact version pin and no experimental features.

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
