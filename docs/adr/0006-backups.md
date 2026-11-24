# ADR 0006: Backups

Status: accepted (step 6b).

## Decision

`parallax backup create` writes one file, `parallax-backup-<UTC time>.tar`,
holding everything Parallax keeps: the database and the server's private
key. `parallax backup restore <file>` puts both back. How to use them:
`docs/backup.md`.

- **The database is copied with `VACUUM INTO`**: one statement, one read
  transaction, so the copy is consistent while other processes write, and
  it's compact. It holds everything, including what the GUI will store.
  TOML isn't in backups; it stays a way to move the configuration only.
- **The layout:** a plaintext `manifest.toml` (format, Parallax version,
  schema version, time, whether encrypted, checksums) and `payload.tar.age`,
  holding `parallax.db` and `wg-server.key`. The manifest needs no
  passphrase, so `backup list` and the version check work without one.
- **Encryption is on by default**, with `age` in passphrase mode (scrypt).
  The operator sets the passphrase once (`parallax backup passphrase`) and
  keeps it in a password manager. The server keeps a copy in a 0600 file next
  to the server key (`server.backup.passphrase_file`), so automatic backups
  run; it's never in the database, so no backup carries it. scrypt's cost is
  fixed (2^18, about a second and 256 MiB) rather than tuned to the host,
  so a slower machine can still restore what a faster one wrote. Turning
  encryption off is an explicit setting, and `doctor` warns when unencrypted
  backups go to a network filesystem. The live database isn't encrypted; its
  key would sit on the same server. Full-disk encryption covers that.
- **Restore replaces rows, not the file.** The backup's database is staged
  next to the live one, migrated forward and integrity-checked. Then every
  table of the live database is emptied and refilled from it in one write
  transaction, ids included. Other processes keep their open connections,
  and no stale log or coordination file can be applied to a swapped-in file.
  Before that, restore shows the configuration and generated-file diff,
  waits for confirmation, and backs up the current state (required: no
  undo backup, no restore). The replace checks, inside its transaction, that
  the configuration is still what was shown and backed up. The server key is
  written first (atomically) and put back if the replace fails, so key and
  database always match.
- **Skip when unchanged.** The plaintext payload is deterministic (same
  database contents and key, same bytes), and the manifest records its
  SHA-256, so an automatic backup with nothing new isn't written. The
  checksum reveals nothing: the payload includes the server's private key.
- **Automatic backups:** `[server.backup] automatic, interval, keep`.
  `backup create --if-due` backs up when the newest backup is older than
  `interval` and something changed, then deletes the oldest past `keep`. The
  container calls it every ten minutes; the daemon (step 7) takes over.

## Why

- **One action, no hand-handling of volumes or the database** (the user,
  2026-11-24). The GUI will store far more than the configuration, so the
  backup is the database itself.
- **`age`** rather than our own construction: audited, and an operator can
  open a backup with the stock `age` tool if Parallax is gone.
- **`tar`**: the same, with any `tar`.

## Rejected

- **Swapping the database file on restore.** Simpler, but another process
  could still be writing to the old file, and the old write-ahead log and
  coordination file would have to be removed at exactly the right moment.
- **Encrypting the manifest too.** Listing backups and refusing a too-new one
  would then need the passphrase.
- **A key pair (`age` recipients) instead of a passphrase.** The private half
  is one more thing to keep safe and is easier to lose. It can come later as
  an advanced option.
- **Including TLS certificates.** They belong to whoever issues them
  (certbot) and renew on their own schedule.
