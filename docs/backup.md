# Backups

One file holds everything Parallax keeps: the database (the configuration,
and later everything the GUI stores) and the server's WireGuard private key.
Restoring it is one command, and clients keep working, because the server key
comes back too.

Backups are on by default: once a day when something changed, the newest 14
kept, encrypted with a passphrase you set once.

## Set the passphrase

Do this once, right after the first start:

```sh
cd docker
sudo docker compose exec parallax parallax backup passphrase --generate
```

It prints a generated passphrase and saves it to
`/etc/parallax/backup.passphrase` (mode 0600; `docker/config/` on the host),
so automatic backups can run. **Put the passphrase in your password manager
now.** A backup can't be restored without it, and if the server's disk dies,
the copy on the server goes with it. To type your own instead, leave out
`--generate`.

Until a passphrase is set, `parallax doctor` warns at every start and
automatic backups fail with a warning in the log. To back up without
encryption, set `server.backup.encrypt = false` (`parallax config edit`).
That's an explicit choice: an unencrypted backup holds every private key in
the clear, and `doctor` warns when one goes to a network filesystem.

## Where backups go

`/var/lib/parallax/backups`, which `docker/compose.yml` mounts from
`docker/backups/` on the host. Copy that folder somewhere else as well
(another disk, a NAS, cloud storage): encrypted backups are safe to keep
anywhere. To write them straight to another disk, change the mount, or set
`server.backup.directory`.

```sh
sudo docker compose exec parallax parallax backup create   # one now
sudo docker compose exec parallax parallax backup list
```

The log shows each automatic backup. `parallax doctor`, which runs at every
start, prints where they go:

```
ok    backups: every 1d to /var/lib/parallax/backups, keeping 14, encrypted
```

## Restore

```sh
sudo docker compose exec parallax parallax backup restore /var/lib/parallax/backups/parallax-backup-20261124T153000Z.tar
```

`restore` checks the file, asks for the passphrase if the server's doesn't
open it, and shows what changes: the configuration (keys hidden), the server
key, and the generated files. It changes nothing until you confirm. Then the
running gateway (`parallax daemon`) restores it and applies it at once. Before
replacing anything it saves the current state as a new backup, so a restore
can be undone with another restore; if it can't, nothing is restored. If the
configuration changes while you're looking at the diff, nothing is restored
either: run it again.

If the database is damaged and won't open, move `parallax.db*` aside and
restore as on a fresh install (below).

A backup from an older Parallax is brought up to date as it's restored. One
from a newer Parallax is refused, naming the version needed.

**On a fresh install** (new disk, new machine): put the backup in
`docker/backups/` and restore before the first start:

```sh
cd docker
sudo docker compose run --rm --no-deps parallax backup restore /var/lib/parallax/backups/parallax-backup-20261124T153000Z.tar
sudo docker compose up -d
```

It asks for the passphrase and saves it again for the next backups. You don't
need a `parallax.toml`.

## Settings

`[server.backup]`, changed with `parallax config edit`:

| Setting | Default | |
|---|---|---|
| `directory` | `/var/lib/parallax/backups` | where backups are written |
| `automatic` | `true` | once per `interval`, back up if something changed |
| `interval` | `"1d"` | `30m`, `6h`, `1d`, ... |
| `keep` | `14` | the oldest are deleted past this many |
| `encrypt` | `true` | encrypt with the passphrase in `passphrase_file` |
| `passphrase_file` | `/etc/parallax/backup.passphrase` | 0600; never in the database or a backup |

`parallax backup passphrase --replace` sets a new passphrase. Older backups
still need the old one.

## What's not in a backup

- **TLS certificates** for proxied services (`server.proxy.certificates`):
  they belong to whoever issues them (certbot), so back them up with that.
- **The backup passphrase.** Keep it in your password manager.
- **Activity logs** (`logs.db`, [logging](logging.md)), on purpose: a backup
  would keep who-went-where records past `server.logs.keep`, in every copy
  of it, and they aren't needed to rebuild the gateway. A restore leaves
  the current `logs.db` alone.
- **Headscale's own data** (the `headscale` container's volume), until
  Parallax drives Headscale (M2).

## Opening one by hand

A backup is a tar file. `manifest.toml` (plaintext) says which Parallax made
it, when, and whether it's encrypted. The rest is in `payload.tar.age`, an
[age](https://age-encryption.org) file encrypted with the passphrase
(`payload.tar` when unencrypted):

```sh
tar -xf parallax-backup-20261124T153000Z.tar
age -d payload.tar.age | tar -x    # asks for the passphrase
# parallax.db: open with sqlite3. wg-server.key: the server's private key.
```
