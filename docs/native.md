# Installing Parallax natively

Parallax can run on the host as a systemd service instead of in rootful
Docker. The service runs as its own unprivileged user, `parallax`, and holds
only two capabilities: `CAP_NET_ADMIN` (wg0, nftables, routes) and
`CAP_NET_BIND_SERVICE` (DNS on port 53). Everything else about the host is
sandboxed away. [ADR 0013](adr/0013-native-install.md) explains the choices.

Parallax runs on Linux only: it needs nftables, kernel WireGuard, `ip` and
systemd. On Windows or macOS, run it in a Linux VM or on a small Linux box
such as a Raspberry Pi.

The host-side setup in [setup.md](setup.md) applies here too: the router's
port forward, the static route, a host firewall, the endpoint, grants and
certificates. The package does two of setup.md's steps for you, the
`wireguard` module and `ip_forward`. This page covers what differs from
Docker.

## Install

Packages and static binaries for x86_64 and aarch64 are built by CI (the
`package` job's artifacts) until releases are published.

**Debian, Ubuntu:**

```sh
sudo apt install ./parallax_<version>-1_amd64.deb
```

**Arch:**

```sh
sudo pacman -U parallax-<version>-1-x86_64.pkg.tar.zst
```

Either one installs:

| Path | What |
|---|---|
| `/usr/bin/parallax` | the binary (static, musl) |
| `/usr/lib/systemd/system/parallax.service` | the service |
| `/usr/lib/sysusers.d/parallax.conf` | the `parallax` system user: no shell, no login |
| `/usr/lib/tmpfiles.d/parallax.conf` | `/etc/parallax`, mode 0700, owned by `parallax` |
| `/usr/lib/modules-load.d/parallax.conf` | loads `wireguard` at boot |
| `/usr/lib/sysctl.d/90-parallax.conf` | `net.ipv4.ip_forward = 1` |
| `/usr/share/doc/parallax/parallax.toml.example` | the example configuration |

Installing creates the user and `/etc/parallax`, loads the module and turns
on forwarding right away, so no reboot is needed. The service is installed
but **not enabled**: it has nothing to run until it has a configuration.

It depends on `nftables`, `wireguard-tools` and `iproute2`. `iptables` and
`ipset` are optional, only for `backend = "iptables-nft"`.

**Static binary, any distribution:** install the binary and the files under
`packaging/` at the paths above, then do what a package does:

```sh
sudo install -m 0755 parallax /usr/bin/parallax
sudo install -m 0644 packaging/systemd/parallax.service /usr/lib/systemd/system/
sudo install -m 0644 packaging/sysusers.d/parallax.conf /usr/lib/sysusers.d/
sudo install -m 0644 packaging/tmpfiles.d/parallax.conf /usr/lib/tmpfiles.d/
sudo install -m 0644 packaging/modules-load.d/parallax.conf /usr/lib/modules-load.d/
sudo install -m 0644 packaging/sysctl.d/90-parallax.conf /usr/lib/sysctl.d/
sudo systemd-sysusers parallax.conf
sudo systemd-tmpfiles --create parallax.conf
sudo systemctl daemon-reload
sudo systemctl restart systemd-sysctl systemd-modules-load   # ip_forward and wireguard now
```

## First start

Put the configuration at `/etc/parallax/parallax.toml`, readable only by the
service. It can hold private and preshared keys:

```sh
sudo install -m 0600 -o parallax -g parallax my-parallax.toml /etc/parallax/parallax.toml
sudo systemctl enable --now parallax
sudo parallax status
```

Before it starts the daemon, the service:

1. imports `parallax.toml` into the database
   (`/var/lib/parallax/parallax.db`), but only if the database is empty;
2. runs `parallax doctor` and refuses to start if a check fails;
3. creates the server key (`/etc/parallax/wg-server.key`) if there isn't
   one, and records its public key in the configuration.

Then `parallax daemon` applies the configuration, brings up `wg0` and starts
the DNS server and the HTTPS proxy. `systemctl start` returns once that has
worked, or fails if it hasn't. The journal shows what went wrong, including
`doctor`'s report from before the daemon started:

```sh
sudo journalctl -u parallax
```

After the first import the database is the configuration. Unlike in Docker,
`parallax.toml` isn't renamed: the unit only imports it. It's ignored from
then on, so delete it once the service runs. Change the configuration
with `sudo parallax config edit` (see setup.md, "Editing the configuration").

Then set the backup passphrase and keep it in your password manager:

```sh
sudo parallax backup passphrase --generate
```

Stopping the service (`sudo systemctl stop parallax`) removes the firewall
table and `wg0`. `sudo systemctl reload parallax` re-applies, like SIGHUP in
Docker. Every saved change applies anyway.

## Running `parallax` commands

Run the CLI as root: `sudo parallax <command>`. While the service runs,
whatever reads or changes the configuration goes through its socket
(`/run/parallax/parallax.sock`, which only `parallax` and root can open), so
the daemon holds the database and applies each change as it's saved.
`sudo parallax doctor` checks the host as root, with the configuration from
the daemon. There's no `parallax` group. Opening the CLI to
another user would hand them the gateway.

When the service isn't running, root refuses commands that would open the
database itself:

```
/var/lib/parallax/parallax.db belongs to user 'parallax', and no daemon answers on /run/parallax/parallax.sock. ...
```

Root would leave files there (the database's `-wal` and `.db-log`) that the
service can't open afterwards. Start the service, or run the command as the
service's user: `sudo -u parallax parallax ...`. Before the first start
nothing of the service's exists yet, so root may restore a backup then
(below). The service takes ownership of `/var/lib/parallax` when it starts.

## Certificates for proxied services

The service reads certificates from `server.proxy.certificates` as the
`parallax` user. certbot keeps `/etc/letsencrypt/live` and `archive`
readable by root only, so point Parallax at a copy that root owns and the
service may only read, and set
`server.proxy.certificates = "/etc/parallax-certs"`. Not under
`/etc/parallax`: the service owns that directory, and a hook running as root
mustn't write anywhere the service could redirect it. A certbot deploy hook
keeps the copy current. It runs after every renewal, as root. Copy only the
certificates Parallax should hold:

```sh
#!/bin/sh
# /etc/letsencrypt/renewal-hooks/deploy/parallax (mode 0755)
set -eu
name=$(basename "$RENEWED_LINEAGE")
case "$name" in
    immich.mydomain.com) ;;   # the hostnames Parallax proxies
    *) exit 0 ;;
esac
dest=/etc/parallax-certs/$name
install -d -m 0750 -o root -g parallax /etc/parallax-certs "$dest"
install -m 0640 -o root -g parallax \
    "$RENEWED_LINEAGE/fullchain.pem" "$RENEWED_LINEAGE/privkey.pem" "$dest/"
```

Run it once by hand for the first copy:
`sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/immich.mydomain.com /etc/letsencrypt/renewal-hooks/deploy/parallax`.
The proxy picks up renewed files within a minute.

## Backups and restores

Backups work as described in [backup.md](backup.md). Use `sudo parallax ...`
where that page uses `docker compose exec parallax parallax ...`. They go to
`/var/lib/parallax/backups`. Copy them off the machine too.

The service can't see `/home`, `/root`, `/tmp` or `/var/tmp`. To restore
while it runs, put the backup in the backup directory first:

```sh
sudo install -d -m 0700 -o parallax -g parallax /var/lib/parallax/backups
sudo install -m 0600 -o parallax -g parallax parallax-backup-20261124T153000Z.tar /var/lib/parallax/backups/
sudo parallax backup restore /var/lib/parallax/backups/parallax-backup-20261124T153000Z.tar
```

**On a fresh install,** restore before the first start, from wherever the
backup is. No `parallax.toml` is needed:

```sh
sudo parallax backup restore ~/parallax-backup-20261124T153000Z.tar
sudo systemctl enable --now parallax
```

That restores the database and the server key. When the backup is
encrypted, it also saves the passphrase you give it for the next backups,
unless one is already set. On its first
start the service takes ownership of `/var/lib/parallax` and applies the
restored configuration. You don't need the `parallax apply` the restore
suggests.

## Upgrading and removing

Install the new package the same way. On Debian and Ubuntu a running
service restarts onto the new binary. On Arch, restart it yourself:
`sudo systemctl restart parallax`.

Removing the package (`apt remove`, `pacman -R`) stops the service, which
takes `wg0` and the firewall table down with it. Even `apt purge` keeps
`/etc/parallax` (the server key, the backup passphrase) and
`/var/lib/parallax` (the database, the backups). Losing the server key means
a new config for every device. To remove those too, after taking a backup:

```sh
sudo rm -r /etc/parallax /var/lib/parallax
```

## Headscale

Headscale is the control plane only. Tailscale traffic doesn't pass through
it, except relayed packets when its embedded DERP relay is on. It can run
anywhere Parallax can reach `server_url`: in rootless Docker (the
`headscale` service in `docker/compose.yml` works as it is: `docker compose
up -d headscale`), its own package, or another machine. Rootless Docker isn't supported for Parallax
itself (setup.md explains why), but it is for Headscale.

## What the service may do

`packaging/systemd/parallax.service` has the full list. In short:

- runs as `parallax`, with `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` as its
  only capabilities, both ambient so the `nft`, `ip` and `wg` it runs get
  them too. It can't gain more: `NoNewPrivileges`, and a bounding set of
  just those two;
- the whole file system is read-only except `/var/lib/parallax`,
  `/run/parallax` and `/etc/parallax`. It sees no home directories, its own
  `/tmp`, no devices and no kernel tunables, modules or logs;
- sockets are limited to Unix, IPv4, IPv6 and netlink, and system calls to
  systemd's `@system-service` set;
- it shares the host's network. That's its job: it owns `wg0`, its nftables
  table and its routes, and the kernel can't limit `CAP_NET_ADMIN` to those.

`systemd-analyze security parallax.service` rates it 1.6 ("OK"). What's left
is the host network and the two capabilities.
