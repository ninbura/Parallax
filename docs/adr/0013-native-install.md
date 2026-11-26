# ADR 0013: The native install

Status: accepted (step 8). Adds a second way to run the gateway next to
rootful Docker. Builds on ADR 0001 (`wg` as a subprocess) and ADR 0007 (the
daemon).

## Context

Rootful Docker is the main install path, but some people won't run a
rootful daemon. Parallax doesn't need root. It needs control of the host's
networking: `wg0`, an nftables table, routes, and a DNS server on port 53.
It runs `nft`, `ip` and `wg` to get there. Under Docker all of that runs as
root with `NET_ADMIN`. A native install can give it much less.

Ubuntu 25.10 and later confine `/usr/bin/wg` with an enforcing AppArmor
profile. The only file it lets `wg` open is under `/etc/wireguard`, so
`wg syncconf wg0 <file>` fails on a config anywhere else.

## Decision

- **An unprivileged system user, `parallax`**, created by sysusers.d. It has
  no shell and no login. It owns `/var/lib/parallax` (the database,
  generated files, backups), `/run/parallax` (the socket) and
  `/etc/parallax` (keys, the passphrase, the first-start TOML).
- **Two capabilities, both ambient:** `CAP_NET_ADMIN` and
  `CAP_NET_BIND_SERVICE`. They have to be ambient because `nft`, `ip` and
  `wg` are child processes, which lose capabilities that aren't. The
  bounding set is the same two, with `NoNewPrivileges`. `parallax doctor`
  checks both. It requires `CAP_NET_ADMIN` in the ambient set when not root,
  and `CAP_NET_BIND_SERVICE` only when a port is below
  `ip_unprivileged_port_start`.
- **A sandboxed unit** (`packaging/systemd/parallax.service`):
  `ProtectSystem=strict` with write access to its three directories only,
  `ProtectHome`, `PrivateTmp`, `PrivateDevices`, the kernel and cgroup
  protections, `RestrictNamespaces`, `MemoryDenyWriteExecute`, sockets
  limited to `AF_UNIX AF_INET AF_INET6 AF_NETLINK`, and system calls to
  `@system-service`. `systemd-analyze security` rates it 1.6. What's left is
  inherent: the host network, the two capabilities, and netlink and IP
  sockets. There's no `PrivateNetwork`, since configuring the host network
  is the job. CI fails above 2.0.
- **AppArmor: the config goes to `wg` on stdin** (8.1, ADR 0001's update).
  AppArmor limits what `wg` opens itself, not a pipe its caller hands it.
  That works under the stock profile, needs no local override, and keeps
  the private key away from another file `wg` has to read. A redirected
  file (`< file`) is still denied: AppArmor checks the file behind it.
- **`Type=notify`:** the daemon tells systemd it's ready after its first
  apply and once its socket answers, so `systemctl start` fails when the
  gateway didn't come up.
- **The startup steps stay separate commands** (`ExecStartPre`): import the
  TOML if the database is empty, `doctor`, then `keygen --if-missing`. Docker
  runs the same commands from its entrypoint.
- **The CLI is root's** (`sudo parallax`). The socket stays 0600, owned by
  `parallax`, with no group for it: whoever can use the CLI controls the
  gateway. With no daemon answering, root refuses to open a database
  another user owns, and `daemon` and `generate` refuse to write into the
  service's directories. Root would otherwise leave root-owned `-wal`,
  `.db-log` or generated files that the service can't open. Keys and
  passphrases root writes into `/etc/parallax` go to the directory's owner.
  Root writes them as new files and hands them over with `lchown`, so a
  link the service left there can't redirect root's write or `chown`.
- **Packages:** one nfpm config builds the `.deb` and the Arch package from
  the static musl binary. Arch's systemd pacman hooks create the user and
  the directory, set the sysctl and load the module. The `.deb` does the
  same in its own scripts, because dpkg runs no such hooks. The service is
  installed, not enabled. Removal stops it; state is never deleted.
- **Linux only.** The gateway relies on nftables (NETMAP, redirects),
  kernel WireGuard, `ip`, `/proc`, systemd and netns tests. macOS would need
  a pf backend, userspace WireGuard, launchd and a new test harness. Windows
  has no in-kernel prefix NAT, so it would need userspace packet rewriting
  or a signed WFP driver. Neither is planned: run the gateway in a Linux VM
  or on a small Linux box. Clients stay cross-platform.

## Consequences

- `tests/integration/netns.sh` with `NETNS_DAEMON=unit` runs its daemon
  through `systemd-run` with the unit's own `[Service]` lines, as an
  unprivileged user. Packet behaviour is tested under the real sandbox, and
  the test and the unit can't drift. CI runs it, and also installs the
  `.deb` on a fresh runner and starts the real service.
- A feature that needs more access (another capability, address family or
  writable path) has to change the unit. Netns unit mode fails until it
  does.
- The service can't see `/home`, `/root` or `/tmp`, so files the daemon
  reads itself (a backup to restore) must be somewhere it can.
- certbot's `/etc/letsencrypt` is root-only. Natively, a deploy hook copies
  certificates into a root-owned directory the service can only read, not
  into `/etc/parallax`, where the service could redirect root's writes.
- `CAP_NET_ADMIN` covers all of the host's networking, not just Parallax's
  table and interface; the kernel can't narrow it. The service's exposure
  is what it does on the network: the DNS server and the proxy, and later
  the GUI.

## Rejected

- **Root with a sandbox.** Simpler, but every bug in the network-facing
  parts would run as root.
- **A `parallax` group for the CLI.** It would make group membership
  equivalent to controlling the gateway, which is as much as root over the
  network.
- **An AppArmor local override, or writing under `/etc/wireguard`.** The
  override is per distribution and needs root to install. `/etc/wireguard`
  is 0700 root, out of the service's reach.
- **WireGuard over netlink.** It would replace `wg syncconf`'s peer diff with
  our own code. Stdin made it unnecessary.
- **Moving the startup steps into the daemon.** It would mean more code in
  the daemon for no gain. The separate commands do the same work in Docker
  and natively.
