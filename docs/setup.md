# Setting up a Parallax gateway (M1: WireGuard path)

## What you need on the host

- Linux with a current nftables and kernel that support prefix NAT (NETMAP;
  any current distribution, and `parallax doctor` checks it) and **rootful
  Docker** with Compose (see below; rootless Docker is not supported).
- The `wireguard` kernel module, loaded on the host at boot. The container
  can't load modules (it has no `SYS_MODULE`):

  ```sh
  echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
  sudo modprobe wireguard
  ```

  On kernels with WireGuard built in rather than as a module, `modprobe`
  succeeds and does nothing; that's fine.
- `net.ipv4.ip_forward = 1` in `/etc/sysctl.d/`. The container shares the
  host network namespace and cannot set it for you:

  ```sh
  echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/90-parallax.conf
  sudo sysctl --system
  ```
- A UDP port forward from your internet router to the host for the WireGuard
  listen port (default 51820). Test it from outside your network (a phone on
  cellular): clients on an isolated VLAN or behind your own router depend on
  hairpin NAT, which may be blocked.
- **A static route on your home router**: send the WireGuard supernet (for
  the example, `10.8.0.0/16`) and the Tailscale range `100.64.0.0/10` to the
  gateway host's LAN address. Parallax routes tunnel traffic into the LAN
  without masquerading so nginx and other services see the real tunnel
  address (that is what the generated `allow` snippets match). Without the
  route, replies from LAN hosts have nowhere to go. If your router cannot
  hold a static route, set `masquerade = true` on that network and accept
  that LAN services then see the gateway's address for every peer.
- **A host firewall, if any, must allow Parallax's traffic too.** Parallax owns
  its own nftables table but cannot override another firewall on the host, and
  a packet must pass both. With ufw active, allow the WireGuard port and DNS
  from the tunnel to the gateway address:

  ```sh
  sudo ufw allow proto udp to <gateway LAN address> port <listen_port>
  sudo ufw allow in on wg0 to <DNS address, e.g. 10.8.0.1> port 53 proto udp
  sudo ufw allow in on wg0 to <DNS address, e.g. 10.8.0.1> port 53 proto tcp
  ```

  The DNS server runs in the host network namespace, so ufw sees tunnel DNS
  as incoming traffic to the host. TCP carries answers too large for UDP.

## Rootful Docker, not rootless

Parallax creates `wg0`, loads an nftables table and runs its DNS server in the
host's own network namespace, and needs `CAP_NET_ADMIN` over it. Under
rootless Docker, the container's root is your unprivileged user on the host:
its capabilities only cover namespaces the rootless daemon created, never the
host's real network. Usually its "host network" is also a private namespace
behind a userspace proxy, so the host's LAN interfaces aren't there, every
incoming connection appears to come from the proxy, LAN devices can't reach
tunnel peers, and throughput drops.

`parallax doctor` checks `/proc/self/uid_map` and refuses to start in a user
namespace, so this fails at startup instead of half working. A rootful daemon
with `userns-remap` enabled refuses host networking on its own; give the
Parallax service `userns_mode: host` there.

### Next to a rootless daemon

A host can run both. Parallax uses the rootful system daemon; everything
else can stay on the rootless one:

```sh
sudo systemctl enable --now docker.service
cd docker && sudo docker compose up -d
```

`sudo docker` talks to the rootful daemon's socket (`/var/run/docker.sock`);
your user's `docker` keeps talking to the rootless one through `DOCKER_HOST`.
Keep the rootless user **out of the `docker` group**: membership gives full
access to the rootful daemon, which is root on the host. Without it (and
without sudo), the rootless side has no path to root.

## Checking the host: `parallax doctor`

The container runs `parallax doctor` on every start and refuses to apply if
any check fails. Run it by hand to see every problem at once:

```sh
cd docker && sudo docker compose run --rm --no-deps parallax doctor
```

It checks:

| Check | Fails when | Fix |
|---|---|---|
| configuration | the file is missing, unparsable or invalid | the listed errors |
| user namespace | running under rootless Docker or `userns-remap` | a rootful daemon (above) |
| CAP_NET_ADMIN | the container lacks the capability | `cap_add: [NET_ADMIN]` |
| ip_forward | `net.ipv4.ip_forward` is 0 | `/etc/sysctl.d/` (above) |
| tools | `nft`, `wg` or `ip` is missing | the image ships them; natively, install them |
| interface \<name\> | a configured LAN or WAN interface doesn't exist | the name in `parallax.toml` (`ip link`) |
| wireguard | a WireGuard interface can't be created | `/etc/modules-load.d/` (above) |
| NETMAP | the kernel or `nft` rejects prefix NAT (`nftables` backend only) | a newer kernel or nftables |

## Choosing the endpoint

`server.wireguard.endpoint` is what clients dial. It must resolve to your
public address **from everywhere, including inside your own network and
through the tunnel**:

- A client resolves the endpoint when the tunnel starts, with whatever DNS it
  has then. If your local DNS answers the same name with a LAN address (split
  horizon, or a wildcard such as `*.example.com -> 192.168.1.5`), a phone
  connected at home pins the LAN address and loses the tunnel as soon as it
  leaves Wi-Fi.
- The iOS app re-resolves on network changes, but by then its DNS points at
  the gateway, through the tunnel that just broke.
- The endpoint cannot be a name your services use either: through the tunnel,
  service names resolve to mapped addresses, and the endpoint must not.

Workable choices:

1. **A name with no local record**, kept current by a DDNS updater (your
   router's DDNS, or a small container). The only option that survives
   public-IP changes with no manual step.
2. **A dedicated name with a specific local record** to the public address
   (for example `public.example.com`, overriding a local wildcard), plus the
   same public record (DNS only, not proxied). Static: update both records if
   your public IP changes. Client configs keep working without re-export.
3. **A local CNAME to a name outside your zones** (a DDNS hostname in another
   domain). Your router chases the target upstream, so it stays current. A CNAME
   to a name *inside* a locally overridden zone resolves locally and does not
   help.
4. **The public IP itself.** Simplest; re-export configs if it changes.

## Public names and `dns.public`

Parallax's DNS server answers each template only the names it may reach: the
zones of its granted networks and the hostnames of its granted services.
Names outside your zones are answered only for templates with
`dns.public = true`, through `server.dns.public_resolver` (default `1.1.1.1`):

```toml
[[template]]
name = "personal"
# ...
[template.dns]
public = true
```

It's off by default, so a guest's lookups don't leave through your
connection. The official mobile WireGuard apps send every query to the
gateway, so a phone on a template without it resolves only that template's
home names while connected; `parallax export` warns about it. Tailscale
splits DNS natively on phones (M2), so Tailscale guests lose nothing.

## Networks that block outbound DNS

If your network only allows DNS to your router, point the public resolver
there:

```toml
[server.dns]
public_resolver = "192.168.1.1"
```

## First start

```sh
mkdir -p docker/config
cp example/parallax.toml docker/config/parallax.toml   # edit to taste
cd docker && sudo docker compose up -d
sudo docker compose logs -f parallax
```

On every start the entrypoint runs `parallax doctor` first. On first start it
then generates `wg-server.key` (mode 0600) next to the config and writes the
public key into it. Then it starts `tailscaled` (idle until M2), applies the
firewall, brings up `wg0`, and starts the DNS server and the HTTPS proxy. If
either of those exits, the container stops and Docker's restart policy takes
over.

## Adding a device

```sh
sudo docker compose exec parallax parallax peer add laptop --template personal --platform linux
sudo docker compose exec parallax parallax peer add sister-phone --template family --platform mobile
sudo docker compose kill -s HUP parallax    # re-apply
```

`peer add` prints the client config once, with the private key, and stores
only the public key unless you pass `--keep-private-key`. `export <peer>
--platform <linux|macos|windows|mobile>` re-renders a config later (with a
placeholder for the key if it was not retained).

## Editing the configuration

Edit `parallax.toml`, then `parallax validate`, `parallax plan` to see the
diff, and send `SIGHUP` to the container (or run `parallax apply`) to
reconcile. Every artifact is regenerated from scratch; nothing under
`/var/lib/parallax` is meant to be edited.

## nginx

Include the generated snippets in vhosts. `nginx/snippets/parallax-<template>.conf`
holds `allow` lines for a tier; `nginx/snippets/parallax-service-<name>.conf`
(for services marked `nginx_vhost = true`) holds every tier that reaches the
service, the local LAN, and `deny all`. Parallax does not reload nginx; copy
the snippets (or bind-mount the output directory) and reload yourself.

## Proxied HTTPS services and certificates

A service with `hostnames` is reached only through Parallax's HTTPS proxy
(`[server.proxy]`, port 8443 on the gateway address by default), which lets
those names through to the service and nothing else. The proxy terminates
TLS, so it needs a certificate for each such hostname. Parallax never issues
one: point `server.proxy.certificates` at a folder you keep current.

- Every directory under the folder holding `fullchain.pem` and `privkey.pem`
  is one certificate. certbot's `live/<name>` directories work as they are.
- Mount only what Parallax should hold. All of `/etc/letsencrypt` hands it
  every key there, wildcards included. For one certificate, mount
  `live/<name>` and `archive/<name>` read-only at the same paths (the files
  in `live/` link into `archive/`) and set
  `certificates = "/etc/letsencrypt/live"`. `docker/compose.yml` has the
  lines, commented out.
- Renewals are picked up within a minute; no restart.
- `parallax plan` and `apply` fail, naming the hostname, when no certificate
  covers a proxied hostname some template is granted.

The proxy verifies the upstream's certificate against the hostname, using
`server.proxy.upstream_ca` (the system bundle by default). An nginx with a
publicly trusted certificate for the name needs nothing more.

## Split DNS on clients

See `docs/client-dns.md`. Short version: Linux configs carry the
`resolvectl` PostUp, macOS and Windows configs carry the one-time recipe as
comments, and the official mobile WireGuard apps get tunnel-wide DNS with a
warning (and public names only with `dns.public`). The product's answer for
phones is the Tailscale transport (M2).
