# Setting up a Parallax gateway (M1: WireGuard path)

## What you need on the host

- Linux with the `wireguard` kernel module (5.6+ has it built in) and
  nftables >= 0.9.4 (any current distribution).
- `net.ipv4.ip_forward = 1` in `/etc/sysctl.d/`. The container shares the
  host network namespace and cannot set it for you; the entrypoint fails
  loudly if it is off.
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
  from the tunnel to the shim:

  ```sh
  sudo ufw allow proto udp to <gateway LAN address> port <listen_port>
  sudo ufw allow in on wg0 to <shim address, e.g. 10.8.0.1> port 53 proto udp
  ```

  The shim runs in the host network namespace, so ufw sees tunnel DNS as
  incoming traffic to the host.

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
  the shim, through the tunnel that just broke.
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

## Networks that block outbound DNS

Mobile WireGuard clients send every query to the shim, which forwards names
outside your zones to `server.dns.public_resolver` (default `1.1.1.1`). If
your network only allows DNS to your router, point it there:

```toml
[server.dns]
public_resolver = "192.168.1.1"
```

## First start

```sh
mkdir -p docker/config
cp example/parallax.toml docker/config/parallax.toml   # edit to taste
cd docker && docker compose up -d
docker compose logs -f parallax
```

On first start the entrypoint generates `wg-server.key` (mode 0600) next to
the config and writes the public key into it. Then it applies the firewall,
brings up `wg0`, starts the DNS shim and `tailscaled` (idle until M2).

## Adding a device

```sh
docker compose exec parallax parallax peer add laptop --template personal --platform linux
docker compose exec parallax parallax peer add sister-phone --template family --platform mobile
docker compose kill -s HUP parallax    # re-apply
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

## Split DNS on clients

See `docs/client-dns.md`. Short version: Linux configs carry the
`resolvectl` PostUp, macOS and Windows configs carry the one-time recipe as
comments, and the official mobile WireGuard apps get tunnel-wide DNS with a
warning. The product's answer for phones is the Tailscale transport (M2).
