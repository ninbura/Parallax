# Setting up a Parallax gateway (M1: WireGuard path)

## What you need on the host

- Linux with the `wireguard` kernel module (5.6+ has it built in) and
  nftables >= 0.9.4 (any current distribution).
- `net.ipv4.ip_forward = 1` in `/etc/sysctl.d/`. The container shares the
  host network namespace and cannot set it for you; the entrypoint fails
  loudly if it is off.
- A UDP port forward from your internet router to the host for the WireGuard
  listen port (default 51820).
- **A static route on your home router**: send the WireGuard supernet (for
  the example, `10.8.0.0/16`) and the Tailscale range `100.64.0.0/10` to the
  gateway host's LAN address. Parallax routes tunnel traffic into the LAN
  without masquerading so nginx and other services see the real tunnel
  address (that is what the generated `allow` snippets match). Without the
  route, replies from LAN hosts have nowhere to go. If your router cannot
  hold a static route, set `masquerade = true` on that network and accept
  that LAN services then see the gateway's address for every peer.

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
