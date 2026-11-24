# Staging gateway

A real Parallax gateway on a development machine: the same image and
entrypoint as `docker/compose.yml`, running host-networked, routing into two
fake LANs in network namespaces. An agent or a developer can bring it up,
change the config, add peers, run end-to-end checks and tear it down without
touching a production gateway. Phones on the same LAN can connect to it with a
QR code.

```
             client namespace / phone on the LAN
                          │ WireGuard to <this host>:51814
   ┌──────────────────────┴───────────────────────┐
   │ host: container parallax-staging, wg1        │
   │ 10.9.0.1, DNS, nft table inet parallax       │
   └──────┬──────────────────────────────┬────────┘
     pxs-lan1 192.168.201.1         pxs-lan2 192.168.202.1
          │ routed                       │ masqueraded
   lan1 (198.19.201.0/24)          lan2 (198.19.202.0/24)
   .5  :80 lan1-immich, :8080      .5  :80 lan2-nas, :8080
   .53 DNS for staging.test
```

Addresses are chosen to coexist with a production gateway on the same LAN
(`10.8.0.0/16`, `198.18.0.0/15`): staging uses tunnel pool `10.9.0.0/16`,
mapped space `198.19.0.0/16`, interface `wg1` and port `51814`. The fake
LANs only exist on this host, so `192.168.201.0/24` and `192.168.202.0/24`
must not be in use on your real network.

## Requirements

Rootful Docker with Compose, `wireguard-tools`, `dnsmasq` (the fake LANs' DNS), `python3`, `dig`,
`curl`, `qrencode`, the `wireguard` kernel module. Everything runs as root,
through `sudo` or `pkexec` (one prompt per command; `up` starts Docker if it's
stopped).

If the host runs a firewall such as ufw, allow the WireGuard port and DNS on
the gateway address, as for any Parallax install (`docs/setup.md`):

```sh
sudo ufw allow proto udp to <this host's LAN address> port 51814
sudo ufw allow in on wg1 to 10.9.0.1 port 53 proto udp
sudo ufw allow in on wg1 to 10.9.0.1 port 53 proto tcp
```

## Commands

```sh
sudo dev/staging/staging.sh up        # fake LANs, config on first run, build, start
sudo dev/staging/staging.sh smoke     # end-to-end checks; prints SMOKE PASS or FAIL
sudo dev/staging/staging.sh peer phone personal mobile   # add a peer, show its QR
sudo dev/staging/staging.sh export > /tmp/staging.toml   # the configuration as TOML
sudo dev/staging/staging.sh import /tmp/staging.toml     # replace it, then re-apply
sudo dev/staging/staging.sh apply     # re-apply (SIGHUP the container)
sudo dev/staging/staging.sh status
sudo dev/staging/staging.sh down      # stop and remove the fake LANs; state is kept
sudo dev/staging/staging.sh reset     # down, then delete all state
```

State lives in `/var/lib/parallax-staging` (override with `STAGING_STATE`),
outside the checkout, so every worktree drives the same gateway with the same
server key and peers, and a phone profile keeps working. It is mode 0700,
owned by the user who ran `sudo`, and holds the server key and exported client
configs.

The first `up` renders `parallax.toml.in` into `config/parallax.toml` there,
taking the endpoint from the default route's source address. Set
`STAGING_ENDPOINT`, `STAGING_PORT` or `STAGING_PUBLIC_RESOLVER` (default: the
default-route gateway, for networks that block outbound DNS) to override. The
container imports that file into its database (`out/parallax.db`) on the
first start and renames it to `parallax.toml.imported`; from then on the
database is the source of truth. Change it with `export` and `import`.

`smoke` adds the peers `smoke-personal` and `smoke-guest`, connects them from
a fresh client namespace to the real endpoint, and checks the following:

- **Database.** The first start imported `parallax.toml` and renamed it, and
  importing an export of the configuration changes nothing.
- **Mapped addresses.** Both LANs are reachable by mapped address. On the
  routed LAN the host sees the tunnel address; on the masqueraded LAN it sees
  the gateway.
- **DNS.** The personal peer gets `staging.test` answers rewritten into mapped
  space, and public names (`dns.public`). The guest, whose only grant is a
  service without hostnames, gets every name refused.
- **LAN-initiated traffic.** On the routed LAN, a host can start a connection
  to a peer.
- **Gateway isolation.** No peer reaches services on the gateway host.
- **Guest limits.** The guest reaches only its granted `host:port`, even with
  `AllowedIPs = 0.0.0.0/0` on the client.

Phones get `mobile` exports (tunnel-wide DNS). They can only reach staging
from the same LAN, since the port is not forwarded from the internet.
