# ADR 0015: The subnet router: one tailscaled, driven through its CLI

Status: accepted (step 13). Builds on ADR 0014 (Headscale's API) and
ADR 0013 (the native install).

## Context

Tailscale devices reach the home networks through a subnet router: a
Tailscale client on the gateway that advertises routes to them. Parallax's
firewall already matches `tailscale0` (NETMAP, the `ts_` tier sets, the
proxy redirect), so the router only has to carry packets. Something has to
log it in to Headscale, advertise the right routes, approve them, and keep
its own filtering and NAT out of the way.

Two `tailscaled` on one machine share `tailscale0`, port 41641 and routing
table 52, so they can't run side by side. Some gateways will already be on
Tailscale (the operator's own node), and Parallax never changes an
operator's own Tailscale or Headscale objects (step 10, external mode).

## Decision

- **One `tailscaled` per machine.** Parallax uses whichever client is at
  `--tailscale-socket` (Tailscale's usual socket by default). The image
  starts its own unless `PARALLAX_TAILSCALED=host`; native installs get
  `parallax-tailscaled.service`, which conflicts with `tailscaled.service`
  and is enabled only on a machine not already on Tailscale.
- **Ownership is read, not configured.** A client that's logged out, or
  logged in as a node of the configured Headscale under the user `parallax`
  (Parallax's own, created on first login), is Parallax's to manage. One
  logged in as any other node is the operator's: Parallax never runs
  `tailscale up` or `set` on it, never approves its routes, and tells the
  operator what to run instead. A node key not known to the configured
  Headscale is left alone too. No configuration field, so no migration.
  Logged out means `LoggedOut` in its prefs (never logged in, or `tailscale
  logout`), not just a missing node key: a `tailscaled` restarted with an
  expired profile has no key either, and its profile's node says whose it is
  (#76).
- **The Headscale user `parallax` is reserved for Parallax's router.**
  Ownership is that user's name, so an operator's own account must not be
  called `parallax` (local or OIDC): Parallax would manage that account's
  nodes as its own. Checking which pre-auth key a node used would need state
  Parallax doesn't keep, for a name an operator can simply avoid.
- **Driven through the `tailscale` CLI** (`status --json`, `debug prefs`,
  `up`, `set`), like `wg` and `nft` (ADR 0001), through `ProcessRunner`.
  Headscale's API creates the user and a single-use pre-auth key (void after
  two days if the login fails) and approves routes. The key goes to
  `tailscale up` on stdin (`--auth-key=file:/dev/stdin`), never in argv.
- **Its settings are Parallax's:** routes to each network's client subnet
  plus the DNS and proxy addresses (so Tailscale devices use the same DNS
  address as WireGuard's, wherever the router's tailnet IP is), netfilter
  mode off, no SNAT, no accepted DNS or routes. Each network's `masquerade`
  decides NAT for both transports. Approved routes are set to exactly the
  advertised ones, so a removed network is withdrawn.
- **The daemon keeps it so**, every 30 seconds and after each saved change,
  in a task of its own: it doesn't touch the database, so it doesn't go
  through the engine. Problems are logged once; `parallax doctor` reports
  the state and only warns. A look whose configuration is replaced, or that
  is in flight when the daemon stops, changes nothing more.
- **It stops routing when Parallax stops.** Its own filtering is off, so
  without Parallax's firewall it would forward Tailscale peers into unmapped
  networks unfiltered (#75). A stopping daemon first takes its own router's
  routes away (`tailscale set --advertise-routes=`: tailscaled then drops
  forwarded packets at once, Headscale or not), then removes the firewall.
  If that fails or takes too long, the daemon fails closed: it leaves the
  firewall and `wg0` in place, as a crash does, and says so. A node key the
  last look found as Parallax's is trusted at shutdown without asking
  Headscale; a client is matched to its Headscale node by key and node id,
  since an earlier login can leave two nodes with one key.
  `parallax-tailscaled.service` is `PartOf=parallax.service` and wanted by
  it, so it stops, restarts and starts with Parallax.
- **Native `tailscaled` runs as root, bounded:** only `CAP_NET_ADMIN` and
  `CAP_NET_RAW`, only `/dev/net/tun`, the service's sandbox otherwise. Its
  `ExecStartPost` makes `parallax` its operator, so the unprivileged daemon
  can manage it.

## Consequences

- A machine already on hosted Tailscale (not the configured Headscale) can't
  be the router; Parallax says so.
- The operator's own router needs their hands on every route change.
- `tailscale up --reset` puts every setting back on login, so manual
  changes to Parallax's own router don't survive (by design).
- Tags, `autoApprovers` and the ACL policy (step 12) can later replace the
  API route approval; the ownership rule stays.
