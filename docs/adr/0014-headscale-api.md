# ADR 0014: Headscale from source, read through its API

Status: accepted (step 11a). The first part of the Headscale transport.
Builds on ADR 0007 (the daemon) and ADR 0010 (named grants).

## Context

Tailscale devices log in to Headscale, which gives each one (a node) an
address in `100.64.0.0/10`. The firewall, the DNS server and the proxy pick
a peer's grants by its source address, so Parallax has to know the address
Headscale gave each Tailscale peer's node, and follow it when it changes.

MagicDNS names and HTTPS certificates for them (`tailscale cert`, HTTPS
`tailscale serve`) must work from the start: apps built on Tailscale expect
them. Headscale implemented certificates in juanfont/headscale#3554, merged
to `main` on 2026-10-18. No release has it yet: v0.29.8 (2026-11-26) is on a
release branch without it. `main` also removed the gRPC API and made the
configuration strict (an unknown or removed key stops Headscale), so the
configuration Parallax shipped for 0.26 no longer loads.

Headscale has two HTTP APIs on `main`. `/api/v1` is its own admin API:
users, nodes, pre-auth keys, routes, the policy. `/api/v2` ports parts of
Tailscale's API, with scoped OAuth credentials, but can't create users.

## Decision

- **Headscale is built from a pinned commit of `main`**
  (`docker/headscale.Dockerfile`), and `docker/compose.yml` builds it
  instead of pulling a release *(since step 20, CI publishes that build as
  `ghcr.io/ninbura/parallax-headscale`, versioned with Parallax, and compose
  pulls it: docs/releasing.md)*. The shipped `docker/headscale/config.yaml`
  passes that build's `headscale check config`, with certificates ready to
  turn on once a DNS provider is set. We go back to the latest stable
  release once one includes certificates.
- **Parallax uses the admin API, `/api/v1`**, at
  `server.headscale.server_url`, with an admin API key read from
  `server.headscale.api_key_file` on every request (so a new key needs no
  restart). HTTPS certificates are checked against
  `server.proxy.upstream_ca`. Later steps need user creation, which only v1
  has.
- **Requests go through a trait** (`io::HeadscaleApi`, one `get`), and
  `parallax_core::headscale` reads the replies. Core tests run against
  replies recorded from the pinned build. Unknown fields in replies are
  ignored, unlike in the configuration: Headscale adds fields between
  releases, and that must not stop the gateway. Error replies show their
  title, detail and messages only, since their `value` fields can echo the
  request.
- **A Tailscale peer's address is its node's.** The daemon asks Headscale
  for its nodes before its first apply, every 10 seconds and when a saved
  change alters where Headscale is, but only while some Tailscale peer names
  a node (`peer.tailscale.node_id`). Addresses are an input to generation
  (`Model::with_tailnet`), like the home's public IP. When they change, the
  daemon applies again, as for any other input. A peer that names a node has
  only the address Headscale gave it: none before Headscale first answers,
  and none once the node is gone. A configured `peer.tailscale.address`
  could belong to another node by then. A peer that names no node keeps its
  configured address. When Headscale stops answering, the last answer stays
  in effect and the failure is logged once: the nodes keep the tunnels they
  have meanwhile, so cutting their access would only break what still
  works. The answer isn't stored, so a restart while Headscale is down
  leaves node peers without access until it answers (fail closed). A saved
  change or a restored backup that points at another Headscale drops the
  last answer: node ids mean nothing there.
- **A node is one peer.** Validation refuses two peers naming the same node,
  whose address would otherwise sit in two tiers.
- **Only addresses in `100.64.0.0/10` count.** Headscale's prefix is
  configurable, but the firewall only takes Tailscale traffic from that
  range.
- **A full apply, not a set refill.** The design had Tailscale sets refilled
  without a new ruleset. A node's address changes only when it registers or
  is deleted, so a full apply (atomic, on both firewall backends, and also
  updating DNS and the proxy) costs little and needs no second path.

## Consequences

- `parallax headscale status` shows Headscale's version, users and nodes,
  and which peer each node is. `parallax doctor` checks that Headscale
  answers with every Tailscale peer's node, only while a peer names one. It
  only warns: doctor gates the gateway's start, and WireGuard, DNS and the
  proxy run without Headscale.
- Proxy certificates are checked for every proxied hostname a tier may use,
  whether or not its peers have addresses yet, so a node appearing later
  can't start failing applies.
  `parallax status` lists the addresses the daemon follows.
- The daemon protocol carries the node addresses (protocol 7).
- The integration test (`netns.sh` (u)) runs a real Headscale from the
  pinned commit and a logged-in node. CI builds both
  (`tests/integration/headscale-binaries.sh`), and builds the image and
  checks the shipped configuration with it.
- Bumping the pinned commit means re-recording the replies the core tests
  use if their shape changed, and checking the configuration again.
- An existing 0.26 Headscale can't jump to this build: Headscale upgrades
  one minor release at a time, through the latest 0.29.x.
- Not yet: creating users and pre-auth keys, matching nodes to Headscale
  users (step 11b), the policy (step 12), approving the subnet router's
  routes (step 13), and Headscale's Unix socket as a way in without an API
  key (managed mode, step 10).
