# ADR 0008: The home's public IP

Status: accepted (step 7.2).

## Decision

A guest template with `internet` (and not `all_networks`) reaches public
addresses only. The home's own public address is public too, but the router
hairpins traffic sent to it back into the home's port forwards, so a guest
would reach what its grants leave out. Each such template's chain drops the
home's public IP: it's in the set of addresses its `internet` accept
excludes. The address is an input to
generation, like the date, so the ruleset stays deterministic.

- **Only when needed.** No such template, no lookup at all.
- **Where it comes from, in order:** `server.public_ip.address` (a fixed
  address, no lookup); the WireGuard endpoint's host when it's a public
  IPv4 address (a private one is a lab or double NAT, not the home's
  public IP); the endpoint's hostname through `server.dns.public_resolver`
  (plain DNS), accepted only when the answer is exactly one public address;
  then each `server.public_ip.encrypted_dns` provider in order (DNS over
  HTTPS, off by default). Providers are tried one after another, never
  raced, so the next one only sees the question when the one before failed.
- **Encrypted DNS is reached by IP address** with its TLS name (Quad9
  `9.9.9.9`/`149.112.112.112` `dns.quad9.net`; Cloudflare
  `1.1.1.1`/`1.0.0.1` `cloudflare-dns.com`), so no lookup comes first.
  Certificates are checked against `server.proxy.upstream_ca`. Quad9 is the
  suggested first: it records no client IP addresses; Cloudflare truncates
  them and deletes them within 25 hours.
- **A set member, not a rule.** The address joins the `not_public` set
  that public-only `internet` accepts exclude, so a grant listed after
  `internet` that covers it (a network on public space) still works.
- **The configuration wins.** A fixed address or an IPv4 endpoint is in
  effect the moment it's saved (`public_ip::effective`); only a hostname
  waits for a lookup. `plan` and `generate` use the same rule.
- **When.** The daemon looks at startup (before the first apply), every 5
  minutes, and when a saved change alters what the lookup depends on; it
  re-applies only when the address in effect changes. A result for
  settings that changed while it ran is dropped. A save looks first when it
  looks names up and the address known wasn't found from its settings, or
  when it moves the endpoint of a configuration that uses names; it keeps
  what it finds only if the save is accepted, and a lookup that started
  before it is dropped. Without a daemon, `parallax apply` looks and stores
  what it finds; `plan`, `generate`, `export` and `peer show` look without
  storing, so they show what `apply` would do. Each lookup gives up after 3 seconds per nameserver,
  and runs off the engine thread, so saves never wait on it.
- **Kept across restarts** in the `daemon_state` table: runtime state, not
  configuration. It's never exported, a save doesn't touch it, and a
  restore keeps this machine's value. All lookups failing keeps the last
  known address and logs why once; never known, `apply` and `doctor` warn
  and there is no rule to add.

## Why

- The test server's resolver answers the endpoint's own hostname with the
  LAN address (a wildcard), and outbound DNS is blocked except to it. A
  plain lookup there can't find the public address; DNS over HTTPS on port
  443 can.
- An answer that isn't a public address is a resolver rewriting the name,
  never the home's public IP, so it's refused rather than dropped as the
  wrong rule.

## Rejected

- **A "what's my IP" service by default.** It tells a third party the home's
  address every 5 minutes. The operator can always set the address.
- **Plain DNS to a public resolver as a fallback.** Blocked exactly where it
  matters, and in clear text.
- **Mullvad's DNS.** Proposed as the second no-log provider; Mullvad shut its
  public DNS down on 2026-11-02.
- **Several addresses.** A home connection has one public IPv4 address; an
  answer with several is refused instead of guessed at. Set the address if
  that's wrong for you.
