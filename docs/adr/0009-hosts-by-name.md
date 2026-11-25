# ADR 0009: Hosts by DNS name

Status: accepted (step 7a).

## Decision

A service's `host` and a `host`/`host_port` grant's `host` may be a DNS name
instead of an address (`host = "nas.mydomain.com"`). The gateway looks the
name up and grants exactly the addresses it has, on the grant's ports. The
home's DNS stays the only place a machine's address is written down.

- **Spelling.** One key, `host`, takes an address or a name: whatever isn't
  an IPv4 address is a name, and must be a valid lower-case DNS name. Grants
  written with the older `ip = ...` still import; export writes `host`. A
  service already has `hostnames` (the names its HTTPS proxy lets through),
  so a separate `hostname` key next to it would invite mix-ups.
- **Where it's asked.** The name must be inside a network's `domains`
  (validation refuses it otherwise), and it's looked up through that
  network's `upstream_dns`, in order: the first resolver that answers
  decides, an empty answer included. That's the resolver the DNS server
  already sends the zone to, so the gateway and its clients see the same
  answer.
- **Allowed answers.** Every address must be inside a configured network's
  real subnet; otherwise the whole answer is refused. A changed or spoofed
  answer can't open a host Parallax doesn't know about.
- **An input to generation.** The addresses are passed in
  (`Model::with_names`), like the date and the home's public IP, so the
  ruleset stays deterministic and tests need no DNS. A name with several
  addresses grants all of them; the HTTPS proxy's upstream is the lowest.
- **When.** The daemon looks every name up right after startup, every 5
  minutes, and when a saved change alters the names or the networks; it
  re-applies only when an address changed. `parallax apply` without a
  daemon looks too.
- **Failure keeps the last good answer.** A lookup that fails or is refused
  keeps the addresses found before, and logs why once. A name never found
  grants nothing (no rule; never open), with a warning. The last good
  answers are kept in `daemon_state` (`name:<hostname>`), so a restart
  doesn't lose them, and a restore leaves them alone.
- **A save can't add a problem.** The daemon looks up the names a change
  adds before saving it, and refuses the change if one doesn't resolve or
  resolves outside every network, naming the host and why; a typo fails
  loudly. It also refuses a change that leaves a known address outside every
  network (a subnet edited under it). Problems that were already there don't
  block unrelated changes: a resolver being down must never stop the
  operator removing a peer. Without a daemon, the CLI saves without asking
  DNS; the daemon warns when it starts.
- **DNS for the tier.** A host granted by name, or a granted service whose
  host is a name, lets the tier look that name up (one name, not its zone),
  like a service's `hostnames`.
- **Client configs.** A `grants_only` export routes the addresses a name had
  when it was exported. If the host moves to an address outside them, export
  the config again (or use `mapped_subnets`, which routes whole networks).

## Why

- Addresses change (DHCP, a moved container) while names don't; the home
  DNS already knows them. A non-web service (a game server, SMB) could only
  be reached by name by granting its whole network.
- Resolving through the zone's own resolvers matches what clients are told,
  and a home resolver often answers names the public internet doesn't know.

## Rejected

- **Re-resolving on the record's TTL.** The `Resolver` trait gives no TTL,
  home records rarely change, and a fixed 5-minute interval is what the
  public IP lookup already uses. A grant follows a changed address within
  minutes either way.
- **Refusing every save while a name can't be looked up.** It would lock the
  operator out of unrelated changes whenever the home resolver is down.
- **Matching a name and an address for the same machine** in the warning
  about grants that bypass the HTTPS proxy. Hosts are compared as written;
  doing it by resolved address would make a validation warning depend on DNS.
