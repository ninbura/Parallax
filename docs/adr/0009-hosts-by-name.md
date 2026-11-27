# ADR 0009: Hosts by DNS name

Status: accepted (step 7a; the home's public IP since 7a.2).

## Decision

A service's `host` and a `host` grant's `host` may be a DNS name
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
  real subnet, or be the home's public IP (ADR 0008); otherwise the whole
  answer is refused. A changed or spoofed answer can't open a host Parallax
  doesn't know about.
- **The home's public IP is port forwards.** A name that resolves there is
  a service the router forwards in (no local path or record). Every port
  there may lead to a different machine, and a web port to every site
  behind one nginx. So for a tier that doesn't reach it anyway (one
  without both `all_networks` and `internet`):
  - listed ports only: a `host` rule there without ports is refused;
  - no raw web ports (tcp/80, tcp/443, udp/443): web traffic must be a
    service with `hostnames`, so the HTTPS proxy checks the name and
    connects to the public IP itself.

  A granted port gets an accept to the public IP out the WAN interface,
  masqueraded; the router hairpins it to the forward. That's what a guest
  with full tunnel needs: it otherwise drops the address (ADR 0008). DNS
  passes the public answer unchanged, so a split-tunnel guest connects
  over its own internet and the gateway isn't involved (the forward is
  public anyway). Client configs never route the public IP: it changes.
  When it does, the old address stops counting as home at once, and the
  name is looked up again.
- **An input to generation.** The addresses are passed in
  (`Model::with_names`), like the date and the home's public IP, so the
  ruleset stays deterministic and tests need no DNS. A name with several
  addresses grants all of them; the HTTPS proxy's upstream is the lowest.
- **When.** The daemon looks every name up right after startup, every 5
  minutes, and when a saved change alters the names or the networks; it
  re-applies only when an address changed. `parallax apply` without a
  daemon looks too.
- **Only the latest answer counts.** A lookup that fails, comes back empty
  or is refused leaves the name granting nothing (no rule; never open)
  until it resolves again, and the daemon logs why once. An earlier answer
  is never kept in its place: a name that's gone may have been dropped on
  purpose, and its old address may belong to something else by now.
  Answers aren't stored either; after a restart the first lookups run right
  after the first apply.
- **A save can't add a problem.** The daemon looks up the names a change
  adds, and the names whose resolvers it changes (`upstream_dns`, or a zone
  moved to another network), before saving it. It refuses the change if one
  doesn't resolve or resolves outside every network, naming the host and
  why; a typo fails loudly. It also refuses a change that leaves a known
  address outside every network (a subnet edited under it) or off the
  home's public IP (`server.public_ip.address` edited). Problems that were
  already there don't block unrelated changes: a resolver being down must
  never stop the operator removing a peer, and a grant's problem never
  stops changing a peer's other grants. A problem is named by its grant
  and rule, not by who holds them. Without a daemon, the CLI saves without asking
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
- **Keeping the last good answer when a lookup fails** (the plan before
  7a.1 was merged). It rides out a resolver restart, but a grant would
  outlive its name: drop a record, or point a new name at the same host,
  and the old name would keep granting. A resolver outage costing guests
  their named hosts for a few minutes is the safer failure.
- **Refusing every save while a name can't be looked up.** It would lock the
  operator out of unrelated changes whenever the home resolver is down.
- **Any public address.** A name could point at a VPS too, but then a
  spoofed answer could open any host on the internet to a guest. Only the
  home's own address, which Parallax already tracks, is allowed.
- **Answering a tunnel address for names on the public IP**, so every
  guest's traffic reaches the gateway. Split-tunnel guests reach the
  forward anyway, and it would mean rewriting public answers.
- **Matching a name and an address for the same machine** in the warning
  about grants that bypass the HTTPS proxy. Hosts are compared as written;
  doing it by resolved address would make a validation warning depend on DNS.
