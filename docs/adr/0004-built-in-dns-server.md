# ADR 0004: A built-in DNS server instead of dnsmasq

Status: accepted (step 3d, before M2)

## Decision

Parallax answers DNS itself: `parallax dns` (crate `parallax-dns`, on
hickory's server and resolver) replaces the dnsmasq shim at the same address
and port. It picks the tier from the query's source address and answers only
the names that tier may reach: its granted networks' zones and its granted
services' hostnames, plus public names for templates with `dns.public`.
Everything else is refused. Home answers are rewritten into mapped space with
the same `Mapping` the NETMAP rules use.

## Why

- **dnsmasq answers every client the same.** A guest who points DNS at the
  gateway gets every home name and has every public lookup forwarded out
  through the operator's connection. The proxy and the firewall already stop
  the traffic; DNS shouldn't hand out the map either.
- **One server per template doesn't work.** Headscale's split DNS is
  tailnet-wide, so Tailscale nodes of every template ask the same address.
  It has to be one server that checks who's asking.
- **The rewrite has to match NETMAP.** dnsmasq's `alias=` was a second copy
  of the mapping in another syntax. Now both come from one function.
- It also drops a process restart on every `apply` (dnsmasq can't reload
  `server=`/`alias=`) and the `--user=root` workaround a native install
  would need.

## Rejected

- **BIND9, Unbound, CoreDNS.** They can answer per client (views, ACLs), but
  none can rewrite `192.168.x` answers into `198.18.x` (CoreDNS only with a
  custom Go plugin).
- **dnsmasq per template.** Breaks on Tailscale (above), and still forwards a
  public-enabled template's lookups with no per-name limit.
- **A hand-written UDP/TCP server on hickory-proto alone.** Truncation, EDNS,
  TCP framing, retries and caching are where DNS servers go wrong; hickory's
  server and resolver already do them.

## Scope

A forwarder, nothing more: no records of its own, no recursion, a small cache
per upstream. DNS stays convenience, never enforcement: the firewall and the
HTTPS proxy are the gate.
