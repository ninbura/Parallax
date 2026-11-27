# Activity logging

Parallax can record who did what through the gateway: which peer connected
where, how much it sent and received, what the firewall blocked, which sites
it used through the HTTPS proxy and, if you ask, which names it looked up.
It's off for everyone until you turn it on, and off costs nothing: no
firewall rules, no events read.

## Levels

The levels work like log verbosity: each includes the ones before it, and the
first is the one that matters most.

| Level | Records | Like |
|---|---|---|
| `off` | nothing (the default) | silent |
| `blocked` | attempts the firewall stopped, rate-limited, and what the HTTPS proxy refused | warnings |
| `connections` | also one record per new connection: peer, destination (as the peer saw it and as it really is), protocol, port; and one per request through the HTTPS proxy: site, method, status | info |
| `detailed` | also the bytes each way when a connection ends, and of each proxied request | debug |

The names say what's recorded rather than borrowing `warnings` or `debug`:
this is a record of what people do, and `connections` on someone's phone is
a list of every service it reaches. `blocked` alone is cheap and private, a
good level for guests.

The HTTPS proxy never records a URL's path, at any level. The site says
which service someone used; the path says what they did in it (which photo,
which album, which search).

DNS queries are not part of any level: they're a [separate
switch](#dns-queries), since the names someone looks up say more about them
than their connections do.

## Who gets which level

Set a level for everyone, for a grant's peers, or for one peer:

```sh
parallax log level connections                       # everyone (server.logs.level)
parallax log level blocked --grant family            # the peers that have 'family'
parallax log level off --peer laptop                 # one peer, whatever its grants say
parallax log level inherit --peer laptop             # back to its grants' level
```

A peer's own level wins. Otherwise it gets the most detailed level among its
grants (grants for everyone included). Otherwise it gets `server.logs.level`.
Only WireGuard peers are logged so far: a Tailscale peer's settings are kept
but record nothing yet.
So "my guests' blocked attempts, nothing of my own devices" is `log level
blocked --grant family` with the global level left at `off`.

The same settings live in the configuration (`config edit`):

```toml
[server.logs]
level = "off"
path = "/var/lib/parallax/logs.db"
keep = "30d"
max_size = "1GiB"

[[grant]]
name = "family"
log = "blocked"
rules = [...]
```

## DNS queries

Off unless you turn it on, and no level turns it on. Set it the same three
ways:

```sh
parallax log dns on --grant family                   # the peers that have 'family'
parallax log dns off --peer laptop                   # one peer, whatever its grants say
parallax log dns inherit --peer laptop               # back to its grants'
parallax log dns on                                  # everyone (server.logs.dns)
```

A peer's own setting wins. Otherwise it's on if any of its grants that say
turn it on, otherwise `server.logs.dns`. In the configuration that's `dns =
true` under `[server.logs]` and `log_dns = true` on a grant or peer.

Each query is one record: the name, its type (`A`, `AAAA`, `HTTPS`, ...)
and how it was answered: `answered`, `refused` (the peer may not look it
up), `nxdomain` (no such name) or `failed`. Never the addresses in the
answer; the connection records show where the peer went. Only queries to the
gateway's DNS server are seen: a peer set up to use another resolver
bypasses it.

## Reading records

```sh
parallax log show                          # the newest 50, oldest first
parallax log show --peer sister-phone --since 1d
parallax log show --kind blocked,blocked_gateway,refused --limit 200
parallax log show --follow                 # and keep showing new ones
```

Each line is one record:

```
2026-11-26T10:50:05Z  sister-phone  opened  tcp 198.18.1.5:2283 (192.168.1.5, home)  grants family
2026-11-26T10:50:19Z  sister-phone  closed  tcp 198.18.1.5:2283 (192.168.1.5, home)  1.2 KiB out, 33.2 KiB in  grants family
2026-11-26T10:50:06Z  sister-phone  blocked  tcp 198.18.1.5:8080 (192.168.1.5, home)  grants family
2026-11-26T10:51:12Z  sister-phone  query  udp 10.8.0.1:53  immich.example.com. A answered  grants family
2026-11-26T10:51:12Z  sister-phone  request  tcp 198.18.1.5:443 (192.168.1.5, home)  GET immich.example.com 200  0 B out, 48.1 KiB in  grants family
2026-11-26T10:51:40Z  sister-phone  refused  tcp 198.18.1.5:443 (192.168.1.5, home)  GET immich.example.com 421: this connection serves a different hostname  grants family
```

The destination is the address the peer used, then in brackets the real one
and its network. `blocked_gateway` is a blocked attempt at the gateway host
itself. `request` is a request through the HTTPS proxy (method, site,
status), recorded when its response is done (a WebSocket's when it closes,
with what it carried); `refused` is one the proxy turned away, with why: a
request naming another site, or a connection for a site the peer may not
use, or one that's no site at all (then the destination is the proxy
itself). `query` is a DNS query. `opened` records come from `connections` up, `closed` ones (with the
bytes) only at `detailed`. Names are kept as they were, so records survive
renaming or removing a peer or grant. A connection's `closed` record comes some seconds after it
closes: the kernel reports a connection's end when it next sweeps its
connection table.

With a daemon running, `log show` asks it; without one, it reads `logs.db`
itself.

## Where records go

Records go in their own database, by default `/var/lib/parallax/logs.db`,
beside the configuration's. `path` moves it: on a Raspberry Pi, put it on a USB SSD rather than
the SD card, which constant small writes wear out; or on `tmpfs` if records
should end at reboot. With Docker, mount a second volume there.

Records are deleted once they're older than `keep` or once they take up more
than `max_size`, whichever comes first, checked every 10 minutes. Past
`max_size`, the oldest go until the records take up 90% of it. Deleted
records leave space that new ones reuse, so the file levels off at about
`max_size` rather than shrinking.

Backups never include records ([backups](backup.md)): a backup would keep
them past `keep`, in every copy made of it, and they aren't needed to
rebuild a gateway. Restoring one leaves `logs.db` as it is.

## Byte counts need a host setting

The kernel counts each connection's bytes only when asked to. Like
`ip_forward`, it's a host setting the container can't change:

```sh
echo 'net.netfilter.nf_conntrack_acct = 1' | sudo tee /etc/sysctl.d/91-parallax-logs.conf
sudo sysctl --system
```

`parallax doctor` warns when a peer logs at `detailed` and it's off.
Without it, connections are still logged, without their bytes.

## How it works

The firewall marks the new connections of logged peers (bit `0x20000000` of
the connection mark, leaving the other bits alone), so the collector keeps
only theirs. Just before each drop a logged peer can hit, a rate-limited rule
hands the blocked packet to the collector (nflog group 20568), at most 20 a
second per rule with bursts of 40, so a peer scanning ports can't flood it.
Peers at `off` are in neither set, and with nobody logged neither the sets
nor the rules exist, and the daemon doesn't read either feed (ADR 0012).

The HTTPS proxy and the DNS server each hand the collector what logged
peers do: the proxy for peers at `blocked` and up, the DNS server for peers
whose queries are logged. They check the caller against that list first, so
anyone else's requests and queries are never handed over. They hand over
through a queue that drops (and says so in the log) rather than slow a
request down. Connections are recorded once when they start and once
when they end, not per packet; blocked attempts are per packet, within that
limit. Packets dropped for being out of a connection's state (stale or
malformed) aren't blocked attempts and aren't logged.
