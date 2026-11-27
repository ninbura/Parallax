# Activity logging

Parallax can record who did what through the gateway: which peer connected
where, how much it sent and received, and what the firewall blocked. It's
off for everyone until you turn it on, and off costs nothing: no firewall
rules, no events read.

> This version sets the levels up and prepares the firewall. The collector
> that records them, and `parallax log` to read the records, come in the
> next release.

## Levels

The levels work like log verbosity: each includes the ones before it, and the
first is the one that matters most.

| Level | Records | Like |
|---|---|---|
| `off` | nothing (the default) | silent |
| `blocked` | attempts the firewall stopped, rate-limited | warnings |
| `connections` | also one record per new connection: peer, destination (as the peer saw it and as it really is), protocol, port | info |
| `detailed` | also the bytes each way when a connection ends | debug |

The names say what's recorded rather than borrowing `warnings` or `debug`:
this is a record of what people do, and `connections` on someone's phone is
a list of every service it reaches. `blocked` alone is cheap and private, a
good level for guests.

DNS queries are not part of any level. They will be a separate opt-in,
since they say more about a person than their connections do.

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

## Where records go

Records go in their own database, by default `/var/lib/parallax/logs.db`,
beside the configuration's. `path` moves it: on a Raspberry Pi, put it on a USB SSD rather than
the SD card, which constant small writes wear out; or on `tmpfs` if records
should end at reboot. With Docker, mount a second volume there.

Records are deleted once they're older than `keep` or once they take up more
than `max_size`, whichever comes first. Backups leave them out by default.

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
nor the rules exist. Connections are recorded once when they start and once
when they end, not per packet; blocked attempts are per packet, within that
limit. Packets dropped for being out of a connection's state (stale or
malformed) aren't blocked attempts and aren't logged.
