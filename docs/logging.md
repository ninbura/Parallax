# Activity logging

Parallax can record who did what through the gateway: which peer connected
where, how much it sent and received, and what the firewall blocked. It's
off for everyone until you turn it on, and off costs nothing: no firewall
rules, no events read.

> This version sets the levels up and prepares the firewall. The collector
> that records them, and `parallax log` to read the records, come in the
> next release.

## Levels

Each level includes the ones before it.

| Level | Records |
|---|---|
| `off` | nothing (the default) |
| `connections` | one record per new connection: peer, destination (as the peer saw it and as it really is), protocol, port |
| `bytes` | also the bytes each way when a connection ends |
| `denied` | also attempts the firewall blocked, at most 20 a second |

DNS queries are not part of any level. They will be a separate opt-in,
since they say more about a person than their connections do.

## Who gets which level

Set a level for everyone, for a grant's peers, or for one peer:

```sh
parallax log level connections                       # everyone (server.logs.level)
parallax log level denied --grant family             # the peers that have 'family'
parallax log level off --peer laptop                 # one peer, whatever its grants say
parallax log level inherit --peer laptop             # back to its grants' level
```

A peer's own level wins. Otherwise it gets the most detailed level among its
grants (grants for everyone included). Otherwise it gets `server.logs.level`.
So "guests logged, my own devices not" is `log level denied --grant family`
with the global level left at `off`.

The same settings live in the configuration (`config edit`):

```toml
[server.logs]
level = "off"
path = "/var/lib/parallax/logs.db"
keep = "30d"
max_size = "1GiB"

[[grant]]
name = "family"
log = "denied"
rules = [...]
```

## Where records go

Records go in their own database, `logs.db`, next to the configuration by
default. `path` moves it: on a Raspberry Pi, put it on a USB SSD rather than
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

`parallax doctor` warns when a peer logs `bytes` or more and it's off.
Without it, connections are still logged, without their bytes.

## How it works

The firewall marks the new connections of logged peers (bit `0x20000000` of
the connection mark, leaving the other bits alone), so the collector keeps
only theirs. Just before each drop a logged peer can hit, a rate-limited rule
hands the blocked packet to the collector (nflog group 20568). Peers at `off`
are in neither set, and with nobody logged neither the sets nor the rules
exist. Nothing is logged per packet: connections are recorded once when they
start and once when they end.
