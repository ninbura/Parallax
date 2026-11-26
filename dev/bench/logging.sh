#!/usr/bin/env bash
# Activity logging cost benchmark on network namespaces (docs/logging.md).
#
# A. Per packet: a WireGuard peer uploads with iperf3 through the gateway to
#    a host on the mapped home LAN, with the peer at `off`, `connections` and
#    `denied`. Throughput and CPU show what the logging rules cost each packet.
# B. Per connection: with the daemon running, a flood of short TCP
#    connections, (1) nobody logged, (2) from the logged peer itself (every
#    event kept and written), (3) from the gateway host with nobody logged
#    and (4) with the peer logged (every event read and discarded: the
#    host-wide cost). Connections
#    per second, the daemon's CPU, records written and events the kernel
#    dropped show what the collector costs.
#
# Needs root, nft, wg, ip, iperf3 and python3, and a release build:
#   cargo build --release && sudo dev/bench/logging.sh [path/to/parallax]
# Tunables: SECONDS_PER_RUN (10), RUNS (3), FLOOD_SECONDS (10), FLOODERS (4).
#
# Every process shares one kernel, so CPU is the whole machine's: compare
# scenarios on one machine, not absolute numbers between machines.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=${1:-$ROOT/target/release/parallax}
SECONDS_PER_RUN="${SECONDS_PER_RUN:-10}"
RUNS="${RUNS:-3}"
FLOOD_SECONDS="${FLOOD_SECONDS:-10}"
FLOODERS="${FLOODERS:-4}"
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
for t in nft wg ip iperf3 python3; do command -v $t >/dev/null || { echo "missing $t"; exit 2; }; done
[ -x "$BIN" ] || { echo "parallax binary not found at $BIN"; exit 2; }

NAMESPACES="lbhome lbgw lbclient"
for ns in $NAMESPACES; do
    ip netns list | grep -q "^$ns\( \|$\)" && { echo "namespace $ns already exists; delete it first"; exit 2; }
done
WORK=$(mktemp -d /tmp/parallax-logbench.XXXXXX)
DAEMON_PID=
cleanup() {
    set +e
    [ -n "${KEEP_LOG:-}" ] && cp "$WORK/daemon.log" "$KEEP_LOG" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    for ns in $NAMESPACES; do ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null; done
    sleep 0.3
    for ns in $NAMESPACES; do ip netns del $ns 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT
inns() { ip netns exec "$@"; }

# ---------------------------------------------------------------- topology
for ns in $NAMESPACES; do ip netns add $ns; inns $ns ip link set lo up; done
ip link add eth0 netns lbgw type veth peer name lan0 netns lbhome
ip link add wan0 netns lbgw type veth peer name wan0 netns lbclient
inns lbgw ip addr add 192.168.1.1/24 dev eth0;   inns lbgw ip link set eth0 up
inns lbgw ip addr add 203.0.113.1/24 dev wan0;   inns lbgw ip link set wan0 up
inns lbhome ip addr add 192.168.1.5/24 dev lan0; inns lbhome ip link set lan0 up
inns lbhome ip route add 10.8.0.0/16 via 192.168.1.1
inns lbclient ip addr add 203.0.113.2/24 dev wan0; inns lbclient ip link set wan0 up
inns lbgw sysctl -qw net.ipv4.ip_forward=1
inns lbgw sysctl -qw net.netfilter.nf_conntrack_acct=1 2>/dev/null || true
# Many short connections: let closed ones go at once.
inns lbgw sysctl -qw net.netfilter.nf_conntrack_tcp_timeout_time_wait=1 2>/dev/null || true
inns lbhome iperf3 -s -D --logfile "$WORK/iperf3-server.log"

# A TCP server that accepts and closes, for the flood.
cat > "$WORK/accept.py" <<'PY'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 7000))
s.listen(4096)
while True:
    c, _ = s.accept()
    c.close()
PY
inns lbhome python3 "$WORK/accept.py" &
# Connects and closes as fast as it can for N seconds from a source address;
# prints the count.
cat > "$WORK/flood.py" <<'PY'
import socket, sys, time
src, dst, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
end, n = time.monotonic() + seconds, 0
while time.monotonic() < end:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    try:
        s.bind((src, 0)) if src else None
        s.connect((dst, 7000))
        n += 1
    except OSError:
        pass
    finally:
        s.close()
print(n)
PY

cat > "$WORK/parallax.toml" <<TOML
[server.wireguard]
supernet = "10.8.0.0/16"
endpoint = "203.0.113.1:51820"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private_key_file = "$WORK/wg-server.key"
[server.firewall]
docker_coexistence = false
[server.proxy]
certificates = "$WORK/certs"
[server.logs]
path = "$WORK/logs.db"
[[network]]
name = "home"
interface = "eth0"
subnet = "192.168.1.0/24"
mapped_to = "198.18.1.0/24"
upstream_dns = ["192.168.1.5"]
domains = ["bench.test"]
[[grant]]
name = "bench"
rules = [{ kind = "host", host = "192.168.1.5", ports = ["5201", "7000/tcp"] }]
TOML
mkdir -p "$WORK/certs"
SOCK="$WORK/parallax.sock"
P=("$BIN" --db "$WORK/parallax.db" --socket "$SOCK")
"${P[@]}" config import "$WORK/parallax.toml" >/dev/null
"${P[@]}" keygen --write-config >/dev/null
GW_PUB=$(wg pubkey < "$WORK/wg-server.key")
"${P[@]}" peer add bench --grant bench --keep-private-key --platform linux > "$WORK/bench.conf" 2>/dev/null
ADDR=$(sed -n 's|^Address = \(.*\)/32$|\1|p' "$WORK/bench.conf")
inns lbgw "${P[@]}" apply -o "$WORK/out" >/dev/null
inns lbclient ip link add wgb type wireguard
inns lbclient ip addr add "$ADDR/32" dev wgb
inns lbclient wg set wgb private-key <(sed -n 's/^PrivateKey = //p' "$WORK/bench.conf") \
    peer "$GW_PUB" endpoint 203.0.113.1:51820 allowed-ips 198.18.1.0/24
inns lbclient ip link set wgb up
inns lbclient ip route add 198.18.1.0/24 dev wgb src "$ADDR"
inns lbclient iperf3 -c 198.18.1.5 -t 2 >/dev/null   # warm up, handshake

cpu_busy() { # jiffies busy and total across all CPUs
    awk '/^cpu / { idle = $5 + $6; total = 0; for (i = 2; i <= NF; i++) total += $i; print total - idle, total }' /proc/stat
}
proc_jiffies() { # utime + stime of a process and its threads
    awk '{ print $14 + $15 }' "/proc/$1/stat"
}

level() { # level for the bench peer, applied (directly or through the daemon)
    "${P[@]}" log level "$1" --peer bench >/dev/null 2>&1
    [ -n "$DAEMON_PID" ] || inns lbgw "${P[@]}" apply -o "$WORK/out" >/dev/null
    sleep 1
}

# ---------------------------------------------------------------- A: per packet
echo "A. per packet: iperf3 through the tunnel, $SECONDS_PER_RUN s per run, $(nproc) CPUs"
printf '%-6s %-12s %4s %8s %7s %11s\n' mode level run Gbit/s cores cores/Gbit
for mode in ${MODES:-tcp udp}; do
    args=(); [ "$mode" = udp ] && args=(-u -b 0 -l 1200)
    for lvl in off connections denied; do
        level "$lvl"
        for run in $(seq 1 "$RUNS"); do
            before=$(cpu_busy)
            inns lbclient iperf3 -c 198.18.1.5 -t "$SECONDS_PER_RUN" "${args[@]}" -J > "$WORK/run.json"
            after=$(cpu_busy)
            python3 - "$mode" "$lvl" "$run" "$(nproc)" "$before" "$after" "$WORK/run.json" <<'PY'
import json, sys
mode, lvl, run, ncpu = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
b_busy, b_total = map(int, sys.argv[5].split())
a_busy, a_total = map(int, sys.argv[6].split())
end = json.load(open(sys.argv[7]))["end"]
gbps = (end["sum_received"]["bits_per_second"] if "sum_received" in end
        else end["sum"]["bits_per_second"] * (1 - end["sum"]["lost_percent"] / 100)) / 1e9
cores = (a_busy - b_busy) / (a_total - b_total) * ncpu
print(f"{mode:<6} {lvl:<12} {run:>4} {gbps:>8.2f} {cores:>7.2f} {cores / gbps:>11.3f}")
PY
        done
    done
done

# ---------------------------------------------------------------- B: per connection
start_daemon() {
    rm -f "$WORK"/logs.db*
    # Not through `inns`: a function runs in a subshell, and $! would be its.
    ip netns exec lbgw "${P[@]}" daemon -o "$WORK/out" --reconcile-every 60 >> "$WORK/daemon.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 100); do "${P[@]}" status >/dev/null 2>&1 && break; sleep 0.1; done
    # wg0 is new: wait for the peer's next handshake.
    for _ in $(seq 100); do
        inns lbclient timeout 1 bash -c 'exec 3<>/dev/tcp/198.18.1.5/7000' 2>/dev/null && break
        sleep 0.2
    done
    sleep 1
}
stop_daemon() { # the collector writes what it holds on the way down
    kill -TERM "$DAEMON_PID"
    for _ in $(seq 300); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
    kill -0 "$DAEMON_PID" 2>/dev/null && { echo "the daemon didn't stop"; exit 1; }
    DAEMON_PID=
}

flood() { # level, namespace, source address ('' for the host's own), destination, label
    local lvl=$1 ns=$2 src=$3 dst=$4 label=$5 before_d before_c after_d after_c total=0
    "${P[@]}" log level "$lvl" --peer bench >/dev/null 2>&1
    start_daemon
    local dropped_before
    dropped_before=$(grep -c 'dropped' "$WORK/daemon.log" || true)
    before_d=$(proc_jiffies "$DAEMON_PID"); before_c=$(cpu_busy)
    local pids=() out=()
    for i in $(seq 1 "$FLOODERS"); do
        out+=("$WORK/flood.$i")
        inns "$ns" python3 "$WORK/flood.py" "$src" "$dst" "$FLOOD_SECONDS" > "$WORK/flood.$i" &
        pids+=($!)
    done
    wait "${pids[@]}"
    after_d=$(proc_jiffies "$DAEMON_PID"); after_c=$(cpu_busy)
    for f in "${out[@]}"; do total=$((total + $(cat "$f"))); done
    sleep 15   # flows end (conntrack's sweep) and the collector writes
    stop_daemon
    # Without a daemon, `log show` reads logs.db itself, whatever its size.
    local records=0
    [ -e "$WORK/logs.db" ] && records=$("${P[@]}" log show --limit 4000000000 --kind opened 2>/dev/null | wc -l)
    local dropped
    dropped=$(( $(grep -c 'dropped' "$WORK/daemon.log" || true) - dropped_before ))
    python3 - "$label" "$total" "$FLOOD_SECONDS" "$before_d" "$after_d" "$before_c" "$after_c" \
        "$(getconf CLK_TCK)" "$(nproc)" "$records" "$dropped" <<'PY'
import sys
label, total, secs = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
bd, ad, tck, ncpu = int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[8]), int(sys.argv[9])
b_busy, b_total = map(int, sys.argv[6].split())
a_busy, a_total = map(int, sys.argv[7].split())
daemon = (ad - bd) / tck / secs * 100
machine = (a_busy - b_busy) / (a_total - b_total) * ncpu
print(f"{label:<34} {total / secs:>9.0f} {daemon:>9.1f} {machine:>7.2f} {sys.argv[10]:>8} {sys.argv[11]:>7}")
PY
}

echo
echo "B. per connection: $FLOODERS flooders for $FLOOD_SECONDS s; daemon% is one core"
echo "   records: opened records written; dropped: overflow reports"
printf '%-34s %9s %9s %7s %8s %7s\n' scenario conn/s daemon% cores records dropped
for run in $(seq 1 "$RUNS"); do
    flood off lbclient "$ADDR" 198.18.1.5 "nobody logged, peer floods"
    flood connections lbclient "$ADDR" 198.18.1.5 "peer logged, peer floods"
    # The host's own connections go to the real address (NETMAP is for
    # tunnels). With a peer logged the collector reads and discards them all.
    flood off lbgw "" 192.168.1.5 "nobody logged, gateway host floods"
    flood connections lbgw "" 192.168.1.5 "peer logged, gateway host floods"
done
