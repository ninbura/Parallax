#!/usr/bin/env bash
# Firewall cost benchmark on network namespaces: a WireGuard peer uploads with
# iperf3 through the gateway to a host on the mapped home LAN, under different
# rulesets. Throughput and CPU are compared to see what re-checking every
# packet a peer sends (instead of accepting established flows up front) costs.
#
# Needs root, nft, wg, ip, dnsmasq, iperf3, python3, and two parallax binaries:
#   PARALLAX       the build under test (default: this checkout's target/release)
#   PARALLAX_BASE  the build to compare against, e.g. one built from main
#                  (optional; without it only the new rules are measured)
# Tunables: PADDING (templates placed before the peer's, 4 rules each; 50),
# SECONDS_PER_RUN (10), RUNS (3), STREAMS (1), MODE (tcp, or udp: 1200-byte
# datagrams at full speed). TCP over WireGuard is merged into large packets
# (GRO) before the firewall sees it, so rules run once per ~64 KB; UDP shows
# the per-packet worst case.
#
# Every process shares one kernel, so CPU is the whole machine's: compare
# cores per Gbit/s between scenarios, not absolute numbers between machines.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PARALLAX="${PARALLAX:-$ROOT/target/release/parallax}"
PARALLAX_BASE="${PARALLAX_BASE:-}"
PADDING="${PADDING:-50}"
SECONDS_PER_RUN="${SECONDS_PER_RUN:-10}"
RUNS="${RUNS:-3}"
STREAMS="${STREAMS:-1}"
MODE="${MODE:-tcp}"
case "$MODE" in
    tcp) IPERF_MODE=() ;;
    udp) IPERF_MODE=(-u -b 0 -l 1200) ;;
    *) echo "MODE is tcp or udp"; exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
for t in nft wg ip dnsmasq iperf3 python3; do command -v $t >/dev/null || { echo "missing $t"; exit 2; }; done
for b in "$PARALLAX" ${PARALLAX_BASE:+"$PARALLAX_BASE"}; do
    [ -x "$b" ] || { echo "parallax binary not found at $b"; exit 2; }
done

NAMESPACES="bhome bgw bclient"
for ns in $NAMESPACES; do
    ip netns list | grep -q "^$ns\( \|$\)" && { echo "namespace $ns already exists; delete it first"; exit 2; }
done
WORK=$(mktemp -d /tmp/parallax-bench.XXXXXX)
cleanup() {
    set +e
    for ns in $NAMESPACES; do ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null; done
    sleep 0.2
    for ns in $NAMESPACES; do ip netns del $ns 2>/dev/null; done
    rm -rf "$WORK"
}
trap cleanup EXIT
inns() { ip netns exec "$@"; }

# ---------------------------------------------------------------- topology
for ns in $NAMESPACES; do ip netns add $ns; inns $ns ip link set lo up; done
ip link add eth0 netns bgw type veth peer name lan0 netns bhome
ip link add wan0 netns bgw type veth peer name wan0 netns bclient
inns bgw ip addr add 192.168.1.1/24 dev eth0;   inns bgw ip link set eth0 up
inns bgw ip addr add 203.0.113.1/24 dev wan0;   inns bgw ip link set wan0 up
inns bhome ip addr add 192.168.1.5/24 dev lan0; inns bhome ip link set lan0 up
inns bhome ip route add 10.8.0.0/16 via 192.168.1.1
inns bclient ip addr add 203.0.113.2/24 dev wan0; inns bclient ip link set wan0 up
inns bgw sysctl -qw net.ipv4.ip_forward=1
inns bhome iperf3 -s -D --logfile "$WORK/iperf3-server.log"

# ---------------------------------------------------------------- configs
config() { # padding templates -> config on stdout. The peer's template comes last,
    # so its packets walk past every padding rule first.
    cat <<TOML
[server.wireguard]
supernet = "10.8.0.0/16"
endpoint = "203.0.113.1:51820"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private_key_file = "$WORK/wg-server.key"
[server.firewall]
docker_coexistence = false
[[network]]
name = "home"
interface = "eth0"
subnet = "192.168.1.0/24"
mapped_to = "198.18.1.0/24"
upstream_dns = ["192.168.1.5"]
domains = ["bench.test"]
TOML
    for i in $(seq 1 "$1"); do
        cat <<TOML
[[template]]
name = "pad$i"
grants = [{ kind = "host_port", ip = "192.168.1.$((i % 200 + 20))", port = 80 }]
[template.wireguard]
pool = "10.8.$((i + 10)).0/24"
[template.headscale]
tag = "tag:pad$i"
TOML
    done
    cat <<TOML
[[template]]
name = "bench"
grants = [{ kind = "host_port", ip = "192.168.1.5", port = 5201 }, { kind = "host_port", ip = "192.168.1.5", proto = "udp", port = 5201 }]
[template.wireguard]
pool = "10.8.2.0/24"
[template.headscale]
tag = "tag:bench"
TOML
}

cpu_busy() { # jiffies busy and total across all CPUs
    awk '/^cpu / { idle = $5 + $6; total = 0; for (i = 2; i <= NF; i++) total += $i; print total - idle, total }' /proc/stat
}

# ---------------------------------------------------------------- scenarios
scenario() { # label, binary, padding
    local label=$1 bin=$2 pad=$3 cfg="$WORK/$1.toml"
    config "$pad" > "$cfg"
    if [ ! -f "$WORK/wg-server.key" ]; then
        "$bin" -c "$cfg" keygen --write-config >/dev/null
        GW_PUB=$(sed -n 's/^public_key = "\(.*\)"/\1/p' "$cfg")
    else
        sed -i "s|^public_key = .*|public_key = \"$GW_PUB\"|" "$cfg"
    fi
    "$bin" -c "$cfg" peer add bench --template bench --keep-private-key --platform linux \
        > "$WORK/$label.conf" 2>/dev/null
    inns bgw "$bin" -c "$cfg" apply -o "$WORK/out" >/dev/null
    local rules
    rules=$(inns bgw nft list chain inet parallax forward | grep -c 'comment')
    inns bclient ip link del wgb 2>/dev/null || true
    inns bclient ip link add wgb type wireguard
    inns bclient ip addr add 10.8.2.1/32 dev wgb
    inns bclient wg set wgb private-key <(sed -n 's/^PrivateKey = //p' "$WORK/$label.conf") \
        peer "$GW_PUB" endpoint 203.0.113.1:51820 allowed-ips 198.18.1.0/24
    inns bclient ip link set wgb up
    inns bclient ip route add 198.18.1.0/24 dev wgb src 10.8.2.1
    inns bclient iperf3 -c 198.18.1.5 -t 2 -P "$STREAMS" >/dev/null   # warm up, handshake
    for run in $(seq 1 "$RUNS"); do
        local before after
        before=$(cpu_busy)
        inns bclient iperf3 -c 198.18.1.5 -t "$SECONDS_PER_RUN" -P "$STREAMS" "${IPERF_MODE[@]}" -J > "$WORK/run.json" \
            || { echo "iperf3 failed:"; cat "$WORK/run.json"; exit 1; }
        after=$(cpu_busy)
        python3 - "$label" "$rules" "$run" "$(nproc)" "$before" "$after" "$WORK/run.json" <<'PY'
import json, sys
label, rules, run, ncpu = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
b_busy, b_total = map(int, sys.argv[5].split())
a_busy, a_total = map(int, sys.argv[6].split())
end = json.load(open(sys.argv[7]))["end"]
if "sum_received" in end:
    gbps = end["sum_received"]["bits_per_second"] / 1e9
else:  # older iperf3, UDP: the sender's rate minus what was lost
    gbps = end["sum"]["bits_per_second"] * (1 - end["sum"]["lost_percent"] / 100) / 1e9
cores = (a_busy - b_busy) / (a_total - b_total) * ncpu
print(f"{label:<14} {rules:>6} {run:>4} {gbps:>8.2f} {cores:>7.2f} {cores / gbps:>11.3f}")
PY
    done
}

echo "mode $MODE, $STREAMS stream(s), $SECONDS_PER_RUN s per run, $(nproc) CPUs"
printf '%-14s %6s %4s %8s %7s %11s\n' scenario rules run Gbit/s cores cores/Gbit
if [ -n "$PARALLAX_BASE" ]; then
    scenario base "$PARALLAX_BASE" 0
    scenario base+padding "$PARALLAX_BASE" "$PADDING"
fi
scenario new "$PARALLAX" 0
scenario new+padding "$PARALLAX" "$PADDING"
